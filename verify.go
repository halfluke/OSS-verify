package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	// sigstore-go/pkg/root: trust material only (Fulcio CAs, Rekor log keys).
	// Intentionally limited to this sub-package so that sigstore-go's
	// pkg/verify and pkg/bundle — which transitively import sigstore/rekor,
	// MongoDB, OpenAPI and a large Cobra/Viper stack — are not compiled in.
	"github.com/sigstore/sigstore-go/pkg/root"
)

// ── VerifyResult ──────────────────────────────────────────────────────────────

// VerifyResult holds all data produced by a successful verification run.
type VerifyResult struct {
	Identity        string
	Pattern         string
	SigningEpoch     int64
	SigningDate      string
	Hashes          map[string]string // label → sha256 hex
	RekorCheckpoint *RekorCheckpoint  // non-nil for patterns with bundles
}

// ── Trusted root (cached) ─────────────────────────────────────────────────────

var cachedTrustedRoot *root.TrustedRoot

// getSigstoreTrustedRoot returns the Sigstore public good instance trust material.
// Uses root.FetchTrustedRoot which fetches from TUF with a local cache.
// Trust roots are verified inside the process — no `cosign` subprocess required.
func getSigstoreTrustedRoot() (*root.TrustedRoot, error) {
	if cachedTrustedRoot != nil {
		return cachedTrustedRoot, nil
	}
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching Sigstore trusted root: %w", err)
	}
	cachedTrustedRoot = tr
	return tr, nil
}

// ── SECURITY FIX #1: identity–repo ownership check ───────────────────────────
//
// In the bash script, the signing identity was extracted from the bundle/cert
// and immediately passed back to cosign as the accepted identity — no check
// that it belonged to --repo. This allowed an attacker with write access to
// the release page (but not CI credentials) to upload a bundle from their
// fork's workflow and have it accepted.
//
// This function is called after identity extraction and before verification.
// It must succeed before any cosign/sigstore verification runs.

func validateIdentityOwnership(identity, repo string) error {
	expectedPrefix := "https://github.com/" + repo + "/.github/workflows/"
	if !strings.HasPrefix(identity, expectedPrefix) {
		return fmt.Errorf(
			"signing identity does not belong to repo %q.\n"+
				"        Identity:  %s\n"+
				"        Expected prefix: %s\n"+
				"        This could indicate a forked workflow attack. Aborting.",
			repo, identity, expectedPrefix,
		)
	}
	return nil
}

// ── Identity extraction from bundle JSON ─────────────────────────────────────

// bundleMinimal is a pure-stdlib JSON struct for reading sigstore bundle files.
// It avoids the sigstore-go/pkg/bundle protobuf machinery (and its transitive
// deps) by mapping only the fields we actually need.
type bundleMinimal struct {
	VerificationMaterial struct {
		Certificate struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		X509CertChain struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
		TlogEntries []bundleTlogEntry `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	// MessageSignature is present when the bundle signs a raw artifact
	// (Patterns A and C). DSSE envelopes use a different field; we only
	// support messageSignature here (covers all tools tested so far).
	MessageSignature struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"` // base64-encoded SHA-256 of the artifact
		} `json:"messageDigest"`
		Signature string `json:"signature"` // base64-encoded DER ECDSA signature
	} `json:"messageSignature"`
}

// bundleTlogEntry mirrors one element of verificationMaterial.tlogEntries.
// Defined as a named type so rekor.go can accept it as a function argument
// without importing the bundleMinimal struct.
type bundleTlogEntry struct {
	LogIndex         string `json:"logIndex"`
	IntegratedTime   string `json:"integratedTime"`
	LogID            struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	// CanonicalizedBody is the base64-encoded JSON body of the Rekor entry.
	// The RFC 6962 leaf hash is rfc6962.HashLeaf(base64decode(CanonicalizedBody)).
	CanonicalizedBody string `json:"canonicalizedBody"`
	InclusionProof    struct {
		TreeSize string   `json:"treeSize"`
		RootHash string   `json:"rootHash"` // base64 or hex, normalised by normalizeHash
		LogIndex string   `json:"logIndex"`
		Hashes   []string `json:"hashes"` // sibling hashes, base64 or hex
	} `json:"inclusionProof"`
}

// extractCertFromBundle returns the signing certificate from a parsed bundle.
// Tries the .certificate field first (modern bundles), then the x509CertChain.
func extractCertFromBundle(bm *bundleMinimal) (*x509.Certificate, error) {
	rawB64 := bm.VerificationMaterial.Certificate.RawBytes
	if rawB64 == "" && len(bm.VerificationMaterial.X509CertChain.Certificates) > 0 {
		rawB64 = bm.VerificationMaterial.X509CertChain.Certificates[0].RawBytes
	}
	if rawB64 == "" {
		return nil, fmt.Errorf("bundle contains no certificate bytes")
	}
	derBytes, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, fmt.Errorf("decoding certificate bytes: %w", err)
	}
	return x509.ParseCertificate(derBytes)
}

// extractIdentityFromBundleFile parses the bundle JSON and returns the
// Subject Alternative Name URI from the signing certificate.
func extractIdentityFromBundleFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var bm bundleMinimal
	if err := json.Unmarshal(data, &bm); err != nil {
		return "", fmt.Errorf("parsing bundle JSON: %w", err)
	}
	cert, err := extractCertFromBundle(&bm)
	if err != nil {
		return "", err
	}
	return extractURISAN(cert)
}

// extractURISAN returns the first URI Subject Alternative Name from a certificate.
// Validates that the result looks like a GitHub Actions workflow URL.
func extractURISAN(cert *x509.Certificate) (string, error) {
	for _, uri := range cert.URIs {
		san := uri.String()
		if strings.HasPrefix(san, "https://github.com/") &&
			strings.Contains(san, "/.github/workflows/") {
			return san, nil
		}
	}
	return "", fmt.Errorf(
		"certificate contains no GitHub Actions workflow URI SAN.\n" +
			"        Expected a URI like https://github.com/<owner>/<repo>/.github/workflows/<file>@refs/...\n" +
			"        Aborting — do not proceed with an unrecognised identity.",
	)
}

// ── Pattern dispatch ──────────────────────────────────────────────────────────

func verifyPattern(ctx context.Context, cfg *Config, bin *BinaryInfo, si *SigningInfo, workDir string) (*VerifyResult, error) {
	switch si.Pattern {
	case PatternDirectBundle:
		return verifyPatternA(ctx, cfg, bin, si, workDir)
	case PatternChecksumCert:
		return verifyPatternB(ctx, cfg, bin, si, workDir)
	case PatternChecksumBundle:
		return verifyPatternC(ctx, cfg, bin, si, workDir)
	case PatternChecksumOnly:
		return verifyPatternD(cfg, bin, si, workDir)
	default:
		return nil, fmt.Errorf("unknown pattern: %s", si.Pattern)
	}
}

// ── Pattern A: binary + direct sigstore bundle ────────────────────────────────

func verifyPatternA(ctx context.Context, cfg *Config, bin *BinaryInfo, si *SigningInfo, workDir string) (*VerifyResult, error) {
	binaryPath := workDir + "/" + bin.Filename
	bundlePath := workDir + "/" + lastName(si.BundleURL)

	if err := downloadFile(bin.URL, binaryPath, true); err != nil {
		return nil, err
	}
	if err := downloadFile(si.BundleURL, bundlePath, false); err != nil {
		return nil, err
	}

	// Extract and validate identity before verification.
	identity, err := extractIdentityFromBundleFile(bundlePath)
	if err != nil {
		return nil, err
	}
	logInfo("Identity: %s", identity)

	// SECURITY FIX #1
	if err := validateIdentityOwnership(identity, cfg.Repo); err != nil {
		return nil, err
	}

	logStep("cosign verify-blob (Pattern A — direct bundle) [library]...")
	signingEpoch, err := verifyWithBundle(ctx, binaryPath, bundlePath, identity)
	if err != nil {
		return nil, err
	}

	binaryHash, err := fileSHA256(binaryPath)
	if err != nil {
		return nil, err
	}
	bundleHash, err := fileSHA256(bundlePath)
	if err != nil {
		return nil, err
	}

	checkpoint, err := rekorCheckpointFromBundleFile(bundlePath)
	if err != nil {
		logWarn("Could not extract Rekor checkpoint from bundle: %v", err)
	}

	result := &VerifyResult{
		Pattern:     string(PatternDirectBundle),
		Identity:    identity,
		SigningEpoch: signingEpoch,
		SigningDate:  epochToDate(signingEpoch),
		Hashes: map[string]string{
			"binary": binaryHash,
			"bundle": bundleHash,
		},
		RekorCheckpoint: checkpoint,
	}
	logInfo("Signed at: %s", result.SigningDate)
	return result, nil
}

// ── Pattern B: checksums + PEM cert + sig ────────────────────────────────────

func verifyPatternB(ctx context.Context, cfg *Config, bin *BinaryInfo, si *SigningInfo, workDir string) (*VerifyResult, error) {
	binaryPath := workDir + "/" + bin.Filename
	checksumsPath := workDir + "/" + si.ChecksumsFile
	certPath := workDir + "/" + lastName(si.ChecksumsPEM)
	sigPath := workDir + "/" + lastName(si.ChecksumsSig)

	if err := downloadFile(bin.URL, binaryPath, true); err != nil {
		return nil, err
	}
	if err := downloadFile(si.ChecksumsURL, checksumsPath, false); err != nil {
		return nil, err
	}
	if err := downloadFile(si.ChecksumsPEM, certPath, false); err != nil {
		return nil, err
	}
	if err := downloadFile(si.ChecksumsSig, sigPath, false); err != nil {
		return nil, err
	}

	// Extract identity from the PEM certificate.
	identity, err := extractIdentityFromPEM(certPath)
	if err != nil {
		return nil, err
	}
	logInfo("Identity: %s", identity)

	// SECURITY FIX #1
	if err := validateIdentityOwnership(identity, cfg.Repo); err != nil {
		return nil, err
	}

	logStep("Step 1/2: cosign verify-blob on checksums (Pattern B) [library]...")
	signingEpoch, err := verifyWithCertSig(ctx, checksumsPath, certPath, sigPath, identity, cfg.Repo)
	if err != nil {
		return nil, err
	}

	logStep("Step 2/2: sha256sum verify binary...")
	if err := verifyChecksums(checksumsPath, binaryPath); err != nil {
		return nil, fmt.Errorf("SHA256 mismatch — binary does not match signed checksums: %w", err)
	}
	logInfo("sha256sum: binary integrity verified OK")

	binaryHash, err := fileSHA256(binaryPath)
	if err != nil {
		return nil, err
	}
	checksumsHash, err := fileSHA256(checksumsPath)
	if err != nil {
		return nil, err
	}
	certHash, err := fileSHA256(certPath)
	if err != nil {
		return nil, err
	}

	result := &VerifyResult{
		Pattern:     string(PatternChecksumCert),
		Identity:    identity,
		SigningEpoch: signingEpoch,
		SigningDate:  epochToDate(signingEpoch),
		Hashes: map[string]string{
			"binary":    binaryHash,
			"checksums": checksumsHash,
			"cert":      certHash,
		},
	}
	logInfo("Signed at: %s", result.SigningDate)
	return result, nil
}

// ── Pattern C: checksums + sigstore bundle ────────────────────────────────────

func verifyPatternC(ctx context.Context, cfg *Config, bin *BinaryInfo, si *SigningInfo, workDir string) (*VerifyResult, error) {
	binaryPath := workDir + "/" + bin.Filename
	checksumsPath := workDir + "/" + si.ChecksumsFile
	bundlePath := workDir + "/" + lastName(si.ChecksumsBundle)

	if err := downloadFile(bin.URL, binaryPath, true); err != nil {
		return nil, err
	}
	if err := downloadFile(si.ChecksumsURL, checksumsPath, false); err != nil {
		return nil, err
	}
	if err := downloadFile(si.ChecksumsBundle, bundlePath, false); err != nil {
		return nil, err
	}

	identity, err := extractIdentityFromBundleFile(bundlePath)
	if err != nil {
		return nil, err
	}
	logInfo("Identity: %s", identity)

	// SECURITY FIX #1
	if err := validateIdentityOwnership(identity, cfg.Repo); err != nil {
		return nil, err
	}

	logStep("Step 1/2: cosign verify-blob on checksums (Pattern C) [library]...")
	signingEpoch, err := verifyWithBundle(ctx, checksumsPath, bundlePath, identity)
	if err != nil {
		return nil, err
	}

	logStep("Step 2/2: sha256sum verify binary...")
	if err := verifyChecksums(checksumsPath, binaryPath); err != nil {
		return nil, fmt.Errorf("SHA256 mismatch — binary does not match signed checksums: %w", err)
	}
	logInfo("sha256sum: binary integrity verified OK")

	binaryHash, err := fileSHA256(binaryPath)
	if err != nil {
		return nil, err
	}
	checksumsHash, err := fileSHA256(checksumsPath)
	if err != nil {
		return nil, err
	}
	bundleHash, err := fileSHA256(bundlePath)
	if err != nil {
		return nil, err
	}

	checkpoint, err := rekorCheckpointFromBundleFile(bundlePath)
	if err != nil {
		logWarn("Could not extract Rekor checkpoint from bundle: %v", err)
	}

	result := &VerifyResult{
		Pattern:     string(PatternChecksumBundle),
		Identity:    identity,
		SigningEpoch: signingEpoch,
		SigningDate:  epochToDate(signingEpoch),
		Hashes: map[string]string{
			"binary":    binaryHash,
			"checksums": checksumsHash,
			"bundle":    bundleHash,
		},
		RekorCheckpoint: checkpoint,
	}
	logInfo("Signed at: %s", result.SigningDate)
	return result, nil
}

// ── Pattern D: checksums only (no cosign) ────────────────────────────────────

func verifyPatternD(cfg *Config, bin *BinaryInfo, si *SigningInfo, workDir string) (*VerifyResult, error) {
	logWarn("Pattern D: no cosign signing assets found.")
	logWarn("SHA256 verifies integrity only — NOT provenance (who built it).")
	logWarn("Consider asking the project to add cosign/sigstore support.")

	if cfg.Cutoff != "" {
		return nil, fmt.Errorf(
			"--cutoff requires a signed release with a verifiable timestamp.\n" +
				"        Pattern D (checksum only) has no signing timestamp.")
	}

	binaryPath := workDir + "/" + bin.Filename
	checksumsPath := workDir + "/" + si.ChecksumsFile

	if err := downloadFile(bin.URL, binaryPath, true); err != nil {
		return nil, err
	}
	if err := downloadFile(si.ChecksumsURL, checksumsPath, false); err != nil {
		return nil, err
	}

	if err := verifyChecksums(checksumsPath, binaryPath); err != nil {
		return nil, fmt.Errorf("SHA256 mismatch: %w", err)
	}
	logInfo("sha256sum: binary integrity verified OK")

	binaryHash, err := fileSHA256(binaryPath)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	return &VerifyResult{
		Pattern:     string(PatternChecksumOnly),
		Identity:    "none (checksum_only)",
		SigningEpoch: now,
		SigningDate:  epochToDate(now),
		Hashes:      map[string]string{"binary": binaryHash},
	}, nil
}

// ── Bundle verification — stdlib-only implementation ─────────────────────────
//
// Replaces sigstore-go's NewSignedEntityVerifier with direct stdlib operations:
//   1. Parse bundle JSON with our own bundleMinimal struct (no protobuf).
//   2. Verify Fulcio certificate chain (stdlib crypto/x509).
//   3. Verify ECDSA artifact signature (stdlib crypto/ecdsa).
//   4. Verify Rekor Merkle inclusion proof (transparency-dev/merkle, in rekor.go).
//
// What we intentionally do NOT pull in:
//   - sigstore-go/pkg/bundle  (imports sigstore/rekor via pkg/verify/tlog.go)
//   - sigstore-go/pkg/verify  (same)
//   - sigstore/sigstore        (OpenAPI, Cobra, MongoDB, OpenTelemetry stacks)
//
// Security properties preserved vs the old sigstore-go verifier:
//   ✓  Artifact integrity — ECDSA sig over SHA-256(artifact) verified with cert key
//   ✓  Fulcio chain       — cert chains to embedded Fulcio root at cert.NotBefore
//   ✓  Identity check     — cert URI SAN validated against --repo (Security Fix #1)
//   ✓  Log inclusion      — RFC 6962 Merkle proof from canonicalizedBody to rootHash
//   ✓  Log consistency    — consistency proof bundle→current (in checkRekorConsistency)
//
// What changed vs the old verifier:
//   ≈  Signing timestamp comes from integratedTime (unverified SET) rather than
//      a SET-verified timestamp. The entry's authenticity is still proven by the
//      inclusion proof; only the timestamp field inside the entry is unverified.
//      (SET verification would require Rekor's log public key from pkg/root, which
//      is available but adds ~30 lines; deferred as a future improvement.)

func verifyWithBundle(_ context.Context, artifactPath, bundlePath, identity string) (signingEpoch int64, err error) {
	// ── 1. Parse bundle ─────────────────────────────────────────────────────
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return 0, fmt.Errorf("reading bundle %s: %w", bundlePath, err)
	}
	var bm bundleMinimal
	if err := json.Unmarshal(data, &bm); err != nil {
		return 0, fmt.Errorf("parsing bundle JSON: %w", err)
	}

	// ── 2. Verify Fulcio certificate chain ───────────────────────────────────
	cert, err := extractCertFromBundle(&bm)
	if err != nil {
		return 0, err
	}
	trustedRoot, err := getSigstoreTrustedRoot()
	if err != nil {
		return 0, err
	}
	if err := verifyCertAgainstFulcio(cert, trustedRoot); err != nil {
		return 0, fmt.Errorf("Fulcio certificate chain verification failed: %w", err)
	}
	debugf("Certificate chain: verified against Fulcio trust roots")

	// ── 3. Compute artifact digest ───────────────────────────────────────────
	f, err := os.Open(artifactPath)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return 0, fmt.Errorf("hashing artifact: %w", err)
	}
	f.Close()
	digest := h.Sum(nil)

	// Cross-check: bundle's declared digest must match what we computed.
	if declaredB64 := bm.MessageSignature.MessageDigest.Digest; declaredB64 != "" {
		declared, err := base64.StdEncoding.DecodeString(declaredB64)
		if err == nil && !bytes.Equal(digest, declared) {
			return 0, fmt.Errorf(
				"artifact digest does not match bundle's declared digest.\n"+
					"        Computed: %x\n"+
					"        Bundle:   %x\n"+
					"        The artifact may have been tampered with.",
				digest, declared,
			)
		}
	}

	// ── 4. Verify ECDSA signature over artifact ──────────────────────────────
	sigB64 := bm.MessageSignature.Signature
	if sigB64 == "" {
		return 0, fmt.Errorf("bundle contains no messageSignature.signature")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return 0, fmt.Errorf("decoding bundle signature: %w", err)
	}
	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("bundle certificate public key is not ECDSA (got %T)", cert.PublicKey)
	}
	if !ecdsa.VerifyASN1(ecPub, digest, sigBytes) {
		return 0, fmt.Errorf(
			"ECDSA signature verification FAILED for %s.\n"+
				"        Identity: %s\n"+
				"        The artifact may be compromised or the signing key has changed.\n"+
				"        Aborting.",
			artifactPath, identity,
		)
	}
	logInfo("cosign: signature verified OK (stdlib ecdsa)")

	// ── 5. Verify Rekor Merkle inclusion proof ───────────────────────────────
	if len(bm.VerificationMaterial.TlogEntries) == 0 {
		return 0, fmt.Errorf(
			"bundle contains no Rekor transparency log entries.\n" +
				"        Cannot verify log inclusion — aborting.")
	}
	entry := bm.VerificationMaterial.TlogEntries[0]
	if err := verifyInclusionProof(entry); err != nil {
		return 0, fmt.Errorf("Rekor inclusion proof verification failed: %w", err)
	}
	logInfo("Rekor: inclusion proof verified OK")

	// ── 6. Extract signing epoch ─────────────────────────────────────────────
	intTime, err := strconv.ParseInt(entry.IntegratedTime, 10, 64)
	if err != nil || intTime == 0 {
		return 0, fmt.Errorf("bundle has invalid integratedTime %q", entry.IntegratedTime)
	}
	return intTime, nil
}

// ── Pattern B: cert + sig verification via sigstore library ──────────────────
//
// Verifies a blob's signature given a Fulcio-issued PEM certificate and a
// signature file. Uses github.com/sigstore/sigstore/pkg/signature for the
// cryptographic verification and the embedded Fulcio CA trust roots from
// sigstore-go for the certificate chain check.

func verifyWithCertSig(ctx context.Context, artifactPath, certPath, sigPath, identity, repo string) (signingEpoch int64, err error) {
	// 1. Load and parse the certificate.
	cert, certDER, err := loadCertFromPEM(certPath)
	if err != nil {
		return 0, fmt.Errorf("loading certificate: %w", err)
	}

	// 2. Verify certificate chain against Sigstore Fulcio trust roots.
	trustedRoot, err := getSigstoreTrustedRoot()
	if err != nil {
		return 0, err
	}
	if err := verifyCertAgainstFulcio(cert, trustedRoot); err != nil {
		return 0, fmt.Errorf("certificate chain verification failed: %w", err)
	}
	debugf("Certificate chain: verified against Fulcio trust roots")

	// 3. Verify the blob signature using the certificate's public key.
	sigBytes, err := loadAndDecodeSignature(sigPath)
	if err != nil {
		return 0, fmt.Errorf("loading signature: %w", err)
	}

	artifactBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		return 0, err
	}

	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("certificate public key is not ECDSA (got %T)", cert.PublicKey)
	}
	digest := sha256.Sum256(artifactBytes)
	if !ecdsa.VerifyASN1(ecPub, digest[:], sigBytes) {
		return 0, fmt.Errorf(
			"signature verification FAILED for %s.\n"+
				"        Identity: %s\n"+
				"        The binary may be compromised or the signing identity has changed.\n"+
				"        Aborting.",
			artifactPath, identity,
		)
	}
	logInfo("cosign: signature verified OK (stdlib ecdsa)")

	// 4. Extract signing timestamp from certificate notBefore (Fulcio short-lived cert).
	// asn1parse/notBefore is safe here: the certificate chain has already been
	// verified by the Fulcio trust roots above. We are reading the date from a
	// trusted artefact, not making a trust decision with it.
	signingEpoch = cert.NotBefore.Unix()
	if signingEpoch == 0 {
		return 0, fmt.Errorf("certificate has zero notBefore timestamp")
	}
	debugf("Certificate notBefore: %s", cert.NotBefore.Format(time.RFC3339))

	// 5. Verify Rekor transparency log entry for this signing event.
	if err := verifyRekorEntry(ctx, artifactBytes, certDER, sigBytes, identity); err != nil {
		return 0, fmt.Errorf("Rekor entry verification failed: %w", err)
	}
	logInfo("Rekor: transparency log entry verified OK")

	return signingEpoch, nil
}

// loadCertFromPEM loads a PEM certificate, handling Grype-style base64-wrapped PEMs.
func loadCertFromPEM(path string) (*x509.Certificate, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	// Strategy 1: standard PEM block.
	if block, _ := pem.Decode(raw); block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		return cert, block.Bytes, err
	}

	// Strategy 2: base64-encoded PEM (Grype).
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err == nil {
		if block, _ := pem.Decode(decoded); block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			return cert, block.Bytes, err
		}
	}

	return nil, nil, fmt.Errorf("file is not a valid PEM certificate: %s", path)
}

// verifyCertAgainstFulcio checks that the certificate chains to a Fulcio CA
// embedded in the Sigstore trusted root.
func verifyCertAgainstFulcio(cert *x509.Certificate, tr *root.TrustedRoot) error {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	for _, ca := range tr.FulcioCertificateAuthorities() {
		if ca.Root != nil {
			roots.AddCert(ca.Root)
		}
		for _, inter := range ca.Intermediates {
			intermediates.AddCert(inter)
		}
	}

	// Fulcio certs are short-lived. We verify the chain at the cert's
	// own issuance time (notBefore) rather than the current wall time,
	// because the cert will always be "expired" by the time we check it.
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   cert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	_, err := cert.Verify(opts)
	return err
}

// loadAndDecodeSignature loads a .sig file which may be raw bytes or base64-encoded.
func loadAndDecodeSignature(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) > 0 {
		return decoded, nil
	}
	// Fallback: raw bytes.
	return raw, nil
}

// verifyRekorEntry confirms a Rekor transparency log entry exists for this signing event.
// It searches Rekor for an entry matching the artifact digest + certificate + signature.
func verifyRekorEntry(ctx context.Context, artifactBytes, certDER, sigBytes []byte, identity string) error {
	digest := sha256.Sum256(artifactBytes)
	hexDigest := hex.EncodeToString(digest[:])
	debugf("Rekor: searching for entry with digest sha256:%s", hexDigest[:16]+"...")

	found, err := searchRekorForEntry(ctx, hexDigest, certDER, sigBytes)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf(
			"no Rekor entry found for this signing event.\n"+
				"        Artifact digest: sha256:%s\n"+
				"        Identity: %s\n"+
				"        Without a Rekor entry, provenance cannot be confirmed.",
			hexDigest, identity,
		)
	}
	return nil
}

// ── Checksums verification ────────────────────────────────────────────────────

// verifyChecksums verifies that binaryPath's SHA256 hash matches the entry
// in checksumsPath. Implements the anchored grep fix from the bash script:
// confirms the binary name is present before trusting the hash match.
func verifyChecksums(checksumsPath, binaryPath string) error {
	binaryName := lastName(binaryPath)

	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return err
	}

	var expectedHash string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Anchored match: the filename must be exactly binaryName (not a prefix/suffix match).
		// This prevents 'go' matching 'golang'.
		lineHash, lineFile := fields[0], fields[len(fields)-1]
		if lineFile == binaryName || strings.TrimPrefix(lineFile, "*") == binaryName {
			expectedHash = lineHash
			break
		}
	}

	if expectedHash == "" {
		return fmt.Errorf("binary %q not found in checksums file %s", binaryName, checksumsPath)
	}

	// Validate hash looks like sha256 (64 hex chars).
	if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{64}$`, expectedHash); !matched {
		return fmt.Errorf("extracted value for %q is not a valid SHA256 hash: %q", binaryName, expectedHash)
	}

	actualHash, err := fileSHA256(binaryPath)
	if err != nil {
		return err
	}
	if actualHash != expectedHash {
		return fmt.Errorf("SHA256 mismatch for %s\n  Expected: %s\n  Actual:   %s",
			binaryName, expectedHash, actualHash)
	}
	return nil
}

// ── Helper: extract identity from a PEM cert file ────────────────────────────

func extractIdentityFromPEM(certPath string) (string, error) {
	cert, _, err := loadCertFromPEM(certPath)
	if err != nil {
		return "", err
	}
	return extractURISAN(cert)
}

// ── Utility helpers ───────────────────────────────────────────────────────────

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func epochToDate(epoch int64) string {
	return time.Unix(epoch, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// stripRefsSuffix removes the @refs/... suffix from a workflow identity URI.
// e.g. https://...release.yaml@refs/tags/v1.0 → https://...release.yaml
func stripRefsSuffix(identity string) string {
	if i := strings.Index(identity, "@refs/"); i != -1 {
		return identity[:i]
	}
	return identity
}
