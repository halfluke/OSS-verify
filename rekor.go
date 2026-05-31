package main

// ── Rekor transparency log — consistency proofs ───────────────────────────────
//
// This file implements the primary new security capability of the Go version:
// Rekor log consistency proofs.
//
// The bash script (and cosign CLI) verify an INCLUSION PROOF: that a specific
// entry exists in the Rekor Merkle tree and that the Merkle path from the entry
// to the signed tree head (STH) is valid.
//
// An inclusion proof alone does not guarantee that the Rekor log is in a
// consistent state globally — a compromised Rekor instance could serve you a
// custom view of the log that includes a fraudulent entry with a valid inclusion
// proof, while showing a different tree to other verifiers (a "split view").
//
// A CONSISTENCY PROOF proves that the tree head you see today is a strict
// extension of the tree head you saw before — no entries have been removed,
// rewritten, or rolled back. Combined with periodic independent witness
// cosigning (witnesses also sign Rekor checkpoints), this makes the log
// tamper-evident not just per-entry but as a whole.
//
// Implementation:
//   1. After bundle verification, extract the Rekor tree state (tree ID,
//      tree size, root hash) from the bundle's inclusion proof.
//   2. Fetch the current Rekor tree head from the Rekor REST API.
//   3. Request a consistency proof between the bundle's tree size and
//      the current tree size.
//   4. Verify the proof using github.com/transparency-dev/merkle
//      (RFC 6962 Merkle tree algorithm).
//   5. On first install, save the current Rekor tree head in the lockfile
//      alongside the binary hashes. On subsequent installs, verify that
//      the current Rekor head is consistent with the saved one.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	// transparency-dev/merkle: RFC 6962 Merkle proof verification.
	// Used to verify Rekor consistency proofs without a Rekor client binary.
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// ── RekorCheckpoint ───────────────────────────────────────────────────────────

// RekorCheckpoint holds a signed Rekor tree state.
// Stored in the lockfile and used for consistency proofs on subsequent runs.
type RekorCheckpoint struct {
	TreeID   string `json:"tree_id"`
	TreeSize int64  `json:"tree_size"`
	RootHash string `json:"root_hash"` // hex-encoded
}

const defaultRekorURL = "https://rekor.sigstore.dev"

// ── Extract Rekor checkpoint from a bundle file ───────────────────────────────

// rekorCheckpointFromBundleFile reads the inclusion proof from a sigstore bundle
// and returns the Rekor tree state at the time the entry was added.
func rekorCheckpointFromBundleFile(bundlePath string) (*RekorCheckpoint, error) {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, err
	}
	var bm bundleMinimal
	if err := json.Unmarshal(data, &bm); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}
	if len(bm.VerificationMaterial.TlogEntries) == 0 {
		return nil, fmt.Errorf("bundle contains no tlog entries")
	}
	entry := bm.VerificationMaterial.TlogEntries[0]

	treeSizeStr := entry.InclusionProof.TreeSize
	rootHashHex := entry.InclusionProof.RootHash
	treeID := entry.LogID.KeyID

	if treeSizeStr == "" || rootHashHex == "" {
		return nil, fmt.Errorf("bundle inclusion proof missing tree size or root hash")
	}

	treeSize, err := strconv.ParseInt(treeSizeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing tree size %q: %w", treeSizeStr, err)
	}

	// Normalize root hash to lowercase hex (bundle may use hex or base64).
	rootHashHex, err = normalizeHash(rootHashHex)
	if err != nil {
		return nil, fmt.Errorf("normalizing root hash: %w", err)
	}

	return &RekorCheckpoint{
		TreeID:   treeID,
		TreeSize: treeSize,
		RootHash: rootHashHex,
	}, nil
}

// ── Fetch current Rekor tree head ─────────────────────────────────────────────

// rekorLogInfo is the response shape from GET /api/v1/log.
type rekorLogInfo struct {
	RootHash       string `json:"rootHash"`
	TreeSize       int64  `json:"treeSize"`
	SignedTreeHead string `json:"signedTreeHead"`
	// TreeID is the decimal numeric tree ID returned by the Rekor API.
	// This is NOT the same as logId.keyId in bundles, which is a key fingerprint.
	TreeID string `json:"treeID"`
}

// fetchCurrentRekorHead fetches the current Rekor tree head.
// treeID should be the decimal numeric tree ID from a previous log response,
// or empty to query the default (active) tree.
func fetchCurrentRekorHead(ctx context.Context, rekorURL, treeID string) (*RekorCheckpoint, error) {
	url := rekorURL + "/api/v1/log"
	if treeID != "" {
		url += "?treeID=" + treeID
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Rekor API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("Rekor API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var info rekorLogInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		return nil, fmt.Errorf("parsing Rekor log info: %w", err)
	}

	rootHash, err := normalizeHash(info.RootHash)
	if err != nil {
		return nil, fmt.Errorf("normalizing Rekor root hash: %w", err)
	}

	// Always use the treeID from the response — this is the canonical decimal
	// numeric ID. If a specific treeID was requested and the response differs,
	// the response wins (it may canonicalise the value).
	resolvedTreeID := info.TreeID
	if resolvedTreeID == "" {
		resolvedTreeID = treeID
	}
	return &RekorCheckpoint{
		TreeID:   resolvedTreeID,
		TreeSize: info.TreeSize,
		RootHash: rootHash,
	}, nil
}

// ── Fetch consistency proof from Rekor ───────────────────────────────────────

// rekorConsistencyProof is the response from GET /api/v1/log/proof.
type rekorConsistencyProof struct {
	RootHash string   `json:"rootHash"`
	Hashes   []string `json:"hashes"`
	TreeSize int64    `json:"treeSize"`
}

// fetchRekorConsistencyProof fetches a Merkle consistency proof between two tree sizes.
func fetchRekorConsistencyProof(ctx context.Context, rekorURL string, firstSize, secondSize int64, treeID string) ([][]byte, error) {
	url := fmt.Sprintf("%s/api/v1/log/proof?firstSize=%d&lastSize=%d",
		rekorURL, firstSize, secondSize)
	if treeID != "" {
		url += "&treeID=" + treeID
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching Rekor consistency proof: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("Rekor consistency proof API returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var cp rekorConsistencyProof
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&cp); err != nil {
		return nil, fmt.Errorf("parsing consistency proof response: %w", err)
	}

	// Decode each proof hash from hex (Rekor returns hex-encoded hashes).
	hashes := make([][]byte, 0, len(cp.Hashes))
	for _, h := range cp.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			// Try base64 fallback.
			b, err = base64.StdEncoding.DecodeString(h)
			if err != nil {
				return nil, fmt.Errorf("decoding consistency proof hash %q: %w", h, err)
			}
		}
		hashes = append(hashes, b)
	}
	return hashes, nil
}

// ── Verify consistency proof ──────────────────────────────────────────────────

// verifyMerkleConsistency verifies a Merkle consistency proof using RFC 6962
// (the algorithm used by Rekor, Certificate Transparency, and related logs).
//
// A valid proof confirms that secondRoot is a strict extension of firstRoot —
// all entries present when firstRoot was computed are still present and
// unchanged in the tree whose root is secondRoot.
func verifyMerkleConsistency(firstSize, secondSize int64, proofHashes [][]byte, firstRootHex, secondRootHex string) error {
	firstRoot, err := hex.DecodeString(firstRootHex)
	if err != nil {
		return fmt.Errorf("decoding first root hash: %w", err)
	}
	secondRoot, err := hex.DecodeString(secondRootHex)
	if err != nil {
		return fmt.Errorf("decoding second root hash: %w", err)
	}

	if err := proof.VerifyConsistency(
		rfc6962.DefaultHasher,
		uint64(firstSize),
		uint64(secondSize),
		proofHashes,
		firstRoot,
		secondRoot,
	); err != nil {
		return fmt.Errorf(
			"Rekor consistency proof FAILED.\n"+
				"        First  tree: size=%d root=%s\n"+
				"        Second tree: size=%d root=%s\n"+
				"        This indicates the Rekor log may have been rolled back or forked.\n"+
				"        Do NOT proceed without investigation.\n"+
				"        Error: %w",
			firstSize, firstRootHex[:16]+"...",
			secondSize, secondRootHex[:16]+"...",
			err,
		)
	}
	return nil
}

// ── Main consistency check entry point ───────────────────────────────────────

// checkRekorConsistency runs the full Rekor consistency check:
//   1. Fetch the current Rekor tree head.
//   2. If the lockfile has a saved checkpoint, verify consistency between
//      the saved checkpoint and the current head.
//   3. Verify consistency between the bundle's checkpoint (from the signing
//      event) and the current head — proves the log hasn't been rolled back
//      since the binary was signed.
//
// On first install (no lockfile checkpoint), step 2 is skipped and the
// current tree head is saved to the lockfile for future checks.
func checkRekorConsistency(ctx context.Context, cfg *Config, result *VerifyResult) error {
	bundleCP := result.RekorCheckpoint
	if bundleCP == nil {
		debugf("Rekor consistency: no bundle checkpoint available, skipping")
		return nil
	}

	rekorURL := defaultRekorURL

	// Fetch the current Rekor tree head. Do NOT pass the bundle's logId.keyId
	// as the treeID — that is a key fingerprint (hex), not the numeric tree ID
	// the API requires. Fetching without treeID returns the active tree's head
	// along with its numeric treeID in the response, which we then use for
	// the consistency proof call.
	currentCP, err := fetchCurrentRekorHead(ctx, rekorURL, "")
	if err != nil {
		logWarn("Could not fetch Rekor tree head: %v — skipping consistency check.", err)
		return nil
	}
	debugf("Rekor current head: treeID=%s treeSize=%d rootHash=%s...",
		currentCP.TreeID, currentCP.TreeSize, currentCP.RootHash[:16])

	// Verify that the current head is an extension of the bundle checkpoint.
	// This proves the log has not been rolled back since the signing event.
	// Use the decimal treeID from the current head for the API call.
	if currentCP.TreeSize > bundleCP.TreeSize {
		proofHashes, err := fetchRekorConsistencyProof(ctx, rekorURL, bundleCP.TreeSize, currentCP.TreeSize, currentCP.TreeID)
		if err != nil {
			logWarn("Could not fetch consistency proof (bundle→current): %v — skipping.", err)
		} else {
			if err := verifyMerkleConsistency(bundleCP.TreeSize, currentCP.TreeSize, proofHashes, bundleCP.RootHash, currentCP.RootHash); err != nil {
				return fmt.Errorf("Rekor log consistency check failed (bundle→current): %w", err)
			}
			logInfo("Rekor: log consistency verified (bundle→current, %d→%d entries)",
				bundleCP.TreeSize, currentCP.TreeSize)
		}
	} else if currentCP.TreeSize == bundleCP.TreeSize {
		if currentCP.RootHash != bundleCP.RootHash {
			return fmt.Errorf(
				"Rekor log MISMATCH: same tree size but different root hash.\n"+
					"        Bundle root: %s\n"+
					"        Current root: %s\n"+
					"        This indicates potential log tampering.",
				bundleCP.RootHash, currentCP.RootHash,
			)
		}
		logInfo("Rekor: log state matches bundle checkpoint exactly")
	} else {
		logWarn("Current Rekor tree (%d) is smaller than bundle checkpoint (%d) — possible rollback.",
			currentCP.TreeSize, bundleCP.TreeSize)
	}

	// Store the current tree head in the result for lockfile persistence.
	result.RekorCheckpoint = currentCP
	return nil
}

// ── Rekor entry search for Pattern B ─────────────────────────────────────────

// rekorSearchRequest is the payload for POST /api/v1/index/retrieve.
type rekorSearchRequest struct {
	Hash string `json:"hash,omitempty"`
}

// searchRekorForEntry searches Rekor for a log entry matching the artifact digest.
// Used in Pattern B (cert+sig) verification to confirm a transparency log entry
// exists for the signing event.
func searchRekorForEntry(ctx context.Context, hexDigest string, certDER, sigBytes []byte) (bool, error) {
	payload, err := json.Marshal(rekorSearchRequest{
		Hash: "sha256:" + hexDigest,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		defaultRekorURL+"/api/v1/index/retrieve",
		strings.NewReader(string(payload)))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("Rekor index search failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, fmt.Errorf("Rekor index API returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Response is an array of log entry UUIDs.
	var uuids []string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&uuids); err != nil {
		return false, fmt.Errorf("parsing Rekor index response: %w", err)
	}
	return len(uuids) > 0, nil
}

// ── Rekor Merkle inclusion proof ─────────────────────────────────────────────

// verifyInclusionProof verifies that the bundle's canonicalized entry body
// is committed to the Merkle tree described by the bundle's inclusion proof.
//
// The RFC 6962 leaf hash is computed as:
//
//	rfc6962.DefaultHasher.HashLeaf(base64decode(entry.CanonicalizedBody))
//	= SHA256(0x00 || canonBodyBytes)
//
// This is then verified against the sibling hashes and root hash from the
// inclusion proof, confirming the entry was appended to the Rekor log at
// the stated position (logIndex).
func verifyInclusionProof(entry bundleTlogEntry) error {
	ip := entry.InclusionProof
	if ip.LogIndex == "" || ip.TreeSize == "" || ip.RootHash == "" || entry.CanonicalizedBody == "" {
		return fmt.Errorf("bundle inclusion proof is incomplete " +
			"(missing logIndex, treeSize, rootHash, or canonicalizedBody)")
	}

	// Compute the RFC 6962 leaf hash from the canonicalized entry body.
	canonBytes, err := base64.StdEncoding.DecodeString(entry.CanonicalizedBody)
	if err != nil {
		return fmt.Errorf("decoding canonicalizedBody: %w", err)
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(canonBytes)

	logIdx, err := strconv.ParseUint(ip.LogIndex, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing inclusionProof.logIndex %q: %w", ip.LogIndex, err)
	}
	treeSz, err := strconv.ParseUint(ip.TreeSize, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing inclusionProof.treeSize %q: %w", ip.TreeSize, err)
	}

	rootHashHex, err := normalizeHash(ip.RootHash)
	if err != nil {
		return fmt.Errorf("normalizing inclusion proof rootHash: %w", err)
	}
	rootHashBytes, err := hex.DecodeString(rootHashHex)
	if err != nil {
		return fmt.Errorf("decoding rootHash hex: %w", err)
	}

	siblingHashes := make([][]byte, 0, len(ip.Hashes))
	for i, h := range ip.Hashes {
		hHex, err := normalizeHash(h)
		if err != nil {
			return fmt.Errorf("normalizing inclusion proof hash[%d]: %w", i, err)
		}
		hBytes, err := hex.DecodeString(hHex)
		if err != nil {
			return fmt.Errorf("decoding inclusion proof hash[%d]: %w", i, err)
		}
		siblingHashes = append(siblingHashes, hBytes)
	}

	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, logIdx, treeSz, leafHash, siblingHashes, rootHashBytes); err != nil {
		return fmt.Errorf(
			"Rekor inclusion proof FAILED.\n"+
				"        LogIndex: %d, TreeSize: %d, RootHash: %s...\n"+
				"        The Rekor entry may be invalid or the bundle tampered with.\n"+
				"        Error: %w",
			logIdx, treeSz, rootHashHex[:16], err,
		)
	}
	return nil
}

// ── Hash normalization ────────────────────────────────────────────────────────

// normalizeHash converts a hash to lowercase hex, accepting either hex or base64 input.
func normalizeHash(h string) (string, error) {
	h = strings.TrimSpace(h)
	// If it looks like hex (64 chars, all hex digits), accept as-is.
	if len(h) == 64 {
		if _, err := hex.DecodeString(h); err == nil {
			return strings.ToLower(h), nil
		}
	}
	// Try base64 decode.
	b, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(h)
		if err != nil {
			return "", fmt.Errorf("hash %q is neither hex nor base64", h[:min(len(h), 16)])
		}
	}
	return hex.EncodeToString(b), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

