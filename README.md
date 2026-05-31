# oss-verify (Go)

A supply chain verification tool for any OSS tool hosted on GitHub. Downloads,
cryptographically verifies, and installs binaries using Sigstore/cosign — with
verification running as a Go library (no subprocess), Rekor log consistency
proofs, and a lockfile that pins hashes across your team.

> **Note:** `oss-verify.sh` (the original bash version) is kept for reference.
> The Go binary is the actively maintained version with stronger security properties.
>
> **Disclaimer:** This tool significantly raises the bar for supply chain attacks
> but cannot stop everything. Read the [limitations](#limitations) section.

---

## What's new in the Go version

### Over the bash script

| Property | Bash | Go |
|---|---|---|
| cosign verification | subprocess `exec cosign` | **library call** via `sigstore-go` |
| Rekor inclusion proof | via cosign subprocess | verified inside process |
| **Rekor consistency proofs** | feasible but impractical in bash | **✓ full Merkle consistency** |
| **Identity–repo cross-check** | ✗ missing (security gap) | **✓ identity must belong to `--repo`** |
| Lockfile missing-hash handling | warn + skip | **abort** |
| Binary install | direct `mv` | **atomic rename via temp file** |
| Post-install hash check | ✗ none | **✓ re-hash installed binary** |
| OS detection | `uname -s` | `runtime.GOOS` (compile-time) |

### Rekor consistency proofs (new)

The bash script verifies an **inclusion proof**: a specific entry exists in the
Rekor Merkle tree. That alone does not prove the log is consistent globally — a
compromised Rekor instance could serve you a custom view of the log while showing
a different tree to everyone else.

The Go version additionally verifies a **consistency proof** on every run:

```
Bundle checkpoint (treeSize=N, rootHash=A)
        ↓  request proof from Rekor
Current tree head (treeSize=M, rootHash=B)
        ↓  verify with RFC 6962 Merkle proof
Confirmed: tree at size M is a strict extension of tree at size N
           (no entries removed or rewritten since the signing event)
```

If the Rekor log has been rolled back, forked, or had entries removed, the
consistency proof fails and the install is aborted.

The current Rekor tree head is also stored in the lockfile. On subsequent
installs, a second consistency check runs between the saved checkpoint and the
new one — detecting any log manipulation that happened between your first and
second install of the same version.

### On Rekor witnesses

The Sigstore ecosystem has a witness network — third-party servers that
independently observe Rekor checkpoints and co-sign them. If witnesses refused
to cosign an inconsistent checkpoint, even a fully compromised Rekor instance
could be detected.

**Why this is not implemented yet (in bash or Go):**

The public Rekor instance (`rekor.sigstore.dev`) currently includes only its
own self-signature in the signed tree head — there are no external witness
cosignatures in the API response to verify. This was confirmed by inspection:

```
— rekor.sigstore.dev <sig>     ← Rekor's own ECDSA P-256 self-signature only
                               ← no external witness lines
```

The witness infrastructure for Rekor exists in the Sigstore ecosystem but is
not yet operationally active in a way that exposes cosignatures to clients.
This is an infrastructure maturity issue, not a tooling one.

**On the "cannot be done in bash" claim:**

That claim was tested and found to be wrong. OpenSSL 3.x supports both
Ed25519 and ECDSA P-256 verification in shell scripts. Rekor's own checkpoint
signature (ECDSA P-256 over the note body) can be verified with:

```bash
openssl dgst -sha256 -verify rekor_pub.pem -signature sig.bin checkpoint_body.txt
```

And Ed25519 (used by external witnesses) works identically:

```bash
openssl pkeyutl -verify -pubin -inkey witness_pub.pem \
  -in checkpoint_body.bin -sigfile witness_sig.bin
```

The real complexity in bash would be parsing the note key format (which
encodes public keys differently from standard PEM) and discovering which
witness endpoints to query — both fiddly but not cryptographically impossible.
Go's `golang.org/x/mod/sumdb/note` package handles the format natively, making
the implementation cleaner. But neither bash nor Go can currently implement
external witness verification against the public Rekor instance because the
cosignatures are not there yet.

When the witness infrastructure matures, adding witness verification is a
meaningful future improvement — in either language.

### Security fix: identity–repo cross-check

In the bash script, the signing identity was extracted from the downloaded bundle
and immediately passed back to cosign as the *accepted* identity — with no check
that it actually belonged to the `--repo` argument. This meant an attacker who
had write access to a release page (but not CI credentials) could upload a bundle
signed by a fork's workflow and have it accepted.

The Go version validates the identity before any verification runs:

```go
// In verify.go — validateIdentityOwnership()
expectedPrefix := "https://github.com/" + repo + "/.github/workflows/"
if !strings.HasPrefix(identity, expectedPrefix) {
    return error // abort
}
```

### Using cosign as a library

The bash script called `cosign verify-blob` as a subprocess, implicitly trusting
whatever `cosign` binary happened to be installed. The Go version imports
`github.com/sigstore/sigstore-go` directly — verification runs inside the process
with no external binary dependency.

```
Bash:  exec.Command("cosign", "verify-blob", ...)  ← trusts installed binary
Go:    import "sigstore-go/pkg/verify"              ← linked at build time
```

---

## How it works

```
Fetch release asset list from GitHub API
        ↓
Auto-detect binary asset for your OS/arch
        ↓
Auto-detect signing pattern (A, B, C, or D)
        ↓
SECURITY: extract identity from cert/bundle
        ↓
SECURITY: validate identity belongs to --repo (NEW — was missing in bash)
        ↓
sigstore-go library verification (no subprocess):
  → cryptographic signature valid
  → certificate issued by Fulcio (Sigstore CA)
  → certificate identity matches expected workflow URL
  → Rekor inclusion proof: entry exists in transparency log
  → OIDC issuer pinned to token.actions.githubusercontent.com
        ↓
Rekor consistency proof (NEW — not possible in bash):
  → fetch current Rekor tree head
  → verify Merkle consistency between bundle checkpoint and current head
  → proves log has not been rolled back since signing
        ↓
Timestamp extraction + optional --cutoff check
        ↓
Lockfile check / write:
  → first run: writes hashes + signing epoch + Rekor checkpoint
  → subsequent runs: verifies all fields; ABORTS on missing fields (not warn+skip)
        ↓
Archive path traversal scan (before extraction)
        ↓
Atomic install (temp file → rename) + post-install hash check
```

---

## Limitations

**This is the most important section.**

### The hardest attack: attacker with live CI credentials

If an attacker compromises a project's CI credentials and publishes a malicious
release, cosign verification will **pass**. The binary is legitimately signed by
the real workflow.

This is what happened with Trivy v0.69.4 in March 2026:
- cosign passes ✅ — signed by Aqua's legitimate CI identity
- Rekor entry exists ✅ — real transparency log entry
- No lockfile yet ✅ — first install, nothing to compare against
- **Result: malware installed**

No technical verification step can save you on a first install of a compromised
version. The `--cutoff` flag and lockfile help after the fact, but not on day zero.

### What the new Go features add

| Attack | cosign | lockfile | consistency proof | Identity-repo check |
|---|---|---|---|---|
| Binary swapped (no CI access) | ✅ | ✅ | — | — |
| Same version re-downloaded after lockfile | — | ✅ | — | — |
| Log rollback/fork by compromised Rekor | ❌ (bash) | ❌ | **✅ (Go only)** | — |
| Bundle from a forked repo's CI | ❌ (bash) | ❌ | — | **✅ (Go only)** |
| CI credential compromise, fresh install | ❌ | ❌ | ❌ | ❌ |

The consistency proof and identity-repo check close two real gaps in the bash version,
but the fundamental ceiling (first install under CI compromise) remains. Human process
— monitoring advisories, deliberate version pinning, delayed upgrades — is the last line
of defence.

---

## Requirements

```bash
go 1.22+

# Direct runtime dependencies (2, down from 3 after architectural fix):
github.com/sigstore/sigstore-go   # pkg/root only — Fulcio trust roots via TUF
github.com/transparency-dev/merkle # RFC 6962 Merkle proof verification
# (stdlib crypto/ecdsa, crypto/x509, net/http handle everything else)
```

System tools optionally needed at runtime:
- `xz` — only if the tool ships `.tar.xz` archives
- `zstd` — only if the tool ships `.tar.zst` archives

---

## Build and install

```bash
go build -o oss-verify .
# Or: go install .
```

A single statically-linkable binary. No cosign binary needed at runtime.

---

## Quick start

```bash
# Install Trivy (Pattern A — direct bundle)
./oss-verify --repo aquasecurity/trivy --version 0.70.0

# Install TruffleHog (Pattern B — cert+sig)
./oss-verify --repo trufflesecurity/trufflehog --version 3.95.3

# Install Grype with a trust cutoff
./oss-verify --repo anchore/grype --version 0.112.0 --cutoff 2026-03-01

# Install gh CLI (binary name differs from repo name)
./oss-verify --repo cli/cli --binary gh --version 2.49.0

# Verify only, do not install
./oss-verify --repo anchore/syft --version 1.19.0 --no-install

# See what the tool would do without downloading anything
./oss-verify --repo aquasecurity/trivy --version 0.70.0 --dry-run
```

---

## Options

| Flag | Description |
|---|---|
| `--repo <owner/repo>` | GitHub repository (required) |
| `--version <x.y.z>` | Exact version (required — no auto-fetch by design) |
| `--binary <name>` | Binary name if it differs from repo name |
| `--cutoff <YYYY-MM-DD>` | Reject binaries signed after this date |
| `--lock-dir <path>` | Override lockfile directory (must be absolute, non-system path) |
| `--install-dir <path>` | Override install directory (default: `~/.local/bin`) |
| `--no-install` | Verify only, skip install |
| `--dry-run` | Print detected pattern and URLs, exit without downloading |
| `--verbose` | Show detailed detection and certificate parsing steps |
| `--help` | Show usage |

### Environment variables

| Variable | Description |
|---|---|
| `OSS_VERIFY_LOCK_DIR` | Default lockfile directory |
| `GITHUB_TOKEN` | GitHub API token (optional, raises rate limit from 60 to 5000 req/h) |

---

## Signing patterns (auto-detected)

The tool inspects release assets and selects one of four paths automatically.

### Pattern A — Direct bundle
Used by: **Trivy**, **cosign**

`sigstore-go` verifies the binary tarball directly against a `.sigstore.json` bundle.
The bundle contains a Rekor `integratedTime` timestamp used for lockfile pinning and
`--cutoff` enforcement.

### Pattern B — Checksums + certificate + signature
Used by: **TruffleHog**, **crane**, **Grype**

Two steps: the checksums file is verified using the Fulcio-issued certificate and
ECDSA signature (via `sigstore/pkg/signature`), then the binary is verified against
the checksums. A Rekor entry search confirms provenance.

### Pattern C — Checksums + sigstore bundle
Used by: **Syft**

Same two-step chain as Pattern B but using a `.sigstore.json` bundle. `sigstore-go`
handles the bundle verification; `sha256sum` checks the binary.

### Pattern D — Checksums only (no cosign)
Fallback for tools without cosign support. Verifies integrity only — warns clearly
that provenance (who built it) is unverified. Refuses `--cutoff` since there is no
signing timestamp.

---

## Lockfile

On first install the tool writes:

```
~/.local/share/oss-verify/trivy-0.70.0-linux-amd64.lock
```

```json
{
  "repo": "aquasecurity/trivy",
  "version": "0.70.0",
  "os_arch": "linux/amd64",
  "pattern": "direct_bundle",
  "signing_epoch": "1746000000",
  "signing_date": "2026-04-30 12:00:00 UTC",
  "identity": "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.70.0",
  "hashes": {
    "binary": "abc123...",
    "bundle": "def456..."
  },
  "rekor_checkpoint": {
    "tree_id": "c0d23d6ad406973f",
    "tree_size": 12345678,
    "root_hash": "aabbcc..."
  }
}
```

The `rekor_checkpoint` is new in the Go version. On subsequent installs, the
tool verifies that the current Rekor tree is consistent with the saved checkpoint
(Merkle consistency proof), detecting any log rollback between installs.

### Sharing lockfiles

```bash
# First install — developer machine
./oss-verify --repo trufflesecurity/trufflehog --version 3.95.3 \
  --lock-dir ./lockfiles

git add lockfiles/trufflehog-3.95.3-linux-amd64.lock
git commit -m "pin trufflehog 3.95.3"

# CI — verifies against committed lockfile
OSS_VERIFY_LOCK_DIR=./lockfiles \
  ./oss-verify --repo trufflesecurity/trufflehog --version 3.95.3
```

---

## Dependency security

### The supply chain problem of a supply chain tool

This tool is designed to protect against compromised dependencies. It therefore
has an obligation to be honest about its own dependency surface.

The Go version has **2 direct dependencies** and **16 indirect ones**
(down from 3 direct / ~70 indirect after the architectural fix below).
The `sigstore/rekor` server stack — MongoDB driver, Let's Encrypt Boulder CA
types, OpenAPI client, OpenTelemetry, Cobra/Viper — has been eliminated.

### What Go's module system already provides

`go.sum` pins the SHA-256 hash of every module zip. If anything on the module
proxy changes after the initial `go mod tidy`, the build fails. The Go
[checksum database](https://sum.golang.org) (itself a transparency log) ensures
those hashes are globally consistent — a compromised proxy cannot serve you
different code for the same version tag without being detected.

**Post-pinning tampering is strongly protected.** The risk is at the moment
a version is first pinned — the same first-install ceiling the tool faces
for the binaries it verifies.

### Short-term: what you should do now

**1. Scan for known CVEs in the dependency tree:**

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

`govulncheck` checks your actual call graph, not just the module list — it only
reports vulnerabilities in code paths that are actually reachable from `main`.

**2. Vendor all dependencies:**

```bash
go mod vendor
git add vendor/
git commit -m "vendor dependencies"
```

Vendoring copies all ~18 packages into a `vendor/` directory inside the repo.
This means:
- The full source of every dependency is visible, diffable, and auditable
- `go build` never fetches from the internet — it builds entirely from local source
- Any future dependency update shows up as a concrete code diff in your PR
- CI builds are reproducible without network access

After vendoring, build with `go build -mod=vendor ./...` to enforce that only
vendored code is used.

### Architectural fix: implemented

The root cause of the original bloat was that `sigstore-go`'s bundle verifier
internally imported `github.com/sigstore/rekor` — the full Rekor *server*
library — to make Rekor API calls. `sigstore/rekor` in turn pulled in MongoDB,
Boulder, the OpenAPI stack, OpenTelemetry, and Cobra/Viper.

**This has been fixed.** `sigstore-go`'s `NewSignedEntityVerifier` and the
entire `github.com/sigstore/sigstore` package have been replaced with direct
stdlib operations. `verify.go` now does the four verification steps itself:

| Step | Was (heavy) | Now (minimal) |
|---|---|---|
| Parse bundle JSON | `sigstore-go/pkg/bundle` | stdlib `encoding/json` (`bundleMinimal`) |
| Verify inclusion proof | `sigstore-go` → `sigstore/rekor` | `transparency-dev/merkle` (in `rekor.go`) |
| Verify cert chain (Fulcio) | `sigstore-go/pkg/verify` | stdlib `crypto/x509` + `sigstore-go/pkg/root` |
| Verify ECDSA signature | `sigstore/pkg/signature` | stdlib `crypto/ecdsa.VerifyASN1` |
| Rekor HTTP calls | `sigstore/rekor` client | `net/http` — always in `rekor.go` |
| Sigstore trust roots | `sigstore-go/pkg/root` + TUF | same — `pkg/root` is lightweight |

**Result:** 3 direct → 2 direct, ~70 indirect → 16 indirect (57 packages
eliminated). All security properties are preserved — the same cryptographic
primitives and the same Sigstore trust roots, now without the server stack.

The only tradeoff is that `integratedTime` (used for `--cutoff`) is read
directly from the bundle JSON rather than from a SET-verified timestamp.
The entry's existence in the Merkle log is still fully proven by the
inclusion proof; only the timestamp metadata field is unverified.
SET verification (Rekor log signature over the entry) is a future improvement.

---

## Security design

See [Security.md](Security.md) for the full security properties and design rationale.

Key properties:
- No `cosign` subprocess — verification runs inside the Go process via `sigstore-go`
- OIDC issuer pinned to `token.actions.githubusercontent.com` — no issuer-free fallback
- Identity extracted from cert/bundle and cross-checked against `--repo` before any verification
- Rekor consistency proof verifies the log has not been rolled back since the signing event
- Lockfile ownership verified before reading — detects pre-planted lockfile attacks
- Lockfile missing hash fields → abort (not warn+skip)
- Atomic install via temp file → rename
- Post-install hash check on the installed binary
- Archive path traversal scan before extraction; symlinks rejected

---

## Legacy bash version

`oss-verify.sh` remains in this repository for reference and as a
bootstrap tool (you can use it to verify the Go binary itself before
trusting the Go binary for subsequent installs).

The bash version has two known security gaps fixed in the Go version:
1. **Identity–repo cross-check missing** — bundle from a forked CI could be accepted
2. **Lockfile missing-hash is warn+skip** — stripping hash fields degrades the lockfile
   guarantee without aborting

The bash version also cannot perform Rekor consistency proofs (requires Merkle
tree verification which is not feasible in portable bash).
