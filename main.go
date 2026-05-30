// oss-verify — Supply chain verification for any OSS tool on GitHub.
// Go reimplementation using cosign/sigstore-go as a library (no subprocess).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ── Colour helpers ────────────────────────────────────────────────────────────

const (
	colRed    = "\033[0;31m"
	colGreen  = "\033[0;32m"
	colYellow = "\033[1;33m"
	colCyan   = "\033[0;36m"
	colReset  = "\033[0m"
)

func logInfo(format string, a ...any) {
	fmt.Printf(colGreen+"[INFO]"+colReset+"  "+format+"\n", a...)
}
func logWarn(format string, a ...any) {
	fmt.Printf(colYellow+"[WARN]"+colReset+"  "+format+"\n", a...)
}
func logStep(format string, a ...any) {
	fmt.Printf(colCyan+"[STEP]"+colReset+"  "+format+"\n", a...)
}
func logFail(format string, a ...any) string {
	return fmt.Sprintf(colRed+"[FAIL]"+colReset+"  "+format, a...)
}

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	Repo       string // owner/repo
	Version    string // without leading v
	Binary     string // override binary name
	Cutoff     string // YYYY-MM-DD
	LockDir    string
	InstallDir string
	NoInstall  bool
	DryRun     bool
	Verbose    bool

	// derived
	RepoOwner string
	RepoName  string
	OS        string
	Arch      string
}

var verbose bool

func debugf(format string, a ...any) {
	if verbose {
		fmt.Printf("       "+format+"\n", a...)
	}
}

// ── Input validation ──────────────────────────────────────────────────────────

var (
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([._-][a-zA-Z0-9]+)*$`)
	binaryRE  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	cutoffRE  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	dateRE    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

func validateConfig(cfg *Config) error {
	if cfg.Repo == "" {
		return fmt.Errorf("--repo is required (e.g. --repo aquasecurity/trivy)")
	}
	if cfg.Version == "" {
		return fmt.Errorf("--version is required — auto-fetching latest is disabled by design.\n" +
			"        Check https://github.com/" + cfg.Repo + "/releases and pin an explicit version.")
	}
	if !repoRE.MatchString(cfg.Repo) {
		return fmt.Errorf("invalid --repo format %q — expected owner/repo", cfg.Repo)
	}
	if !versionRE.MatchString(cfg.Version) {
		return fmt.Errorf("invalid --version format %q", cfg.Version)
	}
	if cfg.Binary != "" && !binaryRE.MatchString(cfg.Binary) {
		return fmt.Errorf("invalid --binary name %q — alphanumeric, hyphen, underscore, dot only", cfg.Binary)
	}
	if cfg.Cutoff != "" && !cutoffRE.MatchString(cfg.Cutoff) {
		return fmt.Errorf("invalid --cutoff date %q — must be YYYY-MM-DD (e.g. 2026-03-01)", cfg.Cutoff)
	}
	if err := validatePath("--lock-dir", cfg.LockDir); err != nil {
		return err
	}
	if err := validatePath("--install-dir", cfg.InstallDir); err != nil {
		return err
	}
	return nil
}

var forbiddenPrefixes = []string{
	"/",
	"/etc",
	"/usr",
	"/bin",
	"/sbin",
	"/boot",
	"/sys",
	"/proc",
	"/dev",
	"/root",
}

func validatePath(label, path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%s must be an absolute path, got: %q", label, path)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("%s must not contain '..', got: %q", label, path)
	}
	for _, forbidden := range forbiddenPrefixes {
		if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
			return fmt.Errorf("%s cannot be inside system directory %q, got: %q", label, forbidden, path)
		}
	}
	return nil
}

// ── Usage ─────────────────────────────────────────────────────────────────────

func usage() {
	fmt.Print(`oss-verify (Go) — Supply chain verification for any OSS tool on GitHub

Uses cosign/sigstore-go as a library (no subprocess). Verifies with the Rekor
transparency log including consistency proofs between runs. Pins all hashes
and the Rekor checkpoint to a lockfile.

USAGE
  ./oss-verify --repo <owner/repo> --version <x.y.z> [OPTIONS]

OPTIONS
  --repo        GitHub repo in owner/repo format (required)
  --version     Exact version to install, e.g. 0.70.0 (required)
  --binary      Binary name if it differs from the repo name
  --cutoff      Reject if signed after this date (YYYY-MM-DD)
  --lock-dir    Lockfile directory (default: ~/.local/share/oss-verify)
  --install-dir Install directory (default: ~/.local/bin)
  --no-install  Verify only
  --dry-run     Print detected pattern and asset URLs then exit
  --verbose     Show detailed detection steps
  --help        Show this message

SIGNING PATTERNS (auto-detected)
  A  direct_bundle    binary.sigstore.json
  B  checksum_certsig checksums.txt + .pem + .sig
  C  checksum_bundle  checksums.txt + .sigstore.json
  D  checksum_only    checksums.txt only (warns — no provenance)

SECURITY
  Two fixes over the bash version:
  1. Identity-repo cross-check: signing identity must belong to --repo
  2. Lockfile abort on missing hash fields (not warn+skip)
  New in Go: Rekor consistency proofs — verifies the transparency log has
  not been rolled back or forked between this and previous verifications.

EXAMPLES
  ./oss-verify --repo aquasecurity/trivy --version 0.70.0
  ./oss-verify --repo trufflesecurity/trufflehog --version 3.95.3
  ./oss-verify --repo anchore/grype --version 0.112.0 --cutoff 2026-03-01
  ./oss-verify --repo cli/cli --binary gh --version 2.49.0
`)
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, logFail("%s", err))
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("oss-verify", flag.ContinueOnError)
	fs.Usage = usage

	repo := fs.String("repo", "", "")
	version := fs.String("version", "", "")
	binary := fs.String("binary", "", "")
	cutoff := fs.String("cutoff", "", "")
	lockDir := fs.String("lock-dir", "", "")
	installDir := fs.String("install-dir", "", "")
	noInstall := fs.Bool("no-install", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	verboseFlag := fs.Bool("verbose", false, "")
	help := fs.Bool("help", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	if *help {
		usage()
		return nil
	}

	verbose = *verboseFlag

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not determine home directory: %w", err)
	}
	defaultLockDir := home + "/.local/share/oss-verify"
	defaultInstallDir := home + "/.local/bin"

	if *lockDir == "" {
		if v := os.Getenv("OSS_VERIFY_LOCK_DIR"); v != "" {
			*lockDir = v
		} else {
			*lockDir = defaultLockDir
		}
	}
	if *installDir == "" {
		*installDir = defaultInstallDir
	}

	// Strip leading v from version
	ver := strings.TrimPrefix(*version, "v")

	cfg := &Config{
		Repo:       *repo,
		Version:    ver,
		Binary:     *binary,
		Cutoff:     *cutoff,
		LockDir:    *lockDir,
		InstallDir: *installDir,
		NoInstall:  *noInstall,
		DryRun:     *dryRun,
		Verbose:    *verboseFlag,
	}

	if err := validateConfig(cfg); err != nil {
		return err
	}

	parts := strings.SplitN(cfg.Repo, "/", 2)
	cfg.RepoOwner = parts[0]
	cfg.RepoName = parts[1]

	// Detect OS/arch
	switch runtime.GOOS {
	case "linux":
		cfg.OS = "linux"
	case "darwin":
		cfg.OS = "darwin"
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64":
		cfg.Arch = "amd64"
	case "arm64":
		cfg.Arch = "arm64"
	case "386":
		cfg.Arch = "386"
	default:
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	logInfo("Repo:    %s", cfg.Repo)
	logInfo("Version: v%s", cfg.Version)
	logInfo("OS/Arch: %s/%s", cfg.OS, cfg.Arch)

	ctx := context.Background()
	return orchestrate(ctx, cfg)
}

// ── Orchestration ─────────────────────────────────────────────────────────────

func orchestrate(ctx context.Context, cfg *Config) error {
	// 1. Fetch release assets
	logStep("Fetching release asset list from GitHub API...")
	assets, err := fetchReleaseAssets(cfg.Repo, cfg.Version)
	if err != nil {
		return err
	}

	// 2. Detect binary
	logStep("Detecting binary asset for %s/%s...", cfg.OS, cfg.Arch)
	bin, err := detectBinary(assets, cfg)
	if err != nil {
		return err
	}
	logInfo("Binary:  %s", bin.Filename)
	logInfo("Name:    %s", bin.Name)

	// Override binary name in config if detected
	if cfg.Binary == "" {
		cfg.Binary = bin.Name
	}

	// 3. Detect signing pattern
	logStep("Detecting signing pattern...")
	signing, err := detectPattern(assets, bin)
	if err != nil {
		return err
	}
	logInfo("Pattern: %s", signing.Pattern)

	// 4. Dry run
	if cfg.DryRun {
		printDryRun(cfg, bin, signing, assets)
		return nil
	}

	// 5. Create work dir
	workDir, err := os.MkdirTemp("", "oss-verify-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	if err := os.MkdirAll(cfg.LockDir, 0o700); err != nil {
		return fmt.Errorf("creating lock dir: %w", err)
	}
	os.Chmod(cfg.LockDir, 0o700)

	// 6. Verify
	result, err := verifyPattern(ctx, cfg, bin, signing, workDir)
	if err != nil {
		return err
	}

	// 7. Check cutoff
	if cfg.Cutoff != "" {
		if err := checkCutoff(result.SigningEpoch, cfg.Cutoff); err != nil {
			return err
		}
		logInfo("Timestamp check passed — signed before cutoff (%s)", cfg.Cutoff)
	} else {
		logWarn("No --cutoff set — skipping timestamp window check.")
	}

	// 8. Rekor consistency proof (patterns with bundles)
	if result.RekorCheckpoint != nil {
		logStep("Verifying Rekor log consistency...")
		if err := checkRekorConsistency(ctx, cfg, result); err != nil {
			return err
		}
	}

	// 9. Lockfile
	lockfilePath := fmt.Sprintf("%s/%s-%s-%s-%s.lock",
		cfg.LockDir, cfg.RepoName, cfg.Version, cfg.OS, cfg.Arch)
	if err := checkOrWriteLockfile(lockfilePath, cfg, result); err != nil {
		return err
	}

	// 10. Install
	if cfg.NoInstall {
		logInfo("Verification complete. Skipping install (--no-install).")
		return nil
	}

	if err := os.MkdirAll(cfg.InstallDir, 0o755); err != nil {
		return fmt.Errorf("creating install dir: %w", err)
	}

	binaryDest := cfg.InstallDir + "/" + cfg.Binary
	binarySrc := workDir + "/" + bin.Filename

	if bin.IsRaw {
		if err := atomicInstall(binarySrc, binaryDest); err != nil {
			return err
		}
	} else {
		if err := extractBinary(binarySrc, cfg.Binary, binaryDest, workDir); err != nil {
			return err
		}
	}
	if err := os.Chmod(binaryDest, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// Post-install hash check
	installedHash, err := fileSHA256(binaryDest)
	if err != nil {
		return fmt.Errorf("post-install hash: %w", err)
	}
	if installedHash != result.Hashes["binary"] {
		return fmt.Errorf("post-install hash mismatch — installed binary differs from verified download.\n" +
			"        Expected: " + result.Hashes["binary"] + "\n" +
			"        Got:      " + installedHash)
	}

	fmt.Println()
	fmt.Println(colGreen + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + colReset)
	fmt.Printf(colGreen+"  %s v%s installed and verified"+colReset+"\n", cfg.Binary, cfg.Version)
	fmt.Println(colGreen + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + colReset)
	fmt.Printf("  Repo:     %s\n", cfg.Repo)
	fmt.Printf("  Binary:   %s\n", binaryDest)
	fmt.Printf("  Pattern:  %s\n", signing.Pattern)
	fmt.Printf("  Lockfile: %s\n", lockfilePath)
	fmt.Printf("\n  Ensure %s is in your PATH:\n", cfg.InstallDir)
	fmt.Printf("  export PATH=\"$HOME/.local/bin:$PATH\"\n\n")
	return nil
}

// ── Timestamp cutoff ──────────────────────────────────────────────────────────

func checkCutoff(signingEpoch int64, cutoff string) error {
	if signingEpoch == 0 {
		return fmt.Errorf("--cutoff was set but signing timestamp could not be extracted.\n" +
			"        Cannot enforce cutoff without a verified timestamp.")
	}
	if !dateRE.MatchString(cutoff) {
		return fmt.Errorf("invalid --cutoff date %q — must be YYYY-MM-DD", cutoff)
	}
	cutoffTime, err := time.Parse("2006-01-02", cutoff)
	if err != nil {
		return fmt.Errorf("invalid --cutoff date %q: %w", cutoff, err)
	}
	if signingEpoch > cutoffTime.Unix() {
		return fmt.Errorf("binary was signed AFTER trust cutoff (%s). Refusing to install.", cutoff)
	}
	return nil
}

// ── Dry run ───────────────────────────────────────────────────────────────────

func printDryRun(cfg *Config, bin *BinaryInfo, signing *SigningInfo, assets []Asset) {
	fmt.Println()
	fmt.Println(colCyan + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + colReset)
	fmt.Println(colCyan + "  Dry run — detected configuration" + colReset)
	fmt.Println(colCyan + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + colReset)
	fmt.Printf("  Repo:             %s\n", cfg.Repo)
	fmt.Printf("  Version:          v%s\n", cfg.Version)
	fmt.Printf("  OS/Arch:          %s/%s\n", cfg.OS, cfg.Arch)
	fmt.Printf("  Pattern:          %s\n", signing.Pattern)
	fmt.Printf("  Binary URL:       %s\n", bin.URL)
	if signing.BundleURL != "" {
		fmt.Printf("  Bundle URL:       %s\n", signing.BundleURL)
	}
	if signing.ChecksumsURL != "" {
		fmt.Printf("  Checksums URL:    %s\n", signing.ChecksumsURL)
	}
	if signing.ChecksumsPEM != "" {
		fmt.Printf("  Cert URL:         %s\n", signing.ChecksumsPEM)
	}
	if signing.ChecksumsSig != "" {
		fmt.Printf("  Sig URL:          %s\n", signing.ChecksumsSig)
	}
	if signing.ChecksumsBundle != "" {
		fmt.Printf("  Bundle URL:       %s\n", signing.ChecksumsBundle)
	}
	fmt.Printf("  Raw binary:       %v\n", bin.IsRaw)
	fmt.Printf("\n  All release assets:\n")
	for _, a := range assets {
		fmt.Printf("    %s\n", a.Name)
	}
	fmt.Println()
}
