package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// ── GitHub API types ──────────────────────────────────────────────────────────

type Asset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

type releaseResponse struct {
	Assets []Asset `json:"assets"`
}

// ── GitHub URL allowlist ──────────────────────────────────────────────────────

func assertGitHubURL(u string) error {
	if strings.HasPrefix(u, "https://github.com/") ||
		strings.HasPrefix(u, "https://objects.githubusercontent.com/") {
		return nil
	}
	return fmt.Errorf("refusing download from non-GitHub URL: %s", u)
}

// ── Fetch release assets ──────────────────────────────────────────────────────

func fetchReleaseAssets(repo, version string) ([]Asset, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/v%s", repo, version)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w\n        URL: https://github.com/%s/releases/tag/v%s", err, repo, version)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GitHub API returned %d for v%s.\n        URL: https://github.com/%s/releases/tag/v%s\n        Response: %s",
			resp.StatusCode, version, repo, version, strings.TrimSpace(string(body)))
	}

	var rel releaseResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("parsing GitHub API response: %w", err)
	}
	if len(rel.Assets) == 0 {
		return nil, fmt.Errorf("release v%s has no assets", version)
	}

	for _, a := range rel.Assets {
		if err := assertGitHubURL(a.DownloadURL); err != nil {
			return nil, err
		}
	}
	return rel.Assets, nil
}

func githubToken() string {
	return os.Getenv("GITHUB_TOKEN")
}

// ── Binary detection ──────────────────────────────────────────────────────────

// BinaryInfo holds the detected binary asset.
type BinaryInfo struct {
	URL      string
	Filename string
	Ext      string
	Name     string
	IsRaw    bool
}

var osLabels = map[string][]string{
	"linux":  {"linux", "Linux", "LINUX"},
	"darwin": {"darwin", "Darwin", "macos", "macOS", "MacOS", "osx", "OSX", "apple"},
}

var archLabels = map[string][]string{
	"amd64": {"amd64", "x86_64", "x86-64", "64bit", "64-bit", "amd-64"},
	"arm64": {"arm64", "aarch64", "ARM64", "arm-64"},
	"386":   {"386", "i386", "i686", "32bit"},
}

var archiveExts = []string{"tar.gz", "tgz", "tar.bz2", "tar.xz", "tar.zst", "zip"}

func detectBinary(assets []Asset, cfg *Config) (*BinaryInfo, error) {
	osLbls := osLabels[cfg.OS]
	archLbls := archLabels[cfg.Arch]

	// Candidate names: user-supplied binary name first, then repo name.
	candidates := []string{cfg.RepoName}
	if cfg.Binary != "" && cfg.Binary != cfg.RepoName {
		candidates = []string{cfg.Binary, cfg.RepoName}
	}

	for _, name := range candidates {
		for _, os := range osLbls {
			for _, arch := range archLbls {
				for _, ext := range archiveExts {
					if url, filename := matchArchive(assets, name, os, arch, ext); url != "" {
						debugf("Matched archive: %s", filename)
						return &BinaryInfo{
							URL:      url,
							Filename: filename,
							Ext:      ext,
							Name:     name,
						}, nil
					}
				}
			}
		}
	}

	// Fallback: raw binary (no archive)
	for _, name := range candidates {
		for _, os := range osLbls {
			for _, arch := range archLbls {
				if url, filename := matchRawBinary(assets, name, os, arch); url != "" {
					debugf("Matched raw binary: %s", filename)
					return &BinaryInfo{
						URL:      url,
						Filename: filename,
						Name:     name,
						IsRaw:    true,
					}, nil
				}
			}
		}
	}

	names := make([]string, len(assets))
	for i, a := range assets {
		names[i] = a.Name
	}
	return nil, fmt.Errorf(
		"could not find a binary asset for %s/%s in release v%s.\n"+
			"        Use --binary <name> if the binary name differs from the repo name.\n"+
			"        Available assets:\n          %s",
		cfg.OS, cfg.Arch, cfg.Version, strings.Join(names, "\n          "),
	)
}

// matchArchive tries six naming patterns for archives.
func matchArchive(assets []Asset, name, osLabel, archLabel, ext string) (url, filename string) {
	extEsc := strings.ReplaceAll(ext, ".", `\.`)
	patterns := []string{
		// trivy, grype, syft: name_version_os_arch.ext
		fmt.Sprintf(`^%s[_.-][^/]*%s[_.-]%s[^/]*\.%s$`, regexEscape(name), regexEscape(osLabel), regexEscape(archLabel), extEsc),
		// arch before os
		fmt.Sprintf(`^%s[_.-][^/]*%s[_.-]%s[^/]*\.%s$`, regexEscape(name), regexEscape(archLabel), regexEscape(osLabel), extEsc),
		// ripgrep style: name-version-os-arch.ext
		fmt.Sprintf(`^%s-[0-9][^/]*-%s-%s[^/]*\.%s$`, regexEscape(name), regexEscape(osLabel), regexEscape(archLabel), extEsc),
		fmt.Sprintf(`^%s-[0-9][^/]*-%s-%s[^/]*\.%s$`, regexEscape(name), regexEscape(archLabel), regexEscape(osLabel), extEsc),
		// no version: name_os_arch.ext (crane)
		fmt.Sprintf(`^%s[_.-]%s[_.-]%s\.%s$`, regexEscape(name), regexEscape(osLabel), regexEscape(archLabel), extEsc),
		fmt.Sprintf(`^%s[_.-]%s[_.-]%s\.%s$`, regexEscape(name), regexEscape(archLabel), regexEscape(osLabel), extEsc),
	}
	for _, pat := range patterns {
		re, err := compileSafe(pat)
		if err != nil {
			continue
		}
		for _, a := range assets {
			if re.MatchString(a.Name) {
				return a.DownloadURL, a.Name
			}
		}
	}
	return "", ""
}

// matchRawBinary tries raw binary patterns (no archive extension).
func matchRawBinary(assets []Asset, name, osLabel, archLabel string) (url, filename string) {
	for _, sep := range []string{"-", "_", "."} {
		for _, a := range assets {
			if matchesExact(a.Name, name+sep+osLabel+sep+archLabel) ||
				matchesExact(a.Name, name+sep+archLabel+sep+osLabel) ||
				matchesExact(a.Name, name+"-"+osLabel+sep+archLabel) ||
				matchesExact(a.Name, name+"-"+archLabel+sep+osLabel) {
				return a.DownloadURL, a.Name
			}
		}
	}
	return "", ""
}

func matchesExact(s, target string) bool { return s == target }

// regexEscape escapes all regex metacharacters in a literal string.
func regexEscape(s string) string {
	return regexp.QuoteMeta(s)
}

// compileSafe compiles a regex, returning nil on error.
func compileSafe(pat string) (*regexp.Regexp, error) {
	return regexp.Compile(pat)
}

// ── Signing pattern detection ─────────────────────────────────────────────────

// SigningInfo holds the detected signing artefact URLs.
type SigningInfo struct {
	Pattern         PatternKind
	BundleURL       string
	ChecksumsURL    string
	ChecksumsFile   string // basename
	ChecksumsPEM    string
	ChecksumsSig    string
	ChecksumsBundle string
}

// PatternKind is the detected signing pattern.
type PatternKind string

const (
	PatternDirectBundle   PatternKind = "direct_bundle"
	PatternChecksumCert   PatternKind = "checksum_certsig"
	PatternChecksumBundle PatternKind = "checksum_bundle"
	PatternChecksumOnly   PatternKind = "checksum_only"
)

func detectPattern(assets []Asset, bin *BinaryInfo) (*SigningInfo, error) {
	si := &SigningInfo{}

	// Pattern A: bundle directly on the binary file.
	for _, suffix := range []string{".sigstore.json", ".sigstore", ".bundle", ".jsonl"} {
		if url := findBySuffix(assets, bin.Filename+suffix); url != "" {
			si.Pattern = PatternDirectBundle
			si.BundleURL = url
			debugf("Pattern A: %s", lastName(url))
			return si, nil
		}
	}

	// Find a checksums file (exact name or versioned prefix).
	checksumsCandidates := []string{
		"checksums.txt", "sha256sums.txt", "SHA256SUMS", "checksums", "sha256sums",
	}
	for _, candidate := range checksumsCandidates {
		if url := findByExact(assets, candidate); url != "" {
			si.ChecksumsURL = url
			si.ChecksumsFile = candidate
			break
		}
		// Versioned prefix: ends with _<candidate>
		if url := findByEndsWith(assets, "_"+candidate); url != "" {
			si.ChecksumsURL = url
			si.ChecksumsFile = lastName(url)
			break
		}
	}

	if si.ChecksumsURL != "" {
		cf := si.ChecksumsFile
		// Pattern B: checksums + PEM cert + sig.
		pemURL := ""
		sigURL := ""
		for _, s := range []string{".pem", ".crt", ".cert"} {
			if url := findBySuffix(assets, cf+s); url != "" {
				pemURL = url
				break
			}
		}
		for _, s := range []string{".sig", ".signature", ".asc"} {
			if url := findBySuffix(assets, cf+s); url != "" {
				sigURL = url
				break
			}
		}
		if pemURL != "" && sigURL != "" {
			si.Pattern = PatternChecksumCert
			si.ChecksumsPEM = pemURL
			si.ChecksumsSig = sigURL
			debugf("Pattern B: cert=%s sig=%s", lastName(pemURL), lastName(sigURL))
			return si, nil
		}

		// Pattern C: checksums + sigstore bundle.
		for _, s := range []string{".sigstore.json", ".sigstore", ".bundle"} {
			if url := findBySuffix(assets, cf+s); url != "" {
				si.Pattern = PatternChecksumBundle
				si.ChecksumsBundle = url
				debugf("Pattern C: %s", lastName(url))
				return si, nil
			}
		}

		// Pattern D: checksums only.
		si.Pattern = PatternChecksumOnly
		debugf("Pattern D: checksum-only")
		return si, nil
	}

	return nil, fmt.Errorf(
		"could not detect a signing pattern — no sigstore bundle, checksums, or signature files found.\n" +
			"        Run with --verbose to see all assets.")
}

// ── Asset lookup helpers ──────────────────────────────────────────────────────

// findByExact returns the download URL for the asset with exactly the given name.
func findByExact(assets []Asset, name string) string {
	for _, a := range assets {
		if a.Name == name {
			return a.DownloadURL
		}
	}
	return ""
}

// findBySuffix returns the download URL for the asset whose name is exactly prefix+suffix.
func findBySuffix(assets []Asset, name string) string {
	return findByExact(assets, name)
}

// findByEndsWith returns the download URL for the first asset whose name ends with suffix.
// Uses glob-style ends-with matching to prevent foo_checksums.txt.sig from matching
// when looking for foo_checksums.txt.
func findByEndsWith(assets []Asset, suffix string) string {
	for _, a := range assets {
		if strings.HasSuffix(a.Name, suffix) {
			return a.DownloadURL
		}
	}
	return ""
}

// lastName returns the last path component of a URL.
func lastName(url string) string {
	parts := strings.Split(url, "/")
	return parts[len(parts)-1]
}

// ── HTTP download helpers ─────────────────────────────────────────────────────

// downloadFile downloads a file from url to dest.
// isBinary: false → enforce 1MB cap (signing files); true → no cap (binaries can be 100MB+).
func downloadFile(url, dest string, isBinary bool) error {
	if err := assertGitHubURL(url); err != nil {
		return err
	}
	logInfo("Downloading %s ...", lastName(url))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("downloading %s: HTTP %d", url, resp.StatusCode)
	}

	var r io.Reader = resp.Body
	if !isBinary {
		r = io.LimitReader(resp.Body, 1<<20) // 1MB cap for signing files
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}

	// Verify the file is non-empty.
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("downloaded file is empty: %s", dest)
	}
	return nil
}
