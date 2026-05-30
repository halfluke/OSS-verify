package main

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ── Archive path traversal scan ───────────────────────────────────────────────

// validateArchiveEntries lists the contents of an archive and rejects any entry
// that could escape the extraction directory via path traversal.
// This scan runs BEFORE any bytes are extracted.
func validateArchiveEntries(archivePath string) error {
	var entries []string
	var err error

	switch {
	case strings.HasSuffix(archivePath, ".tar.gz") || strings.HasSuffix(archivePath, ".tgz"):
		entries, err = listTar(archivePath, "gz")
	case strings.HasSuffix(archivePath, ".tar.bz2"):
		entries, err = listTar(archivePath, "bz2")
	case strings.HasSuffix(archivePath, ".tar.xz"):
		entries, err = listTar(archivePath, "xz")
	case strings.HasSuffix(archivePath, ".tar.zst"):
		entries, err = listTar(archivePath, "zst")
	case strings.HasSuffix(archivePath, ".zip"):
		entries, err = listZip(archivePath)
	default:
		return fmt.Errorf("unsupported archive format: %s", archivePath)
	}
	if err != nil {
		return fmt.Errorf("listing archive %s: %w", archivePath, err)
	}

	for _, entry := range entries {
		if isUnsafePath(entry) {
			return fmt.Errorf(
				"archive contains unsafe path %q\n"+
					"        This archive may be malicious — refusing to extract.",
				entry,
			)
		}
	}
	return nil
}

// isUnsafePath returns true if an archive entry path could escape the
// extraction directory.
func isUnsafePath(p string) bool {
	return strings.HasPrefix(p, "/") ||
		p == ".." ||
		strings.HasPrefix(p, "../") ||
		strings.Contains(p, "/../") ||
		strings.HasSuffix(p, "/..")
}

// ── Binary extraction ─────────────────────────────────────────────────────────

// extractBinary extracts binaryName from archivePath into destPath.
// It performs path traversal validation, symlink rejection, and path escape
// detection after extraction.
func extractBinary(archivePath, binaryName, destPath, workDir string) error {
	// Validate archive contents before extracting anything.
	if err := validateArchiveEntries(archivePath); err != nil {
		return err
	}

	// Extract into a subdirectory of workDir to avoid polluting the temp root.
	extractDir := filepath.Join(workDir, "extract")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		return fmt.Errorf("creating extract dir: %w", err)
	}

	switch {
	case strings.HasSuffix(archivePath, ".tar.gz") || strings.HasSuffix(archivePath, ".tgz"):
		if err := extractTar(archivePath, "gz", extractDir); err != nil {
			return err
		}
	case strings.HasSuffix(archivePath, ".tar.bz2"):
		if err := extractTar(archivePath, "bz2", extractDir); err != nil {
			return err
		}
	case strings.HasSuffix(archivePath, ".tar.xz"):
		if err := extractTar(archivePath, "xz", extractDir); err != nil {
			return err
		}
	case strings.HasSuffix(archivePath, ".tar.zst"):
		if err := extractTar(archivePath, "zst", extractDir); err != nil {
			return err
		}
	case strings.HasSuffix(archivePath, ".zip"):
		if err := extractZip(archivePath, extractDir); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported archive format: %s", archivePath)
	}

	// Find the binary: must be a regular file, not a symlink.
	found, err := findBinaryInDir(extractDir, binaryName)
	if err != nil {
		return err
	}
	if found == "" {
		return fmt.Errorf(
			"binary %q not found as a regular file after extraction.\n"+
				"        Use --binary to specify the correct binary name inside the archive.",
			binaryName,
		)
	}

	// Confirm the resolved path stays within the extraction directory.
	realFound, err := filepath.EvalSymlinks(found)
	if err != nil {
		return fmt.Errorf("resolving extracted binary path: %w", err)
	}
	realExtractDir, err := filepath.EvalSymlinks(extractDir)
	if err != nil {
		return fmt.Errorf("resolving extract dir: %w", err)
	}
	if !strings.HasPrefix(realFound, realExtractDir+"/") {
		return fmt.Errorf(
			"extracted binary path escapes the working directory.\n"+
				"        Expected prefix: %s\n"+
				"        Resolved path:   %s\n"+
				"        The archive may contain a malicious symlink. Refusing to install.",
			realExtractDir, realFound,
		)
	}

	return atomicInstall(found, destPath)
}

// findBinaryInDir walks dir and returns the path of the first regular,
// non-symlink file named binaryName.
func findBinaryInDir(dir, binaryName string) (string, error) {
	var found string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() != binaryName {
			return nil
		}
		// Reject symlinks explicitly.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// ModeSymlink check above covers lstat; also verify with Lstat for safety.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		found = path
		return io.EOF // signal early exit
	})
	if err == io.EOF {
		err = nil
	}
	return found, err
}

// ── Atomic install ────────────────────────────────────────────────────────────

// atomicInstall copies src to dest using a temp file + rename for atomicity.
// This prevents a partially-written binary from being visible at the
// destination path, even if the process is killed mid-write.
var rawBinaryRE = regexp.MustCompile(`^[A-Za-z0-9_.,+=-]+$`)

func atomicInstall(src, dest string) error {
	// Validate source filename contains only safe characters.
	srcBase := filepath.Base(src)
	if !rawBinaryRE.MatchString(srcBase) {
		return fmt.Errorf(
			"source binary filename contains unexpected characters: %q\n"+
				"        Expected only alphanumeric, hyphen, underscore, dot, plus, equals.",
			srcBase,
		)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening source binary: %w", err)
	}
	defer in.Close()

	destDir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(destDir, ".oss-verify-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file for install: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op if rename succeeded

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return fmt.Errorf("writing binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Atomic rename — same filesystem, so this is guaranteed atomic on POSIX.
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("installing binary to %s: %w", dest, err)
	}
	return nil
}

// ── Archive listing helpers ───────────────────────────────────────────────────

func listTar(path, compression string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tr, err := tarReader(f, compression)
	if err != nil {
		return nil, err
	}

	var entries []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, h.Name)
	}
	return entries, nil
}

func listZip(path string) ([]string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	entries := make([]string, 0, len(r.File))
	for _, f := range r.File {
		entries = append(entries, f.Name)
	}
	return entries, nil
}

// ── Archive extraction helpers ────────────────────────────────────────────────

func extractTar(path, compression, destDir string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tr, err := tarReader(f, compression)
	if err != nil {
		return err
	}

	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		if isUnsafePath(h.Name) {
			return fmt.Errorf("unsafe path in archive: %q", h.Name)
		}

		dest := filepath.Join(destDir, filepath.Clean(h.Name))

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}
			out, err := os.Create(dest)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, 512<<20)); err != nil { // 512MB per file cap
				out.Close()
				return err
			}
			out.Close()
		case tar.TypeSymlink:
			// Reject symlinks — prevents symlink-based escape attacks.
			return fmt.Errorf("archive contains symlink %q → %q; refusing to extract",
				h.Name, h.Linkname)
		}
	}
	return nil
}

func extractZip(path, destDir string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if isUnsafePath(f.Name) {
			return fmt.Errorf("unsafe path in archive: %q", f.Name)
		}
		dest := filepath.Join(destDir, filepath.Clean(f.Name))

		if f.FileInfo().IsDir() {
			os.MkdirAll(dest, 0o755)
			continue
		}
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive contains symlink %q; refusing to extract", f.Name)
		}

		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(dest)
		if err != nil {
			rc.Close()
			return err
		}
		_, cpErr := io.Copy(out, io.LimitReader(rc, 512<<20))
		out.Close()
		rc.Close()
		if cpErr != nil {
			return cpErr
		}
	}
	return nil
}

// tarReader returns a *tar.Reader wrapping the decompressed stream.
// xz and zst require external tools; pure-Go readers handle gz and bz2.
func tarReader(r io.Reader, compression string) (*tar.Reader, error) {
	switch compression {
	case "gz":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return tar.NewReader(gz), nil
	case "bz2":
		return tar.NewReader(bzip2.NewReader(r)), nil
	case "xz":
		// Pure-Go xz is available via golang.org/x/crypto or xi2/xz.
		// For maximum portability, exec xz if available.
		return nil, fmt.Errorf("xz decompression requires the 'xz' system tool — " +
			"install it with: apt install xz-utils  or  brew install xz")
	case "zst":
		return nil, fmt.Errorf("zst decompression requires the 'zstd' system tool — " +
			"install it with: apt install zstd  or  brew install zstd")
	default:
		return nil, fmt.Errorf("unsupported compression: %s", compression)
	}
}
