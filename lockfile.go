package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// ── LockfileData ──────────────────────────────────────────────────────────────

// LockfileData is the schema of the JSON lockfile written on first install.
// All fields are exported for JSON marshaling.
type LockfileData struct {
	Repo            string            `json:"repo"`
	Version         string            `json:"version"`
	OSArch          string            `json:"os_arch"`
	Pattern         string            `json:"pattern"`
	SigningEpoch     string            `json:"signing_epoch"`
	SigningDate      string            `json:"signing_date"`
	Identity        string            `json:"identity"`
	Hashes          map[string]string `json:"hashes"`           // label → sha256 hex
	RekorCheckpoint *RekorCheckpoint  `json:"rekor_checkpoint,omitempty"`
}

// ── checkOrWriteLockfile ──────────────────────────────────────────────────────

// checkOrWriteLockfile implements the lockfile protocol:
//   - First install: write a new lockfile with all hashes and the Rekor checkpoint.
//   - Subsequent installs: read the lockfile, verify ownership, compare all fields.
//
// SECURITY FIX #2 (over bash script): if the lockfile exists but a hash field is
// missing (e.g. stripped by malware or manual editing), the function ABORTS rather
// than emitting a warning and continuing. The lockfile's re-install guarantee is
// only meaningful if every pinned field is verified without silent degradation.
func checkOrWriteLockfile(lockfilePath string, cfg *Config, result *VerifyResult) error {
	if _, err := os.Stat(lockfilePath); os.IsNotExist(err) {
		return writeLockfile(lockfilePath, cfg, result)
	}

	// Lockfile exists: verify ownership then compare.
	logInfo("Lockfile found — verifying pinned values...")

	// Verify lockfile is owned by the current user.
	// This detects pre-planted lockfile attacks where another user writes a
	// forged lockfile before your first install.
	currentUID := os.Getuid()
	fileUID, err := fileOwnerUID(lockfilePath)
	if err != nil {
		return fmt.Errorf("could not determine owner of lockfile %q.\n"+
			"        stat failed on this system. Cannot safely verify lockfile ownership.", lockfilePath)
	}
	if fileUID != currentUID {
		return fmt.Errorf(
			"lockfile is not owned by current user.\n"+
				"        Owner uid: %d  Current uid: %d\n"+
				"        This could indicate tampering. Remove and re-run to re-pin:\n"+
				"        rm %q",
			fileUID, currentUID, lockfilePath,
		)
	}

	return verifyLockfile(lockfilePath, cfg, result)
}

func writeLockfile(path string, cfg *Config, result *VerifyResult) error {
	data := LockfileData{
		Repo:            cfg.Repo,
		Version:         cfg.Version,
		OSArch:          cfg.OS + "/" + cfg.Arch,
		Pattern:         result.Pattern,
		SigningEpoch:     strconv.FormatInt(result.SigningEpoch, 10),
		SigningDate:      result.SigningDate,
		Identity:        result.Identity,
		Hashes:          result.Hashes,
		RekorCheckpoint: result.RekorCheckpoint,
	}

	logInfo("First install — writing lockfile...")

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing lockfile: %w", err)
	}

	// Write atomically: temp file → rename.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("writing lockfile temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("installing lockfile: %w", err)
	}
	os.Chmod(path, 0o600)

	logWarn("Lockfile: %s", path)
	logWarn("Commit to your repo to share pinned trust across your team.")
	return nil
}

func verifyLockfile(path string, cfg *Config, result *VerifyResult) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading lockfile: %w", err)
	}
	var pinned LockfileData
	if err := json.Unmarshal(raw, &pinned); err != nil {
		return fmt.Errorf("parsing lockfile: %w", err)
	}

	mismatch := false

	// Compare signing epoch.
	currentEpoch := strconv.FormatInt(result.SigningEpoch, 10)
	if currentEpoch != pinned.SigningEpoch {
		logWarn("Signing epoch MISMATCH  pinned=%s  current=%s", pinned.SigningEpoch, currentEpoch)
		mismatch = true
	}

	// Compare identity.
	if result.Identity != pinned.Identity {
		logWarn("Identity MISMATCH\n  Pinned:  %s\n  Current: %s", pinned.Identity, result.Identity)
		mismatch = true
	}

	// Compare all hash fields.
	// SECURITY FIX #2: if a hash field is present in the current result but
	// MISSING from the lockfile, that is treated as a lockfile integrity failure —
	// not silently skipped. This prevents a stripped lockfile from passing verification.
	for label, currentHash := range result.Hashes {
		pinnedHash, ok := pinned.Hashes[label]
		if !ok || pinnedHash == "" {
			// ABORT — do not warn+skip as the bash script did.
			return fmt.Errorf(
				"lockfile is missing pinned hash for %q.\n"+
					"        This field was present on first install and must not be absent.\n"+
					"        Possible lockfile tampering. Remove and re-run to re-pin:\n"+
					"        rm %q",
				label, path,
			)
		}
		if currentHash != pinnedHash {
			logWarn("%s SHA256 MISMATCH\n  Pinned:  %s\n  Current: %s", label, pinnedHash, currentHash)
			mismatch = true
		}
	}

	// Verify Rekor checkpoint consistency if both runs produced one.
	if result.RekorCheckpoint != nil && pinned.RekorCheckpoint != nil {
		if result.RekorCheckpoint.TreeSize < pinned.RekorCheckpoint.TreeSize {
			return fmt.Errorf(
				"Rekor tree size DECREASED between installs (pinned=%d, current=%d).\n"+
					"        This indicates a Rekor log rollback. Do not proceed.",
				pinned.RekorCheckpoint.TreeSize, result.RekorCheckpoint.TreeSize,
			)
		}
		debugf("Rekor checkpoint: tree size %d → %d (consistent)",
			pinned.RekorCheckpoint.TreeSize, result.RekorCheckpoint.TreeSize)
	}

	if mismatch {
		return fmt.Errorf("lockfile mismatch — values differ from first install. Investigate before proceeding.")
	}

	logInfo("Lockfile check passed")
	return nil
}

// fileOwnerUID returns the UID of the file owner using syscall.Stat_t.
func fileOwnerUID(path string) (int, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return -1, err
	}
	return int(stat.Uid), nil
}
