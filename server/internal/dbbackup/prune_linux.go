package dbbackup

import (
	"context"
	"io"
	"os"
	"time"
)

// Prune removes expired archives in this package's private filename namespace.
// A verified latest success is always retained, and unsafe candidates stop the
// preflight before any deletion. It does not remove state or incomplete output.
func Prune(ctx context.Context, directory, expectedFingerprint string, retention time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if retention < 24*time.Hour || retention > 365*24*time.Hour || !privateDirectory(directory) {
		return 0, ErrUnavailable
	}
	guard, err := lock(directory)
	if err != nil {
		return 0, err
	}
	defer guard.Close()
	status, err := VerifyWithBudget(ctx, directory, expectedFingerprint, 7*24*time.Hour, 30*time.Minute)
	if err != nil {
		return 0, err
	}
	if status.InProgress {
		return 0, ErrLastAttempt
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return 0, ErrUnavailable
	}
	defer dir.Close()
	cutoff := time.Now().UTC().Add(-retention)
	var candidates []string
	seen := 0
	for {
		if ctx.Err() != nil {
			return 0, ErrUnavailable
		}
		entries, readErr := dir.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return 0, ErrUnavailable
		}
		for _, entry := range entries {
			seen++
			if seen > 10000 {
				return 0, ErrIntegrity
			}
			name := entry.Name()
			if !archivePattern.MatchString(name) || name == status.Receipt.Archive {
				continue
			}
			started, err := time.Parse("20060102T150405Z", name[7:23])
			if err != nil {
				return 0, ErrIntegrity
			}
			info, err := root.Lstat(name)
			if err != nil || !privateFile(info) || info.Size() < 5 || info.Size() > 1<<40 {
				return 0, ErrIntegrity
			}
			if !started.Before(cutoff) || !info.ModTime().Before(cutoff) {
				continue
			}
			file, err := root.Open(name)
			if err != nil {
				return 0, ErrUnavailable
			}
			var prefix [5]byte
			_, readErr := io.ReadFull(file, prefix[:])
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || string(prefix[:]) != "PGDMP" {
				return 0, ErrIntegrity
			}
			candidates = append(candidates, name)
		}
		if readErr == io.EOF {
			break
		}
	}
	removed := 0
	for _, name := range candidates {
		if ctx.Err() != nil {
			return removed, ErrUnavailable
		}
		// Recheck before removing a name observed during the bounded preflight.
		info, err := root.Lstat(name)
		if err != nil || !privateFile(info) || !info.ModTime().Before(cutoff) {
			return removed, ErrIntegrity
		}
		if err := root.Remove(name); err != nil {
			return removed, ErrUnavailable
		}
		removed++
	}
	if removed > 0 && dir.Sync() != nil {
		return removed, ErrUnavailable
	}
	return removed, nil
}
