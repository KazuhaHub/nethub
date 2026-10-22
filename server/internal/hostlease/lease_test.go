package hostlease

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLeaseHelper(t *testing.T) {
	if os.Getenv("NETHUB_LEASE_HELPER") != "1" {
		return
	}
	path := os.Getenv("NETHUB_LEASE_PATH")
	lease, err := Acquire(path)
	if err != nil {
		os.Exit(3)
	}
	defer lease.Close()
	if os.WriteFile(path+".ready", []byte("ready"), 0600) != nil {
		os.Exit(4)
	}
	time.Sleep(30 * time.Second)
}

func TestLeaseContendsAcrossProcessesAndRecoversAfterDeath(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("fixture")
	}
	path := filepath.Join(directory, "operation.lock")
	child := exec.Command(os.Args[0], "-test.run=^TestLeaseHelper$", "-test.timeout=35s")
	child.Env = append(os.Environ(), "NETHUB_LEASE_HELPER=1", "NETHUB_LEASE_PATH="+path)
	if child.Start() != nil {
		t.Fatal("start owned lease child")
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := os.Stat(path + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned lease child did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lease, err := Acquire(path); !errors.Is(err, ErrBusy) || lease != nil {
		t.Fatal("separate process lease did not contend", err)
	}
	if child.Process.Kill() != nil {
		t.Fatal("terminate exact owned child")
	}
	_ = child.Wait()
	waited = true
	lease, err := Acquire(path)
	if err != nil {
		t.Fatal("process death left a false persistent lock", err)
	}
	lease.Close()
	lease.Close()
	if stat, err := os.Stat(path); err != nil || stat.Size() != 0 {
		t.Fatal("lease inode was removed or changed")
	}
	lease, err = Acquire(path)
	if err != nil {
		t.Fatal("terminal lease not reusable")
	}
	lease.Close()
}

func TestLeaseRefusesUnexpectedInodesWithoutChangingOutsideFile(t *testing.T) {
	for _, change := range []string{"nonempty", "symlink", "hardlink", "permissions", "parent"} {
		t.Run(change, func(t *testing.T) {
			directory := t.TempDir()
			_ = os.Chmod(directory, 0700)
			path := filepath.Join(directory, "operation.lock")
			outside := filepath.Join(t.TempDir(), "outside")
			if os.WriteFile(outside, []byte("unchanged"), 0600) != nil {
				t.Fatal("fixture")
			}
			switch change {
			case "nonempty":
				_ = os.WriteFile(path, []byte("unexpected"), 0600)
			case "symlink":
				if os.Symlink(outside, path) != nil {
					t.Skip("symlink unavailable")
				}
			case "hardlink":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX single-link check")
				}
				_ = os.WriteFile(path, nil, 0600)
				if os.Link(path, path+".alias") != nil {
					t.Fatal("fixture")
				}
			case "permissions":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX mode check")
				}
				_ = os.WriteFile(path, nil, 0644)
				_ = os.Chmod(path, 0644)
			case "parent":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX mode check")
				}
				_ = os.Chmod(directory, 0755)
			}
			if lease, err := Acquire(path); err == nil || lease != nil {
				t.Fatal("unsafe lease path accepted")
			}
			raw, err := os.ReadFile(outside)
			if err != nil || string(raw) != "unchanged" {
				t.Fatal("outside file changed")
			}
		})
	}
}
