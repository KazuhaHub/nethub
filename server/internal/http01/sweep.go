package http01

import (
	"container/heap"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// SweepResult contains only counters, never hostnames or validation material.
type SweepResult struct {
	Scanned       int  `json:"scanned"`
	Retired       int  `json:"retired"`
	Busy          int  `json:"busy"`
	Errors        int  `json:"errors"`
	CycleComplete bool `json:"cycle_complete"`
}

type sweepCursor struct {
	Version int    `json:"version"`
	Last    string `json:"last"`
}
type hostHeap []string

func (h hostHeap) Len() int           { return len(h) }
func (h hostHeap) Less(i, j int) bool { return h[i] > h[j] }
func (h hostHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *hostHeap) Push(v any)        { *h = append(*h, v.(string)) }
func (h *hostHeap) Pop() any          { v := *h; last := v[len(v)-1]; *h = v[:len(v)-1]; return last }

// SweepExpired visits at most 128 hosts, with a durable lexical cursor so a
// busy or corrupt host cannot starve later hosts. It needs neither the database
// nor an account key. A caller may repeat batches until CycleComplete within its
// deadline; a later invocation resumes an interrupted batch. Independent host
// scheduling is required because static HTTP files have no per-request expiry.
func (p *Publisher) SweepExpired(ctx context.Context) (SweepResult, error) {
	return p.sweepExpired(ctx, 128)
}

func (p *Publisher) sweepExpired(ctx context.Context, limit int) (SweepResult, error) {
	var result SweepResult
	if limit < 1 || limit > 128 {
		return result, ErrInput
	}
	if cancelled(ctx) != nil {
		return result, ErrCancelled
	}
	if protected(p.state, true, 0700) != nil || protected(p.public, true, 0755) != nil {
		return result, ErrState
	}
	path := filepath.Join(p.public, ".publisher-lease")
	if protected(path, false, 0644) != nil {
		return result, ErrState
	}
	lock, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return result, ErrState
	}
	defer lock.Close()
	if info, err := lock.Stat(); err != nil || info.Size() != 0 || !owned(info) {
		return result, ErrState
	}
	if err := lockFile(lock); err != nil {
		return result, err
	}
	defer unlockFile(lock)
	cursorPath := filepath.Join(p.state, "sweep.json")
	cursor := sweepCursor{Version: 1}
	if !missing(cursorPath) && (readCanonical(cursorPath, &cursor) != nil || cursor.Version != 1 || cursor.Last != "" && !p.validHost(cursor.Last)) {
		return result, ErrState
	}
	selectHosts := func(after string) ([]string, int, error) {
		directory, err := os.Open(p.state)
		if err != nil {
			return nil, 0, ErrState
		}
		defer directory.Close()
		selected := &hostHeap{}
		heap.Init(selected)
		eligible := 0
		for {
			if cancelled(ctx) != nil {
				return nil, 0, ErrCancelled
			}
			entries, readErr := directory.ReadDir(128)
			for _, entry := range entries {
				name := entry.Name()
				if name == "namespace.json" || name == "sweep.json" {
					continue
				}
				if !p.validHost(name) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
					result.Errors++
					continue
				}
				if name <= after {
					continue
				}
				eligible++
				if selected.Len() < limit {
					heap.Push(selected, name)
				} else if name < (*selected)[0] {
					heap.Pop(selected)
					heap.Push(selected, name)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return nil, 0, ErrState
			}
		}
		out := []string(*selected)
		sort.Strings(out)
		return out, eligible, nil
	}
	hosts, eligible, err := selectHosts(cursor.Last)
	if err != nil {
		return result, err
	}
	if len(hosts) == 0 && cursor.Last != "" {
		cursor.Last = ""
		if writeCanonical(cursorPath, cursor) != nil {
			return result, ErrState
		}
		result.CycleComplete = true
		if result.Errors > 0 {
			return result, ErrState
		}
		return result, nil
	}
	for _, host := range hosts {
		if cancelled(ctx) != nil {
			return result, ErrCancelled
		}
		var retired bool
		var err error
		directory := filepath.Join(p.state, host)
		if protected(directory, true, 0700) != nil {
			err = ErrState
		} else if !missing(filepath.Join(directory, "active.json")) {
			if protected(filepath.Join(directory, "operations"), true, 0700) != nil || protected(filepath.Join(directory, "lease"), false, 0600) != nil {
				err = ErrState
			} else {
				retired, err = p.cleanupExpired(ctx, host)
			}
		}
		result.Scanned++
		switch {
		case errors.Is(err, ErrBusy):
			result.Busy++
		case err != nil:
			result.Errors++
		case retired:
			result.Retired++
		}
		cursor.Last = host
		if writeCanonical(cursorPath, cursor) != nil {
			return result, ErrState
		}
	}
	result.CycleComplete = eligible <= limit
	if result.CycleComplete {
		cursor.Last = ""
		if writeCanonical(cursorPath, cursor) != nil {
			return result, ErrState
		}
	}
	if result.Errors > 0 {
		return result, ErrState
	}
	return result, nil
}
