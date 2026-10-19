// Collect license and notice files for the modules linked into a helper binary.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	if err := collect(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func collect() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: licenses PACKAGE OUTPUT_DIRECTORY")
	}
	output, err := exec.Command("go", "list", "-deps", "-json", os.Args[1]).Output()
	if err != nil {
		return fmt.Errorf("list linked modules: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	modules := map[string]string{}
	for {
		var pkg struct {
			Module *struct {
				Path, Version, Dir string
				Main               bool
			} `json:"Module"`
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if pkg.Module != nil && !pkg.Module.Main {
			modules[pkg.Module.Path+"@"+pkg.Module.Version] = pkg.Module.Dir
		}
	}
	index := make([]string, 0, len(modules))
	for name, dir := range modules {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		count := 0
		for _, entry := range entries {
			lower := strings.ToLower(entry.Name())
			if !strings.HasPrefix(lower, "license") && !strings.HasPrefix(lower, "licence") &&
				!strings.HasPrefix(lower, "copying") && !strings.HasPrefix(lower, "notice") && !strings.HasPrefix(lower, "copyright") {
				continue
			}
			source := filepath.Join(dir, entry.Name())
			if err := filepath.WalkDir(source, func(path string, item os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if item.IsDir() {
					return nil
				}
				info, err := item.Info()
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("nonregular license file: %s", path)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				relative, err := filepath.Rel(dir, path)
				if err != nil {
					return err
				}
				destination := filepath.Join(os.Args[2], name, relative)
				if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
					return err
				}
				count++
				return os.WriteFile(destination, data, 0644)
			}); err != nil {
				return err
			}
		}
		if count == 0 {
			return fmt.Errorf("module has no license/notice files: %s", name)
		}
		index = append(index, name)
	}
	sort.Strings(index)
	if err := os.MkdirAll(os.Args[2], 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(os.Args[2], "modules.txt"), []byte(strings.Join(index, "\n")+"\n"), 0644)
}
