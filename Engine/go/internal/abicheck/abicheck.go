// SPDX-License-Identifier: MIT

// Package abicheck compares the functions a hand-written C header declares
// with the //export directives of a Go package, for the bridge and
// test-support tests.
package abicheck

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	declRE   = regexp.MustCompile(`^[A-Za-z_][\w\s\*]*?\b(wgex_\w+)\s*\(`)
	exportRE = regexp.MustCompile(`^//export\s+(\w+)\s*$`)
)

// HeaderFunctions returns the sorted function names declared in header,
// skipping comments and typedefs.
func HeaderFunctions(header string) ([]string, error) {
	b, err := os.ReadFile(header)
	if err != nil {
		return nil, err
	}
	var out []string
	inBlock := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if inBlock {
			if i := strings.Index(line, "*/"); i >= 0 {
				inBlock = false
				line = strings.TrimSpace(line[i+2:])
			} else {
				continue
			}
		}
		if strings.HasPrefix(line, "/*") {
			if !strings.Contains(line, "*/") {
				inBlock = true
			}
			continue
		}
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "typedef") || strings.HasPrefix(line, "#") {
			continue
		}
		if m := declRE.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return out, nil
}

// Exports returns the sorted //export names of the non-test Go files in dir.
func Exports(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			if m := exportRE.FindStringSubmatch(sc.Text()); m != nil {
				out = append(out, m[1])
			}
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	slices.Sort(out)
	return out, nil
}
