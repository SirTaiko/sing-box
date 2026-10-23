package main

// Shared helpers for the submission 5 no-follow regressions. No build tag: the
// Unix and Windows test files both use them.
import (
	"os"
	"testing"
)

func securityV5Write(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func securityV5Read(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func securityV5OpenInput(t *testing.T, path string) []protectedToolFile {
	t.Helper()
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	info, err := input.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return []protectedToolFile{{Role: "input", Info: info}}
}
