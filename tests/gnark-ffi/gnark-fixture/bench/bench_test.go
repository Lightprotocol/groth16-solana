package bench

// Determinism gate for the fixture generator. The whole design of
// tests/program rests on GenerateAll producing byte-identical
// output on every run (the SBF program build and the host test build
// each regenerate the fixtures independently and must agree). If a
// gnark upgrade starts drawing randomness concurrently or outside
// crypto/rand.Reader, this test fails.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateIsDeterministic(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	if err := GenerateAll(dirA); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := GenerateAll(dirB); err != nil {
		t.Fatalf("second run: %v", err)
	}

	entries, err := os.ReadDir(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no fixture files generated")
	}
	// 4 plain sets x 5 files + 4 bsb22 sets x 7 files
	if want := 4*5 + 4*7; len(entries) != want {
		t.Fatalf("expected %d fixture files, got %d", want, len(entries))
	}

	for _, e := range entries {
		a, err := os.ReadFile(filepath.Join(dirA, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dirB, e.Name()))
		if err != nil {
			t.Fatalf("%s missing from second run: %v", e.Name(), err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between runs (%d vs %d bytes)", e.Name(), len(a), len(b))
		}
	}
}
