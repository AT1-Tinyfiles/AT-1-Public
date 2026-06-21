package at1

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Decode each committed test vector and assert byte-identity with the expected
// (Python-produced) output -- the same vectors the native Makefile checks.
func TestDecodeVectors(t *testing.T) {
	vroot := filepath.Join("..", "..", "..", "c_decoder", "testvectors")
	cases := []struct{ at1, expected string }{
		{"sample.at1", "sample.expected"},
		{"applog.at1", "applog.expected"},
		{"ssh.at1", "ssh.expected"},
		{"ghjson.at1", "ghjson.expected"},
		{"osm.at1", "osm.expected"},
		{"vcf.at1", "vcf.expected"},
		{"jsondoc.at1", "jsondoc.expected"},
		{"qcol.at1", "qcol.expected"},
		{"qjson.at1", "qjson.expected"},
	}
	for _, c := range cases {
		in, err := os.ReadFile(filepath.Join(vroot, c.at1))
		if err != nil {
			t.Skipf("missing vector %s", c.at1)
			continue
		}
		want, err := os.ReadFile(filepath.Join(vroot, c.expected))
		if err != nil {
			t.Fatalf("missing expected %s: %v", c.expected, err)
		}
		got, err := Decode(in)
		if err != nil {
			t.Errorf("%s: decode error: %v", c.at1, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: NOT byte-identical (got %d, want %d)", c.at1, len(got), len(want))
		}
	}
}

// Malformed input must be rejected cleanly, not crash the process.
func TestRejectMalformed(t *testing.T) {
	bad := []byte{0x41, 0x54, 0x31, 0x02, 0x07, 0xff, 0xff, 0x00}
	if _, err := Decode(bad); err == nil {
		t.Error("expected error on malformed input, got nil")
	}
}

func TestVersion(t *testing.T) {
	if Version() == "" {
		t.Error("empty version string")
	}
}
