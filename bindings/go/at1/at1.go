// Package at1 is a cgo binding over the AT-1 reference decoder C ABI
// (c_decoder/at1_decode.h). It decodes .at1 files byte-for-byte; malformed input
// returns an error rather than crashing the process (the C ABI longjmps on failure
// instead of exit()ing).
//
//	import "github.com/AT1-Tinyfiles/AT-1-Public/bindings/go/at1"
//	original, err := at1.Decode(at1Bytes)
//
// Build needs liblzma + libzstd dev libraries (the same as the native decoder).
// CGO must be enabled (CGO_ENABLED=1) with a C compiler on PATH.
package at1

/*
#cgo CFLAGS: -I${SRCDIR}/csrc -I${SRCDIR}/../../../c_decoder -DAT1_NO_MAIN -O2
#cgo LDFLAGS: -llzma -lzstd
#include <stdlib.h>
#include "at1_decode.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Error codes mirrored from at1_decode.h.
const (
	ok         = 0
	errCorrupt = 2
	errBackend = 3
)

// Stats holds the three billing axes the AT-1 control plane meters (see at1.py
// `_meter_usage`). Decode/restore is NOT itself billed, so this binding makes no
// network call -- it only exposes the counters so a host can report them to its
// own meter if it chooses.
type Stats struct {
	OriginalBytes   uint64 // reconstructed (pre-compression) size
	CompressedBytes uint64 // size of the .at1 input
	IOBytes         uint64 // bytes read to produce this output (== CompressedBytes here)
}

// Decode reconstructs the original bytes from an AT-1 container. It returns an
// error for malformed/hostile input (the decoder is fuzz-hardened and never
// crashes the host).
func Decode(in []byte) ([]byte, error) {
	out, _, err := DecodeWithStats(in)
	return out, err
}

// DecodeWithStats reconstructs the original bytes and returns the billing
// counters alongside them, so a metering host can report
// (original_bytes, compressed_bytes, io_bytes) without a second pass. The decode
// itself is unmetered; the counters are informational.
func DecodeWithStats(in []byte) ([]byte, Stats, error) {
	var outPtr *C.uint8_t
	var outLen C.size_t
	var inPtr *C.uint8_t
	if len(in) > 0 {
		inPtr = (*C.uint8_t)(unsafe.Pointer(&in[0]))
	}
	rc := C.at1_decode_buffer(inPtr, C.size_t(len(in)), &outPtr, &outLen)
	if rc != ok {
		switch rc {
		case errCorrupt:
			return nil, Stats{}, fmt.Errorf("at1: corrupt or hostile input rejected (rc=%d)", int(rc))
		case errBackend:
			return nil, Stats{}, fmt.Errorf("at1: backend (xz/zstd/allocation) error (rc=%d)", int(rc))
		default:
			return nil, Stats{}, fmt.Errorf("at1: decode failed (rc=%d)", int(rc))
		}
	}
	defer C.at1_free(outPtr)
	out := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))
	stats := Stats{
		OriginalBytes:   uint64(len(out)),
		CompressedBytes: uint64(len(in)),
		IOBytes:         uint64(len(in)),
	}
	return out, stats, nil
}

// Version returns the decoder version string.
func Version() string {
	return C.GoString(C.at1_version())
}
