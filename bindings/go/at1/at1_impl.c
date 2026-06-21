/* Compile the AT-1 reference decoder into this cgo package so the binding is
 * self-contained and `go get`-able (the C source is vendored INSIDE the module, in
 * csrc/, which a registry/proxy fetch can see -- files above the module root it cannot).
 * csrc/ is a SUBDIR so cgo does not also compile it standalone (that would double-define
 * symbols). The vendored csrc/at1_decode.c is a verbatim copy of c_decoder/at1_decode.c;
 * bindings/check_vendor.py guards against drift. AT1_NO_MAIN is set via the CFLAGS. */
#if defined(__has_include) && __has_include("csrc/at1_decode.c")
#include "csrc/at1_decode.c"
#else
#include "../../../c_decoder/at1_decode.c"
#endif
