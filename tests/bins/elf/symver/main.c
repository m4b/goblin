#define _GNU_SOURCE
#include <dlfcn.h>
#include <assert.h>

// Links against default symbol in the lib.so.
extern void some_func();

int main() {
    // Call the default version.
    some_func();

#ifdef _GNU_SOURCE
    typedef void (*fnptr)();

    // Unversioned & version lookup.
    fnptr fn_v0 = (fnptr)dlsym(RTLD_DEFAULT, "some_func");
    fnptr fn_v1 = (fnptr)dlvsym(RTLD_DEFAULT, "some_func", "v1");
    fnptr fn_v2 = (fnptr)dlvsym(RTLD_DEFAULT, "some_func", "v2");

    assert(fn_v0 != 0);
    assert(fn_v1 != 0);
    assert(fn_v2 != 0);

    fn_v0();
    fn_v1();
    fn_v2();
#endif

    return 0;
}
