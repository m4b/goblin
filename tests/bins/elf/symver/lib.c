#include <stdio.h>

// Bind function symbols to version nodes.
//
// ..@       -> Is the unversioned symbol.
// ..@@..    -> Is the default symbol.
//
// For details check:
//   https://sourceware.org/binutils/docs/ld/VERSION.html#VERSION
__asm__ (".symver some_func_v0,some_func@");
__asm__ (".symver some_func_v1,some_func@v1");
__asm__ (".symver some_func_v2,some_func@@v2");

void some_func_v0() {
    puts("some_func_v0");
}

void some_func_v1() {
    puts("some_func_v1");
}

void some_func_v2() {
    puts("some_func_v2");
}
