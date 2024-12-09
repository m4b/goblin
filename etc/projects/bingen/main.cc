#include <Windows.h>

#if !(_WIN64)
#error "Only x64 is supported"
#endif

#ifdef ENABLE_TLS
EXTERN_C unsigned int _tls_index{};
static void NTAPI tls_callback(PVOID, DWORD, PVOID) {}

// Force include unreferenced symbols
// Marker symbol to tell the linker that TLS is being used
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback")

#pragma data_seg(".tls")   
int _tls_start = 0;
#pragma const_seg()

#pragma data_seg(".tls$ZZZ")   
int _tls_end = 0;
#pragma const_seg()

#pragma data_seg(".CRT$XLA")   
int __xl_a = 0;
#pragma const_seg()

#pragma data_seg(".CRT$XLZ")   
int __xl_z = 0;
#pragma const_seg()

#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback[] = { &tls_callback, 0 };
#pragma const_seg()

EXTERN_C IMAGE_TLS_DIRECTORY _tls_used = {
    /*StartAddressOfRawData*/(ULONG64)&_tls_start,
    /*EndAddressOfRawData*/(ULONG64)&_tls_end,
    /*AddressOfIndex*/(ULONG64)&_tls_index,
    /*AddressOfCallbacks*/(ULONG64)&_tls_callback,
    /*SizeOfZeroFill*/0,
    /*Characteristics*/{0},
};
#endif // #ifdef ENABLE_TLS

int main() { return 0; }
