#ifndef UTILITY_MACROS_H
#define UTILITY_MACROS_H

#include "hannibal.h"

// TODO: Implement these and don't use builtins
#define pic_memset  __stosb
#define pic_free __builtin_free
#define pic_realloc __builtin_realloc
#define pic_RtlSecureZeroMemory RtlSecureZeroMemory


void *pic_memcpy(void* dest, const void* src, size_t n);

INT MemCompare( PVOID s1, PVOID s2, INT len);

VOID CfgAddressAdd(
    IN PVOID ImageBase,
    IN PVOID Function
);

void buffer_append_alloc(UINT8 **buffer, size_t *current_size, size_t *current_usage, const WCHAR *str);

#endif // UTILITY_MACROS_H