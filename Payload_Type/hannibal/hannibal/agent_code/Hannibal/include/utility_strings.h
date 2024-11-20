#ifndef UTILITY_STRINGS_H
#define UTILITY_STRINGS_H

#include "hannibal.h"


#define H_MAGIC_KEY       5381
#define H_MAGIC_SEED      5
#define H_MODULE_NTDLL    0x70e61753
#define H_MODULE_KERNEL32 0xadd31df0

// Sometimes builtins are janky. Prefer custom PIC version.
// #define pic_sprintf __builtin_sprintf
// #define pic_sscanf __builtin_sscanf
// #define pic_tolower __builtin_tolower
// #define pic_strdup __builtin_strdup
// #define pic_snprintf __builtin_snprintf

#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#else
#define CONSTEXPR
#endif

#define HASH_STR( x ) ExprHashStringA( ( x ) )

CONSTEXPR ULONG ExprHashStringA(
    _In_ PCHAR String
) {
    ULONG Hash = { 0 };
    CHAR  Char = { 0 };

    Hash = H_MAGIC_KEY;

    if ( ! String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        /* turn current character to uppercase */
        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}


ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
);

size_t pic_strlen(const char *str);
size_t pic_strlenW(const wchar_t *wstr);

char *pic_strcpy(char* dest, const char* src);
int pic_strcmp(const char *str1, const char *str2);
int pic_strcmpW(const wchar_t *wstr1, const wchar_t *wstr2);
int pic_strncmp(const char *s1, const char *s2, size_t n);

char *pic_strncpy(char *dest, const char *src, size_t n);

void pic_strcat(char *str1, char *str2);
void pic_strcatW(wchar_t *wstr1, wchar_t *wstr2);

void dword_to_wchar(DWORD value, WCHAR* buffer, int base);
void ulong_to_wchar(ULONG64 value, WCHAR *buffer);

#endif // UTILITY_STRINGS_H