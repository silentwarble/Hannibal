#include "utility_strings.h"

/**
 * TODO: Cleanup. Functions are inconsistent in design and operation.
 */



/*!
 * @brief
 *  Hashing data
 *
 * @param String
 *  Data/String to hash
 *
 * @param Length
 *  size of data/string to hash.
 *  if 0 then hash data til null terminator is found.
 *
 * @return
 *  hash of specified data/string
 */
SECTION_CODE ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash = { 0 };
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Hash = H_MAGIC_KEY;
    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( (UINT_PTR)( Ptr - (UINT_PTR)( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << 5 ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}



SECTION_CODE char* pic_strcpy(char* dest, const char* src) 
{
    char* d = dest;
    const char* s = src;
    
    // Copy characters one by one until the null terminator is found
    while ((*d++ = *s++)) {
        // Loop continues until null terminator is copied
    }
    
    return dest;
}

SECTION_CODE size_t pic_strlen(const char *str) 
{ // Len not including null terminator
    const char *s = str;
    while (*s != '\0') {
        s++;
    }
    return (size_t)(s - str);
}

SECTION_CODE size_t pic_strlenW(const wchar_t *wstr) 
{
    const wchar_t *s = wstr;
    while (*s != L'\0') {
        s++;
    }
    return (size_t)(s - wstr);
}

/*
    0: If the strings are identical up to the end of the shortest string (i.e., they are equal).
    Positive Value: If the first differing character in str1 is greater than the corresponding character in str2.
    Negative Value: If the first differing character in str1 is less than the corresponding character in str2.
*/
SECTION_CODE int pic_strcmp(const char *str1, const char *str2)
{
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return (*(unsigned char *)str1 - *(unsigned char *)str2);
}

SECTION_CODE int pic_strcmpW(const wchar_t *wstr1, const wchar_t *wstr2) 
{
    while (*wstr1 && (*wstr1 == *wstr2)) {
        wstr1++;
        wstr2++;
    }
    return (int)(*wstr1 - *wstr2);
}

SECTION_CODE int pic_strncmp(const char *s1, const char *s2, size_t n) 
{
    // Compare up to `n` characters or until a null terminator is encountered
    while (n > 0 && *s1 && *s2) {
        if (*s1 != *s2) {
            return (unsigned char)*s1 - (unsigned char)*s2;
        }
        s1++;
        s2++;
        n--;
    }
    
    // If we've exhausted the `n` characters, or one string ended
    if (n == 0) {
        return 0;
    }
    
    // If any of the strings are terminated, return the difference of the characters
    if (*s1 != *s2) {
        return (unsigned char)*s1 - (unsigned char)*s2;
    }
    
    return 0;
}

SECTION_CODE char *pic_strncpy(char *dest, const char *src, size_t n)
{
    char *d = dest;
    const char *s = src;
    
    while (n > 0) {
        if (*s == '\0') {
            // If the source string ends, fill the rest with null bytes
            *d = '\0';
            while (--n > 0) {
                *(++d) = '\0';
            }
            break;
        }
        // Copy the character from source to destination
        *d++ = *s++;
        --n;
    }
    
    // If n reaches 0, ensure null-termination
    if (n == 0) {
        *d = '\0';
    }
    
    return dest;
}

SECTION_CODE void pic_strcat(char *str1, char *str2)
{

    int i, j=0;

    // Otherwise If UUID not intialized, segfault
    // if(str2 != '0x00'){
    //     return;
    // }

    //Copying string 2 to the end of string 1
    for( i=pic_strlen(str1); str2[j]!='\0'; i++ ) {
        str1[i]=str2[j];
        j++;
    }

    str1[i]='\0';
}

SECTION_CODE void pic_strcatW(wchar_t *wstr1, wchar_t *wstr2)
{
    // Find the end of the first wide string
    wchar_t *end = wstr1;
    while (*end != L'\0') {
        end++;
    }

    // Append the second wide string to the end of the first one
    while (*wstr2 != L'\0') {
        *end = *wstr2;
        end++;
        wstr2++;
    }

    // Null-terminate the concatenated string
    *end = L'\0';
}

// Helper function to convert DWORD to WCHAR string
SECTION_CODE void dword_to_wchar(DWORD value, WCHAR* buffer, int base) 
{
    WCHAR* ptr = buffer;
    WCHAR* ptr1 = buffer;
    WCHAR tmp_char;
    DWORD quotient = value;

    // Handle 0 explicitly
    if (value == 0) {
        *ptr++ = L'0';
        *ptr = L'\0';
        return;
    }

    // Convert to string
    while (quotient != 0) {
        DWORD digit = quotient % base;
        *ptr++ = (WCHAR)(digit < 10 ? L'0' + digit : L'A' + digit - 10);
        quotient /= base;
    }
    *ptr-- = L'\0';

    // Reverse the string
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
}


SECTION_CODE void ulong_to_wchar(ULONG64 value, WCHAR *buffer) 
{
    WCHAR* ptr = buffer;
    WCHAR* ptr1 = buffer;
    WCHAR tmp_char;
    ULONG64 quotient = value;

    // Handle 0 explicitly
    if (value == 0) {
        *ptr++ = L'0';
        *ptr = L'\0';
        return;
    }

    // Convert to string
    while (quotient != 0) {
        ULONG64 digit = quotient % 10;
        *ptr++ = (WCHAR)(digit < 10 ? L'0' + digit : L'A' + digit - 10);
        quotient /= 10;
    }
    *ptr-- = L'\0';

    // Reverse the string
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
}