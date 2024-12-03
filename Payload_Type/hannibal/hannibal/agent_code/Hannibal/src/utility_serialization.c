#include "utility_serialization.h"

/**
 * TODO: Needs cleanup. Add more functions. The readstring functions
 *       don't read a string as much as they just allocate a buffer
 *       memcpy, then iterate the buffer pointer. 
 * 
 */

SECTION_CODE void WriteUint8(UINT8 **buffer, UINT8 value) 
{
    **buffer = value;
    (*buffer)++;
}

SECTION_CODE void WriteUint32(UINT8 **buffer, UINT32 value) 
{ 
    // Ensure little-endian encoding
    for (int i = 0; i < 4; i++) {
        **buffer = (UINT8)(value & 0xFF); // Write the least significant byte first
        (*buffer)++;
        value >>= 8; // Shift right to get the next byte
    }
}

SECTION_CODE void WriteUint64(UINT8 **buffer, UINT64 value) 
{
    for (size_t i = 0; i < sizeof(UINT64); i++) {
        **buffer = (UINT8)(value & 0xFF); 
        (*buffer)++;
        value >>= 8; 
    }
}

SECTION_CODE void WriteString(UINT8 **buffer, const char *str, BOOL include_null)
{
    while (*str) {
        **buffer = *str;
        (*buffer)++;
        str++;
    }
    if (include_null){
        **buffer = 0;
        (*buffer)++;
    }
}

SECTION_CODE void WriteStringW(UINT8 **buffer, const wchar_t *str, BOOL include_null)
{
    while (*str) {
        // Write each wide character (2 bytes)
        **buffer = (UINT8)(*str & 0xFF);         // Lower byte
        (*buffer)++;
        **buffer = (UINT8)((*str >> 8) & 0xFF); // Upper byte
        (*buffer)++;
        str++;
    }
    if (include_null) {
        // Write the null terminator (0x0000) as 2 bytes
        **buffer = 0x00;
        (*buffer)++;
        **buffer = 0x00;
        (*buffer)++;
    }
}

SECTION_CODE void WriteBytes(UINT8 **buffer, const char *str, int size)
{
    for (int i = 0; i < size; i++){
        **buffer = *str;
        (*buffer)++;
        str++;
    }
}

SECTION_CODE UINT8 ReadUint8(UINT8 **buffer) 
{
    UINT8 value = **buffer;
    (*buffer)++;
    return value;
}

SECTION_CODE UINT32 ReadUint32(UINT8 **buffer) 
{
    UINT32 value = 0;
    for (int i = 0; i < 4; i++) {
        value |= ((UINT32)**buffer) << (8 * i);
        (*buffer)++;
    }
    return value;
}

SECTION_CODE UINT8* ReadBytes(UINT8 **buffer, UINT32 length) 
{
    HANNIBAL_INSTANCE_PTR

    UINT8* bytes = (UINT8*)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!bytes) return NULL;

    pic_memcpy(bytes, *buffer, length);

    *buffer += length;

    return bytes;
}

/**
 * Expects that the string is null terminated. If not, you can use
 * the length param.
 */
SECTION_CODE PCHAR ReadString(UINT8 **buffer, UINT32 length) 
{
    
    HANNIBAL_INSTANCE_PTR

    UINT32 str_len = 0;
    
    while ((*buffer)[str_len] != '\0'){
        str_len++;
    }
    
    PCHAR str = (PCHAR)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, str_len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!str) return NULL;
    pic_memcpy(str, *buffer, str_len + 1);
    *buffer += str_len + 1;
    return str;
}

/**
 * Expects that the string is null terminated. If not, you can use
 * the length param.
 */
SECTION_CODE PWCHAR ReadStringW(UINT8 **buffer, UINT32 length)
{
    HANNIBAL_INSTANCE_PTR

    UINT32 str_len = 0;
    
    while (((PWCHAR)(*buffer))[str_len] != L'\0'){
        str_len++;
    }
    
    PWCHAR str = (PWCHAR)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, (str_len + 1) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!str) return NULL;
    pic_memcpy(str, *buffer, (str_len + 1) * sizeof(WCHAR));
    *buffer += (str_len + 1) * sizeof(WCHAR);
    return str;
}

SECTION_CODE DWORD pic_htonl(DWORD hostlong) 
{
    return ((hostlong & 0xFF000000) >> 24) | // Move byte 3 to byte 0
           ((hostlong & 0x00FF0000) >> 8)  | // Move byte 2 to byte 1
           ((hostlong & 0x0000FF00) << 8)  | // Move byte 1 to byte 2
           ((hostlong & 0x000000FF) << 24);   // Move byte 0 to byte 3
}