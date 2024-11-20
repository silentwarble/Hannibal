// Credit: https://github.com/Cracked5pider/Stardust

#include "utility_winapi_function_resolution.h"

/*!
 * @brief
 *  resolve module from peb
 *
 * @param Buffer
 *  Buffer: either string or hash
 *
 * @param Hashed
 *  is the Buffer a hash value
 *
 * @return
 *  module base pointer
 */
SECTION_CODE PVOID get_module_ptr_from_peb(
    _In_ ULONG Hash
) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = (PVOID)Entry;

        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash ) {
            return Data->DllBase;
        }
    }

    return NULL;
}

/*!
 * @brief
 *  retrieve image header
 *
 * @param Image
 *  image base pointer to retrieve header from
 *
 * @return
 *  pointer to Nt Header
 */
SECTION_CODE PIMAGE_NT_HEADERS LdrpImageHeader(
        _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = (PVOID)( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = (PVOID)( (UINT_PTR)( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

SECTION_CODE PVOID get_func_ptr_from_module_eat(
    _In_ PVOID Library,
    _In_ ULONG Function
) {

    HANNIBAL_INSTANCE_PTR

    PVOID                   Address    = { 0 };
    PIMAGE_NT_HEADERS       NtHeader   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
    SIZE_T                  ExpDirSize = { 0 };
    PDWORD                  AddrNames  = { 0 };
    PDWORD                  AddrFuncs  = { 0 };
    PWORD                   AddrOrdns  = { 0 };
    PCHAR                   FuncName   = { 0 };

    if ( ! Library || ! Function ) {
        return NULL;
    }

    if ( ! ( NtHeader = LdrpImageHeader( Library ) ) ) {
        return NULL;
    }

    ExpDir     = (PVOID)( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = (PVOID)( Library + ExpDir->AddressOfNames );
    AddrFuncs  = (PVOID)( Library + ExpDir->AddressOfFunctions );
    AddrOrdns  = (PVOID)( Library + ExpDir->AddressOfNameOrdinals );

     for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {

        FuncName = (PVOID)( (UINT_PTR)( Library ) + AddrNames[ i ] );

        if ( HashString( FuncName, 0 ) != Function ) {
            continue;
        }

        Address = (PVOID)( (UINT_PTR)( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        if ( ( (UINT_PTR)( Address ) >= (UINT_PTR)( ExpDir ) ) &&
             ( (UINT_PTR)( Address ) <  (UINT_PTR)( ExpDir ) + ExpDirSize )
        ) {
            //
            // TODO: need to add support for forwarded functions
            //

            __debugbreak();
        }

        break;
    }

    return Address;
}