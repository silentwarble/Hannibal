#include "utility_strings.h"

SECTION_GLOBAL PVOID __Instance = (PVOID)'placeholder';

EXTERN_C SECTION_CODE VOID InitializeHannibal(
    PVOID Param
) {
    INSTANCE hannibal_instance = { 0 };
    PVOID    current_process_heap = { 0 };
    PVOID    global_section_addr = { 0 };
    SIZE_T   global_section_size = { 0 };
    ULONG    old_mem_permission = { 0 };

    pic_RtlSecureZeroMemory( & hannibal_instance, sizeof( hannibal_instance ) );

    current_process_heap = NtCurrentPeb()->ProcessHeap;

    hannibal_instance.Base.Buffer = StRipStart();
    hannibal_instance.Base.Length = (UINT_PTR)StRipEnd() - (UINT_PTR)hannibal_instance.Base.Buffer;

    global_section_addr = hannibal_instance.Base.Buffer + (UINT_PTR)&__Instance_offset;
    global_section_size = sizeof( PVOID );

    if ( ( hannibal_instance.Modules.Ntdll = get_module_ptr_from_peb( H_MODULE_NTDLL ) ) ) {
        if ( ! ( hannibal_instance.Win32.RtlAllocateHeap        = get_func_ptr_from_module_eat( hannibal_instance.Modules.Ntdll, HASH_STR( "RtlAllocateHeap"        ) ) ) ||
             ! ( hannibal_instance.Win32.NtProtectVirtualMemory = get_func_ptr_from_module_eat( hannibal_instance.Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) ) )
        ) {
            return;
        }
    }

    if ( ! NT_SUCCESS( hannibal_instance.Win32.NtProtectVirtualMemory(
        NtCurrentProcess(),
        & global_section_addr,
        & global_section_size,
        PAGE_READWRITE,
        & old_mem_permission
    ) ) ) {
        return;
    }

    if ( ! ( *(PVOID*)global_section_addr = hannibal_instance.Win32.RtlAllocateHeap(
        current_process_heap, 
        HEAP_ZERO_MEMORY, 
        sizeof( INSTANCE ) 
        ) ) ) {
        return;
    }


    pic_memcpy( *(PVOID*)global_section_addr, &hannibal_instance, sizeof( INSTANCE ) );
    pic_RtlSecureZeroMemory( &hannibal_instance, sizeof( INSTANCE ) );
    pic_RtlSecureZeroMemory( (PVOID)( (UINT_PTR)global_section_addr+ sizeof( PVOID ) ), 0x18 );

    Hannibal( Param );
}