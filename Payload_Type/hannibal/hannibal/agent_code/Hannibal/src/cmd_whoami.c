#include "config.h"


#ifdef INCLUDE_CMD_WHOAMI

#include "hannibal_tasking.h"

/**
 * Requires Advapi32.dll.
 */
SECTION_CODE void cmd_whoami(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_WHOAMI *who = (CMD_WHOAMI *)t.cmd;

    HANDLE hToken;
    if(hannibal_instance_ptr->Win32.OpenProcessToken(-1, TOKEN_QUERY, &hToken)){
       
        DWORD dwSize = 0;
       
        hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenUser, 0, 0, &dwSize);
       
        BYTE buffer[dwSize];
        PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer;

        if (hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)){

            WCHAR name[256];
            WCHAR domain[256];
            DWORD nameSize = sizeof(name);
            DWORD domainSize = sizeof(domain);
            SID_NAME_USE sidType;
            
            if(hannibal_instance_ptr->Win32.LookupAccountSidW(NULL, pTokenUser->User.Sid, name, &nameSize, domain, &domainSize, &sidType)){

                WCHAR response[sizeof(domain) + sizeof(name) + pic_strlenW(L"\\") + 2];
                pic_memcpy(response, domain, pic_strlenW(domain)*sizeof(WCHAR));
                pic_strcatW(response + pic_strlenW(domain), L"\\");
                pic_strcatW(response + pic_strlenW(domain) + pic_strlenW(L"\\"), name);
                hannibal_response(response, t.task_uuid);

            }
        }
    }
    
    hannibal_instance_ptr->Win32.CloseHandle(hToken);
    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
    
}

#endif