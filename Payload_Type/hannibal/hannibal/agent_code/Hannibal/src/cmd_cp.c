#include "config.h"


#ifdef INCLUDE_CMD_CP

#include "hannibal_tasking.h"

/**
 * TODO: Better error messages
 */
SECTION_CODE void copy_directory(LPCWSTR src_dir, LPCWSTR dst_dir) 
{
    HANNIBAL_INSTANCE_PTR

    if (!hannibal_instance_ptr->Win32.CreateDirectoryW(dst_dir, NULL)) {
        // DWORD error = GetLastError();
        // if (error != ERROR_ALREADY_EXISTS) {
        //     // Handle the error (e.g., log it)
        //     return;
        // }
    }

    WIN32_FIND_DATAW find_data;
    HANDLE hFind;

    WCHAR search_path[MAX_PATH];
    int i = 0;
    while (src_dir[i] != L'\0') {
        search_path[i] = src_dir[i];
        i++;
    }
    search_path[i++] = L'\\';  
    search_path[i++] = L'*';   
    search_path[i] = L'\0';    

    hFind = hannibal_instance_ptr->Win32.FindFirstFileW(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return; 
    }

    do {
        if (find_data.cFileName[0] != L'.') {
            WCHAR src_path[MAX_PATH];
            WCHAR dst_path[MAX_PATH];

            int j = 0;
            while (src_dir[j] != L'\0') {
                src_path[j] = src_dir[j];
                j++;
            }
            src_path[j++] = L'\\';  
            for (int k = 0; find_data.cFileName[k] != L'\0'; k++, j++) {
                src_path[j] = find_data.cFileName[k];
            }
            src_path[j] = L'\0';

            j = 0;
            while (dst_dir[j] != L'\0') {
                dst_path[j] = dst_dir[j];
                j++;
            }
            dst_path[j++] = L'\\';  
            for (int k = 0; find_data.cFileName[k] != L'\0'; k++, j++) {
                dst_path[j] = find_data.cFileName[k];
            }
            dst_path[j] = L'\0';

            DWORD attributes = hannibal_instance_ptr->Win32.GetFileAttributesW(src_path);
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
                    copy_directory(src_path, dst_path);
                } else {
                    hannibal_instance_ptr->Win32.CopyFileW(src_path, dst_path, FALSE);
                }
            }
        }
    } while (hannibal_instance_ptr->Win32.FindNextFileW(hFind, &find_data));

    hannibal_instance_ptr->Win32.FindClose(hFind);
    
}


SECTION_CODE void cmd_cp(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_CP *cp = (CMD_CP *)t.cmd;
    LPCWSTR src_path = cp->src_path;
    LPCWSTR dest_path = cp->dst_path;

    DWORD attributes = hannibal_instance_ptr->Win32.GetFileAttributesW(src_path);

    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
            copy_directory(src_path, dest_path);
        } else {
            if (!hannibal_instance_ptr->Win32.CopyFileW(src_path, dest_path, FALSE)) {
                // DWORD error = GetLastError();
            }
        }
    } else {
        // DWORD error = GetLastError();
    }

    LPCWSTR response_content = L"Command Issued";

    TASK response_t;
    response_t.output = (LPCSTR)response_content;
    response_t.output_size = pic_strlenW(response_content)*sizeof(WCHAR) + 2;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, cp->src_path);
    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, cp->dst_path);
    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, t.cmd);
    
}

#endif