#include "config.h"


#ifdef INCLUDE_CMD_LS

#include "hannibal_tasking.h"


// YYYY-MM-DD HH:MM:SS
SECTION_CODE void format_time(SYSTEMTIME *st, WCHAR *buffer) {
    int len = 0;

    // Format Year
    buffer[len++] = L'0' + (st->wYear / 1000);
    buffer[len++] = L'0' + (st->wYear / 100 % 10);
    buffer[len++] = L'0' + (st->wYear / 10 % 10);
    buffer[len++] = L'0' + (st->wYear % 10);
    buffer[len++] = L'-';

    // Format Month
    buffer[len++] = L'0' + (st->wMonth / 10);
    buffer[len++] = L'0' + (st->wMonth % 10);
    buffer[len++] = L'-';

    // Format Day
    buffer[len++] = L'0' + (st->wDay / 10);
    buffer[len++] = L'0' + (st->wDay % 10);
    buffer[len++] = L' ';

    // Format Hour
    buffer[len++] = L'0' + (st->wHour / 10);
    buffer[len++] = L'0' + (st->wHour % 10);
    buffer[len++] = L':';

    // Format Minute
    buffer[len++] = L'0' + (st->wMinute / 10);
    buffer[len++] = L'0' + (st->wMinute % 10);
    buffer[len++] = L':';

    // Format Second
    buffer[len++] = L'0' + (st->wSecond / 10);
    buffer[len++] = L'0' + (st->wSecond % 10);

    // Null-terminate the string
    buffer[len] = L'\0';
}


// Use unix timestamps if you prefer
// SECTION_CODE void format_unix_time(SYSTEMTIME *st, WCHAR *buffer) 
// {
//     HANNIBAL_INSTANCE_PTR

//     // Convert SYSTEMTIME to FILETIME
//     FILETIME ft;
//     hannibal_instance_ptr->Win32.SystemTimeToFileTime(st, &ft);

//     // Convert FILETIME to 64-bit integer
//     ULARGE_INTEGER ull;
//     ull.LowPart = ft.dwLowDateTime;
//     ull.HighPart = ft.dwHighDateTime;

//     // Calculate Unix time (seconds since Jan 1, 1970)
//     // FILETIME is in 100-nanosecond intervals since Jan 1, 1601
//     // We need to subtract the number of 100-nanosecond intervals from Jan 1, 1601, to Jan 1, 1970
//     const ULONGLONG UNIX_EPOCH_OFFSET = 116444736000000000ULL; // Offset in 100-nanosecond intervals
//     ULONGLONG unixTime = (ull.QuadPart - UNIX_EPOCH_OFFSET) / 10000000; // Convert to seconds

//     // Format the Unix time into the wide char buffer
//     int len = 0;
//     if (unixTime == 0) {
//         // Handle zero case separately if needed
//         buffer[len++] = L'0';
//     } else {
//         // Convert the number to wide char string
//         WCHAR temp[20]; // Sufficient for a 64-bit number
//         int pos = 0;
//         while (unixTime > 0) {
//             temp[pos++] = L'0' + (unixTime % 10);
//             unixTime /= 10;
//         }
//         // Reverse the string to correct the order
//         for (int i = 0; i < pos; i++) {
//             buffer[len++] = temp[pos - 1 - i];
//         }
//     }
//     buffer[len] = L'\0'; // Null-terminate the string
// }

// Takes a number and converts it into its string representation
SECTION_CODE void format_size(ULONGLONG size, WCHAR *buffer) 
{
    int len = 0;
    if (size == 0) {
        buffer[len++] = L'0';
    } else {
        while (size > 0) {
            buffer[len++] = L'0' + (size % 10);
            size /= 10;
        }
    }
    // Reverse the string
    for (int i = 0; i < len / 2; i++) {
        WCHAR temp = buffer[i];
        buffer[i] = buffer[len - i - 1];
        buffer[len - i - 1] = temp;
    }
    buffer[len] = L'\0';
}

SECTION_CODE void append_to_buffer(WCHAR *buffer, int *cursor, const WCHAR *str) 
{
    while (*str) {
        buffer[(*cursor)++] = *str++;
    }
}

/**
 * TODO: This function can be simplified by using buffer_append_alloc and remove append_to_buffer
 */
SECTION_CODE void cmd_ls(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_LS *ls = (CMD_LS *)t.cmd;

    WIN32_FIND_DATAW ffd;
    WCHAR szDir[MAX_PATH*sizeof(WCHAR)] = {0};
    HANDLE hFind = INVALID_HANDLE_VALUE;

    if (pic_strlenW(ls->path) * sizeof(WCHAR) > MAX_PATH*sizeof(WCHAR)) {
        return;
    }

    pic_strcatW(szDir, ls->path);
    pic_strcatW(szDir + pic_strlenW(ls->path), L"\\*");
    pic_strcatW(szDir + pic_strlenW(ls->path) + pic_strlenW(L"\\*"), L"\0");

    hFind = hannibal_instance_ptr->Win32.FindFirstFileW(szDir, &ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD errorCode = hannibal_instance_ptr->Win32.GetLastError();
        WCHAR errorMessage[256] = L"Error Code: ";
        
        // Convert the error code to string
        WCHAR codeBuffer[20];
        dword_to_wchar(errorCode, codeBuffer, 10);
        
        pic_strcatW(errorMessage, codeBuffer);

        WCHAR *response_content = (WCHAR *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE);

        for (int i = 0; i < 256; i++) {
            response_content[i] = errorMessage[i];
        }

        TASK response_t;
        response_t.output = (LPCSTR)response_content;
        // response_t.output_size = (pic_strlenW(response_t.output) + 1) * sizeof(WCHAR);
        response_t.output_size = (pic_strlenW(response_content) + 1) * sizeof(WCHAR);
        response_t.task_uuid = t.task_uuid;

        task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

        if (ls->path) {
            hannibal_instance_ptr->Win32.VirtualFree(ls->path, 0, MEM_RELEASE);
        }
        if (t.cmd) {
            hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
        }
        return;
    }

    int buff_cursor = 0;
    int INITIAL_BUFFER_SIZE = 1024;
    int CURRENT_BUFFER_SIZE = INITIAL_BUFFER_SIZE;
    int CURRENT_BUFFER_USAGE = 0;

    // Freed in mythic_http_post_tasks()
    WCHAR *response_content = (WCHAR *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, INITIAL_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
    response_content[0] = 0;

    WCHAR sizeBuffer[20];
    WCHAR timeBuffer[50];
    WCHAR itemBuffer[512];

    while (hFind != INVALID_HANDLE_VALUE) {
        if (pic_strcmpW(ffd.cFileName, L".") != 0 && pic_strcmpW(ffd.cFileName, L"..") != 0) {
            WCHAR *fileType = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? L"<DIR>" : L"";
            ULONGLONG fileSize = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 0 : ((ULONGLONG)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;

            SYSTEMTIME creationTime, accessTime, writeTime;
            hannibal_instance_ptr->Win32.FileTimeToSystemTime(&ffd.ftCreationTime, &creationTime);
            hannibal_instance_ptr->Win32.FileTimeToSystemTime(&ffd.ftLastAccessTime, &accessTime);
            hannibal_instance_ptr->Win32.FileTimeToSystemTime(&ffd.ftLastWriteTime, &writeTime);

            WCHAR accessBuffer[30], writeBuffer[30];

            // Unix Time
            // format_unix_time(&creationTime, timeBuffer);
            // format_unix_time(&accessTime, accessBuffer);
            // format_unix_time(&writeTime, writeBuffer);

            // Human Readable Timestamps.             
            format_time(&creationTime, timeBuffer);
            format_time(&accessTime, accessBuffer);
            format_time(&writeTime, writeBuffer);

            // Create the item string
            int itemLength = pic_strlenW(fileType) + pic_strlenW(timeBuffer) + pic_strlenW(accessBuffer) + pic_strlenW(writeBuffer) + pic_strlenW(ffd.cFileName) + 50;
            if (CURRENT_BUFFER_USAGE + itemLength * sizeof(WCHAR) > CURRENT_BUFFER_SIZE) {
                int newSize = CURRENT_BUFFER_USAGE + (itemLength * sizeof(WCHAR)) + INITIAL_BUFFER_SIZE;
                WCHAR *newResponseContent = (WCHAR *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, newSize, MEM_COMMIT, PAGE_READWRITE);
                if (newResponseContent) {
                    for (int j = 0; j < buff_cursor; j++) {
                        newResponseContent[j] = response_content[j];
                    }
                    hannibal_instance_ptr->Win32.VirtualFree(response_content, 0, MEM_RELEASE);
                    response_content = newResponseContent;
                    CURRENT_BUFFER_SIZE = newSize;
                }
            }

            
            format_size(fileSize, sizeBuffer);
            

            /**
             * If you need to parse this stuff at the controller like using Mythic's file
             * browser, then use a char to seperate the fields your translater code
             * can split on. Turn on/off whatever you want to go across the network. 
             * The less the better. Ideally we would do fancy string formatting on the controller.
             */

            int index = 0;            
            // append_to_buffer(itemBuffer, &index, timeBuffer);
            // append_to_buffer(itemBuffer, &index, L",");
            append_to_buffer(itemBuffer, &index, accessBuffer);
            append_to_buffer(itemBuffer, &index, L"\t");
            // append_to_buffer(itemBuffer, &index, writeBuffer);
            // append_to_buffer(itemBuffer, &index, L",");
            append_to_buffer(itemBuffer, &index, L" UTC\t");
            append_to_buffer(itemBuffer, &index, fileType);
            append_to_buffer(itemBuffer, &index, L"\t");
            append_to_buffer(itemBuffer, &index, sizeBuffer);
            append_to_buffer(itemBuffer, &index, L"\t");
            append_to_buffer(itemBuffer, &index, ffd.cFileName);
            append_to_buffer(itemBuffer, &index, L"\n");

            for (int i = 0; i < index; i++) {
                response_content[buff_cursor++] = itemBuffer[i];
            }

            CURRENT_BUFFER_USAGE += index * sizeof(WCHAR);
        }

        if (hannibal_instance_ptr->Win32.FindNextFileW(hFind, &ffd) == 0) {
            break;
        }
    }

    response_content[buff_cursor] = L'\0';
    CURRENT_BUFFER_USAGE += 2;

    TASK response_t;

    response_t.output = (LPCSTR)response_content;
    response_t.output_size = CURRENT_BUFFER_USAGE;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.VirtualFree(ls->path, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);

    if (hFind != INVALID_HANDLE_VALUE) {
        hannibal_instance_ptr->Win32.FindClose(hFind);
    }
}

#endif