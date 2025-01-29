#include "config.h"


#ifdef INCLUDE_CMD_HOSTNAME

#include "hannibal_tasking.h"


SECTION_CODE void cmd_hostname(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_HOSTNAME *hst = (CMD_HOSTNAME *)t.cmd;

    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = sizeof(hostname) / sizeof(hostname[0]);

    hannibal_instance_ptr->Win32.GetComputerNameExW(ComputerNameNetBIOS, hostname, &size);

    hannibal_response(hostname, t.task_uuid);

    hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->config.process_heap, 0, t.cmd);
}

#endif