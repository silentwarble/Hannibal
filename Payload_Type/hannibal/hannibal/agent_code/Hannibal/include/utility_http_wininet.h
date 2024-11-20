#ifndef UTILITY_HTTP_WININET_H
#define UTILITY_HTTP_WININET_H

#include "hannibal.h"

// #define HTTP_METHOD_GET 1
// #define HTTP_METHOD_POST 2

typedef struct to_utility_http_wininet_msg {
    WCHAR *http_method;
    WCHAR *user_agent;
    WCHAR *dst_host;
    WCHAR *dst_url;
    CHAR *content;
    int content_length;
} to_utility_http_wininet_msg;

typedef struct from_utility_http_wininet_msg {
    int bytes_read;
    char *content;
} from_utility_http_wininet_msg;


from_utility_http_wininet_msg http_wininet_request(to_utility_http_wininet_msg req);


#endif