#include "config.h"


#ifdef INCLUDE_CMD_IPINFO

#include "hannibal_tasking.h"


SECTION_CODE void cmd_ipinfo(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_IPINFO *ipinfo = (CMD_IPINFO *)t.cmd;

    
    size_t INITIAL_BUFFER_SIZE = 4096;
    size_t CURRENT_BUFFER_SIZE = INITIAL_BUFFER_SIZE;
    size_t CURRENT_BUFFER_USAGE = 0;

    UINT8 *response_content = (UINT8 *)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, INITIAL_BUFFER_SIZE);

    ULONG out_len = sizeof(IP_ADAPTER_ADDRESSES);
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, out_len);

    // Get size. GAA_FLAG_INCLUDE_ALL_INTERFACES for disabled as well
    if (hannibal_instance_ptr->Win32.GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddresses, &out_len) == ERROR_BUFFER_OVERFLOW) {
        hannibal_instance_ptr->Win32.VirtualFree(pAddresses, 0, MEM_RELEASE);
        pAddresses = (PIP_ADAPTER_ADDRESSES)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->config.process_heap, HEAP_ZERO_MEMORY, out_len);
    }

    if (hannibal_instance_ptr->Win32.GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddresses, &out_len) == NO_ERROR) {

        PIP_ADAPTER_ADDRESSES pCurr = pAddresses;

        while (pCurr) {

            WCHAR *name = (PWCHAR)pCurr->FriendlyName;;
            WCHAR *description = (PWCHAR)pCurr->Description;;

            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, name);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, description);
            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

             // MAC Address. TODO: MAC is mangled in PIC mode.

            // buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"MAC: ");
            
            // BYTE *mac = pCurr->PhysicalAddress;

            // for (int i = 0; i < 6; i++) {
            //     if (i > 0) {
            //         buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L":");
            //     }
            //     WCHAR byte_str[2] = {0}; 
            //     byte_str[0] = (mac[i] >> 4) < 10 ? (mac[i] >> 4) + '0' : (mac[i] >> 4) - 10 + L'A'; // High nibble. TODO: I think this can be extracted out into a function as other places do the same.
            //     byte_str[1] = (mac[i] & 0x0F) < 10 ? (mac[i] & 0x0F) + '0' : (mac[i] & 0x0F) - 10 + L'A'; // Low nibble.
            //     buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, byte_str);
            // }

            // buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

            // Default Gateways
            PIP_ADAPTER_GATEWAY_ADDRESS pGateway = pCurr->FirstGatewayAddress;
            while (pGateway) {

                if (pGateway->Address.lpSockaddr->sa_family == AF_INET) {

                    struct sockaddr_in* gw_sa_in = (struct sockaddr_in*)pGateway->Address.lpSockaddr;
                    WCHAR gw_str[INET_ADDRSTRLEN];
                    hannibal_instance_ptr->Win32.InetNtopW(AF_INET, &gw_sa_in->sin_addr, gw_str, sizeof(gw_str) / sizeof(WCHAR));
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"Gateway: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, gw_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                } else if (pGateway->Address.lpSockaddr->sa_family == AF_INET6) {

                    struct sockaddr_in6* gw_sa_in6 = (struct sockaddr_in6*)pGateway->Address.lpSockaddr;
                    WCHAR gw_str[INET6_ADDRSTRLEN];
                    hannibal_instance_ptr->Win32.InetNtopW(AF_INET6, &gw_sa_in6->sin6_addr, gw_str, sizeof(gw_str) / sizeof(WCHAR));
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"Gateway: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, gw_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                }
                pGateway = pGateway->Next; 
            }

            
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress;
            while (pUnicast) {

                // IPv4
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {

                    struct sockaddr_in* sa_in = (struct sockaddr_in*)pUnicast->Address.lpSockaddr;
                    WCHAR ip_str[INET_ADDRSTRLEN];
                    WCHAR mask_str[INET_ADDRSTRLEN];
                    ULONG subnet_mask_val = 0xFFFFFFFF << (32 - pUnicast->OnLinkPrefixLength);

                    // IP
                    hannibal_instance_ptr->Win32.InetNtopW(AF_INET, &sa_in->sin_addr, ip_str, sizeof(ip_str) / sizeof(WCHAR));
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"v4: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, ip_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                    // Mask
                    struct sockaddr_in mask;
                    mask.sin_addr.S_un.S_addr = pic_htonl(subnet_mask_val);
                    hannibal_instance_ptr->Win32.InetNtopW(AF_INET, &mask.sin_addr, mask_str, sizeof(mask_str) / sizeof(WCHAR));
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"Mask: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, mask_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                // IPv6    
                } else if(pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {

                    struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)pUnicast->Address.lpSockaddr;
                    WCHAR ip_str[INET6_ADDRSTRLEN];
                    WCHAR mask_str[16]; 

                    ULONG prefix_length = pUnicast->OnLinkPrefixLength;

                    // IPv6 to wstring
                    hannibal_instance_ptr->Win32.InetNtopW(AF_INET6, &sa_in6->sin6_addr, ip_str, sizeof(ip_str) / sizeof(WCHAR));
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"v6: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, ip_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                    // Prefix length to wstring
                    dword_to_wchar(prefix_length, mask_str, 10);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"Subnet Prefix Length: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, mask_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                }
                pUnicast = pUnicast->Next;
            } // while (pUnicast)

            // DNS
            PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pCurr->FirstDnsServerAddress;
            while (pDns) {

                if (pDns->Address.lpSockaddr->sa_family == AF_INET) {

                    struct sockaddr_in* dns_sa_in = (struct sockaddr_in*)pDns->Address.lpSockaddr;
                    WCHAR dns_str[INET_ADDRSTRLEN];
                    hannibal_instance_ptr->Win32.InetNtopW(AF_INET, &dns_sa_in->sin_addr, dns_str, sizeof(dns_str) / sizeof(WCHAR));
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"DNS: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, dns_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                } else if (pDns->Address.lpSockaddr->sa_family == AF_INET6) {

                    struct sockaddr_in6* dns_sa_in6 = (struct sockaddr_in6*)pDns->Address.lpSockaddr;
                    WCHAR dns_str[INET6_ADDRSTRLEN];
                    hannibal_instance_ptr->Win32.InetNtopW(AF_INET6, &dns_sa_in6->sin6_addr, dns_str, sizeof(dns_str) / sizeof(WCHAR));
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"DNS: ");
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, dns_str);
                    buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");

                }
                pDns = pDns->Next;
            }

            buffer_append_alloc(&response_content, &CURRENT_BUFFER_SIZE, &CURRENT_BUFFER_USAGE, L"\n");
            
            pCurr = pCurr->Next;
        } //  while (pCurr)
    }  

    TASK response_t;

    response_t.output = (LPCSTR)response_content;
    response_t.output_size = CURRENT_BUFFER_USAGE;
    response_t.task_uuid = t.task_uuid;

    task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

    hannibal_instance_ptr->Win32.VirtualFree(pAddresses, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
}

#endif