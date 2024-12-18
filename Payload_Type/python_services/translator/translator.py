# TODO: Refactor. Overly verbose and not commented well.

import json
import struct
import base64
import codecs

from mythic_container.TranslationBase import *


class hannibal_python_translator(TranslationContainer):
    name = "hannibal_python_translator"
    description = "Python translation service for custom TLV encoding."
    author = "@silentwarble"


    #################################### Message Types

    MESSAGE_TYPE_CHECKIN = 1
    MESSAGE_TYPE_CHECKIN_RESPONSE = 2
    MESSAGE_TYPE_GET_TASKS = 3
    MESSAGE_TYPE_GET_TASKS_RESPONSE = 4
    MESSAGE_TYPE_POST_TASKS = 5
    MESSAGE_TYPE_START_DOWNLOAD = 6
    MESSAGE_TYPE_CONTINUE_DOWNLOAD = 7
    MESSAGE_TYPE_POST_TASKS_RESPONSE = 8
    MESSAGE_TYPE_FILE_UPLOAD = 9

    #################################### TLV Defs

    TLV_CHECKIN_UUID = 2
    TLV_CHECKIN_IPS = 3
    TLV_CHECKIN_OS = 4
    TLV_CHECKIN_USER = 5
    TLV_CHECKIN_HOST = 6
    TLV_CHECKIN_PID = 7
    TLV_CHECKIN_ARCHITECTURE = 8
    TLV_CHECKIN_DOMAIN = 9
    TLV_CHECKIN_INTEGRITY_LEVEL = 10
    TLV_CHECKIN_EXTERNAL_IP = 11
    TLV_CHECKIN_ENCRYPTION_KEY = 12
    TLV_CHECKIN_DECRYPTION_KEY = 13
    TLV_CHECKIN_PROCESS_NAME = 14

    # CHECKIN RESPONSE
    TLV_CHECKIN_RESPONSE_ID = 15

    # COMMANDS
    TLV_CMD_ID = 16

    # LS
    TLV_CMD_LS_PARAM_PATH = 17

    # POST TASKING
    TLV_POST_TASKING = 20
    TLV_POST_TASKING_ID = 21
    TLV_POST_TASKING_CONTENT = 22

    # Download
    TLV_START_DOWNLOAD_CHUNK_COUNT = 23
    TLV_START_DOWNLOAD_CHUNK_SIZE = 24
    TLV_DOWNLOAD_PARAM_PATH = 25
    TLV_CONTINUE_DOWNLOAD_CHUNK_NUMBER = 26
    TLV_CONTINUE_DOWNLOAD_FILE_ID = 27
    TLV_CONTINUE_DOWNLOAD_FILE_DATA = 28
    TLV_START_DOWNLOAD_FILEPATH = 29

    # Upload
    TLV_UPLOAD_REMOTE_PATH = 30
    TLV_UPLOAD_FILE_UUID = 31
    TLV_UPLOAD_CHUNK_NUMBER = 32
    TLV_UPLOAD_CHUNK_SIZE = 33
    TLV_UPLOAD_CHUNK_COUNT = 34

    # execute_hbin
    TLV_CMD_EXECUTE_HBIN_ARGS = 35
    TLV_CMD_EXECUTE_HBIN_BIN = 36

    # rm
    TLV_CMD_RM_PATH = 37

    # cd
    TLV_CMD_CD_PATH = 38

    # cp
    TLV_CMD_CP_SRC_PATH = 39
    TLV_CMD_CP_DST_PATH = 40

    # mv
    TLV_CMD_MV_SRC_PATH = 41
    TLV_CMD_MV_DST_PATH = 42

    # mkdir
    TLV_CMD_MKDIR_PATH = 43

    # execute
    TLV_CMD_EXECUTE_PATH = 44

     # sleep
    TLV_CMD_SLEEP_INTERVAL = 45
    TLV_CMD_SLEEP_JITTER = 46

    


    #################################### CMD IDs

    CMD_LS_MESSAGE = 1
    CMD_EXIT_MESSAGE = 2
    CMD_DOWNLOAD_MESSAGE = 3 # Not treated like a normal command in Hannibal
    CMD_UPLOAD_MESSAGE = 4 # Not treated like a normal command in Hannibal
    CMD_EXECUTE_HBIN_MESSAGE = 5
    CMD_RM_MESSAGE = 6
    CMD_PWD_MESSAGE = 7
    CMD_CD_MESSAGE = 8
    CMD_CP_MESSAGE = 9
    CMD_MV_MESSAGE = 10
    CMD_HOSTNAME_MESSAGE = 11
    CMD_WHOAMI_MESSAGE = 12
    CMD_MKDIR_MESSAGE = 13
    CMD_PS_MESSAGE = 14
    CMD_IPINFO_MESSAGE = 15
    CMD_LISTDRIVES_MESSAGE = 16
    CMD_EXECUTE_MESSAGE = 17
    CMD_SLEEP_MESSAGE = 18
    CMD_AGENTINFO_MESSAGE = 19




    # Currently unused as Mythic handles the encrypt/decrypt
    # async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
    #     response = TrGenerateEncryptionKeysMessageResponse(Success=True)
    #     response.DecryptionKey = b""
    #     response.EncryptionKey = b""
    #     return response



    ###############################################################################################
    ############################################# To Agent
    # Notes:
    # Strings are null byte terminated going to agent due to C null terminating strings


    def encode_uint8(self, value):
        return struct.pack('<B', value)
    
    def encode_uint16(self, value):
        return struct.pack('<H', value)

    def encode_uint32(self, value):
        return struct.pack('<I', value)

    def encode_string(self, value):
        return value.encode('utf-8') + b'\x00'  # Append null terminator

    def encode_stringW(self, value):
        return value.encode('utf-16-le') + b'\x00\x00'

    def encode_tlv(self, tlv_type, value):
        length = len(value)
        return self.encode_uint8(tlv_type) + self.encode_uint32(length) + value

    def serialize_checkin_response(self, json_dict):

        data = b''
        data += struct.pack('<B', self.MESSAGE_TYPE_CHECKIN_RESPONSE)

        if (json_dict["status"] == "success"):
            data += struct.pack('<B', 1)
        else:
            data += struct.pack('<B', 0)

        data += self.encode_uint8(self.TLV_CHECKIN_RESPONSE_ID)
        data += self.encode_uint32(len(json_dict["id"]) + 1) # +1 for null byte
        data += self.encode_string(json_dict["id"])

        return data

    def serialize_get_tasks_response(self, json_object):

        #raise Exception(json_object)
        data = b''
        data += struct.pack('<B', self.MESSAGE_TYPE_GET_TASKS_RESPONSE)
        data += struct.pack('<B', len(json_object["tasks"]))

        for task in json_object["tasks"]:
            if(task["command"] == "ls"):
                data += self.encode_uint8(self.CMD_LS_MESSAGE) #define CMD_ID_LS 1 "hannibal_tasking.h"

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_LS_PARAM_PATH)
                unicode_len = len(self.encode_stringW(params["path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["path"])

            if(task["command"] == "rm"):
                data += self.encode_uint8(self.CMD_RM_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_RM_PATH)
                unicode_len = len(self.encode_stringW(params["path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["path"])

            if(task["command"] == "pwd"):
                data += self.encode_uint8(self.CMD_PWD_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

            if(task["command"] == "agentinfo"):
                data += self.encode_uint8(self.CMD_AGENTINFO_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

            if(task["command"] == "ps"):
                data += self.encode_uint8(self.CMD_PS_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

            if(task["command"] == "hostname"):
                data += self.encode_uint8(self.CMD_HOSTNAME_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

            if(task["command"] == "whoami"):
                data += self.encode_uint8(self.CMD_WHOAMI_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

            if(task["command"] == "ipinfo"):
                data += self.encode_uint8(self.CMD_IPINFO_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

            if(task["command"] == "listdrives"):
                data += self.encode_uint8(self.CMD_LISTDRIVES_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

            if(task["command"] == "cd"):
                data += self.encode_uint8(self.CMD_CD_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_CD_PATH)
                unicode_len = len(self.encode_stringW(params["path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["path"])

            if(task["command"] == "cp"):
                data += self.encode_uint8(self.CMD_CP_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_CP_SRC_PATH)
                unicode_len = len(self.encode_stringW(params["src_path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["src_path"])

                data += self.encode_uint8(self.TLV_CMD_CP_DST_PATH)
                unicode_len = len(self.encode_stringW(params["dst_path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["dst_path"])

            if(task["command"] == "mv"):
                data += self.encode_uint8(self.CMD_MV_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_MV_SRC_PATH)
                unicode_len = len(self.encode_stringW(params["src_path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["src_path"])

                data += self.encode_uint8(self.TLV_CMD_MV_DST_PATH)
                unicode_len = len(self.encode_stringW(params["dst_path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["dst_path"])

            if(task["command"] == "sleep"):
                data += self.encode_uint8(self.CMD_SLEEP_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_SLEEP_INTERVAL)
                data += self.encode_uint32(struct.calcsize('I'))
                data += self.encode_uint32(int(params["interval"]))

                data += self.encode_uint8(self.TLV_CMD_SLEEP_JITTER)
                data += self.encode_uint32(struct.calcsize('I'))
                data += self.encode_uint32(int(params["jitter"]))

            if(task["command"] == "mkdir"):
                data += self.encode_uint8(self.CMD_MKDIR_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_MKDIR_PATH)
                unicode_len = len(self.encode_stringW(params["path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["path"])

            if(task["command"] == "execute"):
                data += self.encode_uint8(self.CMD_EXECUTE_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_CMD_EXECUTE_PATH)
                unicode_len = len(self.encode_stringW(params["path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["path"])

            if(task["command"] == "exit"):
                data += self.encode_uint8(self.CMD_EXIT_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint32(struct.calcsize('I'))
                data += self.encode_uint8(int(params["type"]))

            if(task["command"] == "download"):
                data += self.encode_uint8(self.CMD_DOWNLOAD_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_DOWNLOAD_PARAM_PATH)
                unicode_len = len(self.encode_stringW(params["path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["path"])

            if(task["command"] == "upload"):
                data += self.encode_uint8(self.CMD_UPLOAD_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                data += self.encode_uint8(self.TLV_UPLOAD_FILE_UUID)
                data += self.encode_uint32(len(params["file"]) + 1)
                data += self.encode_string(params["file"])

                data += self.encode_uint8(self.TLV_UPLOAD_REMOTE_PATH)
                unicode_len = len(self.encode_stringW(params["remote_path"]))
                data += self.encode_uint32(unicode_len)
                data += self.encode_stringW(params["remote_path"])

            if(task["command"] == "execute_hbin"):

                data += self.encode_uint8(self.CMD_EXECUTE_HBIN_MESSAGE)

                data += self.encode_uint8(self.TLV_CMD_ID)
                data += self.encode_uint32(len(task["id"]) + 1)
                data += self.encode_string(task["id"])

                params = json.loads(task["parameters"])

                # TYPE
                data += self.encode_uint8(self.TLV_CMD_EXECUTE_HBIN_ARGS)

                # LENGTH
                arg_buf_len = 0
                for arg in params["hbin_arguments"]:
                    if arg[0] == "int32":
                        arg_buf_len += 4  # Size of uint32
                    elif arg[0] == "string":
                        arg_buf_len += len(arg[1]) + 1  # Length + null terminator
                    elif arg[0] == "wchar":
                        arg_buf_len += len(arg[1]) * 2 + 2  # In terms of bytes each character is 2 bytes

                data += self.encode_uint32(arg_buf_len)

                # VALUE
                for arg in params["hbin_arguments"]:
                    if arg[0] == "int32":
                        data += self.encode_uint32(int(arg[1])) # The json.loads converts everything to string
                    elif arg[0] == "string":
                        data += self.encode_string(arg[1]) 
                    elif arg[0] == "wchar":
                        data += self.encode_stringW(arg[1])


                data += self.encode_uint8(self.TLV_CMD_EXECUTE_HBIN_BIN)

                raw_string = params["raw"]
                raw_string = raw_string[2:-1] # Remove the leading "b'" and the trailing "'"
                decoded_string = codecs.decode(raw_string.encode('utf-8'), 'unicode_escape')
                hbin_bytes = decoded_string.encode('latin1')  # Convert to bytes
                data += self.encode_uint32(len(hbin_bytes))
                data += hbin_bytes

                # TODO: Add base64 option and decode into raw bytes.

                # choices=["int16", "int32", "string", "wchar", "base64"],

            # {'action': 'get_tasking', 'tasks': [{'timestamp': 1729031837, 'command': 'execute_hbin', 'parameters': '{"hbin": "a001aa77-dec8-4f33-9f08-d93f703dbf22", "hbin_arguments": [["wchar", "test"]], "file_size": "32768", "raw": "b\'VH\\\\x89\\\\xe6H\\\\x83\\\\xe4\\\\
            

        return data
    
    # https://docs.mythic-c2.net/customizing/payload-type-development/create_tasking/agent-side-coding/action-post_response
    # For now we don't care about the task id or the error string
    def serialize_post_response(self, json_object):
        data = b''
        data += struct.pack('<B', self.MESSAGE_TYPE_POST_TASKS_RESPONSE)

        if(json_object["responses"][0]["status"] == "success"):
            data += struct.pack('<B', 1)
        else:
            data += struct.pack('<B', 0)

        return data

    def serialize_init_file_download(self, json_object):

        data = b''
        data += struct.pack('<B', self.MESSAGE_TYPE_START_DOWNLOAD)

        if(json_object["responses"][0]["status"] == "success"):
            data += struct.pack('<B', 1)
        else:
            data += struct.pack('<B', 0)

        data += self.encode_string(json_object["responses"][0]["file_id"])
        data += self.encode_string(json_object["responses"][0]["task_id"])

        return data
    
    # https://docs.mythic-c2.net/customizing/hooking-features/action-upload
    def serialize_upload_response(self, json_object):
        data = b''
        data += struct.pack('<B', self.MESSAGE_TYPE_FILE_UPLOAD)

        # status
        if(json_object["responses"][0]["status"] == "success"):
            data += struct.pack('<B', 1)
        else:
            data += struct.pack('<B', 0)

        data += self.encode_uint32(json_object["responses"][0]["total_chunks"])
        data += self.encode_uint32(json_object["responses"][0]["chunk_num"])
        raw_bytes = base64.b64decode(json_object["responses"][0]["chunk_data"])
        raw_bytes_len = len(raw_bytes)
        data += self.encode_uint32(raw_bytes_len)
        data += raw_bytes
        
        return data


    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:

        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)

        if (inputMsg.Message["action"] == "checkin"):
            response.Message = self.serialize_checkin_response(inputMsg.Message)
        elif (inputMsg.Message["action"] == "get_tasking"):
            response.Message = self.serialize_get_tasks_response(inputMsg.Message)
        elif (inputMsg.Message["action"] == "post_response"):
            if("file_id" in inputMsg.Message["responses"][0] and "chunk_data" not in inputMsg.Message["responses"][0]):
                response.Message = self.serialize_init_file_download(inputMsg.Message)
            elif("chunk_data" in inputMsg.Message["responses"][0]):
                response.Message = self.serialize_upload_response(inputMsg.Message)
            elif("file_id" not in inputMsg.Message["responses"][0]):
                response.Message = self.serialize_post_response(inputMsg.Message)

        return response


    ###############################################################################################
    ############################################# From Agent


    def read_uint8(self, data):
        """Parse a UINT8 (1 byte) from the given binary data."""

        if len(data) < 1:
            raise ValueError("Insufficient data to unpack UINT8")
        value = struct.unpack('<B', data[:1])[0]

        return value, data[1:]

    def read_uint32(self, data):
        """Parse a UINT32 (4 bytes) from the given binary data."""

        if len(data) < 4:
            raise ValueError("Insufficient data to unpack UINT32")
        value = struct.unpack('<I', data[:4])[0]

        return value, data[4:]

    def parse_tlvs(self, data):
        """Parse TLVs from the given binary data."""

        buf = data
        tlvs = []

        while buf:
            try:
                tlv_type, buf = self.read_uint8(buf)

                if (tlv_type == 0): # Invalid type or end of message
                    break

                length, buf = self.read_uint32(buf)

                value = buf[:length]
                buf = buf[length:]

                tlvs.append((tlv_type, length, value))

            except ValueError as e:
                print(f"Error parsing TLV: {e}")
                break

        return tlvs

    def parse_checkin_message(self, tlvs):

        json_object = {
        "action": "checkin",  # Required
        "uuid": "",  # Required
        "ips": [],  # Internal IP addresses - optional
        # "os": "",  # OS version - optional
        # "user": "",  # Username of current user - optional
        # "host": "",  # Hostname of the computer - optional
        # "pid": -1,  # PID of the current process - optional
        # "architecture": "",  # Platform architecture - optional
        # "domain": "",  # Domain of the host - optional
        # "integrity_level": -1,  # Integrity level of the process - optional
        # "external_ip": "",  # External IP if known - optional
        # "encryption_key": "",  # Encryption key - optional
        # "decryption_key": "",  # Decryption key - optional
        # "process_name": "",  # Name of the current process - optional
    }

        # Match with profile_mythic_http.h TLVType enum
        for tlv_type, length, value in tlvs:
            if tlv_type == self.TLV_CHECKIN_UUID:
                json_object["uuid"] = value.decode('utf-8')
            elif tlv_type == self.TLV_CHECKIN_IPS and length > 0:
                json_object["ips"].append(value.decode('utf-16-le'))
            elif tlv_type == self.TLV_CHECKIN_OS and length > 0:
                json_object["os"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_USER and length > 0:
                json_object["user"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_HOST and length > 0:
                json_object["host"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_PID and length > 0:
                json_object["pid"] = struct.unpack('<I', value)[0]
            elif tlv_type == self.TLV_CHECKIN_ARCHITECTURE and length > 0:
                json_object["architecture"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_DOMAIN and length > 0:
                json_object["domain"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_INTEGRITY_LEVEL and length > 0:
                json_object["integrity_level"] = struct.unpack('<I', value)[0]
            elif tlv_type == self.TLV_CHECKIN_EXTERNAL_IP and length > 0:
                json_object["external_ip"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_ENCRYPTION_KEY and length > 0:
                json_object["encryption_key"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_DECRYPTION_KEY and length > 0:
                json_object["decryption_key"] = value.decode('utf-16-le')
            elif tlv_type == self.TLV_CHECKIN_PROCESS_NAME and length > 0:
                json_object["process_name"] = value.decode('utf-16-le')

        return json_object

    def parse_get_tasks(self, data):

        json_object = {
            "action": "get_tasking",
            # "tasking_size": 0,
            # "get_delegate_tasks": 0
        }

        tasking_size, buf = self.read_uint8(data) # tasking_size
        get_delegate_tasks, buf = self.read_uint8(data) # get_delegate_tasks

        if (tasking_size == 0):
            json_object["tasking_size"] = -1
        else:
            json_object["tasking_size"] = tasking_size
        if(get_delegate_tasks == 0):
            json_object["get_delegate_tasks"] = False
        else:
            json_object["get_delegate_tasks"] = True

        return json_object

    def parse_post_tasks(self, tlvs):

        json_object = {
            "action": "post_response",
            "responses": [],
        }

        task_iter = 0 # Not needed atm as we're only sending one response at a time.
        task_count = 0

        for tlv_type, length, value in tlvs:
            if tlv_type == self.TLV_POST_TASKING: # For now we aren't actually using this. One response per POST vs all at in one
                task_count = int.from_bytes(value, byteorder='little')
            elif tlv_type == self.TLV_POST_TASKING_ID:
                json_object["responses"].append({"task_id": value.decode('utf-8')})
            elif tlv_type == self.TLV_POST_TASKING_CONTENT:
                json_object["responses"][task_iter]["user_output"] = value.decode('utf-16-le')
                task_iter += 1
            

        return json_object
    
    def parse_init_file_download(self, tlvs):

        json_object = {
            "action": "post_response",
            "responses": [
                {
                    "task_id": "",
                    "download": {
                        "total_chunks": 0,
                        "chunk_size": 0,
                        "full_path": ""
                    }
                }
            ],
        }

        for tlv_type, length, value in tlvs: # There should only be one
            if tlv_type == self.TLV_POST_TASKING_ID:
                json_object["responses"][0]["task_id"] = value.decode('utf-8')
            elif tlv_type == self.TLV_START_DOWNLOAD_CHUNK_COUNT:
                json_object["responses"][0]["download"]["total_chunks"] = int.from_bytes(value, byteorder='little')
            elif tlv_type == self.TLV_START_DOWNLOAD_CHUNK_SIZE:
                json_object["responses"][0]["download"]["chunk_size"] = int.from_bytes(value, byteorder='little')
            elif tlv_type == self.TLV_START_DOWNLOAD_FILEPATH:
                json_object["responses"][0]["download"]["full_path"] = value.decode('utf-16-le')

        return json_object
    
    def parse_continue_file_download(self, tlvs):

        json_object = {
            "action": "post_response", 
            "responses": [
                {
                    "task_id": "",
                    "download": {
                        "chunk_num": 0, # Starts at 1
                        "file_id": "", 
                        "chunk_data": "",
                    }
                }
            ]
        }

        for tlv_type, length, value in tlvs: 
            if tlv_type == self.TLV_POST_TASKING_ID:
                json_object["responses"][0]["task_id"] = value.decode('utf-8')
            elif tlv_type == self.TLV_CONTINUE_DOWNLOAD_CHUNK_NUMBER:
                json_object["responses"][0]["download"]["chunk_num"] = int.from_bytes(value, byteorder='little')
            elif tlv_type == self.TLV_CONTINUE_DOWNLOAD_FILE_ID:
                json_object["responses"][0]["download"]["file_id"] = value.decode('utf-8')
            elif tlv_type == self.TLV_CONTINUE_DOWNLOAD_FILE_DATA:
                b64_bin = base64.b64encode(value)
                json_object["responses"][0]["download"]["chunk_data"] = b64_bin.decode('utf-8')

        return json_object
    
    def parse_file_upload(self, tlvs):

        json_object = {
            "action": "post_response",
            "responses": [
                {
                    "upload": {
                        "chunk_size": 0, 
                        "file_id": "",
                        "chunk_num": 0,
                        "full_path": ""
                    },
                    "task_id": "" 
                }
            ]
        }

        for tlv_type, length, value in tlvs: 
            if tlv_type == self.TLV_POST_TASKING_ID:
                json_object["responses"][0]["task_id"] = value.decode('utf-8')
            if tlv_type == self.TLV_UPLOAD_FILE_UUID:
                json_object["responses"][0]["upload"]["file_id"] = value.decode('utf-8')
            elif tlv_type == self.TLV_UPLOAD_CHUNK_SIZE:
                json_object["responses"][0]["upload"]["chunk_size"] = int.from_bytes(value, byteorder='little')
            elif tlv_type == self.TLV_UPLOAD_CHUNK_NUMBER:
                json_object["responses"][0]["upload"]["chunk_num"] = int.from_bytes(value, byteorder='little')
            elif tlv_type == self.TLV_UPLOAD_FILE_UUID:
                json_object["responses"][0]["upload"]["full_path"] = value.decode('utf-16-le')

        return json_object


    def read_msg(self, data):

        message_type, buf = self.read_uint8(data)

        if(message_type == self.MESSAGE_TYPE_CHECKIN):
            parsed_tlvs = self.parse_tlvs(data[1:])
            json_msg = self.parse_checkin_message(parsed_tlvs)

        elif (message_type == self.MESSAGE_TYPE_GET_TASKS):
            json_msg = self.parse_get_tasks(buf)

        elif (message_type == self.MESSAGE_TYPE_POST_TASKS):
            parsed_tlvs = self.parse_tlvs(data[1:])
            json_msg = self.parse_post_tasks(parsed_tlvs)

        elif (message_type == self.MESSAGE_TYPE_START_DOWNLOAD):
            parsed_tlvs = self.parse_tlvs(data[1:])
            json_msg = self.parse_init_file_download(parsed_tlvs)

        elif (message_type == self.MESSAGE_TYPE_CONTINUE_DOWNLOAD):
            parsed_tlvs = self.parse_tlvs(data[1:])
            json_msg = self.parse_continue_file_download(parsed_tlvs)

        elif (message_type == self.MESSAGE_TYPE_FILE_UPLOAD):
            parsed_tlvs = self.parse_tlvs(data[1:])
            json_msg = self.parse_file_upload(parsed_tlvs)

        return json_msg


    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        json_msg = self.read_msg(inputMsg.Message)
        response.Message = json.loads(json.dumps(json_msg))
        return response