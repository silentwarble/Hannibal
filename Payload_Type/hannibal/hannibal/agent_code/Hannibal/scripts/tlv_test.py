"""
This is a snippet of the translator.py code. I used this to test deserializing the raw unencrypted binary
from the agent.
It is not synced with the latest translator code and very messy, but may still be useful.
TODO: Clean this up.
"""

import json
import struct

def read_uint8(data):
    """Parse a UINT8 (1 byte) from the given binary data and iterate data pointer."""
    if len(data) < 1:
        raise ValueError("Insufficient data to unpack UINT8")
    value = struct.unpack('<B', data[:1])[0]
    return value, data[1:]

def read_uint32(data):
    """Parse a UINT32 (4 bytes) from the given binary data."""
    if len(data) < 4:
        raise ValueError("Insufficient data to unpack UINT32")
    value = struct.unpack('<I', data[:4])[0]
    return value, data[4:]

def read_string(data):

    value = b''
    for i in range(len(data)):
        if(data[i] == 0):
            return value, data[i:]
        else:
            value += data[i]


def encode_uint8(value):
    return struct.pack('<B', value)

def encode_uint32(value):
    return struct.pack('<I', value)

def encode_string(value):
    return value.encode('utf-8') + b'\x00'  # Append null terminator

def encode_tlv(tlv_type, value):
    length = len(value)
    return encode_uint8(tlv_type) + encode_uint32(length) + value

def parse_tlvs(data):
    """Parse TLVs from the given binary data."""

    buf = data
    tlvs = []

    while buf:
        try:
            tlv_type, buf = read_uint8(buf)

            if (tlv_type == 0): # Invalid type or end of message
                break

            length, buf = read_uint32(buf)

            value = buf[:length]
            buf = buf[length:]

            tlvs.append((tlv_type, length, value))

        except ValueError as e:
            print(f"Error parsing TLV: {e}")
            break

    return tlvs

def parse_checkin_message(tlvs):
    
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
        if tlv_type == 2:  
            json_object["uuid"] = value.decode('utf-8')
        elif tlv_type == 3 and length > 0:  
            json_object["ips"].append(value.decode('utf-8'))
        elif tlv_type == 4 and length > 0: 
            json_object["os"] = value.decode('utf-16-le')
        elif tlv_type == 5 and length > 0:  
            json_object["user"] = value.decode('utf-8')
        elif tlv_type == 6 and length > 0:  
            json_object["host"] = value.decode('utf-16-le')
        elif tlv_type == 7 and length > 0:  
            json_object["pid"] = struct.unpack('<I', value)[0]
        elif tlv_type == 8 and length > 0:
            json_object["architecture"] = value.decode('utf-8')
        elif tlv_type == 9 and length > 0:
            json_object["domain"] = value.decode('utf-8')
        elif tlv_type == 10 and length > 0:
            json_object["integrity_level"] = struct.unpack('<I', value)[0]
        elif tlv_type == 11 and length > 0: 
            json_object["external_ip"] = value.decode('utf-8')
        elif tlv_type == 12 and length > 0: 
            json_object["encryption_key"] = value.decode('utf-8')
        elif tlv_type == 13 and length > 0: 
            json_object["decryption_key"] = value.decode('utf-8')
        elif tlv_type == 14 and length > 0: 
            json_object["process_name"] = value.decode('utf-8')

    return json_object

def parse_get_tasks(data):

    json_object = {
        "action": "get_tasking",
        # "tasking_size": 0,
        # "get_delegate_tasks": 0
    }

    tasking_size, buf = read_uint8(data) # tasking_size
    get_delegate_tasks, buf = read_uint8(data) # get_delegate_tasks

    if (tasking_size == 0):
        json_object["tasking_size"] = -1
    if(get_delegate_tasks == 0):
        json_object["get_delegate_tasks"] = False

    return json_object


def serialize_checkin_response(json_dict):

    # UINT8 | UINT8 | UINT8 | UINT32 | Value

    data = b''

    data += struct.pack('<B', 2) # #define MESSAGE_TYPE_CHECKIN_RESPONSE 2

    if (json_dict["status"] == "success"):
        data += struct.pack('<B', 1)
    else:
        data += struct.pack('<B', 0)

    data += encode_uint8(15) # TLV_CHECKIN_RESPONSE_ID = 15,
    data += encode_uint32(len(json_dict["id"]))
    data += encode_string(json_dict["id"])

    return data

def serialize_get_tasks_response(json_object):

    data = b''

    data += struct.pack('<B', 4) # #define MESSAGE_TYPE_GET_TASKS_RESPONSE 4

    for task in json_object["tasks"]:
        if(task["command"] == "ls"):
            data += encode_uint8(1) #define CMD_LS 1 task_core.h

            data += encode_uint8(16) # TLV_CMD_ID = 16,
            data += encode_uint32(len(task["id"]))
            data += encode_string(task["id"])

            params = json.loads(task["parameters"])
            
            data += encode_uint8(17) # TLV_CMD_LS_PARAM_PATH = 17,
            data += encode_uint32(len(params["host"]))
            data += encode_string(params["host"])

            data += encode_uint8(18) # TLV_CMD_LS_PARAM_HOST = 18
            data += encode_uint32(len(params["path"]))
            data += encode_string(params["path"])

        return data


def parse_post_tasks(tlvs):

    json_object = {
        "action": "post_response",
        "responses": [], 
    }

    task_count = 0
    task_iter = 0

    for tlv_type, length, value in tlvs:
        if tlv_type == 20:
            task_count = value
        elif tlv_type == 21:
            json_object["responses"].append({"task_id": value.decode('utf-8')})
        elif tlv_type == 22:
            json_object["responses"][task_iter]["user_output"] = value.decode('utf-8')

    return json_object

def read_msg(data):
    
    message_type, buf = read_uint8(data)

    if(message_type == 1): #define MESSAGE_TYPE_CHECKIN 1
        parsed_tlvs = parse_tlvs(data[1:])
        json_msg = parse_checkin_message(parsed_tlvs)
    elif (message_type == 3): #define MESSAGE_TYPE_GET_TASKS 3
        json_msg = parse_get_tasks(buf)
    elif (message_type == 5):
        parsed_tlvs = parse_tlvs(data[1:])
        json_msg = parse_post_tasks(parsed_tlvs)
    elif (message_type == 6):
        parsed_tlvs = parse_tlvs(data[1:])


    return json_msg


# json_dict = {
#     "id": "44990ed4-5534-4bd4-9376-c73f1a80c967", 
#     "status": "success"
# }

# print(serialize_checkin_response(json_dict))



# # Example binary data
# binary_data = (b'\x01\x02%\x00\x00\x0044990ed4-5534-4bd4-9376-c73f1a80c967\x00\x04\x0b\x00\x00\x00Windows 11\x00\x05\x12\x00\x00\x00DOMAIN\\BillyBones\x00\x06\x07\x00\x00\x00myhost\x00\x07\x04\x00\x00\x00\\\x11\x00\x00\x08\x04\x00\x00\x00x64\x00\t\r\x00\x00\x00DOMAIN.local\x00\x0e\x0e\x00\x00\x00C:\\loader.exe\x00\x00\x00\x00\x00\x00\x00')
# binary_data =   b'\x01\x02%\x00\x00\x0044990ed4-5534-4bd4-9376-c73f1a80c967\x00\x03\x0e\x00\x00\x00192.168.10.10\x00\x03\x0e\x00\x00\x00192.168.20.20\x00\x04\x0b\x00\x00\x00Windows 11\x00\x05\x12\x00\x00\x00DOMAIN\\BillyBones\x00\x06\x07\x00\x00\x00myhost\x00\x07\x04\x00\x00\x00\\\x11\x00\x00\x08\x04\x00\x00\x00x64\x00\t\r\x00\x00\x00DOMAIN.local\x00\n\x04\x00\x00\x00\x05\x00\x00\x00\x0b\x0c\x00\x00\x00'
# binary_data = b'\x03\x00\x00'
# binary_data = b'\x01\x02$\x00\x00\x0044990ed4-5534-4bd4-9376-c73f1a80c967\x03\r\x00\x00\x00192.168.10.10\x04\n\x00\x00\x00Windows 11\x05\x11\x00\x00\x00DOMAIN\\BillyBones\x06\x06\x00\x00\x00myhost\x07\x04\x00\x00\x00\\\x11\x00\x00\x08\x03\x00\x00\x00x64\t\x0c\x00\x00\x00DOMAIN.local\n\x04\x00\x00\x00\x05\x00\x00\x00\x0b\x0b\x00\x00\x0055.55.55.55\x0e\r\x00\x00\x00C:\\loader.exe'
# binary_data = b'\x05\x14\x04\x00\x00\x00\x01\x00\x00\x00\x15$\x00\x00\x00feaf577e-6a33-498d-8c6a-77e35f50bb66\x16\xcc\x00\x00\x00$Recycle.Bin\ncode\ndocs\nDocuments and Settings\nDumpStack.log.tmp\npagefile.sys\nPerfLogs\nProgram Files\nProgram Files (x86)\nProgramData\nPython312\nRecovery\nswapfile.sys\nSys'
# binary_data = b'\x01\x02$\x00\x00\x0044990ed4-5534-4bd4-9376-c73f1a80c967\x03\r\x00\x00\x00192.168.10.10\x03\r\x00\x00\x00192.168.20.20\x04\x14\x00\x00\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x001\x001\x00\x05\x11\x00\x00\x00DOMAIN\\BillyBones\x06\x0c\x00\x00\x00m\x00y\x00h\x00o\x00s\x00t\x00\x07\x04\x00\x00\x00\\\x11\x00\x00\x08\x03\x00\x00\x00x64\t\x0c\x00\x00\x00DOMAIN.local\n\x04\x00\x00\x00\x05\x00\x00\x00\x0b\x0b\x00\x00\x0055.55.55.55\x0e\r\x00\x00\x00C:\\loader.exe'
binary_data = b'\x06\x15$\x00\x00\x000fc6d768-c98e-46b7-9644-4905f616b1d0\x17\x04\x00\x00\x00\x01\x00\x00\x00\x18\x04\x00\x00\x00 \xa1\x07\x00\x00\x00\x00\x00'
json_msg = read_msg(binary_data)

print(json.dumps(json_msg, indent=4))


# get_tasks_json = {'action': 'get_tasking', 
#                   'tasks': [
#                       {
#                        'timestamp': 1725147009, 
#                        'command': 'ls', 
#                        'parameters': '{"path": "c:\\\\test", "host": ""}', 
#                        'id': '1a8c9c44-ee75-48b3-bae2-8cce9bb40e04'
#                        }
#                     ]
#                 }

# print(serialize_get_tasks_response(get_tasks_json))