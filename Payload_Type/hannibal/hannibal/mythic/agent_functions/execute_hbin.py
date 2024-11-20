# Adapted from Apollo and Athena

from mythic_container.MythicCommandBase import *  
from mythic_container.MythicRPC import *

class ExecuteHbinArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hbin",
                type=ParameterType.File,
                description="Upload HBIN file to be executed. Be aware a UINT32 cannot be > 4294967295.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=0,
                        )
                    ],
            ),
            CommandParameter(
                name="hbin_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.TypedArray,
                default_value=[],
                choices=["int32", "string", "wchar"], # TODO: Add base64 back and decode to support passing raw binary to hbins
                description="""Arguments to pass to the HBIN via the following way:
                -i:123 or int32:123
                -z:hello or string:hello
                -Z:hello or wchar:hello
                -b:abc== or base64:abc==""",
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=1
                    ),
                ]),
        ]

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        
        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True)
        argumentSplitArray = []
        
        for argValue in arguments.InputArray:
            argSplitResult = argValue.split(" ")
            for spaceSplitArg in argSplitResult:
                argumentSplitArray.append(spaceSplitArg)

        hbin_arguments = []

        for argument in argumentSplitArray:
        
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
        
            if argType == "":
                pass
            elif argType == "int32" or argType == "-i":
                hbin_arguments.append(["int32",int(value)])
            elif argType == "string" or argType == "-z":
                hbin_arguments.append(["string",value])
            elif argType == "wchar" or argType == "-Z":
                hbin_arguments.append(["wchar",value])
            # elif argType == "base64" or argType == "-b":
            #     hbin_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False, Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=hbin_arguments)
        
        return argumentResponse

    
    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)


class ExecuteHbinCommand(CommandBase):
    cmd = "execute_hbin"
    needs_admin = False
    help_cmd = "execute_hbin"
    description = "Execute a hbin file in same thread."
    version = 1
    author = "@silentwarble"
    argument_class = ExecuteHbinArguments
    attackmapping = []
    attributes = CommandAttributes(
        load_only=False,
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        fData = FileData()
        fData.AgentFileId = taskData.args.get_arg("hbin")
        file = await SendMythicRPCFileGetContent(fData)

        if file.Success:
            taskData.args.add_arg("file_size", len(file.Content))
            taskData.args.add_arg("raw", file.Content)
        else:
            raise Exception("Failed to get file contents: " + file.Error)

        response.DisplayParams = ""

        return response


    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
            resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
            return resp