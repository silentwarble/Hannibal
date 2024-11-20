from mythic_container.MythicCommandBase import *
import json


class DownloadArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path to file to download.",
                type=ParameterType.String,
                description="File to download.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=0
                    )
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            json_cmd = json.loads(self.command_line)
            self.add_arg("path", json_cmd["path"])
      

class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download <full path to file>"
    description = "Download a file off the target system."
    version = 1
    supported_ui_features = []
    author = "@silentwarble"
    argument_class = DownloadArguments
    attackmapping = []
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        path = taskData.args.get_arg("path")
        response.DisplayParams = path
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp