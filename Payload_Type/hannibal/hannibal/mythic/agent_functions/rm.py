from mythic_container.MythicCommandBase import *
import json

class RmArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path to list files from.",
                type=ParameterType.String,
                description="Path to list files from.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=0
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            json_cmd = json.loads(self.command_line)
            self.add_arg("path", json_cmd["path"])
        if self.get_arg("path") is None:
            self.add_arg("path", ".")
        if self.get_arg("path") is not None and self.get_arg("path")[-1] == "\\":
            self.add_arg("path", self.get_arg("path")[:-1])



class RmCommand(CommandBase):
    cmd = "rm"
    needs_admin = False
    help_cmd = "rm [path]"
    description = "Delete a file or a folder. File delete supports simple wildcards (rm c:\\test\*.txt). NOTE: This recursively deletes folders so you won't get an error if folder isn't empty. Be aware of this so you don't accidentally destroy data."
    version = 1
    supported_ui_features = []
    author = "@silentwarble"
    argument_class = RmArguments
    attackmapping = []

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