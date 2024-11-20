from mythic_container.MythicCommandBase import *
import json


class ExecuteArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path to execute.",
                type=ParameterType.String,
                description="Path to execute.",
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



class ExecuteCommand(CommandBase):
    cmd = "execute"
    needs_admin = False
    help_cmd = "execute [path]"
    description = "Runs CreateProcess. Beware OPSEC considerations."
    version = 1
    supported_ui_features = []
    author = "@silentwarble"
    argument_class = ExecuteArguments
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