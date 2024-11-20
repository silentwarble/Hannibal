from mythic_container.MythicCommandBase import *
import json

class CpArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="src_path",
                cli_name="src_path",
                display_name="Src to copy",
                type=ParameterType.String,
                description="Src to copy",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=0
                    ),
                ]),
                CommandParameter(
                name="dst_path",
                cli_name="dst_path",
                display_name="Dst to copy",
                type=ParameterType.String,
                description="Dst to copy",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 1:
            json_cmd = json.loads(self.command_line)
            self.add_arg("src_path", json_cmd["src_path"])
            self.add_arg("dst_path", json_cmd["dst_path"])
        if self.get_arg("src_path") is None or self.get_arg("dst_path") is None:
            raise Exception("src_path and dst_path required.")
        if self.get_arg("src_path") is not None and self.get_arg("src_path")[-1] == "\\":
            self.add_arg("src_path", self.get_arg("src_path")[:-1])
        if self.get_arg("dst_path") is not None and self.get_arg("dst_path")[-1] == "\\":
            self.add_arg("dst_path", self.get_arg("dst_path")[:-1])


class CdCommand(CommandBase):
    cmd = "cp"
    needs_admin = False
    help_cmd = "cp [src_path] [dst_path]"
    description = "Copy file or folder from src to dst. Non-empty folders are recursively copied."
    version = 1
    supported_ui_features = []
    author = "@silentwarble"
    argument_class = CpArguments
    attackmapping = []

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-src {} -dst {}".format(
            taskData.args.get_arg("src_path"), taskData.args.get_arg("dst_path")
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp