from mythic_container.MythicCommandBase import *
import json


class ExitArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="type",
                cli_name="type",
                display_name="Exit process or thread.",
                type=ParameterType.String,
                description="Exit process or thread.",
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
            if "type" in json_cmd:
                if json_cmd["type"] == "thread":
                    self.add_arg("type", int(1))
                else:
                    self.add_arg("type", int(0))
            else:
                self.add_arg("type", int(0))


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit, exit thread"
    description = "Task the implant to exit. Runs either ExitProcess or ExitThread."
    version = 1
    supported_ui_features = ["callback_table:exit"]
    author = "@silentwarble"
    argument_class = ExitArguments
    attackmapping = []

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        type = taskData.args.get_arg("type")
        response.DisplayParams = type
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp