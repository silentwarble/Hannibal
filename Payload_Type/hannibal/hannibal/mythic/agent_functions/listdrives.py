# https://github.com/MythicAgents/Apollo/blob/master/Payload_Type/apollo/apollo/mythic/agent_functions/pwd.py

from mythic_container.MythicCommandBase import *
import json


class ListdrivesArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("listdrives takes no command line arguments.")
        pass


class ListdrivesCommand(CommandBase):
    cmd = "listdrives"
    needs_admin = False
    help_cmd = "listdrives"
    description = "Lists drives on the machine."
    version = 1
    author = "@silentwarble"
    argument_class = ListdrivesArguments
    attackmapping = []

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp