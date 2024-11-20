# https://github.com/MythicAgents/Apollo/blob/master/Payload_Type/apollo/apollo/mythic/agent_functions/pwd.py

from mythic_container.MythicCommandBase import *
import json


class IpinfoArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("ipinfo takes no command line arguments.")
        pass


class IpinfoCommand(CommandBase):
    cmd = "ipinfo"
    needs_admin = False
    help_cmd = "ipinfo"
    description = "List IP Adapter Info."
    version = 1
    author = "@silentwarble"
    argument_class = IpinfoArguments
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