# my_plugin.py
from slinger.lib.plugin_base import PluginBase
import argparse
from slinger.utils.cli import app_cmds_parser

class MyPlugin(PluginBase):
    def get_parser(self):
        # define a new subparser to return to merge with the main parser
        subparsers = app_cmds_parser.add_subparsers(dest='command')
        plugincmd_parser = subparsers.add_parser("plugincmd", help="My subparser")
        plugincmd_parser.add_argument("--plugincmd", help="My argument")
        

    def execute(self, args):
        print("Executing MyPlugin with args:", args)

    def get_commands(self):
        return ["mycmd"]