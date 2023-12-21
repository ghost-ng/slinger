# my_plugin.py
from slinger.lib.plugin_base import PluginBase
import argparse

class MyPlugin(PluginBase):
    def get_parser(self):
        # define a new subparser to return to merge with the main parser
        parser = argparse.ArgumentParser(add_help=False)
        subparsers = parser.add_subparsers(dest='command')
        plugincmd_parser = subparsers.add_parser("plugincmd", help="My plugin subparser")
        plugincmd_parser.add_argument("--plugincmd", help="My plugin argument")
        return parser

    def execute(self, args):
        print(f"Executing {args.command} with {args.plugincmd}")

    def get_commands(self):
        return ["plugincmd"]