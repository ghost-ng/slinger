# my_plugin.py
from slinger.lib.plugin_base import PluginBase
import argparse
from slinger.lib.dcetransport import *

class MyPlugin(PluginBase):

    def get_parser(self):
        # define a new subparser to return to merge with the main parser
        parser = argparse.ArgumentParser(add_help=False)
        subparsers = parser.add_subparsers(dest='command')
        plugincmd_parser = subparsers.add_parser("plugincmd", help="My plugin subparser")
        plugincmd_parser.add_argument("--plugincmd", help="My plugin argument")
        return parser

    def run(self, args):
        print(f"Executing {args.command} with arg value of {args.plugincmd}")
        
        # example of using the SlingerClient object
        self.client.info()

        # example of using the DCETransport object
        self.client.dce_transport._connect('srvsvc')
        response = self.client.dce_transport._enum_info()
        #print_log(response.dump())
        print_info("Server Info:")
        info = response['InfoStruct']['ServerInfo101']
        print_log(f"Server name: {info['sv101_name']}")
        print_log(f"Server platform id: {info['sv101_platform_id']}")
        print_log(f"Server version: {info['sv101_version_major']}.{info['sv101_version_minor']}")
        print_log(f"Server type: {info['sv101_type']}")
        print_log(f"Server comment: {info['sv101_comment']}")
        print_info("Server Disk Info:")
        self.client.enum_server_disk()
