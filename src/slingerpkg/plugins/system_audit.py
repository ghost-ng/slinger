# my_plugin.py
from slingerpkg.lib.plugin_base import PluginBase   # required
import argparse  # required
from slingerpkg.utils.printlib import * # required, use pre-defined print functions

from slingerpkg.utils.common import tee_output  # optional but cool

plugin_name = "System Audit"
author_name = "ghost-ng"
author_meta = "https://github.com/ghost-ng/"
credits = "iamSiddhartha"
version = "1.0"

class MyPlugin(PluginBase):
    # Name
    name = plugin_name  # required
    author_block = {"name": author_name, "meta": author_meta, "credits": credits, "version": version} # required

    def get_parser(self):   # required
        # define a new subparser to return to merge with the main parser
        parser = argparse.ArgumentParser(add_help=False)    # required
        subparsers = parser.add_subparsers(dest='command')  # required
        plugincmd_parser = subparsers.add_parser("audit", help="System Audit")  # required
        plugincmd_parser.add_argument("-s", "--save", help="Save to file")
        plugincmd_parser.set_defaults(func=self.run) # required entry point
        return parser

    def run(self, args):    # required
        print_block(f"Running System Audit")

        # Dictionary mapping audit actions to their corresponding method calls
        audit_dict = {
            "System Info": self.client.enum_info,
            "Other Info": self.client.info,
            "IP Config": self.client.ipconfig,
            "Hostname": self.client.hostname,
            "Environment Variables": self.client.show_env,
            "System Logons": self.client.enum_logons,
            "Server Disk Info": self.client.enum_server_disk,
            "Sessions": self.client.who,
            "Net Shares": self.client.list_shares,
            "Enum Services": self.client.enum_services,
            "Enum Processes": self.client.show_process_list,
        }

        with tee_output(args.save):
            # Iterate through the dictionary and execute each function
            for key, func in audit_dict.items():
                print_log()
                print_block(f"{key}", color=colors.BLUE)
                try:
                    result = func()  
                    if result:
                        print_log(f"{key} Result: {result}")
                except Exception as e:
                    print_log(f"Error while executing {key}: {str(e)}")

        print_block(f"System Audit Complete", color=colors.YELLOW)