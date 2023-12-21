# plugin_base.py
import argparse
import importlib
import os

def load_plugins(plugin_dir):
    plugins = []
    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py"):
            spec = importlib.util.spec_from_file_location("module.name", os.path.join(plugin_dir, filename))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for obj in vars(module).values():
                if isinstance(obj, type) and issubclass(obj, PluginBase) and obj is not PluginBase:
                    plugins.append(obj())
    return plugins

class PluginBase:
    def get_parser(self):
        parser = argparse.ArgumentParser(add_help=False)
        return parser

    def execute(self, args):
        raise NotImplementedError
    
    def get_commands(self):
        return []