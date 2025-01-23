# plugin_base.py
import argparse
import importlib
import os

def load_plugins(plugin_dirs, client):
    plugins = []
    for plugin_dir in plugin_dirs:
        for filename in os.listdir(plugin_dir):
            if filename.endswith(".py"):
                spec = importlib.util.spec_from_file_location("module.name", os.path.join(plugin_dir, filename))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for obj in vars(module).values():
                    if isinstance(obj, type) and issubclass(obj, PluginBase) and obj is not PluginBase:
                        plugins.append(obj(client))
    return plugins


class PluginBase:
    def __init__(self, client, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = client

    def get_parser(self):
        parser = argparse.ArgumentParser(add_help=False)
        return parser

    def run(self, args):
        raise NotImplementedError
    
