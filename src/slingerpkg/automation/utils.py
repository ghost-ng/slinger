import argparse


def extract_commands_and_args(parser: argparse.ArgumentParser) -> dict:
    """
    Walk an argparse parser built by slingerpkg.utils.cli.setup_cli_parser(...)
    and return a dict of {command_name: {...}} for every sub‐command.
    """
    commands: dict = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for cmd, subp in action.choices.items():
                desc = getattr(subp, "description", "")
                commands[cmd] = {"description": desc, "arguments": []}
                for sa in subp._actions:
                    if isinstance(sa, argparse._StoreAction):
                        commands[cmd]["arguments"].append(
                            {
                                "name": sa.dest,
                                "help": sa.help,
                                "choices": sa.choices,
                                "default": sa.default,
                                "required": getattr(sa, "required", False),
                            }
                        )
    return commands
