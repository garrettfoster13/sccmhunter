#
# coding=utf-8
"""This module contains constants used throughout ``cmd2``."""

# Unless documented in https://cmd2.readthedocs.io/en/latest/api/index.html
# nothing here should be considered part of the public API of this module

INFINITY = float('inf')

# Used for command parsing, output redirection, tab completion and word
# breaks. Do not change.
QUOTES = ['"', "'"]
REDIRECTION_PIPE = '|'
REDIRECTION_OUTPUT = '>'
REDIRECTION_APPEND = '>>'
REDIRECTION_CHARS = [REDIRECTION_PIPE, REDIRECTION_OUTPUT]
REDIRECTION_TOKENS = [REDIRECTION_PIPE, REDIRECTION_OUTPUT, REDIRECTION_APPEND]
COMMENT_CHAR = '#'
MULTILINE_TERMINATOR = ';'

LINE_FEED = '\n'

# One character ellipsis
HORIZONTAL_ELLIPSIS = '…'

DEFAULT_SHORTCUTS = {'?': 'help', '!': 'shell', '@': 'run_script', '@@': '_relative_run_script'}

# Used as the command name placeholder in disabled command messages.
COMMAND_NAME = "<COMMAND_NAME>"

# All command functions start with this
COMMAND_FUNC_PREFIX = 'do_'

# All help functions start with this
HELP_FUNC_PREFIX = 'help_'

# All command completer functions start with this
COMPLETER_FUNC_PREFIX = 'complete_'

# The custom help category a command belongs to
CMD_ATTR_HELP_CATEGORY = 'help_category'
CLASS_ATTR_DEFAULT_HELP_CATEGORY = 'cmd2_default_help_category'

# The argparse parser for the command
CMD_ATTR_ARGPARSER = 'argparser'

# Whether or not tokens are unquoted before sending to argparse
CMD_ATTR_PRESERVE_QUOTES = 'preserve_quotes'

# subcommand attributes for the base command name and the subcommand name
SUBCMD_ATTR_COMMAND = 'parent_command'
SUBCMD_ATTR_NAME = 'subcommand_name'
SUBCMD_ATTR_ADD_PARSER_KWARGS = 'subcommand_add_parser_kwargs'

# arpparse attribute linking to command set instance
PARSER_ATTR_COMMANDSET = 'command_set'

# custom attributes added to argparse Namespaces
NS_ATTR_SUBCMD_HANDLER = '__subcmd_handler__'
