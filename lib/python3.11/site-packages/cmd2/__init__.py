#
# -*- coding: utf-8 -*-
# flake8: noqa F401
"""This simply imports certain things for backwards compatibility."""

import sys

# For python 3.8 and later
if sys.version_info >= (3, 8):
    import importlib.metadata as importlib_metadata
else:
    # For everyone else
    import importlib_metadata
try:
    __version__ = importlib_metadata.version(__name__)
except importlib_metadata.PackageNotFoundError:  # pragma: no cover
    # package is not installed
    pass

from typing import List

from .ansi import (
    Cursor,
    Bg,
    Fg,
    EightBitBg,
    EightBitFg,
    RgbBg,
    RgbFg,
    TextStyle,
    style,
)
from .argparse_custom import (
    Cmd2ArgumentParser,
    Cmd2AttributeWrapper,
    CompletionItem,
    register_argparse_argument_parameter,
    set_default_argument_parser_type,
)

# Check if user has defined a module that sets a custom value for argparse_custom.DEFAULT_ARGUMENT_PARSER.
# Do this before loading cmd2.Cmd class so its commands use the custom parser.
import argparse

cmd2_parser_module = getattr(argparse, 'cmd2_parser_module', None)
if cmd2_parser_module is not None:
    import importlib

    importlib.import_module(cmd2_parser_module)

from .argparse_completer import set_default_ap_completer_type

from .cmd2 import Cmd
from .command_definition import CommandSet, with_default_category
from .constants import COMMAND_NAME, DEFAULT_SHORTCUTS
from .decorators import with_argument_list, with_argparser, with_category, as_subcommand_to
from .exceptions import (
    Cmd2ArgparseError,
    CommandSetRegistrationError,
    CompletionError,
    PassThroughException,
    SkipPostcommandHooks,
)
from . import plugin
from .parsing import Statement
from .py_bridge import CommandResult
from .utils import categorize, CompletionMode, CustomCompletionSettings, Settable


__all__: List[str] = [
    'COMMAND_NAME',
    'DEFAULT_SHORTCUTS',
    # ANSI Exports
    'Cursor',
    'Bg',
    'Fg',
    'EightBitBg',
    'EightBitFg',
    'RgbBg',
    'RgbFg',
    'TextStyle',
    'style',
    # Argparse Exports
    'Cmd2ArgumentParser',
    'Cmd2AttributeWrapper',
    'CompletionItem',
    'register_argparse_argument_parameter',
    'set_default_argument_parser_type',
    'set_default_ap_completer_type',
    # Cmd2
    'Cmd',
    'CommandResult',
    'CommandSet',
    'Statement',
    # Decorators
    'with_argument_list',
    'with_argparser',
    'with_category',
    'with_default_category',
    'as_subcommand_to',
    # Exceptions
    'Cmd2ArgparseError',
    'CommandSetRegistrationError',
    'CompletionError',
    'SkipPostcommandHooks',
    # modules
    'plugin',
    # Utilities
    'categorize',
    'CompletionMode',
    'CustomCompletionSettings',
    'Settable',
]
