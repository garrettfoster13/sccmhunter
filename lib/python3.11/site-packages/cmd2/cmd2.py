# coding=utf-8
"""Variant on standard library's cmd with extra features.

To use, simply import cmd2.Cmd instead of cmd.Cmd; use precisely as though you
were using the standard library's cmd, while enjoying the extra features.

Searchable command history (commands: "history")
Run commands from file, save to file, edit commands in file
Multi-line commands
Special-character shortcut commands (beyond cmd's "?" and "!")
Settable environment parameters
Parsing commands with `argparse` argument parsers (flags)
Redirection to file or paste buffer (clipboard) with > or >>
Easy transcript-based testing of applications (see examples/example.py)
Bash-style ``select`` available

Note that redirection with > and | will only work if `self.poutput()`
is used in place of `print`.

- Catherine Devlin, Jan 03 2008 - catherinedevlin.blogspot.com

Git repository on GitHub at https://github.com/python-cmd2/cmd2
"""
# This module has many imports, quite a few of which are only
# infrequently utilized. To reduce the initial overhead of
# import this module, many of these imports are lazy-loaded
# i.e. we only import the module when we use it
# For example, we don't import the 'traceback' module
# until the pexcept() function is called and the debug
# setting is True
import argparse
import cmd
import functools
import glob
import inspect
import os
import pydoc
import re
import sys
import threading
from code import (
    InteractiveConsole,
)
from collections import (
    OrderedDict,
    namedtuple,
)
from contextlib import (
    redirect_stdout,
)
from types import (
    FrameType,
    ModuleType,
)
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    TextIO,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from . import (
    ansi,
    argparse_completer,
    argparse_custom,
    constants,
    plugin,
    utils,
)
from .argparse_custom import (
    ChoicesProviderFunc,
    CompleterFunc,
    CompletionItem,
)
from .clipboard import (
    can_clip,
    get_paste_buffer,
    write_to_paste_buffer,
)
from .command_definition import (
    CommandFunc,
    CommandSet,
)
from .constants import (
    CLASS_ATTR_DEFAULT_HELP_CATEGORY,
    COMMAND_FUNC_PREFIX,
    COMPLETER_FUNC_PREFIX,
    HELP_FUNC_PREFIX,
)
from .decorators import (
    as_subcommand_to,
    with_argparser,
)
from .exceptions import (
    Cmd2ShlexError,
    CommandSetRegistrationError,
    CompletionError,
    EmbeddedConsoleExit,
    EmptyStatement,
    PassThroughException,
    RedirectionError,
    SkipPostcommandHooks,
)
from .history import (
    History,
    HistoryItem,
)
from .parsing import (
    Macro,
    MacroArg,
    Statement,
    StatementParser,
    shlex_split,
)
from .rl_utils import (
    RlType,
    rl_escape_prompt,
    rl_get_point,
    rl_get_prompt,
    rl_set_prompt,
    rl_type,
    rl_warning,
    vt100_support,
)
from .table_creator import (
    Column,
    SimpleTable,
)
from .utils import (
    Settable,
    get_defining_class,
    strip_doc_annotations,
)

# Set up readline
if rl_type == RlType.NONE:  # pragma: no cover
    sys.stderr.write(ansi.style_warning(rl_warning))
else:
    from .rl_utils import (  # type: ignore[attr-defined]
        readline,
        rl_force_redisplay,
    )

    # Used by rlcompleter in Python console loaded by py command
    orig_rl_delims = readline.get_completer_delims()

    if rl_type == RlType.PYREADLINE:

        # Save the original pyreadline3 display completion function since we need to override it and restore it
        # noinspection PyProtectedMember,PyUnresolvedReferences
        orig_pyreadline_display = readline.rl.mode._display_completions

    elif rl_type == RlType.GNU:

        # Get the readline lib so we can make changes to it
        import ctypes

        from .rl_utils import (
            readline_lib,
        )

        rl_basic_quote_characters = ctypes.c_char_p.in_dll(readline_lib, "rl_basic_quote_characters")
        orig_rl_basic_quotes = cast(bytes, ctypes.cast(rl_basic_quote_characters, ctypes.c_void_p).value)


class _SavedReadlineSettings:
    """readline settings that are backed up when switching between readline environments"""

    def __init__(self) -> None:
        self.completer = None
        self.delims = ''
        self.basic_quotes: Optional[bytes] = None


class _SavedCmd2Env:
    """cmd2 environment settings that are backed up when entering an interactive Python shell"""

    def __init__(self) -> None:
        self.readline_settings = _SavedReadlineSettings()
        self.readline_module: Optional[ModuleType] = None
        self.history: List[str] = []
        self.sys_stdout: Optional[TextIO] = None
        self.sys_stdin: Optional[TextIO] = None


# Contains data about a disabled command which is used to restore its original functions when the command is enabled
DisabledCommand = namedtuple('DisabledCommand', ['command_function', 'help_function', 'completer_function'])


class Cmd(cmd.Cmd):
    """An easy but powerful framework for writing line-oriented command interpreters.

    Extends the Python Standard Library’s cmd package by adding a lot of useful features
    to the out of the box configuration.

    Line-oriented command interpreters are often useful for test harnesses, internal tools, and rapid prototypes.
    """

    DEFAULT_EDITOR = utils.find_editor()

    INTERNAL_COMMAND_EPILOG = (
        "Notes:\n" "  This command is for internal use and is not intended to be called from the\n" "  command line."
    )

    # Sorting keys for strings
    ALPHABETICAL_SORT_KEY = utils.norm_fold
    NATURAL_SORT_KEY = utils.natural_keys

    def __init__(
        self,
        completekey: str = 'tab',
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
        *,
        persistent_history_file: str = '',
        persistent_history_length: int = 1000,
        startup_script: str = '',
        silence_startup_script: bool = False,
        include_py: bool = False,
        include_ipy: bool = False,
        allow_cli_args: bool = True,
        transcript_files: Optional[List[str]] = None,
        allow_redirection: bool = True,
        multiline_commands: Optional[List[str]] = None,
        terminators: Optional[List[str]] = None,
        shortcuts: Optional[Dict[str, str]] = None,
        command_sets: Optional[Iterable[CommandSet]] = None,
        auto_load_commands: bool = True,
    ) -> None:
        """An easy but powerful framework for writing line-oriented command
        interpreters. Extends Python's cmd package.

        :param completekey: readline name of a completion key, default to Tab
        :param stdin: alternate input file object, if not specified, sys.stdin is used
        :param stdout: alternate output file object, if not specified, sys.stdout is used
        :param persistent_history_file: file path to load a persistent cmd2 command history from
        :param persistent_history_length: max number of history items to write
                                          to the persistent history file
        :param startup_script: file path to a script to execute at startup
        :param silence_startup_script: if ``True``, then the startup script's output will be
                                       suppressed. Anything written to stderr will still display.
        :param include_py: should the "py" command be included for an embedded Python shell
        :param include_ipy: should the "ipy" command be included for an embedded IPython shell
        :param allow_cli_args: if ``True``, then :meth:`cmd2.Cmd.__init__` will process command
                               line arguments as either commands to be run or, if ``-t`` or
                               ``--test`` are given, transcript files to run. This should be
                               set to ``False`` if your application parses its own command line
                               arguments.
        :param transcript_files: pass a list of transcript files to be run on initialization.
                                 This allows running transcript tests when ``allow_cli_args``
                                 is ``False``. If ``allow_cli_args`` is ``True`` this parameter
                                 is ignored.
        :param allow_redirection: If ``False``, prevent output redirection and piping to shell
                                  commands. This parameter prevents redirection and piping, but
                                  does not alter parsing behavior. A user can still type
                                  redirection and piping tokens, and they will be parsed as such
                                  but they won't do anything.
        :param multiline_commands: list of commands allowed to accept multi-line input
        :param terminators: list of characters that terminate a command. These are mainly
                            intended for terminating multiline commands, but will also
                            terminate single-line commands. If not supplied, the default
                            is a semicolon. If your app only contains single-line commands
                            and you want terminators to be treated as literals by the parser,
                            then set this to an empty list.
        :param shortcuts: dictionary containing shortcuts for commands. If not supplied,
                          then defaults to constants.DEFAULT_SHORTCUTS. If you do not want
                          any shortcuts, pass an empty dictionary.
        :param command_sets: Provide CommandSet instances to load during cmd2 initialization.
                             This allows CommandSets with custom constructor parameters to be
                             loaded.  This also allows the a set of CommandSets to be provided
                             when `auto_load_commands` is set to False
        :param auto_load_commands: If True, cmd2 will check for all subclasses of `CommandSet`
                                   that are currently loaded by Python and automatically
                                   instantiate and register all commands. If False, CommandSets
                                   must be manually installed with `register_command_set`.
        """
        # Check if py or ipy need to be disabled in this instance
        if not include_py:
            setattr(self, 'do_py', None)
        if not include_ipy:
            setattr(self, 'do_ipy', None)

        # initialize plugin system
        # needs to be done before we call __init__(0)
        self._initialize_plugin_system()

        # Call super class constructor
        super().__init__(completekey=completekey, stdin=stdin, stdout=stdout)

        # Attributes which should NOT be dynamically settable via the set command at runtime
        self.default_to_shell = False  # Attempt to run unrecognized commands as shell commands
        self.allow_redirection = allow_redirection  # Security setting to prevent redirection of stdout

        # Attributes which ARE dynamically settable via the set command at runtime
        self.always_show_hint = False
        self.debug = False
        self.echo = False
        self.editor = Cmd.DEFAULT_EDITOR
        self.feedback_to_output = False  # Do not include nonessentials in >, | output by default (things like timing)
        self.quiet = False  # Do not suppress nonessential output
        self.timing = False  # Prints elapsed time for each command

        # The maximum number of CompletionItems to display during tab completion. If the number of completion
        # suggestions exceeds this number, they will be displayed in the typical columnized format and will
        # not include the description value of the CompletionItems.
        self.max_completion_items = 50

        # A dictionary mapping settable names to their Settable instance
        self._settables: Dict[str, Settable] = dict()
        self._always_prefix_settables: bool = False

        # CommandSet containers
        self._installed_command_sets: Set[CommandSet] = set()
        self._cmd_to_command_sets: Dict[str, CommandSet] = {}

        self.build_settables()

        # Use as prompt for multiline commands on the 2nd+ line of input
        self.continuation_prompt = '> '

        # Allow access to your application in embedded Python shells and scripts py via self
        self.self_in_py = False

        # Commands to exclude from the help menu and tab completion
        self.hidden_commands = ['eof', '_relative_run_script']

        # Initialize history
        self._persistent_history_length = persistent_history_length
        self._initialize_history(persistent_history_file)

        # Commands to exclude from the history command
        self.exclude_from_history = ['eof', 'history']

        # Dictionary of macro names and their values
        self.macros: Dict[str, Macro] = dict()

        # Keeps track of typed command history in the Python shell
        self._py_history: List[str] = []

        # The name by which Python environments refer to the PyBridge to call app commands
        self.py_bridge_name = 'app'

        # Defines app-specific variables/functions available in Python shells and pyscripts
        self.py_locals: Dict[str, Any] = dict()

        # True if running inside a Python shell or pyscript, False otherwise
        self._in_py = False

        self.statement_parser = StatementParser(
            terminators=terminators, multiline_commands=multiline_commands, shortcuts=shortcuts
        )

        # Stores results from the last command run to enable usage of results in Python shells and pyscripts
        self.last_result: Any = None

        # Used by run_script command to store current script dir as a LIFO queue to support _relative_run_script command
        self._script_dir: List[str] = []

        # Context manager used to protect critical sections in the main thread from stopping due to a KeyboardInterrupt
        self.sigint_protection = utils.ContextFlag()

        # If the current command created a process to pipe to, then this will be a ProcReader object.
        # Otherwise it will be None. It's used to know when a pipe process can be killed and/or waited upon.
        self._cur_pipe_proc_reader: Optional[utils.ProcReader] = None

        # Used to keep track of whether we are redirecting or piping output
        self._redirecting = False

        # Used to keep track of whether a continuation prompt is being displayed
        self._at_continuation_prompt = False

        # The multiline command currently being typed which is used to tab complete multiline commands.
        self._multiline_in_progress = ''

        # Set the header used for the help function's listing of documented functions
        self.doc_header = "Documented commands (use 'help -v' for verbose/'help <topic>' for details):"

        # The error that prints when no help information can be found
        self.help_error = "No help on {}"

        # The error that prints when a non-existent command is run
        self.default_error = "{} is not a recognized command, alias, or macro"

        # If non-empty, this string will be displayed if a broken pipe error occurs
        self.broken_pipe_warning = ''

        # Commands that will run at the beginning of the command loop
        self._startup_commands: List[str] = []

        # If a startup script is provided and exists, then execute it in the startup commands
        if startup_script:
            startup_script = os.path.abspath(os.path.expanduser(startup_script))
            if os.path.exists(startup_script):
                script_cmd = f"run_script {utils.quote_string(startup_script)}"
                if silence_startup_script:
                    script_cmd += f" {constants.REDIRECTION_OUTPUT} {os.devnull}"
                self._startup_commands.append(script_cmd)

        # Transcript files to run instead of interactive command loop
        self._transcript_files: Optional[List[str]] = None

        # Check for command line args
        if allow_cli_args:
            parser = argparse_custom.DEFAULT_ARGUMENT_PARSER()
            parser.add_argument('-t', '--test', action="store_true", help='Test against transcript(s) in FILE (wildcards OK)')
            callopts, callargs = parser.parse_known_args()

            # If transcript testing was called for, use other arguments as transcript files
            if callopts.test:
                self._transcript_files = callargs
            # If commands were supplied at invocation, then add them to the command queue
            elif callargs:
                self._startup_commands.extend(callargs)
        elif transcript_files:
            self._transcript_files = transcript_files

        # Set the pager(s) for use with the ppaged() method for displaying output using a pager
        if sys.platform.startswith('win'):
            self.pager = self.pager_chop = 'more'
        else:
            # Here is the meaning of the various flags we are using with the less command:
            # -S causes lines longer than the screen width to be chopped (truncated) rather than wrapped
            # -R causes ANSI "style" escape sequences to be output in raw form (i.e. colors are displayed)
            # -X disables sending the termcap initialization and deinitialization strings to the terminal
            # -F causes less to automatically exit if the entire file can be displayed on the first screen
            self.pager = 'less -RXF'
            self.pager_chop = 'less -SRXF'

        # This boolean flag determines whether or not the cmd2 application can interact with the clipboard
        self._can_clip = can_clip

        # This determines the value returned by cmdloop() when exiting the application
        self.exit_code = 0

        # This lock should be acquired before doing any asynchronous changes to the terminal to
        # ensure the updates to the terminal don't interfere with the input being typed or output
        # being printed by a command.
        self.terminal_lock = threading.RLock()

        # Commands that have been disabled from use. This is to support commands that are only available
        # during specific states of the application. This dictionary's keys are the command names and its
        # values are DisabledCommand objects.
        self.disabled_commands: Dict[str, DisabledCommand] = dict()

        # If any command has been categorized, then all other commands that haven't been categorized
        # will display under this section in the help output.
        self.default_category = 'Uncategorized'

        # The default key for sorting string results. Its default value performs a case-insensitive alphabetical sort.
        # If natural sorting is preferred, then set this to NATURAL_SORT_KEY.
        # cmd2 uses this key for sorting:
        #     command and category names
        #     alias, macro, settable, and shortcut names
        #     tab completion results when self.matches_sorted is False
        self.default_sort_key = Cmd.ALPHABETICAL_SORT_KEY

        ############################################################################################################
        # The following variables are used by tab completion functions. They are reset each time complete() is run
        # in _reset_completion_defaults() and it is up to completer functions to set them before returning results.
        ############################################################################################################

        # If True and a single match is returned to complete(), then a space will be appended
        # if the match appears at the end of the line
        self.allow_appended_space = True

        # If True and a single match is returned to complete(), then a closing quote
        # will be added if there is an unmatched opening quote
        self.allow_closing_quote = True

        # An optional hint which prints above tab completion suggestions
        self.completion_hint = ''

        # Normally cmd2 uses readline's formatter to columnize the list of completion suggestions.
        # If a custom format is preferred, write the formatted completions to this string. cmd2 will
        # then print it instead of the readline format. ANSI style sequences and newlines are supported
        # when using this value. Even when using formatted_completions, the full matches must still be returned
        # from your completer function. ArgparseCompleter writes its tab completion tables to this string.
        self.formatted_completions = ''

        # Used by complete() for readline tab completion
        self.completion_matches: List[str] = []

        # Use this list if you need to display tab completion suggestions that are different than the actual text
        # of the matches. For instance, if you are completing strings that contain a common delimiter and you only
        # want to display the final portion of the matches as the tab completion suggestions. The full matches
        # still must be returned from your completer function. For an example, look at path_complete() which
        # uses this to show only the basename of paths as the suggestions. delimiter_complete() also populates
        # this list. These are ignored if self.formatted_completions is populated.
        self.display_matches: List[str] = []

        # Used by functions like path_complete() and delimiter_complete() to properly
        # quote matches that are completed in a delimited fashion
        self.matches_delimited = False

        # Set to True before returning matches to complete() in cases where matches have already been sorted.
        # If False, then complete() will sort the matches using self.default_sort_key before they are displayed.
        # This does not affect self.formatted_completions.
        self.matches_sorted = False

        ############################################################################################################
        # The following code block loads CommandSets, verifies command names, and registers subcommands.
        # This block should appear after all attributes have been created since the registration code
        # depends on them and it's possible a module's on_register() method may need to access some.
        ############################################################################################################
        # Load modular commands
        if command_sets:
            for command_set in command_sets:
                self.register_command_set(command_set)

        if auto_load_commands:
            self._autoload_commands()

        # Verify commands don't have invalid names (like starting with a shortcut)
        for cur_cmd in self.get_all_commands():
            valid, errmsg = self.statement_parser.is_valid_command(cur_cmd)
            if not valid:
                raise ValueError(f"Invalid command name '{cur_cmd}': {errmsg}")

        # Add functions decorated to be subcommands
        self._register_subcommands(self)

    def find_commandsets(self, commandset_type: Type[CommandSet], *, subclass_match: bool = False) -> List[CommandSet]:
        """
        Find all CommandSets that match the provided CommandSet type.
        By default, locates a CommandSet that is an exact type match but may optionally return all CommandSets that
        are sub-classes of the provided type
        :param commandset_type: CommandSet sub-class type to search for
        :param subclass_match: If True, return all sub-classes of provided type, otherwise only search for exact match
        :return: Matching CommandSets
        """
        return [
            cmdset
            for cmdset in self._installed_command_sets
            if type(cmdset) == commandset_type or (subclass_match and isinstance(cmdset, commandset_type))
        ]

    def find_commandset_for_command(self, command_name: str) -> Optional[CommandSet]:
        """
        Finds the CommandSet that registered the command name
        :param command_name: command name to search
        :return: CommandSet that provided the command
        """
        return self._cmd_to_command_sets.get(command_name)

    def _autoload_commands(self) -> None:
        """Load modular command definitions."""
        # Search for all subclasses of CommandSet, instantiate them if they weren't already provided in the constructor
        all_commandset_defs = CommandSet.__subclasses__()
        existing_commandset_types = [type(command_set) for command_set in self._installed_command_sets]

        def load_commandset_by_type(commandset_types: List[Type[CommandSet]]) -> None:
            for cmdset_type in commandset_types:
                # check if the type has sub-classes. We will only auto-load leaf class types.
                subclasses = cmdset_type.__subclasses__()
                if subclasses:
                    load_commandset_by_type(subclasses)
                else:
                    init_sig = inspect.signature(cmdset_type.__init__)
                    if not (
                        cmdset_type in existing_commandset_types
                        or len(init_sig.parameters) != 1
                        or 'self' not in init_sig.parameters
                    ):
                        cmdset = cmdset_type()
                        self.register_command_set(cmdset)

        load_commandset_by_type(all_commandset_defs)

    def register_command_set(self, cmdset: CommandSet) -> None:
        """
        Installs a CommandSet, loading all commands defined in the CommandSet

        :param cmdset: CommandSet to load
        """
        existing_commandset_types = [type(command_set) for command_set in self._installed_command_sets]
        if type(cmdset) in existing_commandset_types:
            raise CommandSetRegistrationError('CommandSet ' + type(cmdset).__name__ + ' is already installed')

        all_settables = self.settables
        if self.always_prefix_settables:
            if not cmdset.settable_prefix.strip():
                raise CommandSetRegistrationError('CommandSet settable prefix must not be empty')
            for key in cmdset.settables.keys():
                prefixed_name = f'{cmdset.settable_prefix}.{key}'
                if prefixed_name in all_settables:
                    raise CommandSetRegistrationError(f'Duplicate settable: {key}')

        else:
            for key in cmdset.settables.keys():
                if key in all_settables:
                    raise CommandSetRegistrationError(f'Duplicate settable {key} is already registered')

        cmdset.on_register(self)
        methods = inspect.getmembers(
            cmdset,
            predicate=lambda meth: isinstance(meth, Callable)  # type: ignore[arg-type]
            and hasattr(meth, '__name__')
            and meth.__name__.startswith(COMMAND_FUNC_PREFIX),
        )

        default_category = getattr(cmdset, CLASS_ATTR_DEFAULT_HELP_CATEGORY, None)

        installed_attributes = []
        try:
            for method_name, method in methods:
                command = method_name[len(COMMAND_FUNC_PREFIX) :]

                self._install_command_function(command, method, type(cmdset).__name__)
                installed_attributes.append(method_name)

                completer_func_name = COMPLETER_FUNC_PREFIX + command
                cmd_completer = getattr(cmdset, completer_func_name, None)
                if cmd_completer is not None:
                    self._install_completer_function(command, cmd_completer)
                    installed_attributes.append(completer_func_name)

                help_func_name = HELP_FUNC_PREFIX + command
                cmd_help = getattr(cmdset, help_func_name, None)
                if cmd_help is not None:
                    self._install_help_function(command, cmd_help)
                    installed_attributes.append(help_func_name)

                self._cmd_to_command_sets[command] = cmdset

                if default_category and not hasattr(method, constants.CMD_ATTR_HELP_CATEGORY):
                    utils.categorize(method, default_category)

            self._installed_command_sets.add(cmdset)

            self._register_subcommands(cmdset)
            cmdset.on_registered()
        except Exception:
            cmdset.on_unregister()
            for attrib in installed_attributes:
                delattr(self, attrib)
            if cmdset in self._installed_command_sets:
                self._installed_command_sets.remove(cmdset)
            if cmdset in self._cmd_to_command_sets.values():
                self._cmd_to_command_sets = {key: val for key, val in self._cmd_to_command_sets.items() if val is not cmdset}
            cmdset.on_unregistered()
            raise

    def _install_command_function(self, command: str, command_wrapper: Callable[..., Any], context: str = '') -> None:
        cmd_func_name = COMMAND_FUNC_PREFIX + command

        # Make sure command function doesn't share name with existing attribute
        if hasattr(self, cmd_func_name):
            raise CommandSetRegistrationError(f'Attribute already exists: {cmd_func_name} ({context})')

        # Check if command has an invalid name
        valid, errmsg = self.statement_parser.is_valid_command(command)
        if not valid:
            raise CommandSetRegistrationError(f"Invalid command name '{command}': {errmsg}")

        # Check if command shares a name with an alias
        if command in self.aliases:
            self.pwarning(f"Deleting alias '{command}' because it shares its name with a new command")
            del self.aliases[command]

        # Check if command shares a name with a macro
        if command in self.macros:
            self.pwarning(f"Deleting macro '{command}' because it shares its name with a new command")
            del self.macros[command]

        setattr(self, cmd_func_name, command_wrapper)

    def _install_completer_function(self, cmd_name: str, cmd_completer: CompleterFunc) -> None:
        completer_func_name = COMPLETER_FUNC_PREFIX + cmd_name

        if hasattr(self, completer_func_name):
            raise CommandSetRegistrationError(f'Attribute already exists: {completer_func_name}')
        setattr(self, completer_func_name, cmd_completer)

    def _install_help_function(self, cmd_name: str, cmd_help: Callable[..., None]) -> None:
        help_func_name = HELP_FUNC_PREFIX + cmd_name

        if hasattr(self, help_func_name):
            raise CommandSetRegistrationError(f'Attribute already exists: {help_func_name}')
        setattr(self, help_func_name, cmd_help)

    def unregister_command_set(self, cmdset: CommandSet) -> None:
        """
        Uninstalls a CommandSet and unloads all associated commands

        :param cmdset: CommandSet to uninstall
        """
        if cmdset in self._installed_command_sets:
            self._check_uninstallable(cmdset)
            cmdset.on_unregister()
            self._unregister_subcommands(cmdset)

            methods = inspect.getmembers(
                cmdset,
                predicate=lambda meth: isinstance(meth, Callable)  # type: ignore[arg-type]
                and hasattr(meth, '__name__')
                and meth.__name__.startswith(COMMAND_FUNC_PREFIX),
            )

            for method in methods:
                cmd_name = method[0][len(COMMAND_FUNC_PREFIX) :]

                # Enable the command before uninstalling it to make sure we remove both
                # the real functions and the ones used by the DisabledCommand object.
                if cmd_name in self.disabled_commands:
                    self.enable_command(cmd_name)

                if cmd_name in self._cmd_to_command_sets:
                    del self._cmd_to_command_sets[cmd_name]

                delattr(self, COMMAND_FUNC_PREFIX + cmd_name)

                if hasattr(self, COMPLETER_FUNC_PREFIX + cmd_name):
                    delattr(self, COMPLETER_FUNC_PREFIX + cmd_name)
                if hasattr(self, HELP_FUNC_PREFIX + cmd_name):
                    delattr(self, HELP_FUNC_PREFIX + cmd_name)

            cmdset.on_unregistered()
            self._installed_command_sets.remove(cmdset)

    def _check_uninstallable(self, cmdset: CommandSet) -> None:
        methods = inspect.getmembers(
            cmdset,
            predicate=lambda meth: isinstance(meth, Callable)  # type: ignore[arg-type]
            and hasattr(meth, '__name__')
            and meth.__name__.startswith(COMMAND_FUNC_PREFIX),
        )

        for method in methods:
            command_name = method[0][len(COMMAND_FUNC_PREFIX) :]

            # Search for the base command function and verify it has an argparser defined
            if command_name in self.disabled_commands:
                command_func = self.disabled_commands[command_name].command_function
            else:
                command_func = self.cmd_func(command_name)

            command_parser = cast(argparse.ArgumentParser, getattr(command_func, constants.CMD_ATTR_ARGPARSER, None))

            def check_parser_uninstallable(parser: argparse.ArgumentParser) -> None:
                for action in parser._actions:
                    if isinstance(action, argparse._SubParsersAction):
                        for subparser in action.choices.values():
                            attached_cmdset = getattr(subparser, constants.PARSER_ATTR_COMMANDSET, None)
                            if attached_cmdset is not None and attached_cmdset is not cmdset:
                                raise CommandSetRegistrationError(
                                    'Cannot uninstall CommandSet when another CommandSet depends on it'
                                )
                            check_parser_uninstallable(subparser)
                        break

            if command_parser is not None:
                check_parser_uninstallable(command_parser)

    def _register_subcommands(self, cmdset: Union[CommandSet, 'Cmd']) -> None:
        """
        Register subcommands with their base command

        :param cmdset: CommandSet or cmd2.Cmd subclass containing subcommands
        """
        if not (cmdset is self or cmdset in self._installed_command_sets):
            raise CommandSetRegistrationError('Cannot register subcommands with an unregistered CommandSet')

        # find methods that have the required attributes necessary to be recognized as a sub-command
        methods = inspect.getmembers(
            cmdset,
            predicate=lambda meth: isinstance(meth, Callable)  # type: ignore[arg-type]
            and hasattr(meth, constants.SUBCMD_ATTR_NAME)
            and hasattr(meth, constants.SUBCMD_ATTR_COMMAND)
            and hasattr(meth, constants.CMD_ATTR_ARGPARSER),
        )

        # iterate through all matching methods
        for method_name, method in methods:
            subcommand_name: str = getattr(method, constants.SUBCMD_ATTR_NAME)
            full_command_name: str = getattr(method, constants.SUBCMD_ATTR_COMMAND)
            subcmd_parser = getattr(method, constants.CMD_ATTR_ARGPARSER)

            subcommand_valid, errmsg = self.statement_parser.is_valid_command(subcommand_name, is_subcommand=True)
            if not subcommand_valid:
                raise CommandSetRegistrationError(f'Subcommand {str(subcommand_name)} is not valid: {errmsg}')

            command_tokens = full_command_name.split()
            command_name = command_tokens[0]
            subcommand_names = command_tokens[1:]

            # Search for the base command function and verify it has an argparser defined
            if command_name in self.disabled_commands:
                command_func = self.disabled_commands[command_name].command_function
            else:
                command_func = self.cmd_func(command_name)

            if command_func is None:
                raise CommandSetRegistrationError(
                    f"Could not find command '{command_name}' needed by subcommand: {str(method)}"
                )
            command_parser = getattr(command_func, constants.CMD_ATTR_ARGPARSER, None)
            if command_parser is None:
                raise CommandSetRegistrationError(
                    f"Could not find argparser for command '{command_name}' needed by subcommand: {str(method)}"
                )

            def find_subcommand(action: argparse.ArgumentParser, subcmd_names: List[str]) -> argparse.ArgumentParser:
                if not subcmd_names:
                    return action
                cur_subcmd = subcmd_names.pop(0)
                for sub_action in action._actions:
                    if isinstance(sub_action, argparse._SubParsersAction):
                        for choice_name, choice in sub_action.choices.items():
                            if choice_name == cur_subcmd:
                                return find_subcommand(choice, subcmd_names)
                        break
                raise CommandSetRegistrationError(f"Could not find subcommand '{full_command_name}'")

            target_parser = find_subcommand(command_parser, subcommand_names)

            for action in target_parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    # Temporary workaround for avoiding subcommand help text repeatedly getting added to
                    # action._choices_actions. Until we have instance-specific parser objects, we will remove
                    # any existing subcommand which has the same name before replacing it. This problem is
                    # exercised when more than one cmd2.Cmd-based object is created and the same subcommands
                    # get added each time. Argparse overwrites the previous subcommand but keeps growing the help
                    # text which is shown by running something like 'alias -h'.
                    action.remove_parser(subcommand_name)  # type: ignore[arg-type,attr-defined]

                    # Get the kwargs for add_parser()
                    add_parser_kwargs = getattr(method, constants.SUBCMD_ATTR_ADD_PARSER_KWARGS, {})

                    # Set subcmd_parser as the parent to the parser we're creating to get its arguments
                    add_parser_kwargs['parents'] = [subcmd_parser]

                    # argparse only copies actions from a parent and not the following settings.
                    # To retain these settings, we will copy them from subcmd_parser and pass them
                    # as ArgumentParser constructor arguments to add_parser().
                    add_parser_kwargs['prog'] = subcmd_parser.prog
                    add_parser_kwargs['usage'] = subcmd_parser.usage
                    add_parser_kwargs['description'] = subcmd_parser.description
                    add_parser_kwargs['epilog'] = subcmd_parser.epilog
                    add_parser_kwargs['formatter_class'] = subcmd_parser.formatter_class
                    add_parser_kwargs['prefix_chars'] = subcmd_parser.prefix_chars
                    add_parser_kwargs['fromfile_prefix_chars'] = subcmd_parser.fromfile_prefix_chars
                    add_parser_kwargs['argument_default'] = subcmd_parser.argument_default
                    add_parser_kwargs['conflict_handler'] = subcmd_parser.conflict_handler
                    add_parser_kwargs['allow_abbrev'] = subcmd_parser.allow_abbrev

                    # Set add_help to False and use whatever help option subcmd_parser already has
                    add_parser_kwargs['add_help'] = False

                    attached_parser = action.add_parser(subcommand_name, **add_parser_kwargs)

                    # Set the subcommand handler
                    defaults = {constants.NS_ATTR_SUBCMD_HANDLER: method}
                    attached_parser.set_defaults(**defaults)

                    # Copy value for custom ArgparseCompleter type, which will be None if not present on subcmd_parser
                    attached_parser.set_ap_completer_type(subcmd_parser.get_ap_completer_type())  # type: ignore[attr-defined]

                    # Set what instance the handler is bound to
                    setattr(attached_parser, constants.PARSER_ATTR_COMMANDSET, cmdset)
                    break

    def _unregister_subcommands(self, cmdset: Union[CommandSet, 'Cmd']) -> None:
        """
        Unregister subcommands from their base command

        :param cmdset: CommandSet containing subcommands
        """
        if not (cmdset is self or cmdset in self._installed_command_sets):
            raise CommandSetRegistrationError('Cannot unregister subcommands with an unregistered CommandSet')

        # find methods that have the required attributes necessary to be recognized as a sub-command
        methods = inspect.getmembers(
            cmdset,
            predicate=lambda meth: isinstance(meth, Callable)  # type: ignore[arg-type]
            and hasattr(meth, constants.SUBCMD_ATTR_NAME)
            and hasattr(meth, constants.SUBCMD_ATTR_COMMAND)
            and hasattr(meth, constants.CMD_ATTR_ARGPARSER),
        )

        # iterate through all matching methods
        for method_name, method in methods:
            subcommand_name = getattr(method, constants.SUBCMD_ATTR_NAME)
            command_name = getattr(method, constants.SUBCMD_ATTR_COMMAND)

            # Search for the base command function and verify it has an argparser defined
            if command_name in self.disabled_commands:
                command_func = self.disabled_commands[command_name].command_function
            else:
                command_func = self.cmd_func(command_name)

            if command_func is None:  # pragma: no cover
                # This really shouldn't be possible since _register_subcommands would prevent this from happening
                # but keeping in case it does for some strange reason
                raise CommandSetRegistrationError(
                    f"Could not find command '{command_name}' needed by subcommand: {str(method)}"
                )
            command_parser = getattr(command_func, constants.CMD_ATTR_ARGPARSER, None)
            if command_parser is None:  # pragma: no cover
                # This really shouldn't be possible since _register_subcommands would prevent this from happening
                # but keeping in case it does for some strange reason
                raise CommandSetRegistrationError(
                    f"Could not find argparser for command '{command_name}' needed by subcommand: {str(method)}"
                )

            for action in command_parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    action.remove_parser(subcommand_name)  # type: ignore[arg-type,attr-defined]
                    break

    @property
    def always_prefix_settables(self) -> bool:
        """
        Flags whether CommandSet settable values should always be prefixed

        :return: True if CommandSet settable values will always be prefixed. False if not.
        """
        return self._always_prefix_settables

    @always_prefix_settables.setter
    def always_prefix_settables(self, new_value: bool) -> None:
        """
        Set whether CommandSet settable values should always be prefixed.

        :param new_value: True if CommandSet settable values should always be prefixed. False if not.
        :raises ValueError: If a registered CommandSet does not have a defined prefix
        """
        if not self._always_prefix_settables and new_value:
            for cmd_set in self._installed_command_sets:
                if not cmd_set.settable_prefix:
                    raise ValueError(
                        f'Cannot force settable prefixes. CommandSet {cmd_set.__class__.__name__} does '
                        f'not have a settable prefix defined.'
                    )
        self._always_prefix_settables = new_value

    @property
    def settables(self) -> Mapping[str, Settable]:
        """
        Get all available user-settable attributes. This includes settables defined in installed CommandSets

        :return: Mapping from attribute-name to Settable of all user-settable attributes from
        """
        all_settables = dict(self._settables)
        for cmd_set in self._installed_command_sets:
            cmdset_settables = cmd_set.settables
            for settable_name, settable in cmdset_settables.items():
                if self.always_prefix_settables:
                    all_settables[f'{cmd_set.settable_prefix}.{settable_name}'] = settable
                else:
                    all_settables[settable_name] = settable
        return all_settables

    def add_settable(self, settable: Settable) -> None:
        """
        Add a settable parameter to ``self.settables``

        :param settable: Settable object being added
        """
        if not self.always_prefix_settables:
            if settable.name in self.settables.keys() and settable.name not in self._settables.keys():
                raise KeyError(f'Duplicate settable: {settable.name}')
        self._settables[settable.name] = settable

    def remove_settable(self, name: str) -> None:
        """
        Convenience method for removing a settable parameter from ``self.settables``

        :param name: name of the settable being removed
        :raises: KeyError if the Settable matches this name
        """
        try:
            del self._settables[name]
        except KeyError:
            raise KeyError(name + " is not a settable parameter")

    def build_settables(self) -> None:
        """Create the dictionary of user-settable parameters"""

        def get_allow_style_choices(cli_self: Cmd) -> List[str]:
            """Used to tab complete allow_style values"""
            return [val.name.lower() for val in ansi.AllowStyle]

        def allow_style_type(value: str) -> ansi.AllowStyle:
            """Converts a string value into an ansi.AllowStyle"""
            try:
                return ansi.AllowStyle[value.upper()]
            except KeyError:
                raise ValueError(
                    f"must be {ansi.AllowStyle.ALWAYS}, {ansi.AllowStyle.NEVER}, or "
                    f"{ansi.AllowStyle.TERMINAL} (case-insensitive)"
                )

        self.add_settable(
            Settable(
                'allow_style',
                allow_style_type,
                'Allow ANSI text style sequences in output (valid values: '
                f'{ansi.AllowStyle.ALWAYS}, {ansi.AllowStyle.NEVER}, {ansi.AllowStyle.TERMINAL})',
                self,
                choices_provider=cast(ChoicesProviderFunc, get_allow_style_choices),
            )
        )

        self.add_settable(
            Settable(
                'always_show_hint',
                bool,
                'Display tab completion hint even when completion suggestions print',
                self,
            )
        )
        self.add_settable(Settable('debug', bool, "Show full traceback on exception", self))
        self.add_settable(Settable('echo', bool, "Echo command issued into output", self))
        self.add_settable(Settable('editor', str, "Program used by 'edit'", self))
        self.add_settable(Settable('feedback_to_output', bool, "Include nonessentials in '|', '>' results", self))
        self.add_settable(
            Settable('max_completion_items', int, "Maximum number of CompletionItems to display during tab completion", self)
        )
        self.add_settable(Settable('quiet', bool, "Don't print nonessential feedback", self))
        self.add_settable(Settable('timing', bool, "Report execution times", self))

    # -----  Methods related to presenting output to the user -----

    @property
    def allow_style(self) -> ansi.AllowStyle:
        """Read-only property needed to support do_set when it reads allow_style"""
        return ansi.allow_style

    @allow_style.setter
    def allow_style(self, new_val: ansi.AllowStyle) -> None:
        """Setter property needed to support do_set when it updates allow_style"""
        ansi.allow_style = new_val

    def _completion_supported(self) -> bool:
        """Return whether tab completion is supported"""
        return self.use_rawinput and bool(self.completekey) and rl_type != RlType.NONE

    @property
    def visible_prompt(self) -> str:
        """Read-only property to get the visible prompt with any ANSI style escape codes stripped.

        Used by transcript testing to make it easier and more reliable when users are doing things like coloring the
        prompt using ANSI color codes.

        :return: prompt stripped of any ANSI escape codes
        """
        return ansi.strip_style(self.prompt)

    def poutput(self, msg: Any = '', *, end: str = '\n') -> None:
        """Print message to self.stdout and appends a newline by default

        Also handles BrokenPipeError exceptions for when a command's output has
        been piped to another process and that process terminates before the
        cmd2 command is finished executing.

        :param msg: object to print
        :param end: string appended after the end of the message, default a newline
        """
        try:
            ansi.style_aware_write(self.stdout, f"{msg}{end}")
        except BrokenPipeError:
            # This occurs if a command's output is being piped to another
            # process and that process closes before the command is
            # finished. If you would like your application to print a
            # warning message, then set the broken_pipe_warning attribute
            # to the message you want printed.
            if self.broken_pipe_warning:
                sys.stderr.write(self.broken_pipe_warning)

    # noinspection PyMethodMayBeStatic
    def perror(self, msg: Any = '', *, end: str = '\n', apply_style: bool = True) -> None:
        """Print message to sys.stderr

        :param msg: object to print
        :param end: string appended after the end of the message, default a newline
        :param apply_style: If True, then ansi.style_error will be applied to the message text. Set to False in cases
                            where the message text already has the desired style. Defaults to True.
        """
        if apply_style:
            final_msg = ansi.style_error(msg)
        else:
            final_msg = str(msg)
        ansi.style_aware_write(sys.stderr, final_msg + end)

    def pwarning(self, msg: Any = '', *, end: str = '\n', apply_style: bool = True) -> None:
        """Wraps perror, but applies ansi.style_warning by default

        :param msg: object to print
        :param end: string appended after the end of the message, default a newline
        :param apply_style: If True, then ansi.style_warning will be applied to the message text. Set to False in cases
                            where the message text already has the desired style. Defaults to True.
        """
        if apply_style:
            msg = ansi.style_warning(msg)
        self.perror(msg, end=end, apply_style=False)

    def pexcept(self, msg: Any, *, end: str = '\n', apply_style: bool = True) -> None:
        """Print Exception message to sys.stderr. If debug is true, print exception traceback if one exists.

        :param msg: message or Exception to print
        :param end: string appended after the end of the message, default a newline
        :param apply_style: If True, then ansi.style_error will be applied to the message text. Set to False in cases
                            where the message text already has the desired style. Defaults to True.
        """
        if self.debug and sys.exc_info() != (None, None, None):
            import traceback

            traceback.print_exc()

        if isinstance(msg, Exception):
            final_msg = f"EXCEPTION of type '{type(msg).__name__}' occurred with message: {msg}"
        else:
            final_msg = str(msg)

        if apply_style:
            final_msg = ansi.style_error(final_msg)

        if not self.debug and 'debug' in self.settables:
            warning = "\nTo enable full traceback, run the following command: 'set debug true'"
            final_msg += ansi.style_warning(warning)

        self.perror(final_msg, end=end, apply_style=False)

    def pfeedback(self, msg: Any, *, end: str = '\n') -> None:
        """For printing nonessential feedback.  Can be silenced with `quiet`.
        Inclusion in redirected output is controlled by `feedback_to_output`.

        :param msg: object to print
        :param end: string appended after the end of the message, default a newline
        """
        if not self.quiet:
            if self.feedback_to_output:
                self.poutput(msg, end=end)
            else:
                self.perror(msg, end=end, apply_style=False)

    def ppaged(self, msg: Any, *, end: str = '\n', chop: bool = False) -> None:
        """Print output using a pager if it would go off screen and stdout isn't currently being redirected.

        Never uses a pager inside of a script (Python or text) or when output is being redirected or piped or when
        stdout or stdin are not a fully functional terminal.

        :param msg: object to print
        :param end: string appended after the end of the message, default a newline
        :param chop: True -> causes lines longer than the screen width to be chopped (truncated) rather than wrapped
                              - truncated text is still accessible by scrolling with the right & left arrow keys
                              - chopping is ideal for displaying wide tabular data as is done in utilities like pgcli
                     False -> causes lines longer than the screen width to wrap to the next line
                              - wrapping is ideal when you want to keep users from having to use horizontal scrolling

        WARNING: On Windows, the text always wraps regardless of what the chop argument is set to
        """
        # msg can be any type, so convert to string before checking if it's blank
        msg_str = str(msg)

        # Consider None to be no data to print
        if msg is None or msg_str == '':
            return

        try:
            import subprocess

            # Attempt to detect if we are not running within a fully functional terminal.
            # Don't try to use the pager when being run by a continuous integration system like Jenkins + pexpect.
            functional_terminal = False

            if self.stdin.isatty() and self.stdout.isatty():
                if sys.platform.startswith('win') or os.environ.get('TERM') is not None:
                    functional_terminal = True

            # Don't attempt to use a pager that can block if redirecting or running a script (either text or Python)
            # Also only attempt to use a pager if actually running in a real fully functional terminal
            if functional_terminal and not self._redirecting and not self.in_pyscript() and not self.in_script():
                if ansi.allow_style == ansi.AllowStyle.NEVER:
                    msg_str = ansi.strip_style(msg_str)
                msg_str += end

                pager = self.pager
                if chop:
                    pager = self.pager_chop

                # Prevent KeyboardInterrupts while in the pager. The pager application will
                # still receive the SIGINT since it is in the same process group as us.
                with self.sigint_protection:
                    pipe_proc = subprocess.Popen(pager, shell=True, stdin=subprocess.PIPE)
                    pipe_proc.communicate(msg_str.encode('utf-8', 'replace'))
            else:
                self.poutput(msg_str, end=end)
        except BrokenPipeError:
            # This occurs if a command's output is being piped to another process and that process closes before the
            # command is finished. If you would like your application to print a warning message, then set the
            # broken_pipe_warning attribute to the message you want printed.`
            if self.broken_pipe_warning:
                sys.stderr.write(self.broken_pipe_warning)

    # -----  Methods related to tab completion -----

    def _reset_completion_defaults(self) -> None:
        """
        Resets tab completion settings
        Needs to be called each time readline runs tab completion
        """
        self.allow_appended_space = True
        self.allow_closing_quote = True
        self.completion_hint = ''
        self.formatted_completions = ''
        self.completion_matches = []
        self.display_matches = []
        self.matches_delimited = False
        self.matches_sorted = False

        if rl_type == RlType.GNU:
            readline.set_completion_display_matches_hook(self._display_matches_gnu_readline)
        elif rl_type == RlType.PYREADLINE:
            # noinspection PyUnresolvedReferences
            readline.rl.mode._display_completions = self._display_matches_pyreadline

    def tokens_for_completion(self, line: str, begidx: int, endidx: int) -> Tuple[List[str], List[str]]:
        """Used by tab completion functions to get all tokens through the one being completed.

        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :return: A 2 item tuple where the items are
                 **On Success**
                 - tokens: list of unquoted tokens - this is generally the list needed for tab completion functions
                 - raw_tokens: list of tokens with any quotes preserved = this can be used to know if a token was quoted
                 or is missing a closing quote
                 Both lists are guaranteed to have at least 1 item. The last item in both lists is the token being tab
                 completed
                 **On Failure**
                 - Two empty lists
        """
        import copy

        unclosed_quote = ''
        quotes_to_try = copy.copy(constants.QUOTES)

        tmp_line = line[:endidx]
        tmp_endidx = endidx

        # Parse the line into tokens
        while True:
            try:
                initial_tokens = shlex_split(tmp_line[:tmp_endidx])

                # If the cursor is at an empty token outside of a quoted string,
                # then that is the token being completed. Add it to the list.
                if not unclosed_quote and begidx == tmp_endidx:
                    initial_tokens.append('')
                break
            except ValueError as ex:
                # Make sure the exception was due to an unclosed quote and
                # we haven't exhausted the closing quotes to try
                if str(ex) == "No closing quotation" and quotes_to_try:
                    # Add a closing quote and try to parse again
                    unclosed_quote = quotes_to_try[0]
                    quotes_to_try = quotes_to_try[1:]

                    tmp_line = line[:endidx]
                    tmp_line += unclosed_quote
                    tmp_endidx = endidx + 1
                else:  # pragma: no cover
                    # The parsing error is not caused by unclosed quotes.
                    # Return empty lists since this means the line is malformed.
                    return [], []

        # Further split tokens on punctuation characters
        raw_tokens = self.statement_parser.split_on_punctuation(initial_tokens)

        # Save the unquoted tokens
        tokens = [utils.strip_quotes(cur_token) for cur_token in raw_tokens]

        # If the token being completed had an unclosed quote, we need
        # to remove the closing quote that was added in order for it
        # to match what was on the command line.
        if unclosed_quote:
            raw_tokens[-1] = raw_tokens[-1][:-1]

        return tokens, raw_tokens

    # noinspection PyMethodMayBeStatic, PyUnusedLocal
    def basic_complete(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
        match_against: Iterable[str],
    ) -> List[str]:
        """
        Basic tab completion function that matches against a list of strings without considering line contents
        or cursor position. The args required by this function are defined in the header of Python's cmd.py.

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param match_against: the strings being matched against
        :return: a list of possible tab completions
        """
        return [cur_match for cur_match in match_against if cur_match.startswith(text)]

    def delimiter_complete(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
        match_against: Iterable[str],
        delimiter: str,
    ) -> List[str]:
        """
        Performs tab completion against a list but each match is split on a delimiter and only
        the portion of the match being tab completed is shown as the completion suggestions.
        This is useful if you match against strings that are hierarchical in nature and have a
        common delimiter.

        An easy way to illustrate this concept is path completion since paths are just directories/files
        delimited by a slash. If you are tab completing items in /home/user you don't get the following
        as suggestions:

        /home/user/file.txt     /home/user/program.c
        /home/user/maps/        /home/user/cmd2.py

        Instead you are shown:

        file.txt                program.c
        maps/                   cmd2.py

        For a large set of data, this can be visually more pleasing and easier to search.

        Another example would be strings formatted with the following syntax: company::department::name
        In this case the delimiter would be :: and the user could easily narrow down what they are looking
        for if they were only shown suggestions in the category they are at in the string.

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param match_against: the list being matched against
        :param delimiter: what delimits each portion of the matches (ex: paths are delimited by a slash)
        :return: a list of possible tab completions
        """
        matches = self.basic_complete(text, line, begidx, endidx, match_against)

        # Display only the portion of the match that's being completed based on delimiter
        if matches:
            # Set this to True for proper quoting of matches with spaces
            self.matches_delimited = True

            # Get the common beginning for the matches
            common_prefix = os.path.commonprefix(matches)
            prefix_tokens = common_prefix.split(delimiter)

            # Calculate what portion of the match we are completing
            display_token_index = 0
            if prefix_tokens:
                display_token_index = len(prefix_tokens) - 1

            # Get this portion for each match and store them in self.display_matches
            for cur_match in matches:
                match_tokens = cur_match.split(delimiter)
                display_token = match_tokens[display_token_index]

                if not display_token:
                    display_token = delimiter
                self.display_matches.append(display_token)

        return matches

    def flag_based_complete(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
        flag_dict: Dict[str, Union[Iterable[str], CompleterFunc]],
        *,
        all_else: Union[None, Iterable[str], CompleterFunc] = None,
    ) -> List[str]:
        """Tab completes based on a particular flag preceding the token being completed.

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param flag_dict: dictionary whose structure is the following:
                          `keys` - flags (ex: -c, --create) that result in tab completion for the next argument in the
                          command line
                          `values` - there are two types of values:
                          1. iterable list of strings to match against (dictionaries, lists, etc.)
                          2. function that performs tab completion (ex: path_complete)
        :param all_else: an optional parameter for tab completing any token that isn't preceded by a flag in flag_dict
        :return: a list of possible tab completions
        """
        # Get all tokens through the one being completed
        tokens, _ = self.tokens_for_completion(line, begidx, endidx)
        if not tokens:  # pragma: no cover
            return []

        completions_matches = []
        match_against = all_else

        # Must have at least 2 args for a flag to precede the token being completed
        if len(tokens) > 1:
            flag = tokens[-2]
            if flag in flag_dict:
                match_against = flag_dict[flag]

        # Perform tab completion using an Iterable
        if isinstance(match_against, Iterable):
            completions_matches = self.basic_complete(text, line, begidx, endidx, match_against)

        # Perform tab completion using a function
        elif callable(match_against):
            completions_matches = match_against(text, line, begidx, endidx)

        return completions_matches

    def index_based_complete(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
        index_dict: Mapping[int, Union[Iterable[str], CompleterFunc]],
        *,
        all_else: Optional[Union[Iterable[str], CompleterFunc]] = None,
    ) -> List[str]:
        """Tab completes based on a fixed position in the input string.

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param index_dict: dictionary whose structure is the following:
                           `keys` - 0-based token indexes into command line that determine which tokens perform tab
                           completion
                           `values` - there are two types of values:
                           1. iterable list of strings to match against (dictionaries, lists, etc.)
                           2. function that performs tab completion (ex: path_complete)
        :param all_else: an optional parameter for tab completing any token that isn't at an index in index_dict
        :return: a list of possible tab completions
        """
        # Get all tokens through the one being completed
        tokens, _ = self.tokens_for_completion(line, begidx, endidx)
        if not tokens:  # pragma: no cover
            return []

        matches = []

        # Get the index of the token being completed
        index = len(tokens) - 1

        # Check if token is at an index in the dictionary
        match_against: Optional[Union[Iterable[str], CompleterFunc]]
        if index in index_dict:
            match_against = index_dict[index]
        else:
            match_against = all_else

        # Perform tab completion using a Iterable
        if isinstance(match_against, Iterable):
            matches = self.basic_complete(text, line, begidx, endidx, match_against)

        # Perform tab completion using a function
        elif callable(match_against):
            matches = match_against(text, line, begidx, endidx)

        return matches

    # noinspection PyUnusedLocal
    def path_complete(
        self, text: str, line: str, begidx: int, endidx: int, *, path_filter: Optional[Callable[[str], bool]] = None
    ) -> List[str]:
        """Performs completion of local file system paths

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param path_filter: optional filter function that determines if a path belongs in the results
                            this function takes a path as its argument and returns True if the path should
                            be kept in the results
        :return: a list of possible tab completions
        """

        # Used to complete ~ and ~user strings
        def complete_users() -> List[str]:

            users = []

            # Windows lacks the pwd module so we can't get a list of users.
            # Instead we will return a result once the user enters text that
            # resolves to an existing home directory.
            if sys.platform.startswith('win'):
                expanded_path = os.path.expanduser(text)
                if os.path.isdir(expanded_path):
                    user = text
                    if add_trailing_sep_if_dir:
                        user += os.path.sep
                    users.append(user)
            else:
                import pwd

                # Iterate through a list of users from the password database
                for cur_pw in pwd.getpwall():

                    # Check if the user has an existing home dir
                    if os.path.isdir(cur_pw.pw_dir):

                        # Add a ~ to the user to match against text
                        cur_user = '~' + cur_pw.pw_name
                        if cur_user.startswith(text):
                            if add_trailing_sep_if_dir:
                                cur_user += os.path.sep
                            users.append(cur_user)

            if users:
                # We are returning ~user strings that resolve to directories,
                # so don't append a space or quote in the case of a single result.
                self.allow_appended_space = False
                self.allow_closing_quote = False

            return users

        # Determine if a trailing separator should be appended to directory completions
        add_trailing_sep_if_dir = False
        if endidx == len(line) or (endidx < len(line) and line[endidx] != os.path.sep):
            add_trailing_sep_if_dir = True

        # Used to replace cwd in the final results
        cwd = os.getcwd()
        cwd_added = False

        # Used to replace expanded user path in final result
        orig_tilde_path = ''
        expanded_tilde_path = ''

        # If the search text is blank, then search in the CWD for *
        if not text:
            search_str = os.path.join(os.getcwd(), '*')
            cwd_added = True
        else:
            # Purposely don't match any path containing wildcards
            wildcards = ['*', '?']
            for wildcard in wildcards:
                if wildcard in text:
                    return []

            # Start the search string
            search_str = text + '*'

            # Handle tilde expansion and completion
            if text.startswith('~'):
                sep_index = text.find(os.path.sep, 1)

                # If there is no slash, then the user is still completing the user after the tilde
                if sep_index == -1:
                    return complete_users()

                # Otherwise expand the user dir
                else:
                    search_str = os.path.expanduser(search_str)

                    # Get what we need to restore the original tilde path later
                    orig_tilde_path = text[:sep_index]
                    expanded_tilde_path = os.path.expanduser(orig_tilde_path)

            # If the search text does not have a directory, then use the cwd
            elif not os.path.dirname(text):
                search_str = os.path.join(os.getcwd(), search_str)
                cwd_added = True

        # Find all matching path completions
        matches = glob.glob(search_str)

        # Filter out results that don't belong
        if path_filter is not None:
            matches = [c for c in matches if path_filter(c)]

        if matches:
            # Set this to True for proper quoting of paths with spaces
            self.matches_delimited = True

            # Don't append a space or closing quote to directory
            if len(matches) == 1 and os.path.isdir(matches[0]):
                self.allow_appended_space = False
                self.allow_closing_quote = False

            # Sort the matches before any trailing slashes are added
            matches.sort(key=self.default_sort_key)
            self.matches_sorted = True

            # Build display_matches and add a slash to directories
            for index, cur_match in enumerate(matches):

                # Display only the basename of this path in the tab completion suggestions
                self.display_matches.append(os.path.basename(cur_match))

                # Add a separator after directories if the next character isn't already a separator
                if os.path.isdir(cur_match) and add_trailing_sep_if_dir:
                    matches[index] += os.path.sep
                    self.display_matches[index] += os.path.sep

            # Remove cwd if it was added to match the text readline expects
            if cwd_added:
                if cwd == os.path.sep:
                    to_replace = cwd
                else:
                    to_replace = cwd + os.path.sep
                matches = [cur_path.replace(to_replace, '', 1) for cur_path in matches]

            # Restore the tilde string if we expanded one to match the text readline expects
            if expanded_tilde_path:
                matches = [cur_path.replace(expanded_tilde_path, orig_tilde_path, 1) for cur_path in matches]

        return matches

    def shell_cmd_complete(self, text: str, line: str, begidx: int, endidx: int, *, complete_blank: bool = False) -> List[str]:
        """Performs completion of executables either in a user's path or a given path

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param complete_blank: If True, then a blank will complete all shell commands in a user's path. If False, then
                               no completion is performed. Defaults to False to match Bash shell behavior.
        :return: a list of possible tab completions
        """
        # Don't tab complete anything if no shell command has been started
        if not complete_blank and not text:
            return []

        # If there are no path characters in the search text, then do shell command completion in the user's path
        if not text.startswith('~') and os.path.sep not in text:
            return utils.get_exes_in_path(text)

        # Otherwise look for executables in the given path
        else:
            return self.path_complete(
                text, line, begidx, endidx, path_filter=lambda path: os.path.isdir(path) or os.access(path, os.X_OK)
            )

    def _redirect_complete(self, text: str, line: str, begidx: int, endidx: int, compfunc: CompleterFunc) -> List[str]:
        """Called by complete() as the first tab completion function for all commands
        It determines if it should tab complete for redirection (|, >, >>) or use the
        completer function for the current command

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param compfunc: the completer function for the current command
                         this will be called if we aren't completing for redirection
        :return: a list of possible tab completions
        """
        # Get all tokens through the one being completed. We want the raw tokens
        # so we can tell if redirection strings are quoted and ignore them.
        _, raw_tokens = self.tokens_for_completion(line, begidx, endidx)
        if not raw_tokens:  # pragma: no cover
            return []

        # Must at least have the command
        if len(raw_tokens) > 1:

            # True when command line contains any redirection tokens
            has_redirection = False

            # Keep track of state while examining tokens
            in_pipe = False
            in_file_redir = False
            do_shell_completion = False
            do_path_completion = False
            prior_token = None

            for cur_token in raw_tokens:
                # Process redirection tokens
                if cur_token in constants.REDIRECTION_TOKENS:
                    has_redirection = True

                    # Check if we are at a pipe
                    if cur_token == constants.REDIRECTION_PIPE:
                        # Do not complete bad syntax (e.g cmd | |)
                        if prior_token == constants.REDIRECTION_PIPE:
                            return []

                        in_pipe = True
                        in_file_redir = False

                    # Otherwise this is a file redirection token
                    else:
                        if prior_token in constants.REDIRECTION_TOKENS or in_file_redir:
                            # Do not complete bad syntax (e.g cmd | >) (e.g cmd > blah >)
                            return []

                        in_pipe = False
                        in_file_redir = True

                # Only tab complete after redirection tokens if redirection is allowed
                elif self.allow_redirection:
                    do_shell_completion = False
                    do_path_completion = False

                    if prior_token == constants.REDIRECTION_PIPE:
                        do_shell_completion = True
                    elif in_pipe or prior_token in (constants.REDIRECTION_OUTPUT, constants.REDIRECTION_APPEND):
                        do_path_completion = True

                prior_token = cur_token

            if do_shell_completion:
                return self.shell_cmd_complete(text, line, begidx, endidx)

            elif do_path_completion:
                return self.path_complete(text, line, begidx, endidx)

            # If there were redirection strings anywhere on the command line, then we
            # are no longer tab completing for the current command
            elif has_redirection:
                return []

        # Call the command's completer function
        return compfunc(text, line, begidx, endidx)

    @staticmethod
    def _pad_matches_to_display(matches_to_display: List[str]) -> Tuple[List[str], int]:  # pragma: no cover
        """Adds padding to the matches being displayed as tab completion suggestions.
        The default padding of readline/pyreadine is small and not visually appealing
        especially if matches have spaces. It appears very squished together.

        :param matches_to_display: the matches being padded
        :return: the padded matches and length of padding that was added
        """
        if rl_type == RlType.GNU:
            # Add 2 to the padding of 2 that readline uses for a total of 4.
            padding = 2 * ' '

        elif rl_type == RlType.PYREADLINE:
            # Add 3 to the padding of 1 that pyreadline3 uses for a total of 4.
            padding = 3 * ' '

        else:
            return matches_to_display, 0

        return [cur_match + padding for cur_match in matches_to_display], len(padding)

    def _display_matches_gnu_readline(
        self, substitution: str, matches: List[str], longest_match_length: int
    ) -> None:  # pragma: no cover
        """Prints a match list using GNU readline's rl_display_match_list()

        :param substitution: the substitution written to the command line
        :param matches: the tab completion matches to display
        :param longest_match_length: longest printed length of the matches
        """
        if rl_type == RlType.GNU:

            # Print hint if one exists and we are supposed to display it
            hint_printed = False
            if self.always_show_hint and self.completion_hint:
                hint_printed = True
                sys.stdout.write('\n' + self.completion_hint)

            # Check if we already have formatted results to print
            if self.formatted_completions:
                if not hint_printed:
                    sys.stdout.write('\n')
                sys.stdout.write('\n' + self.formatted_completions + '\n\n')

            # Otherwise use readline's formatter
            else:
                # Check if we should show display_matches
                if self.display_matches:
                    matches_to_display = self.display_matches

                    # Recalculate longest_match_length for display_matches
                    longest_match_length = 0

                    for cur_match in matches_to_display:
                        cur_length = ansi.style_aware_wcswidth(cur_match)
                        if cur_length > longest_match_length:
                            longest_match_length = cur_length
                else:
                    matches_to_display = matches

                # Add padding for visual appeal
                matches_to_display, padding_length = self._pad_matches_to_display(matches_to_display)
                longest_match_length += padding_length

                # We will use readline's display function (rl_display_match_list()), so we
                # need to encode our string as bytes to place in a C array.
                encoded_substitution = bytes(substitution, encoding='utf-8')
                encoded_matches = [bytes(cur_match, encoding='utf-8') for cur_match in matches_to_display]

                # rl_display_match_list() expects matches to be in argv format where
                # substitution is the first element, followed by the matches, and then a NULL.
                # noinspection PyCallingNonCallable,PyTypeChecker
                strings_array = cast(List[Optional[bytes]], (ctypes.c_char_p * (1 + len(encoded_matches) + 1))())

                # Copy in the encoded strings and add a NULL to the end
                strings_array[0] = encoded_substitution
                strings_array[1:-1] = encoded_matches
                strings_array[-1] = None

                # rl_display_match_list(strings_array, number of completion matches, longest match length)
                readline_lib.rl_display_match_list(strings_array, len(encoded_matches), longest_match_length)

            # Redraw prompt and input line
            rl_force_redisplay()

    def _display_matches_pyreadline(self, matches: List[str]) -> None:  # pragma: no cover
        """Prints a match list using pyreadline3's _display_completions()

        :param matches: the tab completion matches to display
        """
        if rl_type == RlType.PYREADLINE:

            # Print hint if one exists and we are supposed to display it
            hint_printed = False
            if self.always_show_hint and self.completion_hint:
                hint_printed = True
                readline.rl.mode.console.write('\n' + self.completion_hint)

            # Check if we already have formatted results to print
            if self.formatted_completions:
                if not hint_printed:
                    readline.rl.mode.console.write('\n')
                readline.rl.mode.console.write('\n' + self.formatted_completions + '\n\n')

                # Redraw the prompt and input lines
                rl_force_redisplay()

            # Otherwise use pyreadline3's formatter
            else:
                # Check if we should show display_matches
                if self.display_matches:
                    matches_to_display = self.display_matches
                else:
                    matches_to_display = matches

                # Add padding for visual appeal
                matches_to_display, _ = self._pad_matches_to_display(matches_to_display)

                # Display matches using actual display function. This also redraws the prompt and input lines.
                orig_pyreadline_display(matches_to_display)

    @staticmethod
    def _determine_ap_completer_type(parser: argparse.ArgumentParser) -> Type[argparse_completer.ArgparseCompleter]:
        """
        Determine what type of ArgparseCompleter to use on a given parser. If the parser does not have one
        set, then use argparse_completer.DEFAULT_AP_COMPLETER.

        :param parser: the parser to examine
        :return: type of ArgparseCompleter
        """
        completer_type: Optional[
            Type[argparse_completer.ArgparseCompleter]
        ] = parser.get_ap_completer_type()  # type: ignore[attr-defined]

        if completer_type is None:
            completer_type = argparse_completer.DEFAULT_AP_COMPLETER
        return completer_type

    def _perform_completion(
        self, text: str, line: str, begidx: int, endidx: int, custom_settings: Optional[utils.CustomCompletionSettings] = None
    ) -> None:
        """
        Helper function for complete() that performs the actual completion

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param custom_settings: optional prepopulated completion settings
        """
        # If custom_settings is None, then we are completing a command's argument.
        # Parse the command line to get the command token.
        command = ''
        if custom_settings is None:
            statement = self.statement_parser.parse_command_only(line)
            command = statement.command

            # Malformed command line (e.g. quoted command token)
            if not command:
                return

            expanded_line = statement.command_and_args

            # We overwrote line with a properly formatted but fully stripped version
            # Restore the end spaces since line is only supposed to be lstripped when
            # passed to completer functions according to Python docs
            rstripped_len = len(line) - len(line.rstrip())
            expanded_line += ' ' * rstripped_len

            # Fix the index values if expanded_line has a different size than line
            if len(expanded_line) != len(line):
                diff = len(expanded_line) - len(line)
                begidx += diff
                endidx += diff

            # Overwrite line to pass into completers
            line = expanded_line

        # Get all tokens through the one being completed
        tokens, raw_tokens = self.tokens_for_completion(line, begidx, endidx)
        if not tokens:  # pragma: no cover
            return

        # Determine the completer function to use for the command's argument
        if custom_settings is None:
            # Check if a macro was entered
            if command in self.macros:
                completer_func = self.path_complete

            # Check if a command was entered
            elif command in self.get_all_commands():
                # Get the completer function for this command
                func_attr = getattr(self, constants.COMPLETER_FUNC_PREFIX + command, None)

                if func_attr is not None:
                    completer_func = func_attr
                else:
                    # There's no completer function, next see if the command uses argparse
                    func = self.cmd_func(command)
                    argparser: Optional[argparse.ArgumentParser] = getattr(func, constants.CMD_ATTR_ARGPARSER, None)

                    if func is not None and argparser is not None:
                        # Get arguments for complete()
                        preserve_quotes = getattr(func, constants.CMD_ATTR_PRESERVE_QUOTES)
                        cmd_set = self._cmd_to_command_sets[command] if command in self._cmd_to_command_sets else None

                        # Create the argparse completer
                        completer_type = self._determine_ap_completer_type(argparser)
                        completer = completer_type(argparser, self)

                        completer_func = functools.partial(
                            completer.complete, tokens=raw_tokens[1:] if preserve_quotes else tokens[1:], cmd_set=cmd_set
                        )
                    else:
                        completer_func = self.completedefault  # type: ignore[assignment]

            # Not a recognized macro or command
            else:
                # Check if this command should be run as a shell command
                if self.default_to_shell and command in utils.get_exes_in_path(command):
                    completer_func = self.path_complete
                else:
                    completer_func = self.completedefault  # type: ignore[assignment]

        # Otherwise we are completing the command token or performing custom completion
        else:
            # Create the argparse completer
            completer_type = self._determine_ap_completer_type(custom_settings.parser)
            completer = completer_type(custom_settings.parser, self)

            completer_func = functools.partial(
                completer.complete, tokens=raw_tokens if custom_settings.preserve_quotes else tokens, cmd_set=None
            )

        # Text we need to remove from completions later
        text_to_remove = ''

        # Get the token being completed with any opening quote preserved
        raw_completion_token = raw_tokens[-1]

        # Used for adding quotes to the completion token
        completion_token_quote = ''

        # Check if the token being completed has an opening quote
        if raw_completion_token and raw_completion_token[0] in constants.QUOTES:

            # Since the token is still being completed, we know the opening quote is unclosed.
            # Save the quote so we can add a matching closing quote later.
            completion_token_quote = raw_completion_token[0]

            # readline still performs word breaks after a quote. Therefore, something like quoted search
            # text with a space would have resulted in begidx pointing to the middle of the token we
            # we want to complete. Figure out where that token actually begins and save the beginning
            # portion of it that was not part of the text readline gave us. We will remove it from the
            # completions later since readline expects them to start with the original text.
            actual_begidx = line[:endidx].rfind(tokens[-1])

            if actual_begidx != begidx:
                text_to_remove = line[actual_begidx:begidx]

                # Adjust text and where it begins so the completer routines
                # get unbroken search text to complete on.
                text = text_to_remove + text
                begidx = actual_begidx

        # Attempt tab completion for redirection first, and if that isn't occurring,
        # call the completer function for the current command
        self.completion_matches = self._redirect_complete(text, line, begidx, endidx, completer_func)

        if self.completion_matches:

            # Eliminate duplicates
            self.completion_matches = utils.remove_duplicates(self.completion_matches)
            self.display_matches = utils.remove_duplicates(self.display_matches)

            if not self.display_matches:
                # Since self.display_matches is empty, set it to self.completion_matches
                # before we alter them. That way the suggestions will reflect how we parsed
                # the token being completed and not how readline did.
                import copy

                self.display_matches = copy.copy(self.completion_matches)

            # Check if we need to add an opening quote
            if not completion_token_quote:

                add_quote = False

                # This is the tab completion text that will appear on the command line.
                common_prefix = os.path.commonprefix(self.completion_matches)

                if self.matches_delimited:
                    # Check if any portion of the display matches appears in the tab completion
                    display_prefix = os.path.commonprefix(self.display_matches)

                    # For delimited matches, we check for a space in what appears before the display
                    # matches (common_prefix) as well as in the display matches themselves.
                    if ' ' in common_prefix or (display_prefix and any(' ' in match for match in self.display_matches)):
                        add_quote = True

                # If there is a tab completion and any match has a space, then add an opening quote
                elif common_prefix and any(' ' in match for match in self.completion_matches):
                    add_quote = True

                if add_quote:
                    # Figure out what kind of quote to add and save it as the unclosed_quote
                    if any('"' in match for match in self.completion_matches):
                        completion_token_quote = "'"
                    else:
                        completion_token_quote = '"'

                    self.completion_matches = [completion_token_quote + match for match in self.completion_matches]

            # Check if we need to remove text from the beginning of tab completions
            elif text_to_remove:
                self.completion_matches = [match.replace(text_to_remove, '', 1) for match in self.completion_matches]

            # If we have one result, then add a closing quote if needed and allowed
            if len(self.completion_matches) == 1 and self.allow_closing_quote and completion_token_quote:
                self.completion_matches[0] += completion_token_quote

    def complete(  # type: ignore[override]
        self, text: str, state: int, custom_settings: Optional[utils.CustomCompletionSettings] = None
    ) -> Optional[str]:
        """Override of cmd's complete method which returns the next possible completion for 'text'

        This completer function is called by readline as complete(text, state), for state in 0, 1, 2, …,
        until it returns a non-string value. It should return the next possible completion starting with text.

        Since readline suppresses any exception raised in completer functions, they can be difficult to debug.
        Therefore, this function wraps the actual tab completion logic and prints to stderr any exception that
        occurs before returning control to readline.

        :param text: the current word that user is typing
        :param state: non-negative integer
        :param custom_settings: used when not tab completing the main command line
        :return: the next possible completion for text or None
        """
        # noinspection PyBroadException
        try:
            if state == 0:
                self._reset_completion_defaults()

                # Check if we are completing a multiline command
                if self._at_continuation_prompt:
                    # lstrip and prepend the previously typed portion of this multiline command
                    lstripped_previous = self._multiline_in_progress.lstrip().replace(constants.LINE_FEED, ' ')
                    line = lstripped_previous + readline.get_line_buffer()

                    # Increment the indexes to account for the prepended text
                    begidx = len(lstripped_previous) + readline.get_begidx()
                    endidx = len(lstripped_previous) + readline.get_endidx()
                else:
                    # lstrip the original line
                    orig_line = readline.get_line_buffer()
                    line = orig_line.lstrip()
                    num_stripped = len(orig_line) - len(line)

                    # Calculate new indexes for the stripped line. If the cursor is at a position before the end of a
                    # line of spaces, then the following math could result in negative indexes. Enforce a max of 0.
                    begidx = max(readline.get_begidx() - num_stripped, 0)
                    endidx = max(readline.get_endidx() - num_stripped, 0)

                # Shortcuts are not word break characters when tab completing. Therefore, shortcuts become part
                # of the text variable if there isn't a word break, like a space, after it. We need to remove it
                # from text and update the indexes. This only applies if we are at the beginning of the command line.
                shortcut_to_restore = ''
                if begidx == 0 and custom_settings is None:
                    for (shortcut, _) in self.statement_parser.shortcuts:
                        if text.startswith(shortcut):
                            # Save the shortcut to restore later
                            shortcut_to_restore = shortcut

                            # Adjust text and where it begins
                            text = text[len(shortcut_to_restore) :]
                            begidx += len(shortcut_to_restore)
                            break
                    else:
                        # No shortcut was found. Complete the command token.
                        parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(add_help=False)
                        parser.add_argument(
                            'command',
                            metavar="COMMAND",
                            help="command, alias, or macro name",
                            choices=self._get_commands_aliases_and_macros_for_completion(),
                        )
                        custom_settings = utils.CustomCompletionSettings(parser)

                self._perform_completion(text, line, begidx, endidx, custom_settings)

                # Check if we need to restore a shortcut in the tab completions
                # so it doesn't get erased from the command line
                if shortcut_to_restore:
                    self.completion_matches = [shortcut_to_restore + match for match in self.completion_matches]

                # If we have one result and we are at the end of the line, then add a space if allowed
                if len(self.completion_matches) == 1 and endidx == len(line) and self.allow_appended_space:
                    self.completion_matches[0] += ' '

                # Sort matches if they haven't already been sorted
                if not self.matches_sorted:
                    self.completion_matches.sort(key=self.default_sort_key)
                    self.display_matches.sort(key=self.default_sort_key)
                    self.matches_sorted = True

            try:
                return self.completion_matches[state]
            except IndexError:
                return None

        except CompletionError as ex:
            # Don't print error and redraw the prompt unless the error has length
            err_str = str(ex)
            if err_str:
                if ex.apply_style:
                    err_str = ansi.style_error(err_str)
                ansi.style_aware_write(sys.stdout, '\n' + err_str + '\n')
                rl_force_redisplay()
            return None
        except Exception as ex:
            # Insert a newline so the exception doesn't print in the middle of the command line being tab completed
            self.perror()
            self.pexcept(ex)
            rl_force_redisplay()
            return None

    def in_script(self) -> bool:
        """Return whether a text script is running"""
        return self._current_script_dir is not None

    def in_pyscript(self) -> bool:
        """Return whether running inside a Python shell or pyscript"""
        return self._in_py

    @property
    def aliases(self) -> Dict[str, str]:
        """Read-only property to access the aliases stored in the StatementParser"""
        return self.statement_parser.aliases

    def get_names(self) -> List[str]:
        """Return an alphabetized list of names comprising the attributes of the cmd2 class instance."""
        return dir(self)

    def get_all_commands(self) -> List[str]:
        """Return a list of all commands"""
        return [
            name[len(constants.COMMAND_FUNC_PREFIX) :]
            for name in self.get_names()
            if name.startswith(constants.COMMAND_FUNC_PREFIX) and callable(getattr(self, name))
        ]

    def get_visible_commands(self) -> List[str]:
        """Return a list of commands that have not been hidden or disabled"""
        return [
            command
            for command in self.get_all_commands()
            if command not in self.hidden_commands and command not in self.disabled_commands
        ]

    # Table displayed when tab completing aliases
    _alias_completion_table = SimpleTable([Column('Value', width=80)], divider_char=None)

    def _get_alias_completion_items(self) -> List[CompletionItem]:
        """Return list of alias names and values as CompletionItems"""
        results: List[CompletionItem] = []

        for cur_key in self.aliases:
            row_data = [self.aliases[cur_key]]
            results.append(CompletionItem(cur_key, self._alias_completion_table.generate_data_row(row_data)))

        return results

    # Table displayed when tab completing macros
    _macro_completion_table = SimpleTable([Column('Value', width=80)], divider_char=None)

    def _get_macro_completion_items(self) -> List[CompletionItem]:
        """Return list of macro names and values as CompletionItems"""
        results: List[CompletionItem] = []

        for cur_key in self.macros:
            row_data = [self.macros[cur_key].value]
            results.append(CompletionItem(cur_key, self._macro_completion_table.generate_data_row(row_data)))

        return results

    # Table displayed when tab completing Settables
    _settable_completion_table = SimpleTable([Column('Value', width=30), Column('Description', width=60)], divider_char=None)

    def _get_settable_completion_items(self) -> List[CompletionItem]:
        """Return list of Settable names, values, and descriptions as CompletionItems"""
        results: List[CompletionItem] = []

        for cur_key in self.settables:
            row_data = [self.settables[cur_key].get_value(), self.settables[cur_key].description]
            results.append(CompletionItem(cur_key, self._settable_completion_table.generate_data_row(row_data)))

        return results

    def _get_commands_aliases_and_macros_for_completion(self) -> List[str]:
        """Return a list of visible commands, aliases, and macros for tab completion"""
        visible_commands = set(self.get_visible_commands())
        alias_names = set(self.aliases)
        macro_names = set(self.macros)
        return list(visible_commands | alias_names | macro_names)

    def get_help_topics(self) -> List[str]:
        """Return a list of help topics"""
        all_topics = [
            name[len(constants.HELP_FUNC_PREFIX) :]
            for name in self.get_names()
            if name.startswith(constants.HELP_FUNC_PREFIX) and callable(getattr(self, name))
        ]

        # Filter out hidden and disabled commands
        return [topic for topic in all_topics if topic not in self.hidden_commands and topic not in self.disabled_commands]

    # noinspection PyUnusedLocal
    def sigint_handler(self, signum: int, _: FrameType) -> None:
        """Signal handler for SIGINTs which typically come from Ctrl-C events.

        If you need custom SIGINT behavior, then override this function.

        :param signum: signal number
        :param _: required param for signal handlers
        """
        if self._cur_pipe_proc_reader is not None:
            # Pass the SIGINT to the current pipe process
            self._cur_pipe_proc_reader.send_sigint()

        # Check if we are allowed to re-raise the KeyboardInterrupt
        if not self.sigint_protection:
            self._raise_keyboard_interrupt()

    def _raise_keyboard_interrupt(self) -> None:
        """Helper function to raise a KeyboardInterrupt"""
        raise KeyboardInterrupt("Got a keyboard interrupt")

    def precmd(self, statement: Union[Statement, str]) -> Statement:
        """Hook method executed just before the command is executed by
        :meth:`~cmd2.Cmd.onecmd` and after adding it to history.

        :param statement: subclass of str which also contains the parsed input
        :return: a potentially modified version of the input Statement object

        See :meth:`~cmd2.Cmd.register_postparsing_hook` and
        :meth:`~cmd2.Cmd.register_precmd_hook` for more robust ways
        to run hooks before the command is executed. See
        :ref:`features/hooks:Postparsing Hooks` and
        :ref:`features/hooks:Precommand Hooks` for more information.
        """
        return Statement(statement) if not isinstance(statement, Statement) else statement

    def postcmd(self, stop: bool, statement: Union[Statement, str]) -> bool:
        """Hook method executed just after a command is executed by
        :meth:`~cmd2.Cmd.onecmd`.

        :param stop: return `True` to request the command loop terminate
        :param statement: subclass of str which also contains the parsed input

        See :meth:`~cmd2.Cmd.register_postcmd_hook` and :meth:`~cmd2.Cmd.register_cmdfinalization_hook` for more robust ways
        to run hooks after the command is executed. See
        :ref:`features/hooks:Postcommand Hooks` and
        :ref:`features/hooks:Command Finalization Hooks` for more information.
        """
        return stop

    def preloop(self) -> None:
        """Hook method executed once when the :meth:`~.cmd2.Cmd.cmdloop()`
        method is called.

        See :meth:`~cmd2.Cmd.register_preloop_hook` for a more robust way
        to run hooks before the command loop begins. See
        :ref:`features/hooks:Application Lifecycle Hooks` for more information.
        """
        pass

    def postloop(self) -> None:
        """Hook method executed once when the :meth:`~.cmd2.Cmd.cmdloop()`
        method is about to return.

        See :meth:`~cmd2.Cmd.register_postloop_hook` for a more robust way
        to run hooks after the command loop completes. See
        :ref:`features/hooks:Application Lifecycle Hooks` for more information.
        """
        pass

    def parseline(self, line: str) -> Tuple[str, str, str]:
        """Parse the line into a command name and a string containing the arguments.

        NOTE: This is an override of a parent class method.  It is only used by other parent class methods.

        Different from the parent class method, this ignores self.identchars.

        :param line: line read by readline
        :return: tuple containing (command, args, line)
        """
        statement = self.statement_parser.parse_command_only(line)
        return statement.command, statement.args, statement.command_and_args

    def onecmd_plus_hooks(
        self, line: str, *, add_to_history: bool = True, raise_keyboard_interrupt: bool = False, py_bridge_call: bool = False
    ) -> bool:
        """Top-level function called by cmdloop() to handle parsing a line and running the command and all of its hooks.

        :param line: command line to run
        :param add_to_history: If True, then add this command to history. Defaults to True.
        :param raise_keyboard_interrupt: if True, then KeyboardInterrupt exceptions will be raised if stop isn't already
                                         True. This is used when running commands in a loop to be able to stop the whole
                                         loop and not just the current command. Defaults to False.
        :param py_bridge_call: This should only ever be set to True by PyBridge to signify the beginning
                               of an app() call from Python. It is used to enable/disable the storage of the
                               command's stdout.
        :return: True if running of commands should stop
        """
        import datetime

        stop = False
        statement = None

        try:
            # Convert the line into a Statement
            statement = self._input_line_to_statement(line)

            # call the postparsing hooks
            postparsing_data = plugin.PostparsingData(False, statement)
            for postparsing_func in self._postparsing_hooks:
                postparsing_data = postparsing_func(postparsing_data)
                if postparsing_data.stop:
                    break

            # unpack the postparsing_data object
            statement = postparsing_data.statement
            stop = postparsing_data.stop
            if stop:
                # we should not run the command, but
                # we need to run the finalization hooks
                raise EmptyStatement

            redir_saved_state: Optional[utils.RedirectionSavedState] = None

            try:
                # Get sigint protection while we set up redirection
                with self.sigint_protection:
                    if py_bridge_call:
                        # Start saving command's stdout at this point
                        self.stdout.pause_storage = False  # type: ignore[attr-defined]

                    redir_saved_state = self._redirect_output(statement)

                timestart = datetime.datetime.now()

                # precommand hooks
                precmd_data = plugin.PrecommandData(statement)
                for precmd_func in self._precmd_hooks:
                    precmd_data = precmd_func(precmd_data)
                statement = precmd_data.statement

                # call precmd() for compatibility with cmd.Cmd
                statement = self.precmd(statement)

                # go run the command function
                stop = self.onecmd(statement, add_to_history=add_to_history)

                # postcommand hooks
                postcmd_data = plugin.PostcommandData(stop, statement)
                for postcmd_func in self._postcmd_hooks:
                    postcmd_data = postcmd_func(postcmd_data)

                # retrieve the final value of stop, ignoring any statement modification from the hooks
                stop = postcmd_data.stop

                # call postcmd() for compatibility with cmd.Cmd
                stop = self.postcmd(stop, statement)

                if self.timing:
                    self.pfeedback(f'Elapsed: {datetime.datetime.now() - timestart}')
            finally:
                # Get sigint protection while we restore stuff
                with self.sigint_protection:
                    if redir_saved_state is not None:
                        self._restore_output(statement, redir_saved_state)

                    if py_bridge_call:
                        # Stop saving command's stdout before command finalization hooks run
                        self.stdout.pause_storage = True  # type: ignore[attr-defined]
        except (SkipPostcommandHooks, EmptyStatement):
            # Don't do anything, but do allow command finalization hooks to run
            pass
        except Cmd2ShlexError as ex:
            self.perror(f"Invalid syntax: {ex}")
        except RedirectionError as ex:
            self.perror(ex)
        except KeyboardInterrupt as ex:
            if raise_keyboard_interrupt and not stop:
                raise ex
        except SystemExit as ex:
            if isinstance(ex.code, int):
                self.exit_code = ex.code
            stop = True
        except PassThroughException as ex:
            raise ex.wrapped_ex
        except Exception as ex:
            self.pexcept(ex)
        finally:
            try:
                stop = self._run_cmdfinalization_hooks(stop, statement)
            except KeyboardInterrupt as ex:
                if raise_keyboard_interrupt and not stop:
                    raise ex
            except SystemExit as ex:
                if isinstance(ex.code, int):
                    self.exit_code = ex.code
                stop = True
            except PassThroughException as ex:
                raise ex.wrapped_ex
            except Exception as ex:
                self.pexcept(ex)

        return stop

    def _run_cmdfinalization_hooks(self, stop: bool, statement: Optional[Statement]) -> bool:
        """Run the command finalization hooks"""
        with self.sigint_protection:
            if not sys.platform.startswith('win') and self.stdin.isatty():
                # Before the next command runs, fix any terminal problems like those
                # caused by certain binary characters having been printed to it.
                import subprocess

                proc = subprocess.Popen(['stty', 'sane'])
                proc.communicate()

        data = plugin.CommandFinalizationData(stop, statement)
        for func in self._cmdfinalization_hooks:
            data = func(data)
        # retrieve the final value of stop, ignoring any
        # modifications to the statement
        return data.stop

    def runcmds_plus_hooks(
        self,
        cmds: Union[List[HistoryItem], List[str]],
        *,
        add_to_history: bool = True,
        stop_on_keyboard_interrupt: bool = False,
    ) -> bool:
        """
        Used when commands are being run in an automated fashion like text scripts or history replays.
        The prompt and command line for each command will be printed if echo is True.

        :param cmds: commands to run
        :param add_to_history: If True, then add these commands to history. Defaults to True.
        :param stop_on_keyboard_interrupt: if True, then stop running contents of cmds if Ctrl-C is pressed instead of moving
                                           to the next command in the list. This is used when the commands are part of a
                                           group, like a text script, which should stop upon Ctrl-C. Defaults to False.
        :return: True if running of commands should stop
        """
        for line in cmds:
            if isinstance(line, HistoryItem):
                line = line.raw

            if self.echo:
                self.poutput(f'{self.prompt}{line}')

            try:
                if self.onecmd_plus_hooks(
                    line, add_to_history=add_to_history, raise_keyboard_interrupt=stop_on_keyboard_interrupt
                ):
                    return True
            except KeyboardInterrupt as ex:
                if stop_on_keyboard_interrupt:
                    self.perror(ex)
                    break

        return False

    def _complete_statement(self, line: str) -> Statement:
        """Keep accepting lines of input until the command is complete.

        There is some pretty hacky code here to handle some quirks of
        self._read_command_line(). It returns a literal 'eof' if the input
        pipe runs out. We can't refactor it because we need to retain
        backwards compatibility with the standard library version of cmd.

        :param line: the line being parsed
        :return: the completed Statement
        :raises: Cmd2ShlexError if a shlex error occurs (e.g. No closing quotation)
        :raises: EmptyStatement when the resulting Statement is blank
        """
        while True:
            try:
                statement = self.statement_parser.parse(line)
                if statement.multiline_command and statement.terminator:
                    # we have a completed multiline command, we are done
                    break
                if not statement.multiline_command:
                    # it's not a multiline command, but we parsed it ok
                    # so we are done
                    break
            except Cmd2ShlexError:
                # we have unclosed quotation marks, lets parse only the command
                # and see if it's a multiline
                statement = self.statement_parser.parse_command_only(line)
                if not statement.multiline_command:
                    # not a multiline command, so raise the exception
                    raise

            # if we get here we must have:
            #   - a multiline command with no terminator
            #   - a multiline command with unclosed quotation marks
            try:
                self._at_continuation_prompt = True

                # Save the command line up to this point for tab completion
                self._multiline_in_progress = line + '\n'

                nextline = self._read_command_line(self.continuation_prompt)
                if nextline == 'eof':
                    # they entered either a blank line, or we hit an EOF
                    # for some other reason. Turn the literal 'eof'
                    # into a blank line, which serves as a command
                    # terminator
                    nextline = '\n'
                    self.poutput(nextline)
                line = f'{self._multiline_in_progress}{nextline}'
            except KeyboardInterrupt:
                self.poutput('^C')
                statement = self.statement_parser.parse('')
                break
            finally:
                self._at_continuation_prompt = False

        if not statement.command:
            raise EmptyStatement
        return statement

    def _input_line_to_statement(self, line: str) -> Statement:
        """
        Parse the user's input line and convert it to a Statement, ensuring that all macros are also resolved

        :param line: the line being parsed
        :return: parsed command line as a Statement
        :raises: Cmd2ShlexError if a shlex error occurs (e.g. No closing quotation)
        :raises: EmptyStatement when the resulting Statement is blank
        """
        used_macros = []
        orig_line = None

        # Continue until all macros are resolved
        while True:
            # Make sure all input has been read and convert it to a Statement
            statement = self._complete_statement(line)

            # Save the fully entered line if this is the first loop iteration
            if orig_line is None:
                orig_line = statement.raw

            # Check if this command matches a macro and wasn't already processed to avoid an infinite loop
            if statement.command in self.macros.keys() and statement.command not in used_macros:
                used_macros.append(statement.command)
                resolve_result = self._resolve_macro(statement)
                if resolve_result is None:
                    raise EmptyStatement
                line = resolve_result
            else:
                break

        # This will be true when a macro was used
        if orig_line != statement.raw:
            # Build a Statement that contains the resolved macro line
            # but the originally typed line for its raw member.
            statement = Statement(
                statement.args,
                raw=orig_line,
                command=statement.command,
                arg_list=statement.arg_list,
                multiline_command=statement.multiline_command,
                terminator=statement.terminator,
                suffix=statement.suffix,
                pipe_to=statement.pipe_to,
                output=statement.output,
                output_to=statement.output_to,
            )
        return statement

    def _resolve_macro(self, statement: Statement) -> Optional[str]:
        """
        Resolve a macro and return the resulting string

        :param statement: the parsed statement from the command line
        :return: the resolved macro or None on error
        """
        if statement.command not in self.macros.keys():
            raise KeyError(f"{statement.command} is not a macro")

        macro = self.macros[statement.command]

        # Make sure enough arguments were passed in
        if len(statement.arg_list) < macro.minimum_arg_count:
            plural = '' if macro.minimum_arg_count == 1 else 's'
            self.perror(f"The macro '{statement.command}' expects at least {macro.minimum_arg_count} argument{plural}")
            return None

        # Resolve the arguments in reverse and read their values from statement.argv since those
        # are unquoted. Macro args should have been quoted when the macro was created.
        resolved = macro.value
        reverse_arg_list = sorted(macro.arg_list, key=lambda ma: ma.start_index, reverse=True)

        for macro_arg in reverse_arg_list:
            if macro_arg.is_escaped:
                to_replace = '{{' + macro_arg.number_str + '}}'
                replacement = '{' + macro_arg.number_str + '}'
            else:
                to_replace = '{' + macro_arg.number_str + '}'
                replacement = statement.argv[int(macro_arg.number_str)]

            parts = resolved.rsplit(to_replace, maxsplit=1)
            resolved = parts[0] + replacement + parts[1]

        # Append extra arguments and use statement.arg_list since these arguments need their quotes preserved
        for stmt_arg in statement.arg_list[macro.minimum_arg_count :]:
            resolved += ' ' + stmt_arg

        # Restore any terminator, suffix, redirection, etc.
        return resolved + statement.post_command

    def _redirect_output(self, statement: Statement) -> utils.RedirectionSavedState:
        """Set up a command's output redirection for >, >>, and |.

        :param statement: a parsed statement from the user
        :return: A bool telling if an error occurred and a utils.RedirectionSavedState object
        :raises: RedirectionError if an error occurs trying to pipe or redirect
        """
        import io
        import subprocess

        # Initialize the redirection saved state
        redir_saved_state = utils.RedirectionSavedState(
            cast(TextIO, self.stdout), sys.stdout, self._cur_pipe_proc_reader, self._redirecting
        )

        # The ProcReader for this command
        cmd_pipe_proc_reader: Optional[utils.ProcReader] = None

        if not self.allow_redirection:
            # Don't return since we set some state variables at the end of the function
            pass

        elif statement.pipe_to:
            # Create a pipe with read and write sides
            read_fd, write_fd = os.pipe()

            # Open each side of the pipe
            subproc_stdin = io.open(read_fd, 'r')
            new_stdout: TextIO = cast(TextIO, io.open(write_fd, 'w'))

            # Create pipe process in a separate group to isolate our signals from it. If a Ctrl-C event occurs,
            # our sigint handler will forward it only to the most recent pipe process. This makes sure pipe
            # processes close in the right order (most recent first).
            kwargs: Dict[str, Any] = dict()
            if sys.platform == 'win32':
                kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs['start_new_session'] = True

                # Attempt to run the pipe process in the user's preferred shell instead of the default behavior of using sh.
                shell = os.environ.get("SHELL")
                if shell:
                    kwargs['executable'] = shell

            # For any stream that is a StdSim, we will use a pipe so we can capture its output
            proc = subprocess.Popen(  # type: ignore[call-overload]
                statement.pipe_to,
                stdin=subproc_stdin,
                stdout=subprocess.PIPE if isinstance(self.stdout, utils.StdSim) else self.stdout,  # type: ignore[unreachable]
                stderr=subprocess.PIPE if isinstance(sys.stderr, utils.StdSim) else sys.stderr,  # type: ignore[unreachable]
                shell=True,
                **kwargs,
            )

            # Popen was called with shell=True so the user can chain pipe commands and redirect their output
            # like: !ls -l | grep user | wc -l > out.txt. But this makes it difficult to know if the pipe process
            # started OK, since the shell itself always starts. Therefore, we will wait a short time and check
            # if the pipe process is still running.
            try:
                proc.wait(0.2)
            except subprocess.TimeoutExpired:
                pass

            # Check if the pipe process already exited
            if proc.returncode is not None:
                subproc_stdin.close()
                new_stdout.close()
                raise RedirectionError(f'Pipe process exited with code {proc.returncode} before command could run')
            else:
                redir_saved_state.redirecting = True  # type: ignore[unreachable]
                cmd_pipe_proc_reader = utils.ProcReader(proc, cast(TextIO, self.stdout), sys.stderr)
                sys.stdout = self.stdout = new_stdout

        elif statement.output:
            import tempfile

            if (not statement.output_to) and (not self._can_clip):
                raise RedirectionError("Cannot redirect to paste buffer; missing 'pyperclip' and/or pyperclip dependencies")

            # Redirecting to a file
            elif statement.output_to:
                # statement.output can only contain REDIRECTION_APPEND or REDIRECTION_OUTPUT
                mode = 'a' if statement.output == constants.REDIRECTION_APPEND else 'w'
                try:
                    # Use line buffering
                    new_stdout = cast(TextIO, open(utils.strip_quotes(statement.output_to), mode=mode, buffering=1))
                except OSError as ex:
                    raise RedirectionError(f'Failed to redirect because: {ex}')

                redir_saved_state.redirecting = True
                sys.stdout = self.stdout = new_stdout

            # Redirecting to a paste buffer
            else:
                new_stdout = cast(TextIO, tempfile.TemporaryFile(mode="w+"))
                redir_saved_state.redirecting = True
                sys.stdout = self.stdout = new_stdout

                if statement.output == constants.REDIRECTION_APPEND:
                    self.stdout.write(get_paste_buffer())
                    self.stdout.flush()

        # These are updated regardless of whether the command redirected
        self._cur_pipe_proc_reader = cmd_pipe_proc_reader
        self._redirecting = redir_saved_state.redirecting

        return redir_saved_state

    def _restore_output(self, statement: Statement, saved_redir_state: utils.RedirectionSavedState) -> None:
        """Handles restoring state after output redirection

        :param statement: Statement object which contains the parsed input from the user
        :param saved_redir_state: contains information needed to restore state data
        """
        if saved_redir_state.redirecting:
            # If we redirected output to the clipboard
            if statement.output and not statement.output_to:
                self.stdout.seek(0)
                write_to_paste_buffer(self.stdout.read())

            try:
                # Close the file or pipe that stdout was redirected to
                self.stdout.close()
            except BrokenPipeError:
                pass

            # Restore the stdout values
            self.stdout = cast(TextIO, saved_redir_state.saved_self_stdout)
            sys.stdout = cast(TextIO, saved_redir_state.saved_sys_stdout)

            # Check if we need to wait for the process being piped to
            if self._cur_pipe_proc_reader is not None:
                self._cur_pipe_proc_reader.wait()

        # These are restored regardless of whether the command redirected
        self._cur_pipe_proc_reader = saved_redir_state.saved_pipe_proc_reader
        self._redirecting = saved_redir_state.saved_redirecting

    def cmd_func(self, command: str) -> Optional[CommandFunc]:
        """
        Get the function for a command

        :param command: the name of the command

        :Example:

        >>> helpfunc = self.cmd_func('help')

        helpfunc now contains a reference to the ``do_help`` method
        """
        func_name = self._cmd_func_name(command)
        if func_name:
            return cast(Optional[CommandFunc], getattr(self, func_name))
        return None

    def _cmd_func_name(self, command: str) -> str:
        """Get the method name associated with a given command.

        :param command: command to look up method name which implements it
        :return: method name which implements the given command
        """
        target = constants.COMMAND_FUNC_PREFIX + command
        return target if callable(getattr(self, target, None)) else ''

    # noinspection PyMethodOverriding
    def onecmd(self, statement: Union[Statement, str], *, add_to_history: bool = True) -> bool:
        """This executes the actual do_* method for a command.

        If the command provided doesn't exist, then it executes default() instead.

        :param statement: intended to be a Statement instance parsed command from the input stream, alternative
                          acceptance of a str is present only for backward compatibility with cmd
        :param add_to_history: If True, then add this command to history. Defaults to True.
        :return: a flag indicating whether the interpretation of commands should stop
        """
        # For backwards compatibility with cmd, allow a str to be passed in
        if not isinstance(statement, Statement):
            statement = self._input_line_to_statement(statement)

        func = self.cmd_func(statement.command)
        if func:
            # Check to see if this command should be stored in history
            if (
                statement.command not in self.exclude_from_history
                and statement.command not in self.disabled_commands
                and add_to_history
            ):
                self.history.append(statement)

            stop = func(statement)

        else:
            stop = self.default(statement)

        return stop if stop is not None else False

    def default(self, statement: Statement) -> Optional[bool]:  # type: ignore[override]
        """Executed when the command given isn't a recognized command implemented by a do_* method.

        :param statement: Statement object with parsed input
        """
        if self.default_to_shell:
            if 'shell' not in self.exclude_from_history:
                self.history.append(statement)

            # noinspection PyTypeChecker
            return self.do_shell(statement.command_and_args)
        else:
            err_msg = self.default_error.format(statement.command)

            # Set apply_style to False so default_error's style is not overridden
            self.perror(err_msg, apply_style=False)
            return None

    def read_input(
        self,
        prompt: str,
        *,
        history: Optional[List[str]] = None,
        completion_mode: utils.CompletionMode = utils.CompletionMode.NONE,
        preserve_quotes: bool = False,
        choices: Optional[Iterable[Any]] = None,
        choices_provider: Optional[ChoicesProviderFunc] = None,
        completer: Optional[CompleterFunc] = None,
        parser: Optional[argparse.ArgumentParser] = None,
    ) -> str:
        """
        Read input from appropriate stdin value. Also supports tab completion and up-arrow history while
        input is being entered.

        :param prompt: prompt to display to user
        :param history: optional list of strings to use for up-arrow history. If completion_mode is
                        CompletionMode.COMMANDS and this is None, then cmd2's command list history will
                        be used. The passed in history will not be edited. It is the caller's responsibility
                        to add the returned input to history if desired. Defaults to None.
        :param completion_mode: tells what type of tab completion to support. Tab completion only works when
                                self.use_rawinput is True and sys.stdin is a terminal. Defaults to
                                CompletionMode.NONE.

        The following optional settings apply when completion_mode is CompletionMode.CUSTOM:

        :param preserve_quotes: if True, then quoted tokens will keep their quotes when processed by
                                ArgparseCompleter. This is helpful in cases when you're tab completing
                                flag-like tokens (e.g. -o, --option) and you don't want them to be
                                treated as argparse flags when quoted. Set this to True if you plan
                                on passing the string to argparse with the tokens still quoted.

        A maximum of one of these should be provided:

        :param choices: iterable of accepted values for single argument
        :param choices_provider: function that provides choices for single argument
        :param completer: tab completion function that provides choices for single argument
        :param parser: an argument parser which supports the tab completion of multiple arguments

        :return: the line read from stdin with all trailing new lines removed
        :raises: any exceptions raised by input() and stdin.readline()
        """
        readline_configured = False
        saved_completer: Optional[CompleterFunc] = None
        saved_history: Optional[List[str]] = None

        def configure_readline() -> None:
            """Configure readline tab completion and history"""
            nonlocal readline_configured
            nonlocal saved_completer
            nonlocal saved_history
            nonlocal parser

            if readline_configured:  # pragma: no cover
                return

            # Configure tab completion
            if self._completion_supported():
                saved_completer = readline.get_completer()

                # Disable completion
                if completion_mode == utils.CompletionMode.NONE:
                    # noinspection PyUnusedLocal
                    def complete_none(text: str, state: int) -> Optional[str]:  # pragma: no cover
                        return None

                    complete_func = complete_none

                # Complete commands
                elif completion_mode == utils.CompletionMode.COMMANDS:
                    complete_func = self.complete

                # Set custom completion settings
                else:
                    if parser is None:
                        parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(add_help=False)
                        parser.add_argument(
                            'arg',
                            suppress_tab_hint=True,
                            choices=choices,  # type: ignore[arg-type]
                            choices_provider=choices_provider,
                            completer=completer,
                        )

                    custom_settings = utils.CustomCompletionSettings(parser, preserve_quotes=preserve_quotes)
                    complete_func = functools.partial(self.complete, custom_settings=custom_settings)

                readline.set_completer(complete_func)

            # Overwrite history if not completing commands or new history was provided
            if completion_mode != utils.CompletionMode.COMMANDS or history is not None:
                saved_history = []
                for i in range(1, readline.get_current_history_length() + 1):
                    # noinspection PyArgumentList
                    saved_history.append(readline.get_history_item(i))

                readline.clear_history()
                if history is not None:
                    for item in history:
                        readline.add_history(item)

            readline_configured = True

        def restore_readline() -> None:
            """Restore readline tab completion and history"""
            nonlocal readline_configured
            if not readline_configured:  # pragma: no cover
                return

            if self._completion_supported():
                readline.set_completer(saved_completer)

            if saved_history is not None:
                readline.clear_history()
                for item in saved_history:
                    readline.add_history(item)

            readline_configured = False

        # Check we are reading from sys.stdin
        if self.use_rawinput:
            if sys.stdin.isatty():
                try:
                    # Deal with the vagaries of readline and ANSI escape codes
                    escaped_prompt = rl_escape_prompt(prompt)

                    with self.sigint_protection:
                        configure_readline()
                    line = input(escaped_prompt)
                finally:
                    with self.sigint_protection:
                        restore_readline()
            else:
                line = input()
                if self.echo:
                    sys.stdout.write(f'{prompt}{line}\n')

        # Otherwise read from self.stdin
        else:
            if self.stdin.isatty():
                # on a tty, print the prompt first, then read the line
                self.poutput(prompt, end='')
                self.stdout.flush()
                line = self.stdin.readline()
                if len(line) == 0:
                    line = 'eof'
            else:
                # we are reading from a pipe, read the line to see if there is
                # anything there, if so, then decide whether to print the
                # prompt or not
                line = self.stdin.readline()
                if len(line):
                    # we read something, output the prompt and the something
                    if self.echo:
                        self.poutput(f'{prompt}{line}')
                else:
                    line = 'eof'

        return line.rstrip('\r\n')

    def _read_command_line(self, prompt: str) -> str:
        """
        Read command line from appropriate stdin

        :param prompt: prompt to display to user
        :return: command line text of 'eof' if an EOFError was caught
        :raises: whatever exceptions are raised by input() except for EOFError
        """
        try:
            # Wrap in try since terminal_lock may not be locked
            try:
                # Command line is about to be drawn. Allow asynchronous changes to the terminal.
                self.terminal_lock.release()
            except RuntimeError:
                pass
            return self.read_input(prompt, completion_mode=utils.CompletionMode.COMMANDS)
        except EOFError:
            return 'eof'
        finally:
            # Command line is gone. Do not allow asynchronous changes to the terminal.
            self.terminal_lock.acquire()

    def _set_up_cmd2_readline(self) -> _SavedReadlineSettings:
        """
        Called at beginning of command loop to set up readline with cmd2-specific settings

        :return: Class containing saved readline settings
        """
        readline_settings = _SavedReadlineSettings()

        if self._completion_supported():

            # Set up readline for our tab completion needs
            if rl_type == RlType.GNU:
                # GNU readline automatically adds a closing quote if the text being completed has an opening quote.
                # We don't want this behavior since cmd2 only adds a closing quote when self.allow_closing_quote is True.
                # To fix this behavior, set readline's rl_basic_quote_characters to NULL. We don't need to worry about setting
                # rl_completion_suppress_quote since we never declared rl_completer_quote_characters.
                readline_settings.basic_quotes = cast(bytes, ctypes.cast(rl_basic_quote_characters, ctypes.c_void_p).value)
                rl_basic_quote_characters.value = None

            readline_settings.completer = readline.get_completer()
            readline.set_completer(self.complete)

            # Set the readline word delimiters for completion
            completer_delims = " \t\n"
            completer_delims += ''.join(constants.QUOTES)
            completer_delims += ''.join(constants.REDIRECTION_CHARS)
            completer_delims += ''.join(self.statement_parser.terminators)

            readline_settings.delims = readline.get_completer_delims()
            readline.set_completer_delims(completer_delims)

            # Enable tab completion
            readline.parse_and_bind(self.completekey + ": complete")

        return readline_settings

    def _restore_readline(self, readline_settings: _SavedReadlineSettings) -> None:
        """
        Called at end of command loop to restore saved readline settings

        :param readline_settings: the readline settings to restore
        """
        if self._completion_supported():

            # Restore what we changed in readline
            readline.set_completer(readline_settings.completer)
            readline.set_completer_delims(readline_settings.delims)

            if rl_type == RlType.GNU:
                readline.set_completion_display_matches_hook(None)
                rl_basic_quote_characters.value = readline_settings.basic_quotes
            elif rl_type == RlType.PYREADLINE:
                # noinspection PyUnresolvedReferences
                readline.rl.mode._display_completions = orig_pyreadline_display

    def _cmdloop(self) -> None:
        """Repeatedly issue a prompt, accept input, parse an initial prefix
        off the received input, and dispatch to action methods, passing them
        the remainder of the line as argument.

        This serves the same role as cmd.cmdloop().
        """
        saved_readline_settings = None

        try:
            # Get sigint protection while we set up readline for cmd2
            with self.sigint_protection:
                saved_readline_settings = self._set_up_cmd2_readline()

            # Run startup commands
            stop = self.runcmds_plus_hooks(self._startup_commands)
            self._startup_commands.clear()

            while not stop:
                # Get commands from user
                try:
                    line = self._read_command_line(self.prompt)
                except KeyboardInterrupt:
                    self.poutput('^C')
                    line = ''

                # Run the command along with all associated pre and post hooks
                stop = self.onecmd_plus_hooks(line)
        finally:
            # Get sigint protection while we restore readline settings
            with self.sigint_protection:
                if saved_readline_settings is not None:
                    self._restore_readline(saved_readline_settings)

    #############################################################
    # Parsers and functions for alias command and subcommands
    #############################################################

    # Top-level parser for alias
    alias_description = "Manage aliases\n" "\n" "An alias is a command that enables replacement of a word by another string."
    alias_epilog = "See also:\n" "  macro"
    alias_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=alias_description, epilog=alias_epilog)
    alias_subparsers = alias_parser.add_subparsers(dest='subcommand', metavar='SUBCOMMAND')
    alias_subparsers.required = True

    # Preserve quotes since we are passing strings to other commands
    @with_argparser(alias_parser, preserve_quotes=True)
    def do_alias(self, args: argparse.Namespace) -> None:
        """Manage aliases"""
        # Call handler for whatever subcommand was selected
        handler = args.cmd2_handler.get()
        handler(args)

    # alias -> create
    alias_create_description = "Create or overwrite an alias"

    alias_create_epilog = (
        "Notes:\n"
        "  If you want to use redirection, pipes, or terminators in the value of the\n"
        "  alias, then quote them.\n"
        "\n"
        "  Since aliases are resolved during parsing, tab completion will function as\n"
        "  it would for the actual command the alias resolves to.\n"
        "\n"
        "Examples:\n"
        "  alias create ls !ls -lF\n"
        "  alias create show_log !cat \"log file.txt\"\n"
        "  alias create save_results print_results \">\" out.txt\n"
    )

    alias_create_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(
        description=alias_create_description, epilog=alias_create_epilog
    )
    alias_create_parser.add_argument('name', help='name of this alias')
    alias_create_parser.add_argument(
        'command', help='what the alias resolves to', choices_provider=_get_commands_aliases_and_macros_for_completion
    )
    alias_create_parser.add_argument(
        'command_args', nargs=argparse.REMAINDER, help='arguments to pass to command', completer=path_complete
    )

    @as_subcommand_to('alias', 'create', alias_create_parser, help=alias_create_description.lower())
    def _alias_create(self, args: argparse.Namespace) -> None:
        """Create or overwrite an alias"""
        self.last_result = False

        # Validate the alias name
        valid, errmsg = self.statement_parser.is_valid_command(args.name)
        if not valid:
            self.perror(f"Invalid alias name: {errmsg}")
            return

        if args.name in self.get_all_commands():
            self.perror("Alias cannot have the same name as a command")
            return

        if args.name in self.macros:
            self.perror("Alias cannot have the same name as a macro")
            return

        # Unquote redirection and terminator tokens
        tokens_to_unquote = constants.REDIRECTION_TOKENS
        tokens_to_unquote.extend(self.statement_parser.terminators)
        utils.unquote_specific_tokens(args.command_args, tokens_to_unquote)

        # Build the alias value string
        value = args.command
        if args.command_args:
            value += ' ' + ' '.join(args.command_args)

        # Set the alias
        result = "overwritten" if args.name in self.aliases else "created"
        self.poutput(f"Alias '{args.name}' {result}")

        self.aliases[args.name] = value
        self.last_result = True

    # alias -> delete
    alias_delete_help = "delete aliases"
    alias_delete_description = "Delete specified aliases or all aliases if --all is used"

    alias_delete_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=alias_delete_description)
    alias_delete_parser.add_argument('-a', '--all', action='store_true', help="delete all aliases")
    alias_delete_parser.add_argument(
        'names',
        nargs=argparse.ZERO_OR_MORE,
        help='alias(es) to delete',
        choices_provider=_get_alias_completion_items,
        descriptive_header=_alias_completion_table.generate_header(),
    )

    @as_subcommand_to('alias', 'delete', alias_delete_parser, help=alias_delete_help)
    def _alias_delete(self, args: argparse.Namespace) -> None:
        """Delete aliases"""
        self.last_result = True

        if args.all:
            self.aliases.clear()
            self.poutput("All aliases deleted")
        elif not args.names:
            self.perror("Either --all or alias name(s) must be specified")
            self.last_result = False
        else:
            for cur_name in utils.remove_duplicates(args.names):
                if cur_name in self.aliases:
                    del self.aliases[cur_name]
                    self.poutput(f"Alias '{cur_name}' deleted")
                else:
                    self.perror(f"Alias '{cur_name}' does not exist")

    # alias -> list
    alias_list_help = "list aliases"
    alias_list_description = (
        "List specified aliases in a reusable form that can be saved to a startup\n"
        "script to preserve aliases across sessions\n"
        "\n"
        "Without arguments, all aliases will be listed."
    )

    alias_list_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=alias_list_description)
    alias_list_parser.add_argument(
        'names',
        nargs=argparse.ZERO_OR_MORE,
        help='alias(es) to list',
        choices_provider=_get_alias_completion_items,
        descriptive_header=_alias_completion_table.generate_header(),
    )

    @as_subcommand_to('alias', 'list', alias_list_parser, help=alias_list_help)
    def _alias_list(self, args: argparse.Namespace) -> None:
        """List some or all aliases as 'alias create' commands"""
        self.last_result = {}  # Dict[alias_name, alias_value]

        tokens_to_quote = constants.REDIRECTION_TOKENS
        tokens_to_quote.extend(self.statement_parser.terminators)

        if args.names:
            to_list = utils.remove_duplicates(args.names)
        else:
            to_list = sorted(self.aliases, key=self.default_sort_key)

        not_found: List[str] = []
        for name in to_list:
            if name not in self.aliases:
                not_found.append(name)
                continue

            # Quote redirection and terminator tokens for the 'alias create' command
            tokens = shlex_split(self.aliases[name])
            command = tokens[0]
            command_args = tokens[1:]
            utils.quote_specific_tokens(command_args, tokens_to_quote)

            val = command
            if command_args:
                val += ' ' + ' '.join(command_args)

            self.poutput(f"alias create {name} {val}")
            self.last_result[name] = val

        for name in not_found:
            self.perror(f"Alias '{name}' not found")

    #############################################################
    # Parsers and functions for macro command and subcommands
    #############################################################

    # Top-level parser for macro
    macro_description = "Manage macros\n" "\n" "A macro is similar to an alias, but it can contain argument placeholders."
    macro_epilog = "See also:\n" "  alias"
    macro_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=macro_description, epilog=macro_epilog)
    macro_subparsers = macro_parser.add_subparsers(dest='subcommand', metavar='SUBCOMMAND')
    macro_subparsers.required = True

    # Preserve quotes since we are passing strings to other commands
    @with_argparser(macro_parser, preserve_quotes=True)
    def do_macro(self, args: argparse.Namespace) -> None:
        """Manage macros"""
        # Call handler for whatever subcommand was selected
        handler = args.cmd2_handler.get()
        handler(args)

    # macro -> create
    macro_create_help = "create or overwrite a macro"
    macro_create_description = "Create or overwrite a macro"

    macro_create_epilog = (
        "A macro is similar to an alias, but it can contain argument placeholders.\n"
        "Arguments are expressed when creating a macro using {#} notation where {1}\n"
        "means the first argument.\n"
        "\n"
        "The following creates a macro called my_macro that expects two arguments:\n"
        "\n"
        "  macro create my_macro make_dinner --meat {1} --veggie {2}\n"
        "\n"
        "When the macro is called, the provided arguments are resolved and the\n"
        "assembled command is run. For example:\n"
        "\n"
        "  my_macro beef broccoli ---> make_dinner --meat beef --veggie broccoli\n"
        "\n"
        "Notes:\n"
        "  To use the literal string {1} in your command, escape it this way: {{1}}.\n"
        "\n"
        "  Extra arguments passed to a macro are appended to resolved command.\n"
        "\n"
        "  An argument number can be repeated in a macro. In the following example the\n"
        "  first argument will populate both {1} instances.\n"
        "\n"
        "    macro create ft file_taxes -p {1} -q {2} -r {1}\n"
        "\n"
        "  To quote an argument in the resolved command, quote it during creation.\n"
        "\n"
        "    macro create backup !cp \"{1}\" \"{1}.orig\"\n"
        "\n"
        "  If you want to use redirection, pipes, or terminators in the value of the\n"
        "  macro, then quote them.\n"
        "\n"
        "    macro create show_results print_results -type {1} \"|\" less\n"
        "\n"
        "  Because macros do not resolve until after hitting Enter, tab completion\n"
        "  will only complete paths while typing a macro."
    )

    macro_create_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(
        description=macro_create_description, epilog=macro_create_epilog
    )
    macro_create_parser.add_argument('name', help='name of this macro')
    macro_create_parser.add_argument(
        'command', help='what the macro resolves to', choices_provider=_get_commands_aliases_and_macros_for_completion
    )
    macro_create_parser.add_argument(
        'command_args', nargs=argparse.REMAINDER, help='arguments to pass to command', completer=path_complete
    )

    @as_subcommand_to('macro', 'create', macro_create_parser, help=macro_create_help)
    def _macro_create(self, args: argparse.Namespace) -> None:
        """Create or overwrite a macro"""
        self.last_result = False

        # Validate the macro name
        valid, errmsg = self.statement_parser.is_valid_command(args.name)
        if not valid:
            self.perror(f"Invalid macro name: {errmsg}")
            return

        if args.name in self.get_all_commands():
            self.perror("Macro cannot have the same name as a command")
            return

        if args.name in self.aliases:
            self.perror("Macro cannot have the same name as an alias")
            return

        # Unquote redirection and terminator tokens
        tokens_to_unquote = constants.REDIRECTION_TOKENS
        tokens_to_unquote.extend(self.statement_parser.terminators)
        utils.unquote_specific_tokens(args.command_args, tokens_to_unquote)

        # Build the macro value string
        value = args.command
        if args.command_args:
            value += ' ' + ' '.join(args.command_args)

        # Find all normal arguments
        arg_list = []
        normal_matches = re.finditer(MacroArg.macro_normal_arg_pattern, value)
        max_arg_num = 0
        arg_nums = set()

        while True:
            try:
                cur_match = normal_matches.__next__()

                # Get the number string between the braces
                cur_num_str = re.findall(MacroArg.digit_pattern, cur_match.group())[0]
                cur_num = int(cur_num_str)
                if cur_num < 1:
                    self.perror("Argument numbers must be greater than 0")
                    return

                arg_nums.add(cur_num)
                if cur_num > max_arg_num:
                    max_arg_num = cur_num

                arg_list.append(MacroArg(start_index=cur_match.start(), number_str=cur_num_str, is_escaped=False))

            except StopIteration:
                break

        # Make sure the argument numbers are continuous
        if len(arg_nums) != max_arg_num:
            self.perror(f"Not all numbers between 1 and {max_arg_num} are present in the argument placeholders")
            return

        # Find all escaped arguments
        escaped_matches = re.finditer(MacroArg.macro_escaped_arg_pattern, value)

        while True:
            try:
                cur_match = escaped_matches.__next__()

                # Get the number string between the braces
                cur_num_str = re.findall(MacroArg.digit_pattern, cur_match.group())[0]

                arg_list.append(MacroArg(start_index=cur_match.start(), number_str=cur_num_str, is_escaped=True))
            except StopIteration:
                break

        # Set the macro
        result = "overwritten" if args.name in self.macros else "created"
        self.poutput(f"Macro '{args.name}' {result}")

        self.macros[args.name] = Macro(name=args.name, value=value, minimum_arg_count=max_arg_num, arg_list=arg_list)
        self.last_result = True

    # macro -> delete
    macro_delete_help = "delete macros"
    macro_delete_description = "Delete specified macros or all macros if --all is used"
    macro_delete_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=macro_delete_description)
    macro_delete_parser.add_argument('-a', '--all', action='store_true', help="delete all macros")
    macro_delete_parser.add_argument(
        'names',
        nargs=argparse.ZERO_OR_MORE,
        help='macro(s) to delete',
        choices_provider=_get_macro_completion_items,
        descriptive_header=_macro_completion_table.generate_header(),
    )

    @as_subcommand_to('macro', 'delete', macro_delete_parser, help=macro_delete_help)
    def _macro_delete(self, args: argparse.Namespace) -> None:
        """Delete macros"""
        self.last_result = True

        if args.all:
            self.macros.clear()
            self.poutput("All macros deleted")
        elif not args.names:
            self.perror("Either --all or macro name(s) must be specified")
            self.last_result = False
        else:
            for cur_name in utils.remove_duplicates(args.names):
                if cur_name in self.macros:
                    del self.macros[cur_name]
                    self.poutput(f"Macro '{cur_name}' deleted")
                else:
                    self.perror(f"Macro '{cur_name}' does not exist")

    # macro -> list
    macro_list_help = "list macros"
    macro_list_description = (
        "List specified macros in a reusable form that can be saved to a startup script\n"
        "to preserve macros across sessions\n"
        "\n"
        "Without arguments, all macros will be listed."
    )

    macro_list_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=macro_list_description)
    macro_list_parser.add_argument(
        'names',
        nargs=argparse.ZERO_OR_MORE,
        help='macro(s) to list',
        choices_provider=_get_macro_completion_items,
        descriptive_header=_macro_completion_table.generate_header(),
    )

    @as_subcommand_to('macro', 'list', macro_list_parser, help=macro_list_help)
    def _macro_list(self, args: argparse.Namespace) -> None:
        """List some or all macros as 'macro create' commands"""
        self.last_result = {}  # Dict[macro_name, macro_value]

        tokens_to_quote = constants.REDIRECTION_TOKENS
        tokens_to_quote.extend(self.statement_parser.terminators)

        if args.names:
            to_list = utils.remove_duplicates(args.names)
        else:
            to_list = sorted(self.macros, key=self.default_sort_key)

        not_found: List[str] = []
        for name in to_list:
            if name not in self.macros:
                not_found.append(name)
                continue

            # Quote redirection and terminator tokens for the 'macro create' command
            tokens = shlex_split(self.macros[name].value)
            command = tokens[0]
            command_args = tokens[1:]
            utils.quote_specific_tokens(command_args, tokens_to_quote)

            val = command
            if command_args:
                val += ' ' + ' '.join(command_args)

            self.poutput(f"macro create {name} {val}")
            self.last_result[name] = val

        for name in not_found:
            self.perror(f"Macro '{name}' not found")

    def complete_help_command(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Completes the command argument of help"""

        # Complete token against topics and visible commands
        topics = set(self.get_help_topics())
        visible_commands = set(self.get_visible_commands())
        strs_to_match = list(topics | visible_commands)
        return self.basic_complete(text, line, begidx, endidx, strs_to_match)

    def complete_help_subcommands(
        self, text: str, line: str, begidx: int, endidx: int, arg_tokens: Dict[str, List[str]]
    ) -> List[str]:
        """Completes the subcommands argument of help"""

        # Make sure we have a command whose subcommands we will complete
        command = arg_tokens['command'][0]
        if not command:
            return []

        # Check if this command uses argparse
        func = self.cmd_func(command)
        argparser = getattr(func, constants.CMD_ATTR_ARGPARSER, None)
        if func is None or argparser is None:
            return []

        completer = argparse_completer.DEFAULT_AP_COMPLETER(argparser, self)
        return completer.complete_subcommand_help(text, line, begidx, endidx, arg_tokens['subcommands'])

    help_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(
        description="List available commands or provide " "detailed help for a specific command"
    )
    help_parser.add_argument(
        '-v', '--verbose', action='store_true', help="print a list of all commands with descriptions of each"
    )
    help_parser.add_argument(
        'command', nargs=argparse.OPTIONAL, help="command to retrieve help for", completer=complete_help_command
    )
    help_parser.add_argument(
        'subcommands', nargs=argparse.REMAINDER, help="subcommand(s) to retrieve help for", completer=complete_help_subcommands
    )

    # Get rid of cmd's complete_help() functions so ArgparseCompleter will complete the help command
    if getattr(cmd.Cmd, 'complete_help', None) is not None:
        delattr(cmd.Cmd, 'complete_help')

    @with_argparser(help_parser)
    def do_help(self, args: argparse.Namespace) -> None:
        """List available commands or provide detailed help for a specific command"""
        self.last_result = True

        if not args.command or args.verbose:
            self._help_menu(args.verbose)

        else:
            # Getting help for a specific command
            func = self.cmd_func(args.command)
            help_func = getattr(self, constants.HELP_FUNC_PREFIX + args.command, None)
            argparser = getattr(func, constants.CMD_ATTR_ARGPARSER, None)

            # If the command function uses argparse, then use argparse's help
            if func is not None and argparser is not None:
                completer = argparse_completer.DEFAULT_AP_COMPLETER(argparser, self)

                # Set end to blank so the help output matches how it looks when "command -h" is used
                self.poutput(completer.format_help(args.subcommands), end='')

            # If there is a help func delegate to do_help
            elif help_func is not None:
                super().do_help(args.command)

            # If there's no help_func __doc__ then format and output it
            elif func is not None and func.__doc__ is not None:
                self.poutput(pydoc.getdoc(func))

            # If there is no help information then print an error
            else:
                err_msg = self.help_error.format(args.command)

                # Set apply_style to False so help_error's style is not overridden
                self.perror(err_msg, apply_style=False)
                self.last_result = False

    def print_topics(self, header: str, cmds: Optional[List[str]], cmdlen: int, maxcol: int) -> None:
        """
        Print groups of commands and topics in columns and an optional header
        Override of cmd's print_topics() to handle headers with newlines, ANSI style sequences, and wide characters

        :param header: string to print above commands being printed
        :param cmds: list of topics to print
        :param cmdlen: unused, even by cmd's version
        :param maxcol: max number of display columns to fit into
        """
        if cmds:
            self.poutput(header)
            if self.ruler:
                divider = utils.align_left('', fill_char=self.ruler, width=ansi.widest_line(header))
                self.poutput(divider)
            self.columnize(cmds, maxcol - 1)
            self.poutput()

    def columnize(self, str_list: Optional[List[str]], display_width: int = 80) -> None:
        """Display a list of single-line strings as a compact set of columns.
        Override of cmd's print_topics() to handle strings with ANSI style sequences and wide characters

        Each column is only as wide as necessary.
        Columns are separated by two spaces (one was not legible enough).
        """
        if not str_list:
            self.poutput("<empty>")
            return

        nonstrings = [i for i in range(len(str_list)) if not isinstance(str_list[i], str)]
        if nonstrings:
            raise TypeError(f"str_list[i] not a string for i in {nonstrings}")
        size = len(str_list)
        if size == 1:
            self.poutput(str_list[0])
            return
        # Try every row count from 1 upwards
        for nrows in range(1, len(str_list)):
            ncols = (size + nrows - 1) // nrows
            colwidths = []
            totwidth = -2
            for col in range(ncols):
                colwidth = 0
                for row in range(nrows):
                    i = row + nrows * col
                    if i >= size:
                        break
                    x = str_list[i]
                    colwidth = max(colwidth, ansi.style_aware_wcswidth(x))
                colwidths.append(colwidth)
                totwidth += colwidth + 2
                if totwidth > display_width:
                    break
            if totwidth <= display_width:
                break
        else:
            # The output is wider than display_width. Print 1 column with each string on its own row.
            nrows = len(str_list)
            ncols = 1
            colwidths = [1]
        for row in range(nrows):
            texts = []
            for col in range(ncols):
                i = row + nrows * col
                if i >= size:
                    x = ""
                else:
                    x = str_list[i]
                texts.append(x)
            while texts and not texts[-1]:
                del texts[-1]
            for col in range(len(texts)):
                texts[col] = utils.align_left(texts[col], width=colwidths[col])
            self.poutput("  ".join(texts))

    def _help_menu(self, verbose: bool = False) -> None:
        """Show a list of commands which help can be displayed for"""
        cmds_cats, cmds_doc, cmds_undoc, help_topics = self._build_command_info()

        if not cmds_cats:
            # No categories found, fall back to standard behavior
            self.poutput(self.doc_leader)
            self._print_topics(self.doc_header, cmds_doc, verbose)
        else:
            # Categories found, Organize all commands by category
            self.poutput(self.doc_leader)
            self.poutput(self.doc_header, end="\n\n")
            for category in sorted(cmds_cats.keys(), key=self.default_sort_key):
                self._print_topics(category, cmds_cats[category], verbose)
            self._print_topics(self.default_category, cmds_doc, verbose)

        self.print_topics(self.misc_header, help_topics, 15, 80)
        self.print_topics(self.undoc_header, cmds_undoc, 15, 80)

    def _build_command_info(self) -> Tuple[Dict[str, List[str]], List[str], List[str], List[str]]:
        # Get a sorted list of help topics
        help_topics = sorted(self.get_help_topics(), key=self.default_sort_key)
        # Get a sorted list of visible command names
        visible_commands = sorted(self.get_visible_commands(), key=self.default_sort_key)
        cmds_doc: List[str] = []
        cmds_undoc: List[str] = []
        cmds_cats: Dict[str, List[str]] = {}
        for command in visible_commands:
            func = self.cmd_func(command)
            has_help_func = False

            if command in help_topics:
                # Prevent the command from showing as both a command and help topic in the output
                help_topics.remove(command)

                # Non-argparse commands can have help_functions for their documentation
                if not hasattr(func, constants.CMD_ATTR_ARGPARSER):
                    has_help_func = True

            if hasattr(func, constants.CMD_ATTR_HELP_CATEGORY):
                category: str = getattr(func, constants.CMD_ATTR_HELP_CATEGORY)
                cmds_cats.setdefault(category, [])
                cmds_cats[category].append(command)
            elif func.__doc__ or has_help_func:
                cmds_doc.append(command)
            else:
                cmds_undoc.append(command)
        return cmds_cats, cmds_doc, cmds_undoc, help_topics

    def _print_topics(self, header: str, cmds: List[str], verbose: bool) -> None:
        """Customized version of print_topics that can switch between verbose or traditional output"""
        import io

        if cmds:
            if not verbose:
                self.print_topics(header, cmds, 15, 80)
            else:
                # Find the widest command
                widest = max([ansi.style_aware_wcswidth(command) for command in cmds])

                # Define the table structure
                name_column = Column('', width=max(widest, 20))
                desc_column = Column('', width=80)

                topic_table = SimpleTable([name_column, desc_column], divider_char=self.ruler)

                # Build the topic table
                table_str_buf = io.StringIO()
                if header:
                    table_str_buf.write(header + "\n")

                divider = topic_table.generate_divider()
                if divider:
                    table_str_buf.write(divider + "\n")

                # Try to get the documentation string for each command
                topics = self.get_help_topics()
                for command in cmds:
                    cmd_func = self.cmd_func(command)
                    doc: Optional[str]

                    # Non-argparse commands can have help_functions for their documentation
                    if not hasattr(cmd_func, constants.CMD_ATTR_ARGPARSER) and command in topics:
                        help_func = getattr(self, constants.HELP_FUNC_PREFIX + command)
                        result = io.StringIO()

                        # try to redirect system stdout
                        with redirect_stdout(result):
                            # save our internal stdout
                            stdout_orig = self.stdout
                            try:
                                # redirect our internal stdout
                                self.stdout = cast(TextIO, result)
                                help_func()
                            finally:
                                # restore internal stdout
                                self.stdout = stdout_orig
                        doc = result.getvalue()

                    else:
                        doc = cmd_func.__doc__

                    # Attempt to locate the first documentation block
                    cmd_desc = strip_doc_annotations(doc) if doc else ''

                    # Add this command to the table
                    table_row = topic_table.generate_data_row([command, cmd_desc])
                    table_str_buf.write(table_row + '\n')

                self.poutput(table_str_buf.getvalue())

    shortcuts_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description="List available shortcuts")

    @with_argparser(shortcuts_parser)
    def do_shortcuts(self, _: argparse.Namespace) -> None:
        """List available shortcuts"""
        # Sort the shortcut tuples by name
        sorted_shortcuts = sorted(self.statement_parser.shortcuts, key=lambda x: self.default_sort_key(x[0]))
        result = "\n".join('{}: {}'.format(sc[0], sc[1]) for sc in sorted_shortcuts)
        self.poutput(f"Shortcuts for other commands:\n{result}")
        self.last_result = True

    eof_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(
        description="Called when Ctrl-D is pressed", epilog=INTERNAL_COMMAND_EPILOG
    )

    @with_argparser(eof_parser)
    def do_eof(self, _: argparse.Namespace) -> Optional[bool]:
        """
        Called when Ctrl-D is pressed and calls quit with no arguments.
        This can be overridden if quit should be called differently.
        """
        self.poutput()

        # self.last_result will be set by do_quit()
        # noinspection PyTypeChecker
        return self.do_quit('')

    quit_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description="Exit this application")

    @with_argparser(quit_parser)
    def do_quit(self, _: argparse.Namespace) -> Optional[bool]:
        """Exit this application"""
        # Return True to stop the command loop
        self.last_result = True
        return True

    def select(self, opts: Union[str, List[str], List[Tuple[Any, Optional[str]]]], prompt: str = 'Your choice? ') -> Any:
        """Presents a numbered menu to the user.  Modeled after
        the bash shell's SELECT.  Returns the item chosen.

        Argument ``opts`` can be:

          | a single string -> will be split into one-word options
          | a list of strings -> will be offered as options
          | a list of tuples -> interpreted as (value, text), so
                                that the return value can differ from
                                the text advertised to the user"""
        local_opts: Union[List[str], List[Tuple[Any, Optional[str]]]]
        if isinstance(opts, str):
            local_opts = cast(List[Tuple[Any, Optional[str]]], list(zip(opts.split(), opts.split())))
        else:
            local_opts = opts
        fulloptions: List[Tuple[Any, Optional[str]]] = []
        for opt in local_opts:
            if isinstance(opt, str):
                fulloptions.append((opt, opt))
            else:
                try:
                    fulloptions.append((opt[0], opt[1]))
                except IndexError:
                    fulloptions.append((opt[0], opt[0]))
        for (idx, (_, text)) in enumerate(fulloptions):
            self.poutput('  %2d. %s' % (idx + 1, text))

        while True:
            try:
                response = self.read_input(prompt)
            except EOFError:
                response = ''
                self.poutput()
            except KeyboardInterrupt as ex:
                self.poutput('^C')
                raise ex

            if not response:
                continue

            try:
                choice = int(response)
                if choice < 1:
                    raise IndexError
                return fulloptions[choice - 1][0]
            except (ValueError, IndexError):
                self.poutput(f"'{response}' isn't a valid choice. Pick a number between 1 and {len(fulloptions)}:")

    def complete_set_value(
        self, text: str, line: str, begidx: int, endidx: int, arg_tokens: Dict[str, List[str]]
    ) -> List[str]:
        """Completes the value argument of set"""
        param = arg_tokens['param'][0]
        try:
            settable = self.settables[param]
        except KeyError:
            raise CompletionError(param + " is not a settable parameter")

        # Create a parser with a value field based on this settable
        settable_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(parents=[Cmd.set_parser_parent])

        # Settables with choices list the values of those choices instead of the arg name
        # in help text and this shows in tab completion hints. Set metavar to avoid this.
        arg_name = 'value'
        settable_parser.add_argument(
            arg_name,
            metavar=arg_name,
            help=settable.description,
            choices=settable.choices,  # type: ignore[arg-type]
            choices_provider=settable.choices_provider,
            completer=settable.completer,
        )

        completer = argparse_completer.DEFAULT_AP_COMPLETER(settable_parser, self)

        # Use raw_tokens since quotes have been preserved
        _, raw_tokens = self.tokens_for_completion(line, begidx, endidx)
        return completer.complete(text, line, begidx, endidx, raw_tokens[1:])

    # When tab completing value, we recreate the set command parser with a value argument specific to
    # the settable being edited. To make this easier, define a parent parser with all the common elements.
    set_description = (
        "Set a settable parameter or show current settings of parameters\n"
        "Call without arguments for a list of all settable parameters with their values.\n"
        "Call with just param to view that parameter's value."
    )
    set_parser_parent = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=set_description, add_help=False)
    set_parser_parent.add_argument(
        'param',
        nargs=argparse.OPTIONAL,
        help='parameter to set or view',
        choices_provider=_get_settable_completion_items,
        descriptive_header=_settable_completion_table.generate_header(),
    )

    # Create the parser for the set command
    set_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(parents=[set_parser_parent])
    set_parser.add_argument(
        'value', nargs=argparse.OPTIONAL, help='new value for settable', completer=complete_set_value, suppress_tab_hint=True
    )

    # Preserve quotes so users can pass in quoted empty strings and flags (e.g. -h) as the value
    @with_argparser(set_parser, preserve_quotes=True)
    def do_set(self, args: argparse.Namespace) -> None:
        """Set a settable parameter or show current settings of parameters"""
        self.last_result = False

        if not self.settables:
            self.pwarning("There are no settable parameters")
            return

        if args.param:
            try:
                settable = self.settables[args.param]
            except KeyError:
                self.perror(f"Parameter '{args.param}' not supported (type 'set' for list of parameters).")
                return

            if args.value:
                # Try to update the settable's value
                try:
                    orig_value = settable.get_value()
                    new_value = settable.set_value(utils.strip_quotes(args.value))
                # noinspection PyBroadException
                except Exception as ex:
                    self.perror(f"Error setting {args.param}: {ex}")
                else:
                    self.poutput(f"{args.param} - was: {orig_value!r}\nnow: {new_value!r}")
                    self.last_result = True
                return

            # Show one settable
            to_show = [args.param]
        else:
            # Show all settables
            to_show = list(self.settables.keys())

        # Define the table structure
        name_label = 'Name'
        max_name_width = max([ansi.style_aware_wcswidth(param) for param in to_show])
        max_name_width = max(max_name_width, ansi.style_aware_wcswidth(name_label))

        cols: List[Column] = [
            Column(name_label, width=max_name_width),
            Column('Value', width=30),
            Column('Description', width=60),
        ]

        table = SimpleTable(cols, divider_char=self.ruler)
        self.poutput(table.generate_header())

        # Build the table and populate self.last_result
        self.last_result = {}  # Dict[settable_name, settable_value]

        for param in sorted(to_show, key=self.default_sort_key):
            settable = self.settables[param]
            row_data = [param, settable.get_value(), settable.description]
            self.poutput(table.generate_data_row(row_data))
            self.last_result[param] = settable.get_value()

    shell_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description="Execute a command as if at the OS prompt")
    shell_parser.add_argument('command', help='the command to run', completer=shell_cmd_complete)
    shell_parser.add_argument(
        'command_args', nargs=argparse.REMAINDER, help='arguments to pass to command', completer=path_complete
    )

    # Preserve quotes since we are passing these strings to the shell
    @with_argparser(shell_parser, preserve_quotes=True)
    def do_shell(self, args: argparse.Namespace) -> None:
        """Execute a command as if at the OS prompt"""
        import signal
        import subprocess

        kwargs: Dict[str, Any] = dict()

        # Set OS-specific parameters
        if sys.platform.startswith('win'):
            # Windows returns STATUS_CONTROL_C_EXIT when application stopped by Ctrl-C
            ctrl_c_ret_code = 0xC000013A
        else:
            # On POSIX, Popen() returns -SIGINT when application stopped by Ctrl-C
            ctrl_c_ret_code = signal.SIGINT.value * -1

            # On POSIX with shell=True, Popen() defaults to /bin/sh as the shell.
            # sh reports an incorrect return code for some applications when Ctrl-C is pressed within that
            # application (e.g. less). Since sh received the SIGINT, it sets the return code to reflect being
            # closed by SIGINT even though less did not exit upon a Ctrl-C press. In the same situation, other
            # shells like bash and zsh report the actual return code of less. Therefore, we will try to run the
            # user's preferred shell which most likely will be something other than sh. This also allows the user
            # to run builtin commands of their preferred shell.
            shell = os.environ.get("SHELL")
            if shell:
                kwargs['executable'] = shell

        # Create a list of arguments to shell
        tokens = [args.command] + args.command_args

        # Expand ~ where needed
        utils.expand_user_in_tokens(tokens)
        expanded_command = ' '.join(tokens)

        # Prevent KeyboardInterrupts while in the shell process. The shell process will
        # still receive the SIGINT since it is in the same process group as us.
        with self.sigint_protection:
            # For any stream that is a StdSim, we will use a pipe so we can capture its output
            proc = subprocess.Popen(  # type: ignore[call-overload]
                expanded_command,
                stdout=subprocess.PIPE if isinstance(self.stdout, utils.StdSim) else self.stdout,  # type: ignore[unreachable]
                stderr=subprocess.PIPE if isinstance(sys.stderr, utils.StdSim) else sys.stderr,  # type: ignore[unreachable]
                shell=True,
                **kwargs,
            )

            proc_reader = utils.ProcReader(proc, cast(TextIO, self.stdout), sys.stderr)  # type: ignore[arg-type]
            proc_reader.wait()

            # Save the return code of the application for use in a pyscript
            self.last_result = proc.returncode

            # If the process was stopped by Ctrl-C, then inform the caller by raising a KeyboardInterrupt.
            # This is to support things like stop_on_keyboard_interrupt in runcmds_plus_hooks().
            if proc.returncode == ctrl_c_ret_code:
                self._raise_keyboard_interrupt()

    @staticmethod
    def _reset_py_display() -> None:
        """
        Resets the dynamic objects in the sys module that the py and ipy consoles fight over.
        When a Python console starts it adopts certain display settings if they've already been set.
        If an ipy console has previously been run, then py uses its settings and ends up looking
        like an ipy console in terms of prompt and exception text. This method forces the Python
        console to create its own display settings since they won't exist.

        IPython does not have this problem since it always overwrites the display settings when it
        is run. Therefore, this method only needs to be called before creating a Python console.
        """
        # Delete any prompts that have been set
        attributes = ['ps1', 'ps2', 'ps3']
        for cur_attr in attributes:
            try:
                del sys.__dict__[cur_attr]
            except KeyError:
                pass

        # Reset functions
        sys.displayhook = sys.__displayhook__
        sys.excepthook = sys.__excepthook__

    def _set_up_py_shell_env(self, interp: InteractiveConsole) -> _SavedCmd2Env:
        """
        Set up interactive Python shell environment
        :return: Class containing saved up cmd2 environment
        """
        cmd2_env = _SavedCmd2Env()

        # Set up readline for Python shell
        if rl_type != RlType.NONE:
            # Save cmd2 history
            for i in range(1, readline.get_current_history_length() + 1):
                # noinspection PyArgumentList
                cmd2_env.history.append(readline.get_history_item(i))

            readline.clear_history()

            # Restore py's history
            for item in self._py_history:
                readline.add_history(item)

            if self._completion_supported():
                # Set up tab completion for the Python console
                # rlcompleter relies on the default settings of the Python readline module
                if rl_type == RlType.GNU:
                    cmd2_env.readline_settings.basic_quotes = cast(
                        bytes, ctypes.cast(rl_basic_quote_characters, ctypes.c_void_p).value
                    )
                    rl_basic_quote_characters.value = orig_rl_basic_quotes

                    if 'gnureadline' in sys.modules:
                        # rlcompleter imports readline by name, so it won't use gnureadline
                        # Force rlcompleter to use gnureadline instead so it has our settings and history
                        if 'readline' in sys.modules:
                            cmd2_env.readline_module = sys.modules['readline']

                        sys.modules['readline'] = sys.modules['gnureadline']

                cmd2_env.readline_settings.delims = readline.get_completer_delims()
                readline.set_completer_delims(orig_rl_delims)

                # rlcompleter will not need cmd2's custom display function
                # This will be restored by cmd2 the next time complete() is called
                if rl_type == RlType.GNU:
                    readline.set_completion_display_matches_hook(None)
                elif rl_type == RlType.PYREADLINE:
                    # noinspection PyUnresolvedReferences
                    readline.rl.mode._display_completions = orig_pyreadline_display

                # Save off the current completer and set a new one in the Python console
                # Make sure it tab completes from its locals() dictionary
                cmd2_env.readline_settings.completer = readline.get_completer()
                interp.runcode("from rlcompleter import Completer")  # type: ignore[arg-type]
                interp.runcode("import readline")  # type: ignore[arg-type]
                interp.runcode("readline.set_completer(Completer(locals()).complete)")  # type: ignore[arg-type]

        # Set up sys module for the Python console
        self._reset_py_display()

        cmd2_env.sys_stdout = sys.stdout
        sys.stdout = self.stdout  # type: ignore[assignment]

        cmd2_env.sys_stdin = sys.stdin
        sys.stdin = self.stdin  # type: ignore[assignment]

        return cmd2_env

    def _restore_cmd2_env(self, cmd2_env: _SavedCmd2Env) -> None:
        """
        Restore cmd2 environment after exiting an interactive Python shell

        :param cmd2_env: the environment settings to restore
        """
        sys.stdout = cmd2_env.sys_stdout  # type: ignore[assignment]
        sys.stdin = cmd2_env.sys_stdin  # type: ignore[assignment]

        # Set up readline for cmd2
        if rl_type != RlType.NONE:
            # Save py's history
            self._py_history.clear()
            for i in range(1, readline.get_current_history_length() + 1):
                # noinspection PyArgumentList
                self._py_history.append(readline.get_history_item(i))

            readline.clear_history()

            # Restore cmd2's history
            for item in cmd2_env.history:
                readline.add_history(item)

            if self._completion_supported():
                # Restore cmd2's tab completion settings
                readline.set_completer(cmd2_env.readline_settings.completer)
                readline.set_completer_delims(cmd2_env.readline_settings.delims)

                if rl_type == RlType.GNU:
                    rl_basic_quote_characters.value = cmd2_env.readline_settings.basic_quotes

                    if 'gnureadline' in sys.modules:
                        # Restore what the readline module pointed to
                        if cmd2_env.readline_module is None:
                            del sys.modules['readline']
                        else:
                            sys.modules['readline'] = cmd2_env.readline_module

    def _run_python(self, *, pyscript: Optional[str] = None) -> Optional[bool]:
        """
        Called by do_py() and do_run_pyscript().
        If pyscript is None, then this function runs an interactive Python shell.
        Otherwise, it runs the pyscript file.

        :param pyscript: optional path to a pyscript file to run. This is intended only to be used by do_run_pyscript()
                         after it sets up sys.argv for the script. (Defaults to None)
        :return: True if running of commands should stop
        """
        self.last_result = False

        def py_quit() -> None:
            """Function callable from the interactive Python console to exit that environment"""
            raise EmbeddedConsoleExit

        from .py_bridge import (
            PyBridge,
        )

        py_bridge = PyBridge(self)
        saved_sys_path = None

        if self.in_pyscript():
            self.perror("Recursively entering interactive Python shells is not allowed")
            return None

        try:
            self._in_py = True
            py_code_to_run = ''

            # Make a copy of self.py_locals for the locals dictionary in the Python environment we are creating.
            # This is to prevent pyscripts from editing it. (e.g. locals().clear()). It also ensures a pyscript's
            # environment won't be filled with data from a previously run pyscript. Only make a shallow copy since
            # it's OK for py_locals to contain objects which are editable in a pyscript.
            local_vars = self.py_locals.copy()
            local_vars[self.py_bridge_name] = py_bridge
            local_vars['quit'] = py_quit
            local_vars['exit'] = py_quit

            if self.self_in_py:
                local_vars['self'] = self

            # Handle case where we were called by do_run_pyscript()
            if pyscript is not None:
                # Read the script file
                expanded_filename = os.path.expanduser(pyscript)

                try:
                    with open(expanded_filename) as f:
                        py_code_to_run = f.read()
                except OSError as ex:
                    self.perror(f"Error reading script file '{expanded_filename}': {ex}")
                    return None

                local_vars['__name__'] = '__main__'
                local_vars['__file__'] = expanded_filename

                # Place the script's directory at sys.path[0] just as Python does when executing a script
                saved_sys_path = list(sys.path)
                sys.path.insert(0, os.path.dirname(os.path.abspath(expanded_filename)))

            else:
                # This is the default name chosen by InteractiveConsole when no locals are passed in
                local_vars['__name__'] = '__console__'

            # Create the Python interpreter
            self.last_result = True
            interp = InteractiveConsole(locals=local_vars)

            # Check if we are running Python code
            if py_code_to_run:
                # noinspection PyBroadException
                try:
                    interp.runcode(py_code_to_run)  # type: ignore[arg-type]
                except BaseException:
                    # We don't care about any exception that happened in the Python code
                    pass

            # Otherwise we will open an interactive Python shell
            else:
                cprt = 'Type "help", "copyright", "credits" or "license" for more information.'
                instructions = (
                    'Use `Ctrl-D` (Unix) / `Ctrl-Z` (Windows), `quit()`, `exit()` to exit.\n'
                    f'Run CLI commands with: {self.py_bridge_name}("command ...")'
                )
                banner = f"Python {sys.version} on {sys.platform}\n{cprt}\n\n{instructions}\n"

                saved_cmd2_env = None

                # noinspection PyBroadException
                try:
                    # Get sigint protection while we set up the Python shell environment
                    with self.sigint_protection:
                        saved_cmd2_env = self._set_up_py_shell_env(interp)

                    # Since quit() or exit() raise an EmbeddedConsoleExit, interact() exits before printing
                    # the exitmsg. Therefore, we will not provide it one and print it manually later.
                    interp.interact(banner=banner, exitmsg='')
                except BaseException:
                    # We don't care about any exception that happened in the interactive console
                    pass
                finally:
                    # Get sigint protection while we restore cmd2 environment settings
                    with self.sigint_protection:
                        if saved_cmd2_env is not None:
                            self._restore_cmd2_env(saved_cmd2_env)
                    self.poutput("Now exiting Python shell...")

        finally:
            with self.sigint_protection:
                if saved_sys_path is not None:
                    sys.path = saved_sys_path
                self._in_py = False

        return py_bridge.stop

    py_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description="Run an interactive Python shell")

    @with_argparser(py_parser)
    def do_py(self, _: argparse.Namespace) -> Optional[bool]:
        """
        Run an interactive Python shell
        :return: True if running of commands should stop
        """
        # self.last_resort will be set by _run_python()
        return self._run_python()

    run_pyscript_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description="Run a Python script file inside the console")
    run_pyscript_parser.add_argument('script_path', help='path to the script file', completer=path_complete)
    run_pyscript_parser.add_argument(
        'script_arguments', nargs=argparse.REMAINDER, help='arguments to pass to script', completer=path_complete
    )

    @with_argparser(run_pyscript_parser)
    def do_run_pyscript(self, args: argparse.Namespace) -> Optional[bool]:
        """
        Run a Python script file inside the console

        :return: True if running of commands should stop
        """
        self.last_result = False

        # Expand ~ before placing this path in sys.argv just as a shell would
        args.script_path = os.path.expanduser(args.script_path)

        # Add some protection against accidentally running a non-Python file. The happens when users
        # mix up run_script and run_pyscript.
        if not args.script_path.endswith('.py'):
            self.pwarning(f"'{args.script_path}' does not have a .py extension")
            selection = self.select('Yes No', 'Continue to try to run it as a Python script? ')
            if selection != 'Yes':
                return None

        # Save current command line arguments
        orig_args = sys.argv

        try:
            # Overwrite sys.argv to allow the script to take command line arguments
            sys.argv = [args.script_path] + args.script_arguments

            # self.last_resort will be set by _run_python()
            py_return = self._run_python(pyscript=args.script_path)
        finally:
            # Restore command line arguments to original state
            sys.argv = orig_args

        return py_return

    ipython_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description="Run an interactive IPython shell")

    # noinspection PyPackageRequirements
    @with_argparser(ipython_parser)
    def do_ipy(self, _: argparse.Namespace) -> Optional[bool]:  # pragma: no cover
        """
        Enter an interactive IPython shell

        :return: True if running of commands should stop
        """
        self.last_result = False

        # Detect whether IPython is installed
        try:
            import traitlets.config.loader as TraitletsLoader  # type: ignore[import]
            from IPython import (  # type: ignore[import]
                start_ipython,
            )
            from IPython.terminal.interactiveshell import (  # type: ignore[import]
                TerminalInteractiveShell,
            )
            from IPython.terminal.ipapp import (  # type: ignore[import]
                TerminalIPythonApp,
            )
        except ImportError:
            self.perror("IPython package is not installed")
            return None

        from .py_bridge import (
            PyBridge,
        )

        if self.in_pyscript():
            self.perror("Recursively entering interactive Python shells is not allowed")
            return None

        self.last_result = True

        try:
            self._in_py = True
            py_bridge = PyBridge(self)

            # Make a copy of self.py_locals for the locals dictionary in the IPython environment we are creating.
            # This is to prevent ipy from editing it. (e.g. locals().clear()). Only make a shallow copy since
            # it's OK for py_locals to contain objects which are editable in ipy.
            local_vars = self.py_locals.copy()
            local_vars[self.py_bridge_name] = py_bridge
            if self.self_in_py:
                local_vars['self'] = self

            # Configure IPython
            config = TraitletsLoader.Config()  # type: ignore
            config.InteractiveShell.banner2 = (
                'Entering an IPython shell. Type exit, quit, or Ctrl-D to exit.\n'
                f'Run CLI commands with: {self.py_bridge_name}("command ...")\n'
            )

            # Start IPython
            start_ipython(config=config, argv=[], user_ns=local_vars)
            self.poutput("Now exiting IPython shell...")

            # The IPython application is a singleton and won't be recreated next time
            # this function runs. That's a problem since the contents of local_vars
            # may need to be changed. Therefore, we must destroy all instances of the
            # relevant classes.
            TerminalIPythonApp.clear_instance()
            TerminalInteractiveShell.clear_instance()

            return py_bridge.stop
        finally:
            self._in_py = False

    history_description = "View, run, edit, save, or clear previously entered commands"

    history_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=history_description)
    history_action_group = history_parser.add_mutually_exclusive_group()
    history_action_group.add_argument('-r', '--run', action='store_true', help='run selected history items')
    history_action_group.add_argument('-e', '--edit', action='store_true', help='edit and then run selected history items')
    history_action_group.add_argument(
        '-o', '--output_file', metavar='FILE', help='output commands to a script file, implies -s', completer=path_complete
    )
    history_action_group.add_argument(
        '-t',
        '--transcript',
        metavar='TRANSCRIPT_FILE',
        help='output commands and results to a transcript file,\nimplies -s',
        completer=path_complete,
    )
    history_action_group.add_argument('-c', '--clear', action='store_true', help='clear all history')

    history_format_group = history_parser.add_argument_group(title='formatting')
    history_format_group.add_argument(
        '-s', '--script', action='store_true', help='output commands in script format, i.e. without command\n' 'numbers'
    )
    history_format_group.add_argument(
        '-x',
        '--expanded',
        action='store_true',
        help='output fully parsed commands with any aliases and\n' 'macros expanded, instead of typed commands',
    )
    history_format_group.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='display history and include expanded commands if they\n' 'differ from the typed command',
    )
    history_format_group.add_argument(
        '-a', '--all', action='store_true', help='display all commands, including ones persisted from\n' 'previous sessions'
    )

    history_arg_help = (
        "empty               all history items\n"
        "a                   one history item by number\n"
        "a..b, a:b, a:, ..b  items by indices (inclusive)\n"
        "string              items containing string\n"
        "/regex/             items matching regular expression"
    )
    history_parser.add_argument('arg', nargs=argparse.OPTIONAL, help=history_arg_help)

    @with_argparser(history_parser)
    def do_history(self, args: argparse.Namespace) -> Optional[bool]:
        """
        View, run, edit, save, or clear previously entered commands

        :return: True if running of commands should stop
        """
        self.last_result = False

        # -v must be used alone with no other options
        if args.verbose:
            if args.clear or args.edit or args.output_file or args.run or args.transcript or args.expanded or args.script:
                self.poutput("-v cannot be used with any other options")
                self.poutput(self.history_parser.format_usage())
                return None

        # -s and -x can only be used if none of these options are present: [-c -r -e -o -t]
        if (args.script or args.expanded) and (args.clear or args.edit or args.output_file or args.run or args.transcript):
            self.poutput("-s and -x cannot be used with -c, -r, -e, -o, or -t")
            self.poutput(self.history_parser.format_usage())
            return None

        if args.clear:
            self.last_result = True

            # Clear command and readline history
            self.history.clear()

            if self.persistent_history_file:
                try:
                    os.remove(self.persistent_history_file)
                except FileNotFoundError:
                    pass
                except OSError as ex:
                    self.perror(f"Error removing history file '{self.persistent_history_file}': {ex}")
                    self.last_result = False
                    return None

            if rl_type != RlType.NONE:
                readline.clear_history()
            return None

        # If an argument was supplied, then retrieve partial contents of the history, otherwise retrieve it all
        history = self._get_history(args)

        if args.run:
            if not args.arg:
                self.perror("Cowardly refusing to run all previously entered commands.")
                self.perror("If this is what you want to do, specify '1:' as the range of history.")
            else:
                stop = self.runcmds_plus_hooks(list(history.values()))
                self.last_result = True
                return stop
        elif args.edit:
            import tempfile

            fd, fname = tempfile.mkstemp(suffix='.txt', text=True)
            fobj: TextIO
            with os.fdopen(fd, 'w') as fobj:
                for command in history.values():
                    if command.statement.multiline_command:
                        fobj.write(f'{command.expanded}\n')
                    else:
                        fobj.write(f'{command.raw}\n')
            try:
                self.run_editor(fname)

                # self.last_resort will be set by do_run_script()
                # noinspection PyTypeChecker
                return self.do_run_script(utils.quote_string(fname))
            finally:
                os.remove(fname)
        elif args.output_file:
            full_path = os.path.abspath(os.path.expanduser(args.output_file))
            try:
                with open(full_path, 'w') as fobj:
                    for item in history.values():
                        if item.statement.multiline_command:
                            fobj.write(f"{item.expanded}\n")
                        else:
                            fobj.write(f"{item.raw}\n")
                plural = '' if len(history) == 1 else 's'
            except OSError as ex:
                self.perror(f"Error saving history file '{full_path}': {ex}")
            else:
                self.pfeedback(f"{len(history)} command{plural} saved to {full_path}")
                self.last_result = True
        elif args.transcript:
            # self.last_resort will be set by _generate_transcript()
            self._generate_transcript(list(history.values()), args.transcript)
        else:
            # Display the history items retrieved
            for idx, hi in history.items():
                self.poutput(hi.pr(idx, script=args.script, expanded=args.expanded, verbose=args.verbose))
            self.last_result = history
        return None

    def _get_history(self, args: argparse.Namespace) -> 'OrderedDict[int, HistoryItem]':
        """If an argument was supplied, then retrieve partial contents of the history; otherwise retrieve entire history.

        This function returns a dictionary with history items keyed by their 1-based index in ascending order.
        """
        if args.arg:
            try:
                int_arg = int(args.arg)
                return OrderedDict({int_arg: self.history.get(int_arg)})
            except ValueError:
                pass

            if '..' in args.arg or ':' in args.arg:
                # Get a slice of history
                history = self.history.span(args.arg, args.all)
            elif args.arg.startswith(r'/') and args.arg.endswith(r'/'):
                history = self.history.regex_search(args.arg, args.all)
            else:
                history = self.history.str_search(args.arg, args.all)
        else:
            # Get a copy of the history so it doesn't get mutated while we are using it
            history = self.history.span(':', args.all)
        return history

    def _initialize_history(self, hist_file: str) -> None:
        """Initialize history using history related attributes

        :param hist_file: optional path to persistent history file. If specified, then history from
                          previous sessions will be included. Additionally, all history will be written
                          to this file when the application exits.
        """
        import json
        import lzma

        self.history = History()
        # with no persistent history, nothing else in this method is relevant
        if not hist_file:
            self.persistent_history_file = hist_file
            return

        hist_file = os.path.abspath(os.path.expanduser(hist_file))

        # On Windows, trying to open a directory throws a permission
        # error, not a `IsADirectoryError`. So we'll check it ourselves.
        if os.path.isdir(hist_file):
            self.perror(f"Persistent history file '{hist_file}' is a directory")
            return

        # Create the directory for the history file if it doesn't already exist
        hist_file_dir = os.path.dirname(hist_file)
        try:
            os.makedirs(hist_file_dir, exist_ok=True)
        except OSError as ex:
            self.perror(f"Error creating persistent history file directory '{hist_file_dir}': {ex}")
            return

        # Read and process history file
        try:
            with open(hist_file, 'rb') as fobj:
                compressed_bytes = fobj.read()
            history_json = lzma.decompress(compressed_bytes).decode(encoding='utf-8')
            self.history = History.from_json(history_json)
        except FileNotFoundError:
            # Just use an empty history
            pass
        except OSError as ex:
            self.perror(f"Cannot read persistent history file '{hist_file}': {ex}")
            return
        except (json.JSONDecodeError, lzma.LZMAError, KeyError, UnicodeDecodeError, ValueError) as ex:
            self.perror(
                f"Error processing persistent history file '{hist_file}': {ex}\n"
                f"The history file will be recreated when this application exits."
            )

        self.history.start_session()
        self.persistent_history_file = hist_file

        # populate readline history
        if rl_type != RlType.NONE:
            last = None
            for item in self.history:
                # Break the command into its individual lines
                for line in item.raw.splitlines():
                    # readline only adds a single entry for multiple sequential identical lines
                    # so we emulate that behavior here
                    if line != last:
                        readline.add_history(line)
                        last = line

        # register a function to write history at save
        # if the history file is in plain text format from 0.9.12 or lower
        # this will fail, and the history in the plain text file will be lost
        import atexit

        atexit.register(self._persist_history)

    def _persist_history(self) -> None:
        """Write history out to the persistent history file as compressed JSON"""
        import lzma

        if not self.persistent_history_file:
            return

        self.history.truncate(self._persistent_history_length)
        try:
            history_json = self.history.to_json()
            compressed_bytes = lzma.compress(history_json.encode(encoding='utf-8'))

            with open(self.persistent_history_file, 'wb') as fobj:
                fobj.write(compressed_bytes)
        except OSError as ex:
            self.perror(f"Cannot write persistent history file '{self.persistent_history_file}': {ex}")

    def _generate_transcript(self, history: Union[List[HistoryItem], List[str]], transcript_file: str) -> None:
        """Generate a transcript file from a given history of commands"""
        self.last_result = False

        # Validate the transcript file path to make sure directory exists and write access is available
        transcript_path = os.path.abspath(os.path.expanduser(transcript_file))
        transcript_dir = os.path.dirname(transcript_path)
        if not os.path.isdir(transcript_dir) or not os.access(transcript_dir, os.W_OK):
            self.perror(f"'{transcript_dir}' is not a directory or you don't have write access")
            return

        commands_run = 0
        try:
            with self.sigint_protection:
                # Disable echo while we manually redirect stdout to a StringIO buffer
                saved_echo = self.echo
                saved_stdout = self.stdout
                self.echo = False

            # The problem with supporting regular expressions in transcripts
            # is that they shouldn't be processed in the command, just the output.
            # In addition, when we generate a transcript, any slashes in the output
            # are not really intended to indicate regular expressions, so they should
            # be escaped.
            #
            # We have to jump through some hoops here in order to catch the commands
            # separately from the output and escape the slashes in the output.
            transcript = ''
            for history_item in history:
                # build the command, complete with prompts. When we replay
                # the transcript, we look for the prompts to separate
                # the command from the output
                first = True
                command = ''
                if isinstance(history_item, HistoryItem):
                    history_item = history_item.raw
                for line in history_item.splitlines():
                    if first:
                        command += f"{self.prompt}{line}\n"
                        first = False
                    else:
                        command += f"{self.continuation_prompt}{line}\n"
                transcript += command

                # Use a StdSim object to capture output
                stdsim = utils.StdSim(cast(TextIO, self.stdout))
                self.stdout = cast(TextIO, stdsim)

                # then run the command and let the output go into our buffer
                try:
                    stop = self.onecmd_plus_hooks(history_item, raise_keyboard_interrupt=True)
                except KeyboardInterrupt as ex:
                    self.perror(ex)
                    stop = True

                commands_run += 1

                # add the regex-escaped output to the transcript
                transcript += stdsim.getvalue().replace('/', r'\/')

                # check if we are supposed to stop
                if stop:
                    break
        finally:
            with self.sigint_protection:
                # Restore altered attributes to their original state
                self.echo = saved_echo
                self.stdout = cast(TextIO, saved_stdout)

        # Check if all commands ran
        if commands_run < len(history):
            self.pwarning(f"Command {commands_run} triggered a stop and ended transcript generation early")

        # finally, we can write the transcript out to the file
        try:
            with open(transcript_path, 'w') as fout:
                fout.write(transcript)
        except OSError as ex:
            self.perror(f"Error saving transcript file '{transcript_path}': {ex}")
        else:
            # and let the user know what we did
            if commands_run == 1:
                plural = 'command and its output'
            else:
                plural = 'commands and their outputs'
            self.pfeedback(f"{commands_run} {plural} saved to transcript file '{transcript_path}'")
            self.last_result = True

    edit_description = (
        "Run a text editor and optionally open a file with it\n"
        "\n"
        "The editor used is determined by a settable parameter. To set it:\n"
        "\n"
        "  set editor (program-name)"
    )

    edit_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=edit_description)
    edit_parser.add_argument(
        'file_path', nargs=argparse.OPTIONAL, help="optional path to a file to open in editor", completer=path_complete
    )

    @with_argparser(edit_parser)
    def do_edit(self, args: argparse.Namespace) -> None:
        """Run a text editor and optionally open a file with it"""

        # self.last_result will be set by do_shell() which is called by run_editor()
        self.run_editor(args.file_path)

    def run_editor(self, file_path: Optional[str] = None) -> None:
        """
        Run a text editor and optionally open a file with it

        :param file_path: optional path of the file to edit. Defaults to None.
        :raises: EnvironmentError if self.editor is not set
        """
        if not self.editor:
            raise EnvironmentError("Please use 'set editor' to specify your text editing program of choice.")

        command = utils.quote_string(os.path.expanduser(self.editor))
        if file_path:
            command += " " + utils.quote_string(os.path.expanduser(file_path))

        # noinspection PyTypeChecker
        self.do_shell(command)

    @property
    def _current_script_dir(self) -> Optional[str]:
        """Accessor to get the current script directory from the _script_dir LIFO queue."""
        if self._script_dir:
            return self._script_dir[-1]
        else:
            return None

    run_script_description = (
        "Run commands in script file that is encoded as either ASCII or UTF-8 text\n"
        "\n"
        "Script should contain one command per line, just like the command would be\n"
        "typed in the console.\n"
        "\n"
        "If the -t/--transcript flag is used, this command instead records\n"
        "the output of the script commands to a transcript for testing purposes.\n"
    )

    run_script_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(description=run_script_description)
    run_script_parser.add_argument(
        '-t',
        '--transcript',
        metavar='TRANSCRIPT_FILE',
        help='record the output of the script as a transcript file',
        completer=path_complete,
    )
    run_script_parser.add_argument('script_path', help="path to the script file", completer=path_complete)

    @with_argparser(run_script_parser)
    def do_run_script(self, args: argparse.Namespace) -> Optional[bool]:
        """Run commands in script file that is encoded as either ASCII or UTF-8 text.

        :return: True if running of commands should stop
        """
        self.last_result = False
        expanded_path = os.path.abspath(os.path.expanduser(args.script_path))

        # Add some protection against accidentally running a Python file. The happens when users
        # mix up run_script and run_pyscript.
        if expanded_path.endswith('.py'):
            self.pwarning(f"'{expanded_path}' appears to be a Python file")
            selection = self.select('Yes No', 'Continue to try to run it as a text script? ')
            if selection != 'Yes':
                return None

        try:
            # An empty file is not an error, so just return
            if os.path.getsize(expanded_path) == 0:
                self.last_result = True
                return None

            # Make sure the file is ASCII or UTF-8 encoded text
            if not utils.is_text_file(expanded_path):
                self.perror(f"'{expanded_path}' is not an ASCII or UTF-8 encoded text file")
                return None

            # Read all lines of the script
            with open(expanded_path, encoding='utf-8') as target:
                script_commands = target.read().splitlines()
        except OSError as ex:
            self.perror(f"Problem accessing script from '{expanded_path}': {ex}")
            return None

        orig_script_dir_count = len(self._script_dir)

        try:
            self._script_dir.append(os.path.dirname(expanded_path))

            if args.transcript:
                # self.last_resort will be set by _generate_transcript()
                self._generate_transcript(script_commands, os.path.expanduser(args.transcript))
            else:
                stop = self.runcmds_plus_hooks(script_commands, stop_on_keyboard_interrupt=True)
                self.last_result = True
                return stop

        finally:
            with self.sigint_protection:
                # Check if a script dir was added before an exception occurred
                if orig_script_dir_count != len(self._script_dir):
                    self._script_dir.pop()
        return None

    relative_run_script_description = run_script_description
    relative_run_script_description += (
        "\n\n"
        "If this is called from within an already-running script, the filename will be\n"
        "interpreted relative to the already-running script's directory."
    )

    relative_run_script_epilog = "Notes:\n" "  This command is intended to only be used within text file scripts."

    relative_run_script_parser = argparse_custom.DEFAULT_ARGUMENT_PARSER(
        description=relative_run_script_description, epilog=relative_run_script_epilog
    )
    relative_run_script_parser.add_argument('file_path', help='a file path pointing to a script')

    @with_argparser(relative_run_script_parser)
    def do__relative_run_script(self, args: argparse.Namespace) -> Optional[bool]:
        """
        Run commands in script file that is encoded as either ASCII or UTF-8 text

        :return: True if running of commands should stop
        """
        file_path = args.file_path
        # NOTE: Relative path is an absolute path, it is just relative to the current script directory
        relative_path = os.path.join(self._current_script_dir or '', file_path)

        # self.last_result will be set by do_run_script()
        # noinspection PyTypeChecker
        return self.do_run_script(utils.quote_string(relative_path))

    def _run_transcript_tests(self, transcript_paths: List[str]) -> None:
        """Runs transcript tests for provided file(s).

        This is called when either -t is provided on the command line or the transcript_files argument is provided
        during construction of the cmd2.Cmd instance.

        :param transcript_paths: list of transcript test file paths
        """
        import time
        import unittest

        import cmd2

        from .transcript import (
            Cmd2TestCase,
        )

        class TestMyAppCase(Cmd2TestCase):
            cmdapp = self

        # Validate that there is at least one transcript file
        transcripts_expanded = utils.files_from_glob_patterns(transcript_paths, access=os.R_OK)
        if not transcripts_expanded:
            self.perror('No test files found - nothing to test')
            self.exit_code = 1
            return

        verinfo = ".".join(map(str, sys.version_info[:3]))
        num_transcripts = len(transcripts_expanded)
        plural = '' if len(transcripts_expanded) == 1 else 's'
        self.poutput(ansi.style(utils.align_center(' cmd2 transcript test ', fill_char='='), bold=True))
        self.poutput(f'platform {sys.platform} -- Python {verinfo}, cmd2-{cmd2.__version__}, readline-{rl_type}')
        self.poutput(f'cwd: {os.getcwd()}')
        self.poutput(f'cmd2 app: {sys.argv[0]}')
        self.poutput(ansi.style(f'collected {num_transcripts} transcript{plural}', bold=True))

        setattr(self.__class__, 'testfiles', transcripts_expanded)
        sys.argv = [sys.argv[0]]  # the --test argument upsets unittest.main()
        testcase = TestMyAppCase()
        stream = cast(TextIO, utils.StdSim(sys.stderr))
        # noinspection PyTypeChecker
        runner = unittest.TextTestRunner(stream=stream)
        start_time = time.time()
        test_results = runner.run(testcase)
        execution_time = time.time() - start_time
        if test_results.wasSuccessful():
            ansi.style_aware_write(sys.stderr, stream.read())
            finish_msg = f' {num_transcripts} transcript{plural} passed in {execution_time:.3f} seconds '
            finish_msg = ansi.style_success(utils.align_center(finish_msg, fill_char='='))
            self.poutput(finish_msg)
        else:
            # Strip off the initial traceback which isn't particularly useful for end users
            error_str = stream.read()
            end_of_trace = error_str.find('AssertionError:')
            file_offset = error_str[end_of_trace:].find('File ')
            start = end_of_trace + file_offset

            # But print the transcript file name and line number followed by what was expected and what was observed
            self.perror(error_str[start:])

            # Return a failure error code to support automated transcript-based testing
            self.exit_code = 1

    def async_alert(self, alert_msg: str, new_prompt: Optional[str] = None) -> None:  # pragma: no cover
        """
        Display an important message to the user while they are at a command line prompt.
        To the user it appears as if an alert message is printed above the prompt and their current input
        text and cursor location is left alone.

        IMPORTANT: This function will not print an alert unless it can acquire self.terminal_lock to ensure
                   a prompt is onscreen. Therefore, it is best to acquire the lock before calling this function
                   to guarantee the alert prints and to avoid raising a RuntimeError.

                   This function is only needed when you need to print an alert while the main thread is blocking
                   at the prompt. Therefore, this should never be called from the main thread. Doing so will
                   raise a RuntimeError.

        :param alert_msg: the message to display to the user
        :param new_prompt: If you also want to change the prompt that is displayed, then include it here.
                           See async_update_prompt() docstring for guidance on updating a prompt.
        :raises RuntimeError: if called from the main thread.
        :raises RuntimeError: if called while another thread holds `terminal_lock`
        """
        if threading.current_thread() is threading.main_thread():
            raise RuntimeError("async_alert should not be called from the main thread")

        if not (vt100_support and self.use_rawinput):
            return

        # Sanity check that can't fail if self.terminal_lock was acquired before calling this function
        if self.terminal_lock.acquire(blocking=False):

            # Windows terminals tend to flicker when we redraw the prompt and input lines.
            # To reduce how often this occurs, only update terminal if there are changes.
            update_terminal = False

            if alert_msg:
                alert_msg += '\n'
                update_terminal = True

            if new_prompt is not None:
                self.prompt = new_prompt

            # Check if the prompt to display has changed from what's currently displayed
            cur_onscreen_prompt = rl_get_prompt()
            new_onscreen_prompt = self.continuation_prompt if self._at_continuation_prompt else self.prompt

            if new_onscreen_prompt != cur_onscreen_prompt:
                update_terminal = True

            if update_terminal:
                import shutil

                # Generate the string which will replace the current prompt and input lines with the alert
                terminal_str = ansi.async_alert_str(
                    terminal_columns=shutil.get_terminal_size().columns,
                    prompt=cur_onscreen_prompt,
                    line=readline.get_line_buffer(),
                    cursor_offset=rl_get_point(),
                    alert_msg=alert_msg,
                )
                if rl_type == RlType.GNU:
                    sys.stderr.write(terminal_str)
                    sys.stderr.flush()
                elif rl_type == RlType.PYREADLINE:
                    # noinspection PyUnresolvedReferences
                    readline.rl.mode.console.write(terminal_str)

                # Update Readline's prompt before we redraw it
                rl_set_prompt(new_onscreen_prompt)

                # Redraw the prompt and input lines below the alert
                rl_force_redisplay()

            self.terminal_lock.release()

        else:
            raise RuntimeError("another thread holds terminal_lock")

    def async_update_prompt(self, new_prompt: str) -> None:  # pragma: no cover
        """
        Update the command line prompt while the user is still typing at it. This is good for alerting the user to
        system changes dynamically in between commands. For instance you could alter the color of the prompt to
        indicate a system status or increase a counter to report an event. If you do alter the actual text of the
        prompt, it is best to keep the prompt the same width as what's on screen. Otherwise the user's input text will
        be shifted and the update will not be seamless.

        IMPORTANT: This function will not update the prompt unless it can acquire self.terminal_lock to ensure
                   a prompt is onscreen. Therefore, it is best to acquire the lock before calling this function
                   to guarantee the prompt changes and to avoid raising a RuntimeError.

                   This function is only needed when you need to update the prompt while the main thread is blocking
                   at the prompt. Therefore, this should never be called from the main thread. Doing so will
                   raise a RuntimeError.

                   If user is at a continuation prompt while entering a multiline command, the onscreen prompt will
                   not change. However, self.prompt will still be updated and display immediately after the multiline
                   line command completes.

        :param new_prompt: what to change the prompt to
        :raises RuntimeError: if called from the main thread.
        :raises RuntimeError: if called while another thread holds `terminal_lock`
        """
        self.async_alert('', new_prompt)

    @staticmethod
    def set_window_title(title: str) -> None:  # pragma: no cover
        """
        Set the terminal window title.

        NOTE: This function writes to stderr. Therefore, if you call this during a command run by a pyscript,
              the string which updates the title will appear in that command's CommandResult.stderr data.

        :param title: the new window title
        """
        if not vt100_support:
            return

        try:
            sys.stderr.write(ansi.set_title(title))
            sys.stderr.flush()
        except AttributeError:
            # Debugging in Pycharm has issues with setting terminal title
            pass

    def enable_command(self, command: str) -> None:
        """
        Enable a command by restoring its functions

        :param command: the command being enabled
        """
        # If the commands is already enabled, then return
        if command not in self.disabled_commands:
            return

        help_func_name = constants.HELP_FUNC_PREFIX + command
        completer_func_name = constants.COMPLETER_FUNC_PREFIX + command

        # Restore the command function to its original value
        dc = self.disabled_commands[command]
        setattr(self, self._cmd_func_name(command), dc.command_function)

        # Restore the help function to its original value
        if dc.help_function is None:
            delattr(self, help_func_name)
        else:
            setattr(self, help_func_name, dc.help_function)

        # Restore the completer function to its original value
        if dc.completer_function is None:
            delattr(self, completer_func_name)
        else:
            setattr(self, completer_func_name, dc.completer_function)

        # Remove the disabled command entry
        del self.disabled_commands[command]

    def enable_category(self, category: str) -> None:
        """
        Enable an entire category of commands

        :param category: the category to enable
        """
        for cmd_name in list(self.disabled_commands):
            func = self.disabled_commands[cmd_name].command_function
            if getattr(func, constants.CMD_ATTR_HELP_CATEGORY, None) == category:
                self.enable_command(cmd_name)

    def disable_command(self, command: str, message_to_print: str) -> None:
        """
        Disable a command and overwrite its functions

        :param command: the command being disabled
        :param message_to_print: what to print when this command is run or help is called on it while disabled

                                 The variable cmd2.COMMAND_NAME can be used as a placeholder for the name of the
                                 command being disabled.
                                 ex: message_to_print = f"{cmd2.COMMAND_NAME} is currently disabled"
        """
        # If the commands is already disabled, then return
        if command in self.disabled_commands:
            return

        # Make sure this is an actual command
        command_function = self.cmd_func(command)
        if command_function is None:
            raise AttributeError(f"'{command}' does not refer to a command")

        help_func_name = constants.HELP_FUNC_PREFIX + command
        completer_func_name = constants.COMPLETER_FUNC_PREFIX + command

        # Add the disabled command record
        self.disabled_commands[command] = DisabledCommand(
            command_function=command_function,
            help_function=getattr(self, help_func_name, None),
            completer_function=getattr(self, completer_func_name, None),
        )

        # Overwrite the command and help functions to print the message
        new_func = functools.partial(
            self._report_disabled_command_usage, message_to_print=message_to_print.replace(constants.COMMAND_NAME, command)
        )
        setattr(self, self._cmd_func_name(command), new_func)
        setattr(self, help_func_name, new_func)

        # Set the completer to a function that returns a blank list
        setattr(self, completer_func_name, lambda *args, **kwargs: [])

    def disable_category(self, category: str, message_to_print: str) -> None:
        """Disable an entire category of commands.

        :param category: the category to disable
        :param message_to_print: what to print when anything in this category is run or help is called on it
                                 while disabled. The variable cmd2.COMMAND_NAME can be used as a placeholder for the name
                                 of the command being disabled.
                                 ex: message_to_print = f"{cmd2.COMMAND_NAME} is currently disabled"
        """
        all_commands = self.get_all_commands()

        for cmd_name in all_commands:
            func = self.cmd_func(cmd_name)
            if getattr(func, constants.CMD_ATTR_HELP_CATEGORY, None) == category:
                self.disable_command(cmd_name, message_to_print)

    def _report_disabled_command_usage(self, *_args: Any, message_to_print: str, **_kwargs: Any) -> None:
        """
        Report when a disabled command has been run or had help called on it

        :param args: not used
        :param message_to_print: the message reporting that the command is disabled
        :param kwargs: not used
        """
        # Set apply_style to False so message_to_print's style is not overridden
        self.perror(message_to_print, apply_style=False)

    def cmdloop(self, intro: Optional[str] = None) -> int:  # type: ignore[override]
        """This is an outer wrapper around _cmdloop() which deals with extra features provided by cmd2.

        _cmdloop() provides the main loop equivalent to cmd.cmdloop().  This is a wrapper around that which deals with
        the following extra features provided by cmd2:
        - transcript testing
        - intro banner
        - exit code

        :param intro: if provided this overrides self.intro and serves as the intro banner printed once at start
        """
        # cmdloop() expects to be run in the main thread to support extensive use of KeyboardInterrupts throughout the
        # other built-in functions. You are free to override cmdloop, but much of cmd2's features will be limited.
        if not threading.current_thread() is threading.main_thread():
            raise RuntimeError("cmdloop must be run in the main thread")

        # Register a SIGINT signal handler for Ctrl+C
        import signal

        original_sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self.sigint_handler)  # type: ignore

        # Grab terminal lock before the command line prompt has been drawn by readline
        self.terminal_lock.acquire()

        # Always run the preloop first
        for func in self._preloop_hooks:
            func()
        self.preloop()

        # If transcript-based regression testing was requested, then do that instead of the main loop
        if self._transcript_files is not None:
            self._run_transcript_tests([os.path.expanduser(tf) for tf in self._transcript_files])
        else:
            # If an intro was supplied in the method call, allow it to override the default
            if intro is not None:
                self.intro = intro

            # Print the intro, if there is one, right after the preloop
            if self.intro is not None:
                self.poutput(self.intro)

            # And then call _cmdloop() to enter the main loop
            self._cmdloop()

        # Run the postloop() no matter what
        for func in self._postloop_hooks:
            func()
        self.postloop()

        # Release terminal lock now that postloop code should have stopped any terminal updater threads
        # This will also zero the lock count in case cmdloop() is called again
        self.terminal_lock.release()

        # Restore the original signal handler
        signal.signal(signal.SIGINT, original_sigint_handler)

        return self.exit_code

    ###
    #
    # plugin related functions
    #
    ###
    def _initialize_plugin_system(self) -> None:
        """Initialize the plugin system"""
        self._preloop_hooks: List[Callable[[], None]] = []
        self._postloop_hooks: List[Callable[[], None]] = []
        self._postparsing_hooks: List[Callable[[plugin.PostparsingData], plugin.PostparsingData]] = []
        self._precmd_hooks: List[Callable[[plugin.PrecommandData], plugin.PrecommandData]] = []
        self._postcmd_hooks: List[Callable[[plugin.PostcommandData], plugin.PostcommandData]] = []
        self._cmdfinalization_hooks: List[Callable[[plugin.CommandFinalizationData], plugin.CommandFinalizationData]] = []

    @classmethod
    def _validate_callable_param_count(cls, func: Callable[..., Any], count: int) -> None:
        """Ensure a function has the given number of parameters."""
        signature = inspect.signature(func)
        # validate that the callable has the right number of parameters
        nparam = len(signature.parameters)
        if nparam != count:
            plural = '' if nparam == 1 else 's'
            raise TypeError(f'{func.__name__} has {nparam} positional argument{plural}, expected {count}')

    @classmethod
    def _validate_prepostloop_callable(cls, func: Callable[[], None]) -> None:
        """Check parameter and return types for preloop and postloop hooks."""
        cls._validate_callable_param_count(func, 0)
        # make sure there is no return notation
        signature = inspect.signature(func)
        if signature.return_annotation is not None:
            raise TypeError(f"{func.__name__} must declare return a return type of 'None'")

    def register_preloop_hook(self, func: Callable[[], None]) -> None:
        """Register a function to be called at the beginning of the command loop."""
        self._validate_prepostloop_callable(func)
        self._preloop_hooks.append(func)

    def register_postloop_hook(self, func: Callable[[], None]) -> None:
        """Register a function to be called at the end of the command loop."""
        self._validate_prepostloop_callable(func)
        self._postloop_hooks.append(func)

    @classmethod
    def _validate_postparsing_callable(cls, func: Callable[[plugin.PostparsingData], plugin.PostparsingData]) -> None:
        """Check parameter and return types for postparsing hooks"""
        cls._validate_callable_param_count(cast(Callable[..., Any], func), 1)
        signature = inspect.signature(func)
        _, param = list(signature.parameters.items())[0]
        if param.annotation != plugin.PostparsingData:
            raise TypeError(f"{func.__name__} must have one parameter declared with type 'cmd2.plugin.PostparsingData'")
        if signature.return_annotation != plugin.PostparsingData:
            raise TypeError(f"{func.__name__} must declare return a return type of 'cmd2.plugin.PostparsingData'")

    def register_postparsing_hook(self, func: Callable[[plugin.PostparsingData], plugin.PostparsingData]) -> None:
        """Register a function to be called after parsing user input but before running the command"""
        self._validate_postparsing_callable(func)
        self._postparsing_hooks.append(func)

    CommandDataType = TypeVar('CommandDataType')

    @classmethod
    def _validate_prepostcmd_hook(
        cls, func: Callable[[CommandDataType], CommandDataType], data_type: Type[CommandDataType]
    ) -> None:
        """Check parameter and return types for pre and post command hooks."""
        signature = inspect.signature(func)
        # validate that the callable has the right number of parameters
        cls._validate_callable_param_count(cast(Callable[..., Any], func), 1)
        # validate the parameter has the right annotation
        paramname = list(signature.parameters.keys())[0]
        param = signature.parameters[paramname]
        if param.annotation != data_type:
            raise TypeError(f'argument 1 of {func.__name__} has incompatible type {param.annotation}, expected {data_type}')
        # validate the return value has the right annotation
        if signature.return_annotation == signature.empty:
            raise TypeError(f'{func.__name__} does not have a declared return type, expected {data_type}')
        if signature.return_annotation != data_type:
            raise TypeError(
                f'{func.__name__} has incompatible return type {signature.return_annotation}, expected ' f'{data_type}'
            )

    def register_precmd_hook(self, func: Callable[[plugin.PrecommandData], plugin.PrecommandData]) -> None:
        """Register a hook to be called before the command function."""
        self._validate_prepostcmd_hook(func, plugin.PrecommandData)
        self._precmd_hooks.append(func)

    def register_postcmd_hook(self, func: Callable[[plugin.PostcommandData], plugin.PostcommandData]) -> None:
        """Register a hook to be called after the command function."""
        self._validate_prepostcmd_hook(func, plugin.PostcommandData)
        self._postcmd_hooks.append(func)

    @classmethod
    def _validate_cmdfinalization_callable(
        cls, func: Callable[[plugin.CommandFinalizationData], plugin.CommandFinalizationData]
    ) -> None:
        """Check parameter and return types for command finalization hooks."""
        cls._validate_callable_param_count(func, 1)
        signature = inspect.signature(func)
        _, param = list(signature.parameters.items())[0]
        if param.annotation != plugin.CommandFinalizationData:
            raise TypeError(f"{func.__name__} must have one parameter declared with type {plugin.CommandFinalizationData}")
        if signature.return_annotation != plugin.CommandFinalizationData:
            raise TypeError("{func.__name__} must declare return a return type of {plugin.CommandFinalizationData}")

    def register_cmdfinalization_hook(
        self, func: Callable[[plugin.CommandFinalizationData], plugin.CommandFinalizationData]
    ) -> None:
        """Register a hook to be called after a command is completed, whether it completes successfully or not."""
        self._validate_cmdfinalization_callable(func)
        self._cmdfinalization_hooks.append(func)

    def _resolve_func_self(
        self,
        cmd_support_func: Callable[..., Any],
        cmd_self: Union[CommandSet, 'Cmd', None],
    ) -> Optional[object]:
        """
        Attempt to resolve a candidate instance to pass as 'self' for an unbound class method that was
        used when defining command's argparse object. Since we restrict registration to only a single CommandSet
        instance of each type, using type is a reasonably safe way to resolve the correct object instance

        :param cmd_support_func: command support function. This could be a completer or namespace provider
        :param cmd_self: The `self` associated with the command or subcommand
        """
        # figure out what class the command support function was defined in
        func_class: Optional[Type[Any]] = get_defining_class(cmd_support_func)

        # Was there a defining class identified? If so, is it a sub-class of CommandSet?
        if func_class is not None and issubclass(func_class, CommandSet):
            # Since the support function is provided as an unbound function, we need to locate the instance
            # of the CommandSet to pass in as `self` to emulate a bound method call.
            # We're searching for candidates that match the support function's defining class type in this order:
            #   1. Is the command's CommandSet a sub-class of the support function's class?
            #   2. Do any of the registered CommandSets in the Cmd2 application exactly match the type?
            #   3. Is there a registered CommandSet that is is the only matching subclass?

            func_self: Optional[Union[CommandSet, 'Cmd']]

            # check if the command's CommandSet is a sub-class of the support function's defining class
            if isinstance(cmd_self, func_class):
                # Case 1: Command's CommandSet is a sub-class of the support function's CommandSet
                func_self = cmd_self
            else:
                # Search all registered CommandSets
                func_self = None
                candidate_sets: List[CommandSet] = []
                for installed_cmd_set in self._installed_command_sets:
                    if type(installed_cmd_set) == func_class:
                        # Case 2: CommandSet is an exact type match for the function's CommandSet
                        func_self = installed_cmd_set
                        break

                    # Add candidate for Case 3:
                    if isinstance(installed_cmd_set, func_class):
                        candidate_sets.append(installed_cmd_set)
                if func_self is None and len(candidate_sets) == 1:
                    # Case 3: There exists exactly 1 CommandSet that is a sub-class match of the function's CommandSet
                    func_self = candidate_sets[0]
            return func_self
        else:
            return self
