# coding=utf-8
"""Decorators for ``cmd2`` commands"""
import argparse
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from . import (
    constants,
)
from .argparse_custom import (
    Cmd2AttributeWrapper,
)
from .command_definition import (
    CommandFunc,
    CommandSet,
)
from .exceptions import (
    Cmd2ArgparseError,
)
from .parsing import (
    Statement,
)
from .utils import (
    strip_doc_annotations,
)

if TYPE_CHECKING:  # pragma: no cover
    import cmd2


def with_category(category: str) -> Callable[[CommandFunc], CommandFunc]:
    """A decorator to apply a category to a ``do_*`` command method.

    :param category: the name of the category in which this command should
                     be grouped when displaying the list of commands.

    :Example:

    >>> class MyApp(cmd2.Cmd):
    >>>   @cmd2.with_category('Text Functions')
    >>>   def do_echo(self, args)
    >>>     self.poutput(args)

    For an alternative approach to categorizing commands using a function, see
    :func:`~cmd2.utils.categorize`
    """

    def cat_decorator(func: CommandFunc) -> CommandFunc:
        from .utils import (
            categorize,
        )

        categorize(func, category)
        return func

    return cat_decorator


##########################
# The _parse_positionals and _arg_swap functions allow for additional positional args to be preserved
# in cmd2 command functions/callables. As long as the 2-ple of arguments we expect to be there can be
# found we can swap out the statement with each decorator's specific parameters
##########################


RawCommandFuncOptionalBoolReturn = Callable[[Union[CommandSet, 'cmd2.Cmd'], Union[Statement, str]], Optional[bool]]


def _parse_positionals(args: Tuple[Any, ...]) -> Tuple['cmd2.Cmd', Union[Statement, str]]:
    """
    Helper function for cmd2 decorators to inspect the positional arguments until the cmd2.Cmd argument is found
    Assumes that we will find cmd2.Cmd followed by the command statement object or string.
    :arg args: The positional arguments to inspect
    :return: The cmd2.Cmd reference and the command line statement
    """
    for pos, arg in enumerate(args):
        from cmd2 import (
            Cmd,
        )

        if (isinstance(arg, Cmd) or isinstance(arg, CommandSet)) and len(args) > pos:
            if isinstance(arg, CommandSet):
                arg = arg._cmd
            next_arg = args[pos + 1]
            if isinstance(next_arg, (Statement, str)):
                return arg, args[pos + 1]

    # This shouldn't happen unless we forget to pass statement in `Cmd.onecmd` or
    # somehow call the unbound class method.
    raise TypeError('Expected arguments: cmd: cmd2.Cmd, statement: Union[Statement, str] Not found')  # pragma: no cover


def _arg_swap(args: Union[Sequence[Any]], search_arg: Any, *replace_arg: Any) -> List[Any]:
    """
    Helper function for cmd2 decorators to swap the Statement parameter with one or more decorator-specific parameters

    :param args: The original positional arguments
    :param search_arg: The argument to search for (usually the Statement)
    :param replace_arg: The arguments to substitute in
    :return: The new set of arguments to pass to the command function
    """
    index = args.index(search_arg)
    args_list = list(args)
    args_list[index : index + 1] = replace_arg
    return args_list


#: Function signature for an Command Function that accepts a pre-processed argument list from user input
#: and optionally returns a boolean
ArgListCommandFuncOptionalBoolReturn = Union[
    Callable[['cmd2.Cmd', List[str]], Optional[bool]],
    Callable[[CommandSet, List[str]], Optional[bool]],
]
#: Function signature for an Command Function that accepts a pre-processed argument list from user input
#: and returns a boolean
ArgListCommandFuncBoolReturn = Union[
    Callable[['cmd2.Cmd', List[str]], bool],
    Callable[[CommandSet, List[str]], bool],
]
#: Function signature for an Command Function that accepts a pre-processed argument list from user input
#: and returns Nothing
ArgListCommandFuncNoneReturn = Union[
    Callable[['cmd2.Cmd', List[str]], None],
    Callable[[CommandSet, List[str]], None],
]

#: Aggregate of all accepted function signatures for Command Functions that accept a pre-processed argument list
ArgListCommandFunc = Union[ArgListCommandFuncOptionalBoolReturn, ArgListCommandFuncBoolReturn, ArgListCommandFuncNoneReturn]


def with_argument_list(
    func_arg: Optional[ArgListCommandFunc] = None,
    *,
    preserve_quotes: bool = False,
) -> Union[RawCommandFuncOptionalBoolReturn, Callable[[ArgListCommandFunc], RawCommandFuncOptionalBoolReturn]]:
    """
    A decorator to alter the arguments passed to a ``do_*`` method. Default
    passes a string of whatever the user typed. With this decorator, the
    decorated method will receive a list of arguments parsed from user input.

    :param func_arg: Single-element positional argument list containing ``do_*`` method
                 this decorator is wrapping
    :param preserve_quotes: if ``True``, then argument quotes will not be stripped
    :return: function that gets passed a list of argument strings

    :Example:

    >>> class MyApp(cmd2.Cmd):
    >>>     @cmd2.with_argument_list
    >>>     def do_echo(self, arglist):
    >>>         self.poutput(' '.join(arglist)
    """
    import functools

    def arg_decorator(func: ArgListCommandFunc) -> RawCommandFuncOptionalBoolReturn:
        """
        Decorator function that ingests an Argument List function and returns a raw command function.
        The returned function will process the raw input into an argument list to be passed to the wrapped function.

        :param func: The defined argument list command function
        :return: Function that takes raw input and converts to an argument list to pass to the wrapped function.
        """

        @functools.wraps(func)
        def cmd_wrapper(*args: Any, **kwargs: Any) -> Optional[bool]:
            """
            Command function wrapper which translates command line into an argument list and calls actual command function

            :param args: All positional arguments to this function.  We're expecting there to be:
                            cmd2_app, statement: Union[Statement, str]
                            contiguously somewhere in the list
            :param kwargs: any keyword arguments being passed to command function
            :return: return value of command function
            """
            cmd2_app, statement = _parse_positionals(args)
            _, parsed_arglist = cmd2_app.statement_parser.get_command_arg_list(command_name, statement, preserve_quotes)
            args_list = _arg_swap(args, statement, parsed_arglist)
            return func(*args_list, **kwargs)  # type: ignore[call-arg]

        command_name = func.__name__[len(constants.COMMAND_FUNC_PREFIX) :]
        cmd_wrapper.__doc__ = func.__doc__
        return cmd_wrapper

    if callable(func_arg):
        # noinspection PyTypeChecker
        return arg_decorator(func_arg)
    else:
        # noinspection PyTypeChecker
        return arg_decorator


# noinspection PyProtectedMember
def _set_parser_prog(parser: argparse.ArgumentParser, prog: str) -> None:
    """
    Recursively set prog attribute of a parser and all of its subparsers so that the root command
    is a command name and not sys.argv[0].

    :param parser: the parser being edited
    :param prog: new value for the parser's prog attribute
    """
    # Set the prog value for this parser
    parser.prog = prog

    # Set the prog value for the parser's subcommands
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            # Set the _SubParsersAction's _prog_prefix value. That way if its add_parser() method is called later,
            # the correct prog value will be set on the parser being added.
            action._prog_prefix = parser.prog

            # The keys of action.choices are subcommand names as well as subcommand aliases. The aliases point to the
            # same parser as the actual subcommand. We want to avoid placing an alias into a parser's prog value.
            # Unfortunately there is nothing about an action.choices entry which tells us it's an alias. In most cases
            # we can filter out the aliases by checking the contents of action._choices_actions. This list only contains
            # help information and names for the subcommands and not aliases. However, subcommands without help text
            # won't show up in that list. Since dictionaries are ordered in Python 3.6 and above and argparse inserts the
            # subcommand name into choices dictionary before aliases, we should be OK assuming the first time we see a
            # parser, the dictionary key is a subcommand and not alias.
            processed_parsers = []

            # Set the prog value for each subcommand's parser
            for subcmd_name, subcmd_parser in action.choices.items():
                # Check if we've already edited this parser
                if subcmd_parser in processed_parsers:
                    continue

                subcmd_prog = parser.prog + ' ' + subcmd_name
                _set_parser_prog(subcmd_parser, subcmd_prog)
                processed_parsers.append(subcmd_parser)

            # We can break since argparse only allows 1 group of subcommands per level
            break


#: Function signature for a Command Function that uses an argparse.ArgumentParser to process user input
#: and optionally returns a boolean
ArgparseCommandFuncOptionalBoolReturn = Union[
    Callable[['cmd2.Cmd', argparse.Namespace], Optional[bool]],
    Callable[[CommandSet, argparse.Namespace], Optional[bool]],
]
#: Function signature for a Command Function that uses an argparse.ArgumentParser to process user input
#: and returns a boolean
ArgparseCommandFuncBoolReturn = Union[
    Callable[['cmd2.Cmd', argparse.Namespace], bool],
    Callable[[CommandSet, argparse.Namespace], bool],
]
#: Function signature for an Command Function that uses an argparse.ArgumentParser to process user input
#: and returns nothing
ArgparseCommandFuncNoneReturn = Union[
    Callable[['cmd2.Cmd', argparse.Namespace], None],
    Callable[[CommandSet, argparse.Namespace], None],
]

#: Aggregate of all accepted function signatures for an argparse Command Function
ArgparseCommandFunc = Union[
    ArgparseCommandFuncOptionalBoolReturn,
    ArgparseCommandFuncBoolReturn,
    ArgparseCommandFuncNoneReturn,
]


def with_argparser(
    parser: argparse.ArgumentParser,
    *,
    ns_provider: Optional[Callable[..., argparse.Namespace]] = None,
    preserve_quotes: bool = False,
    with_unknown_args: bool = False,
) -> Callable[[ArgparseCommandFunc], RawCommandFuncOptionalBoolReturn]:
    """A decorator to alter a cmd2 method to populate its ``args`` argument by parsing arguments
    with the given instance of argparse.ArgumentParser.

    :param parser: unique instance of ArgumentParser
    :param ns_provider: An optional function that accepts a cmd2.Cmd or cmd2.CommandSet object as an argument and returns an
                        argparse.Namespace. This is useful if the Namespace needs to be prepopulated with state data that
                        affects parsing.
    :param preserve_quotes: if ``True``, then arguments passed to argparse maintain their quotes
    :param with_unknown_args: if true, then capture unknown args
    :return: function that gets passed argparse-parsed args in a ``Namespace``
             A :class:`cmd2.argparse_custom.Cmd2AttributeWrapper` called ``cmd2_statement`` is included
             in the ``Namespace`` to provide access to the :class:`cmd2.Statement` object that was created when
             parsing the command line. This can be useful if the command function needs to know the command line.

    :Example:

    >>> parser = cmd2.Cmd2ArgumentParser()
    >>> parser.add_argument('-p', '--piglatin', action='store_true', help='atinLay')
    >>> parser.add_argument('-s', '--shout', action='store_true', help='N00B EMULATION MODE')
    >>> parser.add_argument('-r', '--repeat', type=int, help='output [n] times')
    >>> parser.add_argument('words', nargs='+', help='words to print')
    >>>
    >>> class MyApp(cmd2.Cmd):
    >>>     @cmd2.with_argparser(parser, preserve_quotes=True)
    >>>     def do_argprint(self, args):
    >>>         "Print the options and argument list this options command was called with."
    >>>         self.poutput(f'args: {args!r}')

    :Example with unknown args:

    >>> parser = cmd2.Cmd2ArgumentParser()
    >>> parser.add_argument('-p', '--piglatin', action='store_true', help='atinLay')
    >>> parser.add_argument('-s', '--shout', action='store_true', help='N00B EMULATION MODE')
    >>> parser.add_argument('-r', '--repeat', type=int, help='output [n] times')
    >>>
    >>> class MyApp(cmd2.Cmd):
    >>>     @cmd2.with_argparser(parser, with_unknown_args=True)
    >>>     def do_argprint(self, args, unknown):
    >>>         "Print the options and argument list this options command was called with."
    >>>         self.poutput(f'args: {args!r}')
    >>>         self.poutput(f'unknowns: {unknown}')

    """
    import functools

    def arg_decorator(func: ArgparseCommandFunc) -> RawCommandFuncOptionalBoolReturn:
        """
        Decorator function that ingests an Argparse Command Function and returns a raw command function.
        The returned function will process the raw input into an argparse Namespace to be passed to the wrapped function.

        :param func: The defined argparse command function
        :return: Function that takes raw input and converts to an argparse Namespace to passed to the wrapped function.
        """

        @functools.wraps(func)
        def cmd_wrapper(*args: Any, **kwargs: Dict[str, Any]) -> Optional[bool]:
            """
            Command function wrapper which translates command line into argparse Namespace and calls actual
            command function

            :param args: All positional arguments to this function.  We're expecting there to be:
                            cmd2_app, statement: Union[Statement, str]
                            contiguously somewhere in the list
            :param kwargs: any keyword arguments being passed to command function
            :return: return value of command function
            :raises: Cmd2ArgparseError if argparse has error parsing command line
            """
            cmd2_app, statement_arg = _parse_positionals(args)
            statement, parsed_arglist = cmd2_app.statement_parser.get_command_arg_list(
                command_name, statement_arg, preserve_quotes
            )

            if ns_provider is None:
                namespace = None
            else:
                # The namespace provider may or may not be defined in the same class as the command. Since provider
                # functions are registered with the command argparser before anything is instantiated, we
                # need to find an instance at runtime that matches the types during declaration
                provider_self = cmd2_app._resolve_func_self(ns_provider, args[0])
                namespace = ns_provider(provider_self if provider_self is not None else cmd2_app)

            try:
                new_args: Union[Tuple[argparse.Namespace], Tuple[argparse.Namespace, List[str]]]
                if with_unknown_args:
                    new_args = parser.parse_known_args(parsed_arglist, namespace)
                else:
                    new_args = (parser.parse_args(parsed_arglist, namespace),)
                ns = new_args[0]
            except SystemExit:
                raise Cmd2ArgparseError
            else:
                # Add wrapped statement to Namespace as cmd2_statement
                setattr(ns, 'cmd2_statement', Cmd2AttributeWrapper(statement))

                # Add wrapped subcmd handler (which can be None) to Namespace as cmd2_handler
                handler = getattr(ns, constants.NS_ATTR_SUBCMD_HANDLER, None)
                setattr(ns, 'cmd2_handler', Cmd2AttributeWrapper(handler))

                # Remove the subcmd handler attribute from the Namespace
                # since cmd2_handler is how a developer accesses it.
                if hasattr(ns, constants.NS_ATTR_SUBCMD_HANDLER):
                    delattr(ns, constants.NS_ATTR_SUBCMD_HANDLER)

                args_list = _arg_swap(args, statement_arg, *new_args)
                return func(*args_list, **kwargs)  # type: ignore[call-arg]

        # argparser defaults the program name to sys.argv[0], but we want it to be the name of our command
        command_name = func.__name__[len(constants.COMMAND_FUNC_PREFIX) :]
        _set_parser_prog(parser, command_name)

        # If the description has not been set, then use the method docstring if one exists
        if parser.description is None and func.__doc__:
            parser.description = strip_doc_annotations(func.__doc__)

        # Set the command's help text as argparser.description (which can be None)
        cmd_wrapper.__doc__ = parser.description

        # Set some custom attributes for this command
        setattr(cmd_wrapper, constants.CMD_ATTR_ARGPARSER, parser)
        setattr(cmd_wrapper, constants.CMD_ATTR_PRESERVE_QUOTES, preserve_quotes)

        return cmd_wrapper

    # noinspection PyTypeChecker
    return arg_decorator


def as_subcommand_to(
    command: str,
    subcommand: str,
    parser: argparse.ArgumentParser,
    *,
    help: Optional[str] = None,
    aliases: Optional[List[str]] = None,
) -> Callable[[ArgparseCommandFunc], ArgparseCommandFunc]:
    """
    Tag this method as a subcommand to an existing argparse decorated command.

    :param command: Command Name. Space-delimited subcommands may optionally be specified
    :param subcommand: Subcommand name
    :param parser: argparse Parser for this subcommand
    :param help: Help message for this subcommand which displays in the list of subcommands of the command we are adding to.
                 This is passed as the help argument to ArgumentParser.add_subparser().
    :param aliases: Alternative names for this subcommand. This is passed as the alias argument to
                    ArgumentParser.add_subparser().
    :return: Wrapper function that can receive an argparse.Namespace
    """

    def arg_decorator(func: ArgparseCommandFunc) -> ArgparseCommandFunc:
        _set_parser_prog(parser, command + ' ' + subcommand)

        # If the description has not been set, then use the method docstring if one exists
        if parser.description is None and func.__doc__:
            parser.description = func.__doc__

        # Set some custom attributes for this command
        setattr(func, constants.SUBCMD_ATTR_COMMAND, command)
        setattr(func, constants.CMD_ATTR_ARGPARSER, parser)
        setattr(func, constants.SUBCMD_ATTR_NAME, subcommand)

        # Keyword arguments for ArgumentParser.add_subparser()
        add_parser_kwargs: Dict[str, Any] = dict()
        if help is not None:
            add_parser_kwargs['help'] = help
        if aliases:
            add_parser_kwargs['aliases'] = aliases[:]

        setattr(func, constants.SUBCMD_ATTR_ADD_PARSER_KWARGS, add_parser_kwargs)

        return func

    # noinspection PyTypeChecker
    return arg_decorator
