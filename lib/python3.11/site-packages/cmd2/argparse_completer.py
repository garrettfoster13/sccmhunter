# coding=utf-8
# flake8: noqa C901
# NOTE: Ignoring flake8 cyclomatic complexity in this file
"""
This module defines the ArgparseCompleter class which provides argparse-based tab completion to cmd2 apps.
See the header of argparse_custom.py for instructions on how to use these features.
"""

import argparse
import inspect
import numbers
from collections import (
    deque,
)
from typing import (
    TYPE_CHECKING,
    Dict,
    List,
    Optional,
    Type,
    Union,
    cast,
)

from .ansi import (
    style_aware_wcswidth,
    widest_line,
)
from .constants import (
    INFINITY,
)

if TYPE_CHECKING:  # pragma: no cover
    from .cmd2 import (
        Cmd,
    )

from .argparse_custom import (
    ChoicesCallable,
    ChoicesProviderFuncWithTokens,
    CompletionItem,
    generate_range_error,
)
from .command_definition import (
    CommandSet,
)
from .exceptions import (
    CompletionError,
)
from .table_creator import (
    Column,
    HorizontalAlignment,
    SimpleTable,
)

# If no descriptive header is supplied, then this will be used instead
DEFAULT_DESCRIPTIVE_HEADER = 'Description'

# Name of the choice/completer function argument that, if present, will be passed a dictionary of
# command line tokens up through the token being completed mapped to their argparse destination name.
ARG_TOKENS = 'arg_tokens'


# noinspection PyProtectedMember
def _build_hint(parser: argparse.ArgumentParser, arg_action: argparse.Action) -> str:
    """Build tab completion hint for a given argument"""
    # Check if hinting is disabled for this argument
    suppress_hint = arg_action.get_suppress_tab_hint()  # type: ignore[attr-defined]
    if suppress_hint or arg_action.help == argparse.SUPPRESS:
        return ''
    else:
        # Use the parser's help formatter to display just this action's help text
        formatter = parser._get_formatter()
        formatter.start_section("Hint")
        formatter.add_argument(arg_action)
        formatter.end_section()
        return formatter.format_help()


def _single_prefix_char(token: str, parser: argparse.ArgumentParser) -> bool:
    """Returns if a token is just a single flag prefix character"""
    return len(token) == 1 and token[0] in parser.prefix_chars


# noinspection PyProtectedMember
def _looks_like_flag(token: str, parser: argparse.ArgumentParser) -> bool:
    """
    Determine if a token looks like a flag. Unless an argument has nargs set to argparse.REMAINDER,
    then anything that looks like a flag can't be consumed as a value for it.
    Based on argparse._parse_optional().
    """
    # Flags have to be at least characters
    if len(token) < 2:
        return False

    # Flags have to start with a prefix character
    if not token[0] in parser.prefix_chars:
        return False

    # If it looks like a negative number, it is not a flag unless there are negative-number-like flags
    if parser._negative_number_matcher.match(token):
        if not parser._has_negative_number_optionals:
            return False

    # Flags can't have a space
    if ' ' in token:
        return False

    # Starts like a flag
    return True


class _ArgumentState:
    """Keeps state of an argument being parsed"""

    def __init__(self, arg_action: argparse.Action) -> None:
        self.action = arg_action
        self.min: Union[int, str]
        self.max: Union[float, int, str]
        self.count = 0
        self.is_remainder = self.action.nargs == argparse.REMAINDER

        # Check if nargs is a range
        nargs_range = self.action.get_nargs_range()  # type: ignore[attr-defined]
        if nargs_range is not None:
            self.min = nargs_range[0]
            self.max = nargs_range[1]

        # Otherwise check against argparse types
        elif self.action.nargs is None:
            self.min = 1
            self.max = 1
        elif self.action.nargs == argparse.OPTIONAL:
            self.min = 0
            self.max = 1
        elif self.action.nargs == argparse.ZERO_OR_MORE or self.action.nargs == argparse.REMAINDER:
            self.min = 0
            self.max = INFINITY
        elif self.action.nargs == argparse.ONE_OR_MORE:
            self.min = 1
            self.max = INFINITY
        else:
            self.min = self.action.nargs
            self.max = self.action.nargs


# noinspection PyProtectedMember
class _UnfinishedFlagError(CompletionError):
    def __init__(self, flag_arg_state: _ArgumentState) -> None:
        """
        CompletionError which occurs when the user has not finished the current flag
        :param flag_arg_state: information about the unfinished flag action
        """
        error = "Error: argument {}: {} ({} entered)".format(
            argparse._get_action_name(flag_arg_state.action),
            generate_range_error(cast(int, flag_arg_state.min), cast(Union[int, float], flag_arg_state.max)),
            flag_arg_state.count,
        )
        super().__init__(error)


class _NoResultsError(CompletionError):
    def __init__(self, parser: argparse.ArgumentParser, arg_action: argparse.Action) -> None:
        """
        CompletionError which occurs when there are no results. If hinting is allowed, then its message will
        be a hint about the argument being tab completed.
        :param parser: ArgumentParser instance which owns the action being tab completed
        :param arg_action: action being tab completed
        """
        # Set apply_style to False because we don't want hints to look like errors
        super().__init__(_build_hint(parser, arg_action), apply_style=False)


# noinspection PyProtectedMember
class ArgparseCompleter:
    """Automatic command line tab completion based on argparse parameters"""

    def __init__(
        self, parser: argparse.ArgumentParser, cmd2_app: 'Cmd', *, parent_tokens: Optional[Dict[str, List[str]]] = None
    ) -> None:
        """
        Create an ArgparseCompleter

        :param parser: ArgumentParser instance
        :param cmd2_app: reference to the Cmd2 application that owns this ArgparseCompleter
        :param parent_tokens: optional dictionary mapping parent parsers' arg names to their tokens
                              This is only used by ArgparseCompleter when recursing on subcommand parsers
                              Defaults to None
        """
        self._parser = parser
        self._cmd2_app = cmd2_app

        if parent_tokens is None:
            parent_tokens = dict()
        self._parent_tokens = parent_tokens

        self._flags = []  # all flags in this command
        self._flag_to_action = {}  # maps flags to the argparse action object
        self._positional_actions = []  # actions for positional arguments (by position index)
        self._subcommand_action = None  # this will be set if self._parser has subcommands

        # Start digging through the argparse structures.
        # _actions is the top level container of parameter definitions
        for action in self._parser._actions:
            # if the parameter is flag based, it will have option_strings
            if action.option_strings:
                # record each option flag
                for option in action.option_strings:
                    self._flags.append(option)
                    self._flag_to_action[option] = action

            # Otherwise this is a positional parameter
            else:
                self._positional_actions.append(action)
                # Check if this action defines subcommands
                if isinstance(action, argparse._SubParsersAction):
                    self._subcommand_action = action

    def complete(
        self, text: str, line: str, begidx: int, endidx: int, tokens: List[str], *, cmd_set: Optional[CommandSet] = None
    ) -> List[str]:
        """
        Complete text using argparse metadata

        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param tokens: list of argument tokens being passed to the parser
        :param cmd_set: if tab completing a command, the CommandSet the command's function belongs to, if applicable.
                        Defaults to None.

        :raises: CompletionError for various types of tab completion errors
        """
        if not tokens:
            return []

        # Positionals args that are left to parse
        remaining_positionals = deque(self._positional_actions)

        # This gets set to True when flags will no longer be processed as argparse flags
        # That can happen when -- is used or an argument with nargs=argparse.REMAINDER is used
        skip_remaining_flags = False

        # _ArgumentState of the current positional
        pos_arg_state: Optional[_ArgumentState] = None

        # _ArgumentState of the current flag
        flag_arg_state: Optional[_ArgumentState] = None

        # Non-reusable flags that we've parsed
        matched_flags: List[str] = []

        # Keeps track of arguments we've seen and any tokens they consumed
        consumed_arg_values: Dict[str, List[str]] = dict()  # dict(arg_name -> List[tokens])

        # Completed mutually exclusive groups
        completed_mutex_groups: Dict[argparse._MutuallyExclusiveGroup, argparse.Action] = dict()

        def consume_argument(arg_state: _ArgumentState) -> None:
            """Consuming token as an argument"""
            arg_state.count += 1
            consumed_arg_values.setdefault(arg_state.action.dest, [])
            consumed_arg_values[arg_state.action.dest].append(token)

        def update_mutex_groups(arg_action: argparse.Action) -> None:
            """
            Check if an argument belongs to a mutually exclusive group and either mark that group
            as complete or print an error if the group has already been completed
            :param arg_action: the action of the argument
            :raises: CompletionError if the group is already completed
            """
            # Check if this action is in a mutually exclusive group
            for group in self._parser._mutually_exclusive_groups:
                if arg_action in group._group_actions:

                    # Check if the group this action belongs to has already been completed
                    if group in completed_mutex_groups:

                        # If this is the action that completed the group, then there is no error
                        # since it's allowed to appear on the command line more than once.
                        completer_action = completed_mutex_groups[group]
                        if arg_action == completer_action:
                            return

                        error = "Error: argument {}: not allowed with argument {}".format(
                            argparse._get_action_name(arg_action), argparse._get_action_name(completer_action)
                        )
                        raise CompletionError(error)

                    # Mark that this action completed the group
                    completed_mutex_groups[group] = arg_action

                    # Don't tab complete any of the other args in the group
                    for group_action in group._group_actions:
                        if group_action == arg_action:
                            continue
                        elif group_action in self._flag_to_action.values():
                            matched_flags.extend(group_action.option_strings)
                        elif group_action in remaining_positionals:
                            remaining_positionals.remove(group_action)

                    # Arg can only be in one group, so we are done
                    break

        #############################################################################################
        # Parse all but the last token
        #############################################################################################
        for token_index, token in enumerate(tokens[:-1]):

            # If we're in a positional REMAINDER arg, force all future tokens to go to that
            if pos_arg_state is not None and pos_arg_state.is_remainder:
                consume_argument(pos_arg_state)
                continue

            # If we're in a flag REMAINDER arg, force all future tokens to go to that until a double dash is hit
            elif flag_arg_state is not None and flag_arg_state.is_remainder:
                if token == '--':
                    flag_arg_state = None
                else:
                    consume_argument(flag_arg_state)
                continue

            # Handle '--' which tells argparse all remaining arguments are non-flags
            elif token == '--' and not skip_remaining_flags:
                # Check if there is an unfinished flag
                if (
                    flag_arg_state is not None
                    and isinstance(flag_arg_state.min, int)
                    and flag_arg_state.count < flag_arg_state.min
                ):
                    raise _UnfinishedFlagError(flag_arg_state)

                # Otherwise end the current flag
                else:
                    flag_arg_state = None
                    skip_remaining_flags = True
                    continue

            # Check the format of the current token to see if it can be an argument's value
            if _looks_like_flag(token, self._parser) and not skip_remaining_flags:

                # Check if there is an unfinished flag
                if (
                    flag_arg_state is not None
                    and isinstance(flag_arg_state.min, int)
                    and flag_arg_state.count < flag_arg_state.min
                ):
                    raise _UnfinishedFlagError(flag_arg_state)

                # Reset flag arg state but not positional tracking because flags can be
                # interspersed anywhere between positionals
                flag_arg_state = None
                action = None

                # Does the token match a known flag?
                if token in self._flag_to_action:
                    action = self._flag_to_action[token]
                elif self._parser.allow_abbrev:
                    candidates_flags = [flag for flag in self._flag_to_action if flag.startswith(token)]
                    if len(candidates_flags) == 1:
                        action = self._flag_to_action[candidates_flags[0]]

                if action is not None:
                    update_mutex_groups(action)
                    if isinstance(action, (argparse._AppendAction, argparse._AppendConstAction, argparse._CountAction)):
                        # Flags with action set to append, append_const, and count can be reused
                        # Therefore don't erase any tokens already consumed for this flag
                        consumed_arg_values.setdefault(action.dest, [])
                    else:
                        # This flag is not reusable, so mark that we've seen it
                        matched_flags.extend(action.option_strings)

                        # It's possible we already have consumed values for this flag if it was used
                        # earlier in the command line. Reset them now for this use of it.
                        consumed_arg_values[action.dest] = []

                    new_arg_state = _ArgumentState(action)

                    # Keep track of this flag if it can receive arguments
                    if new_arg_state.max > 0:  # type: ignore[operator]
                        flag_arg_state = new_arg_state
                        skip_remaining_flags = flag_arg_state.is_remainder

            # Check if we are consuming a flag
            elif flag_arg_state is not None:
                consume_argument(flag_arg_state)

                # Check if we have finished with this flag
                if isinstance(flag_arg_state.max, (float, int)) and flag_arg_state.count >= flag_arg_state.max:
                    flag_arg_state = None

            # Otherwise treat as a positional argument
            else:
                # If we aren't current tracking a positional, then get the next positional arg to handle this token
                if pos_arg_state is None:
                    # Make sure we are still have positional arguments to parse
                    if remaining_positionals:
                        action = remaining_positionals.popleft()

                        # Are we at a subcommand? If so, forward to the matching completer
                        if action == self._subcommand_action:
                            if token in self._subcommand_action.choices:
                                # Merge self._parent_tokens and consumed_arg_values
                                parent_tokens = {**self._parent_tokens, **consumed_arg_values}

                                # Include the subcommand name if its destination was set
                                if action.dest != argparse.SUPPRESS:
                                    parent_tokens[action.dest] = [token]

                                parser: argparse.ArgumentParser = self._subcommand_action.choices[token]
                                completer_type = self._cmd2_app._determine_ap_completer_type(parser)

                                completer = completer_type(parser, self._cmd2_app, parent_tokens=parent_tokens)

                                return completer.complete(
                                    text, line, begidx, endidx, tokens[token_index + 1 :], cmd_set=cmd_set
                                )
                            else:
                                # Invalid subcommand entered, so no way to complete remaining tokens
                                return []

                        # Otherwise keep track of the argument
                        else:
                            pos_arg_state = _ArgumentState(action)

                # Check if we have a positional to consume this token
                if pos_arg_state is not None:
                    update_mutex_groups(pos_arg_state.action)
                    consume_argument(pos_arg_state)

                    # No more flags are allowed if this is a REMAINDER argument
                    if pos_arg_state.is_remainder:
                        skip_remaining_flags = True

                    # Check if we have finished with this positional
                    elif isinstance(pos_arg_state.max, (float, int)) and pos_arg_state.count >= pos_arg_state.max:
                        pos_arg_state = None

                        # Check if the next positional has nargs set to argparse.REMAINDER.
                        # At this point argparse allows no more flags to be processed.
                        if remaining_positionals and remaining_positionals[0].nargs == argparse.REMAINDER:
                            skip_remaining_flags = True

        #############################################################################################
        # We have parsed all but the last token and have enough information to complete it
        #############################################################################################

        # Check if we are completing a flag name. This check ignores strings with a length of one, like '-'.
        # This is because that could be the start of a negative number which may be a valid completion for
        # the current argument. We will handle the completion of flags that start with only one prefix
        # character (-f) at the end.
        if _looks_like_flag(text, self._parser) and not skip_remaining_flags:
            if (
                flag_arg_state is not None
                and isinstance(flag_arg_state.min, int)
                and flag_arg_state.count < flag_arg_state.min
            ):
                raise _UnfinishedFlagError(flag_arg_state)
            return self._complete_flags(text, line, begidx, endidx, matched_flags)

        completion_results = []

        # Check if we are completing a flag's argument
        if flag_arg_state is not None:
            completion_results = self._complete_arg(
                text, line, begidx, endidx, flag_arg_state, consumed_arg_values, cmd_set=cmd_set
            )

            # If we have results, then return them
            if completion_results:
                # Don't overwrite an existing hint
                if not self._cmd2_app.completion_hint:
                    self._cmd2_app.completion_hint = _build_hint(self._parser, flag_arg_state.action)
                return completion_results

            # Otherwise, print a hint if the flag isn't finished or text isn't possibly the start of a flag
            elif (
                (isinstance(flag_arg_state.min, int) and flag_arg_state.count < flag_arg_state.min)
                or not _single_prefix_char(text, self._parser)
                or skip_remaining_flags
            ):
                raise _NoResultsError(self._parser, flag_arg_state.action)

        # Otherwise check if we have a positional to complete
        elif pos_arg_state is not None or remaining_positionals:

            # If we aren't current tracking a positional, then get the next positional arg to handle this token
            if pos_arg_state is None:
                action = remaining_positionals.popleft()
                pos_arg_state = _ArgumentState(action)

            completion_results = self._complete_arg(
                text, line, begidx, endidx, pos_arg_state, consumed_arg_values, cmd_set=cmd_set
            )

            # If we have results, then return them
            if completion_results:
                # Don't overwrite an existing hint
                if not self._cmd2_app.completion_hint:
                    self._cmd2_app.completion_hint = _build_hint(self._parser, pos_arg_state.action)
                return completion_results

            # Otherwise, print a hint if text isn't possibly the start of a flag
            elif not _single_prefix_char(text, self._parser) or skip_remaining_flags:
                raise _NoResultsError(self._parser, pos_arg_state.action)

        # If we aren't skipping remaining flags, then complete flag names if either is True:
        #   1. text is a single flag prefix character that didn't complete against any argument values
        #   2. there are no more positionals to complete
        if not skip_remaining_flags and (_single_prefix_char(text, self._parser) or not remaining_positionals):
            # Reset any completion settings that may have been set by functions which actually had no matches.
            # Otherwise, those settings could alter how the flags are displayed.
            self._cmd2_app._reset_completion_defaults()
            return self._complete_flags(text, line, begidx, endidx, matched_flags)

        return completion_results

    def _complete_flags(self, text: str, line: str, begidx: int, endidx: int, matched_flags: List[str]) -> List[str]:
        """Tab completion routine for a parsers unused flags"""

        # Build a list of flags that can be tab completed
        match_against = []

        for flag in self._flags:
            # Make sure this flag hasn't already been used
            if flag not in matched_flags:
                # Make sure this flag isn't considered hidden
                action = self._flag_to_action[flag]
                if action.help != argparse.SUPPRESS:
                    match_against.append(flag)

        matches = self._cmd2_app.basic_complete(text, line, begidx, endidx, match_against)

        # Build a dictionary linking actions with their matched flag names
        matched_actions: Dict[argparse.Action, List[str]] = dict()
        for flag in matches:
            action = self._flag_to_action[flag]
            matched_actions.setdefault(action, [])
            matched_actions[action].append(flag)

        # For tab completion suggestions, group matched flags by action
        for action, option_strings in matched_actions.items():
            flag_text = ', '.join(option_strings)

            # Mark optional flags with brackets
            if not action.required:
                flag_text = '[' + flag_text + ']'
            self._cmd2_app.display_matches.append(flag_text)

        return matches

    def _format_completions(self, arg_state: _ArgumentState, completions: Union[List[str], List[CompletionItem]]) -> List[str]:
        """Format CompletionItems into hint table"""

        # Nothing to do if we don't have at least 2 completions which are all CompletionItems
        if len(completions) < 2 or not all(isinstance(c, CompletionItem) for c in completions):
            return cast(List[str], completions)

        completion_items = cast(List[CompletionItem], completions)

        # Check if the data being completed have a numerical type
        all_nums = all(isinstance(c.orig_value, numbers.Number) for c in completion_items)

        # Sort CompletionItems before building the hint table
        if not self._cmd2_app.matches_sorted:
            # If all orig_value types are numbers, then sort by that value
            if all_nums:
                completion_items.sort(key=lambda c: c.orig_value)  # type: ignore[no-any-return]

            # Otherwise sort as strings
            else:
                completion_items.sort(key=self._cmd2_app.default_sort_key)

            self._cmd2_app.matches_sorted = True

        # Check if there are too many CompletionItems to display as a table
        if len(completions) <= self._cmd2_app.max_completion_items:
            four_spaces = 4 * ' '

            # If a metavar was defined, use that instead of the dest field
            destination = arg_state.action.metavar if arg_state.action.metavar else arg_state.action.dest

            # Handle case where metavar was a tuple
            if isinstance(destination, tuple):
                # Figure out what string in the tuple to use based on how many of the arguments have been completed.
                # Use min() to avoid going passed the end of the tuple to support nargs being ZERO_OR_MORE and
                # ONE_OR_MORE. In those cases, argparse limits metavar tuple to 2 elements but we may be completing
                # the 3rd or more argument here.
                tuple_index = min(len(destination) - 1, arg_state.count)
                destination = destination[tuple_index]

            desc_header = arg_state.action.get_descriptive_header()  # type: ignore[attr-defined]
            if desc_header is None:
                desc_header = DEFAULT_DESCRIPTIVE_HEADER

            # Replace tabs with 4 spaces so we can calculate width
            desc_header = desc_header.replace('\t', four_spaces)

            # Calculate needed widths for the token and description columns of the table
            token_width = style_aware_wcswidth(destination)
            desc_width = widest_line(desc_header)

            for item in completion_items:
                token_width = max(style_aware_wcswidth(item), token_width)

                # Replace tabs with 4 spaces so we can calculate width
                item.description = item.description.replace('\t', four_spaces)
                desc_width = max(widest_line(item.description), desc_width)

            cols = list()
            dest_alignment = HorizontalAlignment.RIGHT if all_nums else HorizontalAlignment.LEFT
            cols.append(
                Column(
                    destination.upper(),
                    width=token_width,
                    header_horiz_align=dest_alignment,
                    data_horiz_align=dest_alignment,
                )
            )
            cols.append(Column(desc_header, width=desc_width))

            hint_table = SimpleTable(cols, divider_char=self._cmd2_app.ruler)
            table_data = [[item, item.description] for item in completion_items]
            self._cmd2_app.formatted_completions = hint_table.generate_table(table_data, row_spacing=0)

        # Return sorted list of completions
        return cast(List[str], completions)

    def complete_subcommand_help(self, text: str, line: str, begidx: int, endidx: int, tokens: List[str]) -> List[str]:
        """
        Supports cmd2's help command in the completion of subcommand names
        :param text: the string prefix we are attempting to match (all matches must begin with it)
        :param line: the current input line with leading whitespace removed
        :param begidx: the beginning index of the prefix text
        :param endidx: the ending index of the prefix text
        :param tokens: arguments passed to command/subcommand
        :return: List of subcommand completions
        """
        # If our parser has subcommands, we must examine the tokens and check if they are subcommands
        # If so, we will let the subcommand's parser handle the rest of the tokens via another ArgparseCompleter.
        if self._subcommand_action is not None:
            for token_index, token in enumerate(tokens):
                if token in self._subcommand_action.choices:
                    parser: argparse.ArgumentParser = self._subcommand_action.choices[token]
                    completer_type = self._cmd2_app._determine_ap_completer_type(parser)

                    completer = completer_type(parser, self._cmd2_app)
                    return completer.complete_subcommand_help(text, line, begidx, endidx, tokens[token_index + 1 :])
                elif token_index == len(tokens) - 1:
                    # Since this is the last token, we will attempt to complete it
                    return self._cmd2_app.basic_complete(text, line, begidx, endidx, self._subcommand_action.choices)
                else:
                    break
        return []

    def format_help(self, tokens: List[str]) -> str:
        """
        Supports cmd2's help command in the retrieval of help text
        :param tokens: arguments passed to help command
        :return: help text of the command being queried
        """
        # If our parser has subcommands, we must examine the tokens and check if they are subcommands
        # If so, we will let the subcommand's parser handle the rest of the tokens via another ArgparseCompleter.
        if self._subcommand_action is not None:
            for token_index, token in enumerate(tokens):
                if token in self._subcommand_action.choices:
                    parser: argparse.ArgumentParser = self._subcommand_action.choices[token]
                    completer_type = self._cmd2_app._determine_ap_completer_type(parser)

                    completer = completer_type(parser, self._cmd2_app)
                    return completer.format_help(tokens[token_index + 1 :])
                else:
                    break
        return self._parser.format_help()

    def _complete_arg(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
        arg_state: _ArgumentState,
        consumed_arg_values: Dict[str, List[str]],
        *,
        cmd_set: Optional[CommandSet] = None,
    ) -> List[str]:
        """
        Tab completion routine for an argparse argument
        :return: list of completions
        :raises: CompletionError if the completer or choices function this calls raises one
        """
        # Check if the arg provides choices to the user
        arg_choices: Union[List[str], ChoicesCallable]
        if arg_state.action.choices is not None:
            arg_choices = list(arg_state.action.choices)
            if not arg_choices:
                return []

            # If these choices are numbers, then sort them now
            if all(isinstance(x, numbers.Number) for x in arg_choices):
                arg_choices.sort()
                self._cmd2_app.matches_sorted = True

            # Since choices can be various types, make sure they are all strings
            for index, choice in enumerate(arg_choices):
                # Prevent converting anything that is already a str (i.e. CompletionItem)
                if not isinstance(choice, str):
                    arg_choices[index] = str(choice)  # type: ignore[unreachable]
        else:
            choices_attr = arg_state.action.get_choices_callable()  # type: ignore[attr-defined]
            if choices_attr is None:
                return []
            arg_choices = choices_attr

        # If we are going to call a completer/choices function, then set up the common arguments
        args = []
        kwargs = {}
        if isinstance(arg_choices, ChoicesCallable):
            # The completer may or may not be defined in the same class as the command. Since completer
            # functions are registered with the command argparser before anything is instantiated, we
            # need to find an instance at runtime that matches the types during declaration
            self_arg = self._cmd2_app._resolve_func_self(arg_choices.to_call, cmd_set)
            if self_arg is None:
                # No cases matched, raise an error
                raise CompletionError('Could not find CommandSet instance matching defining type for completer')

            args.append(self_arg)

            # Check if arg_choices.to_call expects arg_tokens
            to_call_params = inspect.signature(arg_choices.to_call).parameters
            if ARG_TOKENS in to_call_params:
                # Merge self._parent_tokens and consumed_arg_values
                arg_tokens = {**self._parent_tokens, **consumed_arg_values}

                # Include the token being completed
                arg_tokens.setdefault(arg_state.action.dest, [])
                arg_tokens[arg_state.action.dest].append(text)

                # Add the namespace to the keyword arguments for the function we are calling
                kwargs[ARG_TOKENS] = arg_tokens

        # Check if the argument uses a specific tab completion function to provide its choices
        if isinstance(arg_choices, ChoicesCallable) and arg_choices.is_completer:
            args.extend([text, line, begidx, endidx])
            results = arg_choices.completer(*args, **kwargs)  # type: ignore[arg-type]

        # Otherwise use basic_complete on the choices
        else:
            # Check if the choices come from a function
            completion_items: List[str] = []
            if isinstance(arg_choices, ChoicesCallable):
                if not arg_choices.is_completer:
                    choices_func = arg_choices.choices_provider
                    if isinstance(choices_func, ChoicesProviderFuncWithTokens):
                        completion_items = choices_func(*args, **kwargs)  # type: ignore[arg-type]
                    else:  # pragma: no cover
                        # This won't hit because runtime checking doesn't check function argument types and will always
                        # resolve true above. Mypy, however, does see the difference and gives an error that can't be
                        # ignored. Mypy issue #5485 discusses this problem
                        completion_items = choices_func(*args)  # type: ignore[arg-type]
                # else case is already covered above
            else:
                completion_items = arg_choices

            # Filter out arguments we already used
            used_values = consumed_arg_values.get(arg_state.action.dest, [])
            completion_items = [choice for choice in completion_items if choice not in used_values]

            # Do tab completion on the choices
            results = self._cmd2_app.basic_complete(text, line, begidx, endidx, completion_items)

        if not results:
            # Reset the value for matches_sorted. This is because completion of flag names
            # may still be attempted after we return and they haven't been sorted yet.
            self._cmd2_app.matches_sorted = False
            return []

        return self._format_completions(arg_state, results)


# The default ArgparseCompleter class for a cmd2 app
DEFAULT_AP_COMPLETER: Type[ArgparseCompleter] = ArgparseCompleter


def set_default_ap_completer_type(completer_type: Type[ArgparseCompleter]) -> None:
    """
    Set the default ArgparseCompleter class for a cmd2 app.

    :param completer_type: Type that is a subclass of ArgparseCompleter.
    """
    global DEFAULT_AP_COMPLETER
    DEFAULT_AP_COMPLETER = completer_type
