# coding=utf-8
"""
This module adds capabilities to argparse by patching a few of its functions.
It also defines a parser class called Cmd2ArgumentParser which improves error
and help output over normal argparse. All cmd2 code uses this parser and it is
recommended that developers of cmd2-based apps either use it or write their own
parser that inherits from it. This will give a consistent look-and-feel between
the help/error output of built-in cmd2 commands and the app-specific commands.
If you wish to override the parser used by cmd2's built-in commands, see
override_parser.py example.

Since the new capabilities are added by patching at the argparse API level,
they are available whether or not Cmd2ArgumentParser is used. However, the help
and error output of Cmd2ArgumentParser is customized to notate nargs ranges
whereas any other parser class won't be as explicit in their output.


**Added capabilities**

Extends argparse nargs functionality by allowing tuples which specify a range
(min, max). To specify a max value with no upper bound, use a 1-item tuple
(min,)

Example::

    # -f argument expects at least 3 values
    parser.add_argument('-f', nargs=(3,))

    # -f argument expects 3 to 5 values
    parser.add_argument('-f', nargs=(3, 5))


**Tab Completion**

cmd2 uses its ArgparseCompleter class to enable argparse-based tab completion
on all commands that use the @with_argparse wrappers. Out of the box you get
tab completion of commands, subcommands, and flag names, as well as instructive
hints about the current argument that print when tab is pressed. In addition,
you can add tab completion for each argument's values using parameters passed
to add_argument().

Below are the 3 add_argument() parameters for enabling tab completion of an
argument's value. Only one can be used at a time.

``choices`` - pass a list of values to the choices parameter.

    Example::

        my_list = ['An Option', 'SomeOtherOption']
        parser.add_argument('-o', '--options', choices=my_list)

``choices_provider`` - pass a function that returns choices. This is good in
cases where the choice list is dynamically generated when the user hits tab.

    Example::

        def my_choices_provider(self):
            ...
            return my_generated_list

        parser.add_argument("arg", choices_provider=my_choices_provider)

``completer`` - pass a tab completion function that does custom completion.

cmd2 provides a few completer methods for convenience (e.g., path_complete,
delimiter_complete)

    Example::

        # This adds file-path completion to an argument
        parser.add_argument('-o', '--options', completer=cmd2.Cmd.path_complete)

    You can use functools.partial() to prepopulate values of the underlying
    choices and completer functions/methods.

    Example::

        # This says to call path_complete with a preset value for its path_filter argument
        dir_completer = functools.partial(path_complete,
                                          path_filter=lambda path: os.path.isdir(path))
        parser.add_argument('-o', '--options', completer=dir_completer)

For ``choices_provider`` and ``completer``, do not set them to a bound method. This
is because ArgparseCompleter passes the `self` argument explicitly to these
functions. When ArgparseCompleter calls one, it will detect whether it is bound
to a `Cmd` subclass or `CommandSet`. If bound to a `cmd2.Cmd subclass`, it will
pass the app instance as the `self` argument. If bound to a `cmd2.CommandSet`
subclass, it will pass the `CommandSet` instance as the `self` argument.
Therefore instead of passing something like `self.path_complete`, pass
`cmd2.Cmd.path_complete`.

``choices_provider`` and ``completer`` functions can also be implemented as
standalone functions (i.e. not a member of a class). In this case,
ArgparseCompleter will pass its ``cmd2.Cmd`` app instance as the first
positional argument.

Of the 3 tab completion parameters, ``choices`` is the only one where argparse
validates user input against items in the choices list. This is because the
other 2 parameters are meant to tab complete data sets that are viewed as
dynamic. Therefore it is up to the developer to validate if the user has typed
an acceptable value for these arguments.

There are times when what's being tab completed is determined by a previous
argument on the command line. In theses cases, ArgparseCompleter can pass a
dictionary that maps the command line tokens up through the one being completed
to their argparse argument name. To receive this dictionary, your
choices/completer function should have an argument called arg_tokens.

    Example::

        def my_choices_provider(self, arg_tokens)
        def my_completer(self, text, line, begidx, endidx, arg_tokens)

All values of the arg_tokens dictionary are lists, even if a particular
argument expects only 1 token. Since ArgparseCompleter is for tab completion,
it does not convert the tokens to their actual argument types or validate their
values. All tokens are stored in the dictionary as the raw strings provided on
the command line. It is up to the developer to determine if the user entered
the correct argument type (e.g. int) and validate their values.

CompletionItem Class - This class was added to help in cases where
uninformative data is being tab completed. For instance, tab completing ID
numbers isn't very helpful to a user without context. Returning a list of
CompletionItems instead of a regular string for completion results will signal
the ArgparseCompleter to output the completion results in a table of completion
tokens with descriptions instead of just a table of tokens::

    Instead of this:
        1     2     3

    The user sees this:
        ITEM_ID     Item Name
        ============================
        1           My item
        2           Another item
        3           Yet another item


The left-most column is the actual value being tab completed and its header is
that value's name. The right column header is defined using the
descriptive_header parameter of add_argument(). The right column values come
from the CompletionItem.description value.

Example::

    token = 1
    token_description = "My Item"
    completion_item = CompletionItem(token, token_description)

Since descriptive_header and CompletionItem.description are just strings, you
can format them in such a way to have multiple columns::

    ITEM_ID     Item Name            Checked Out    Due Date
    ==========================================================
    1           My item              True           02/02/2022
    2           Another item         False
    3           Yet another item     False

To use CompletionItems, just return them from your choices_provider or
completer functions. They can also be used as argparse choices. When a
CompletionItem is created, it stores the original value (e.g. ID number) and
makes it accessible through a property called orig_value. cmd2 has patched
argparse so that when evaluating choices, input is compared to
CompletionItem.orig_value instead of the CompletionItem instance.

To avoid printing a ton of information to the screen at once when a user
presses tab, there is a maximum threshold for the number of CompletionItems
that will be shown. Its value is defined in cmd2.Cmd.max_completion_items. It
defaults to 50, but can be changed. If the number of completion suggestions
exceeds this number, they will be displayed in the typical columnized format
and will not include the description value of the CompletionItems.


**Patched argparse functions**

``argparse._ActionsContainer.add_argument`` - adds arguments related to tab
completion and enables nargs range parsing. See _add_argument_wrapper for
more details on these arguments.

``argparse.ArgumentParser._check_value`` - adds support for using
``CompletionItems`` as argparse choices. When evaluating choices, input is
compared to ``CompletionItem.orig_value`` instead of the ``CompletionItem``
instance.
See _ArgumentParser_check_value for more details.

``argparse.ArgumentParser._get_nargs_pattern`` - adds support for nargs ranges.
See _get_nargs_pattern_wrapper for more details.

``argparse.ArgumentParser._match_argument`` - adds support for nargs ranges.
See _match_argument_wrapper for more details.

``argparse._SubParsersAction.remove_parser`` - new function which removes a
sub-parser from a sub-parsers group. See _SubParsersAction_remove_parser for
more details.

**Added accessor methods**

cmd2 has patched ``argparse.Action`` to include the following accessor methods
for cases in which you need to manually access the cmd2-specific attributes.

- ``argparse.Action.get_choices_callable()`` - See
  :func:`_action_get_choices_callable` for more details.
- ``argparse.Action.set_choices_provider()`` - See
  :func:`_action_set_choices_provider` for more details.
- ``argparse.Action.set_completer()`` - See
  :func:`_action_set_completer` for more details.
- ``argparse.Action.get_descriptive_header()`` - See
  :func:`_action_get_descriptive_header` for more details.
- ``argparse.Action.set_descriptive_header()`` - See
  :func:`_action_set_descriptive_header` for more details.
- ``argparse.Action.get_nargs_range()`` - See
  :func:`_action_get_nargs_range` for more details.
- ``argparse.Action.set_nargs_range()`` - See
  :func:`_action_set_nargs_range` for more details.
- ``argparse.Action.get_suppress_tab_hint()`` - See
  :func:`_action_get_suppress_tab_hint` for more details.
- ``argparse.Action.set_suppress_tab_hint()`` - See
  :func:`_action_set_suppress_tab_hint` for more details.

cmd2 has patched ``argparse.ArgumentParser`` to include the following accessor methods

- ``argparse.ArgumentParser.get_ap_completer_type()`` - See
  :func:`_ArgumentParser_get_ap_completer_type` for more details.
- ``argparse.Action.set_ap_completer_type()`` - See
  :func:`_ArgumentParser_set_ap_completer_type` for more details.

**Subcommand removal**

cmd2 has patched ``argparse._SubParsersAction`` to include a ``remove_parser()``
method which can be used to remove a subcommand.

``argparse._SubParsersAction.remove_parser`` - new function which removes a
sub-parser from a sub-parsers group. See
:func:`_SubParsersAction_remove_parser` for more details.
"""

import argparse
import re
import sys

# noinspection PyUnresolvedReferences,PyProtectedMember
from argparse import (
    ONE_OR_MORE,
    ZERO_OR_MORE,
    ArgumentError,
)
from gettext import (
    gettext,
)
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NoReturn,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    Union,
    cast,
)

from . import (
    ansi,
    constants,
)

try:
    from typing import (
        Protocol,
        runtime_checkable,
    )
except ImportError:
    from typing_extensions import (  # type: ignore[assignment]
        Protocol,
        runtime_checkable,
    )


if TYPE_CHECKING:  # pragma: no cover
    from .argparse_completer import (
        ArgparseCompleter,
    )


def generate_range_error(range_min: int, range_max: Union[int, float]) -> str:
    """Generate an error message when the the number of arguments provided is not within the expected range"""
    err_str = "expected "

    if range_max == constants.INFINITY:
        plural = '' if range_min == 1 else 's'
        err_str += f"at least {range_min}"
    else:
        plural = '' if range_max == 1 else 's'
        if range_min == range_max:
            err_str += f"{range_min}"
        else:
            err_str += f"{range_min} to {range_max}"

    err_str += f" argument{plural}"

    return err_str


class CompletionItem(str):
    """
    Completion item with descriptive text attached

    See header of this file for more information
    """

    def __new__(cls, value: object, *args: Any, **kwargs: Any) -> 'CompletionItem':
        return super(CompletionItem, cls).__new__(cls, value)

    # noinspection PyUnusedLocal
    def __init__(self, value: object, description: str = '', *args: Any) -> None:
        """
        CompletionItem Initializer

        :param value: the value being tab completed
        :param description: description text to display
        :param args: args for str __init__
        :param kwargs: kwargs for str __init__
        """
        super().__init__(*args)
        self.description = description

        # Save the original value to support CompletionItems as argparse choices.
        # cmd2 has patched argparse so input is compared to this value instead of the CompletionItem instance.
        self._orig_value = value

    @property
    def orig_value(self) -> Any:
        """Read-only property for _orig_value"""
        return self._orig_value


############################################################################################################
# Class and functions related to ChoicesCallable
############################################################################################################


@runtime_checkable
class ChoicesProviderFuncBase(Protocol):
    """
    Function that returns a list of choices in support of tab completion
    """

    def __call__(self) -> List[str]:
        ...  # pragma: no cover


@runtime_checkable
class ChoicesProviderFuncWithTokens(Protocol):
    """
    Function that returns a list of choices in support of tab completion and accepts a dictionary of prior arguments.
    """

    def __call__(self, *, arg_tokens: Dict[str, List[str]] = {}) -> List[str]:
        ...  # pragma: no cover


ChoicesProviderFunc = Union[ChoicesProviderFuncBase, ChoicesProviderFuncWithTokens]


@runtime_checkable
class CompleterFuncBase(Protocol):
    """
    Function to support tab completion with the provided state of the user prompt
    """

    def __call__(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
    ) -> List[str]:
        ...  # pragma: no cover


@runtime_checkable
class CompleterFuncWithTokens(Protocol):
    """
    Function to support tab completion with the provided state of the user prompt and accepts a dictionary of prior
    arguments.
    """

    def __call__(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
        *,
        arg_tokens: Dict[str, List[str]] = {},
    ) -> List[str]:
        ...  # pragma: no cover


CompleterFunc = Union[CompleterFuncBase, CompleterFuncWithTokens]


class ChoicesCallable:
    """
    Enables using a callable as the choices provider for an argparse argument.
    While argparse has the built-in choices attribute, it is limited to an iterable.
    """

    def __init__(
        self,
        is_completer: bool,
        to_call: Union[CompleterFunc, ChoicesProviderFunc],
    ) -> None:
        """
        Initializer
        :param is_completer: True if to_call is a tab completion routine which expects
                             the args: text, line, begidx, endidx
        :param to_call: the callable object that will be called to provide choices for the argument
        """
        self.is_completer = is_completer
        if is_completer:
            if not isinstance(to_call, (CompleterFuncBase, CompleterFuncWithTokens)):  # pragma: no cover
                # runtime checking of Protocols do not currently check the parameters of a function.
                raise ValueError(
                    'With is_completer set to true, to_call must be either CompleterFunc, CompleterFuncWithTokens'
                )
        else:
            if not isinstance(to_call, (ChoicesProviderFuncBase, ChoicesProviderFuncWithTokens)):  # pragma: no cover
                # runtime checking of Protocols do not currently check the parameters of a function.
                raise ValueError(
                    'With is_completer set to false, to_call must be either: '
                    'ChoicesProviderFuncBase, ChoicesProviderFuncWithTokens'
                )
        self.to_call = to_call

    @property
    def completer(self) -> CompleterFunc:
        if not isinstance(self.to_call, (CompleterFuncBase, CompleterFuncWithTokens)):  # pragma: no cover
            # this should've been caught in the constructor, just a backup check
            raise ValueError('Function is not a CompleterFunc')
        return self.to_call

    @property
    def choices_provider(self) -> ChoicesProviderFunc:
        if not isinstance(self.to_call, (ChoicesProviderFuncBase, ChoicesProviderFuncWithTokens)):  # pragma: no cover
            # this should've been caught in the constructor, just a backup check
            raise ValueError('Function is not a ChoicesProviderFunc')
        return self.to_call


############################################################################################################
# The following are names of custom argparse Action attributes added by cmd2
############################################################################################################

# ChoicesCallable object that specifies the function to be called which provides choices to the argument
ATTR_CHOICES_CALLABLE = 'choices_callable'

# Descriptive header that prints when using CompletionItems
ATTR_DESCRIPTIVE_HEADER = 'descriptive_header'

# A tuple specifying nargs as a range (min, max)
ATTR_NARGS_RANGE = 'nargs_range'

# Pressing tab normally displays the help text for the argument if no choices are available
# Setting this attribute to True will suppress these hints
ATTR_SUPPRESS_TAB_HINT = 'suppress_tab_hint'


############################################################################################################
# Patch argparse.Action with accessors for choice_callable attribute
############################################################################################################
def _action_get_choices_callable(self: argparse.Action) -> Optional[ChoicesCallable]:
    """
    Get the choices_callable attribute of an argparse Action.

    This function is added by cmd2 as a method called ``get_choices_callable()`` to ``argparse.Action`` class.

    To call: ``action.get_choices_callable()``

    :param self: argparse Action being queried
    :return: A ChoicesCallable instance or None if attribute does not exist
    """
    return cast(Optional[ChoicesCallable], getattr(self, ATTR_CHOICES_CALLABLE, None))


setattr(argparse.Action, 'get_choices_callable', _action_get_choices_callable)


def _action_set_choices_callable(self: argparse.Action, choices_callable: ChoicesCallable) -> None:
    """
    Set the choices_callable attribute of an argparse Action.

    This function is added by cmd2 as a method called ``_set_choices_callable()`` to ``argparse.Action`` class.

    Call this using the convenience wrappers ``set_choices_provider()`` and ``set_completer()`` instead.

    :param self: action being edited
    :param choices_callable: the ChoicesCallable instance to use
    :raises: TypeError if used on incompatible action type
    """
    # Verify consistent use of parameters
    if self.choices is not None:
        err_msg = "None of the following parameters can be used alongside a choices parameter:\n" "choices_provider, completer"
        raise (TypeError(err_msg))
    elif self.nargs == 0:
        err_msg = (
            "None of the following parameters can be used on an action that takes no arguments:\n"
            "choices_provider, completer"
        )
        raise (TypeError(err_msg))

    setattr(self, ATTR_CHOICES_CALLABLE, choices_callable)


setattr(argparse.Action, '_set_choices_callable', _action_set_choices_callable)


def _action_set_choices_provider(
    self: argparse.Action,
    choices_provider: ChoicesProviderFunc,
) -> None:
    """
    Set choices_provider of an argparse Action.

    This function is added by cmd2 as a method called ``set_choices_callable()`` to ``argparse.Action`` class.

    To call: ``action.set_choices_provider(choices_provider)``

    :param self: action being edited
    :param choices_provider: the choices_provider instance to use
    :raises: TypeError if used on incompatible action type
    """
    self._set_choices_callable(ChoicesCallable(is_completer=False, to_call=choices_provider))  # type: ignore[attr-defined]


setattr(argparse.Action, 'set_choices_provider', _action_set_choices_provider)


def _action_set_completer(
    self: argparse.Action,
    completer: CompleterFunc,
) -> None:
    """
    Set completer of an argparse Action.

    This function is added by cmd2 as a method called ``set_completer()`` to ``argparse.Action`` class.

    To call: ``action.set_completer(completer)``

    :param self: action being edited
    :param completer: the completer instance to use
    :raises: TypeError if used on incompatible action type
    """
    self._set_choices_callable(ChoicesCallable(is_completer=True, to_call=completer))  # type: ignore[attr-defined]


setattr(argparse.Action, 'set_completer', _action_set_completer)


############################################################################################################
# Patch argparse.Action with accessors for descriptive_header attribute
############################################################################################################
def _action_get_descriptive_header(self: argparse.Action) -> Optional[str]:
    """
    Get the descriptive_header attribute of an argparse Action.

    This function is added by cmd2 as a method called ``get_descriptive_header()`` to ``argparse.Action`` class.

    To call: ``action.get_descriptive_header()``

    :param self: argparse Action being queried
    :return: The value of descriptive_header or None if attribute does not exist
    """
    return cast(Optional[str], getattr(self, ATTR_DESCRIPTIVE_HEADER, None))


setattr(argparse.Action, 'get_descriptive_header', _action_get_descriptive_header)


def _action_set_descriptive_header(self: argparse.Action, descriptive_header: Optional[str]) -> None:
    """
    Set the descriptive_header attribute of an argparse Action.

    This function is added by cmd2 as a method called ``set_descriptive_header()`` to ``argparse.Action`` class.

    To call: ``action.set_descriptive_header(descriptive_header)``

    :param self: argparse Action being updated
    :param descriptive_header: value being assigned
    """
    setattr(self, ATTR_DESCRIPTIVE_HEADER, descriptive_header)


setattr(argparse.Action, 'set_descriptive_header', _action_set_descriptive_header)


############################################################################################################
# Patch argparse.Action with accessors for nargs_range attribute
############################################################################################################
def _action_get_nargs_range(self: argparse.Action) -> Optional[Tuple[int, Union[int, float]]]:
    """
    Get the nargs_range attribute of an argparse Action.

    This function is added by cmd2 as a method called ``get_nargs_range()`` to ``argparse.Action`` class.

    To call: ``action.get_nargs_range()``

    :param self: argparse Action being queried
    :return: The value of nargs_range or None if attribute does not exist
    """
    return cast(Optional[Tuple[int, Union[int, float]]], getattr(self, ATTR_NARGS_RANGE, None))


setattr(argparse.Action, 'get_nargs_range', _action_get_nargs_range)


def _action_set_nargs_range(self: argparse.Action, nargs_range: Optional[Tuple[int, Union[int, float]]]) -> None:
    """
    Set the nargs_range attribute of an argparse Action.

    This function is added by cmd2 as a method called ``set_nargs_range()`` to ``argparse.Action`` class.

    To call: ``action.set_nargs_range(nargs_range)``

    :param self: argparse Action being updated
    :param nargs_range: value being assigned
    """
    setattr(self, ATTR_NARGS_RANGE, nargs_range)


setattr(argparse.Action, 'set_nargs_range', _action_set_nargs_range)


############################################################################################################
# Patch argparse.Action with accessors for suppress_tab_hint attribute
############################################################################################################
def _action_get_suppress_tab_hint(self: argparse.Action) -> bool:
    """
    Get the suppress_tab_hint attribute of an argparse Action.

    This function is added by cmd2 as a method called ``get_suppress_tab_hint()`` to ``argparse.Action`` class.

    To call: ``action.get_suppress_tab_hint()``

    :param self: argparse Action being queried
    :return: The value of suppress_tab_hint or False if attribute does not exist
    """
    return cast(bool, getattr(self, ATTR_SUPPRESS_TAB_HINT, False))


setattr(argparse.Action, 'get_suppress_tab_hint', _action_get_suppress_tab_hint)


def _action_set_suppress_tab_hint(self: argparse.Action, suppress_tab_hint: bool) -> None:
    """
    Set the suppress_tab_hint attribute of an argparse Action.

    This function is added by cmd2 as a method called ``set_suppress_tab_hint()`` to ``argparse.Action`` class.

    To call: ``action.set_suppress_tab_hint(suppress_tab_hint)``

    :param self: argparse Action being updated
    :param suppress_tab_hint: value being assigned
    """
    setattr(self, ATTR_SUPPRESS_TAB_HINT, suppress_tab_hint)


setattr(argparse.Action, 'set_suppress_tab_hint', _action_set_suppress_tab_hint)


############################################################################################################
# Allow developers to add custom action attributes
############################################################################################################

CUSTOM_ACTION_ATTRIBS: Set[str] = set()
_CUSTOM_ATTRIB_PFX = '_attr_'


def register_argparse_argument_parameter(param_name: str, param_type: Optional[Type[Any]]) -> None:
    """
    Registers a custom argparse argument parameter.

    The registered name will then be a recognized keyword parameter to the parser's `add_argument()` function.

    An accessor functions will be added to the parameter's Action object in the form of: ``get_{param_name}()``
    and ``set_{param_name}(value)``.

    :param param_name: Name of the parameter to add.
    :param param_type: Type of the parameter to add.
    """
    attr_name = f'{_CUSTOM_ATTRIB_PFX}{param_name}'
    if param_name in CUSTOM_ACTION_ATTRIBS or hasattr(argparse.Action, attr_name):
        raise KeyError(f'Custom parameter {param_name} already exists')
    if not re.search('^[A-Za-z_][A-Za-z0-9_]*$', param_name):
        raise KeyError(f'Invalid parameter name {param_name} - cannot be used as a python identifier')

    getter_name = f'get_{param_name}'

    def _action_get_custom_parameter(self: argparse.Action) -> Any:
        f"""
        Get the custom {param_name} attribute of an argparse Action.

        This function is added by cmd2 as a method called ``{getter_name}()`` to ``argparse.Action`` class.

        To call: ``action.{getter_name}()``

        :param self: argparse Action being queried
        :return: The value of {param_name} or None if attribute does not exist
        """
        return getattr(self, attr_name, None)

    setattr(argparse.Action, getter_name, _action_get_custom_parameter)

    setter_name = f'set_{param_name}'

    def _action_set_custom_parameter(self: argparse.Action, value: Any) -> None:
        f"""
        Set the custom {param_name} attribute of an argparse Action.

        This function is added by cmd2 as a method called ``{setter_name}()`` to ``argparse.Action`` class.

        To call: ``action.{setter_name}({param_name})``

        :param self: argparse Action being updated
        :param value: value being assigned
        """
        if param_type and not isinstance(value, param_type):
            raise TypeError(f'{param_name} must be of type {param_type}, got: {value} ({type(value)})')
        setattr(self, attr_name, value)

    setattr(argparse.Action, setter_name, _action_set_custom_parameter)

    CUSTOM_ACTION_ATTRIBS.add(param_name)


############################################################################################################
# Patch _ActionsContainer.add_argument with our wrapper to support more arguments
############################################################################################################


# Save original _ActionsContainer.add_argument so we can call it in our wrapper
# noinspection PyProtectedMember
orig_actions_container_add_argument = argparse._ActionsContainer.add_argument


# noinspection PyProtectedMember
def _add_argument_wrapper(
    self: argparse._ActionsContainer,
    *args: Any,
    nargs: Union[int, str, Tuple[int], Tuple[int, int], Tuple[int, float], None] = None,
    choices_provider: Optional[ChoicesProviderFunc] = None,
    completer: Optional[CompleterFunc] = None,
    suppress_tab_hint: bool = False,
    descriptive_header: Optional[str] = None,
    **kwargs: Any,
) -> argparse.Action:
    """
    Wrapper around _ActionsContainer.add_argument() which supports more settings used by cmd2

    # Args from original function
    :param self: instance of the _ActionsContainer being added to
    :param args: arguments expected by argparse._ActionsContainer.add_argument

    # Customized arguments from original function
    :param nargs: extends argparse nargs functionality by allowing tuples which specify a range (min, max)
                  to specify a max value with no upper bound, use a 1-item tuple (min,)

    # Added args used by ArgparseCompleter
    :param choices_provider: function that provides choices for this argument
    :param completer: tab completion function that provides choices for this argument
    :param suppress_tab_hint: when ArgparseCompleter has no results to show during tab completion, it displays the
                              current argument's help text as a hint. Set this to True to suppress the hint. If this
                              argument's help text is set to argparse.SUPPRESS, then tab hints will not display
                              regardless of the value passed for suppress_tab_hint. Defaults to False.
    :param descriptive_header: if the provided choices are CompletionItems, then this header will display
                               during tab completion. Defaults to None.

    # Args from original function
    :param kwargs: keyword-arguments recognized by argparse._ActionsContainer.add_argument

    Note: You can only use 1 of the following in your argument:
          choices, choices_provider, completer

          See the header of this file for more information

    :return: the created argument action
    :raises: ValueError on incorrect parameter usage
    """
    # Verify consistent use of arguments
    choices_callables = [choices_provider, completer]
    num_params_set = len(choices_callables) - choices_callables.count(None)

    if num_params_set > 1:
        err_msg = "Only one of the following parameters may be used at a time:\n" "choices_provider, completer"
        raise (ValueError(err_msg))

    # Pre-process special ranged nargs
    nargs_range = None

    if nargs is not None:
        nargs_adjusted: Union[int, str, Tuple[int], Tuple[int, int], Tuple[int, float], None]
        # Check if nargs was given as a range
        if isinstance(nargs, tuple):

            # Handle 1-item tuple by setting max to INFINITY
            if len(nargs) == 1:
                nargs = (nargs[0], constants.INFINITY)

            # Validate nargs tuple
            if (
                len(nargs) != 2
                or not isinstance(nargs[0], int)  # type: ignore[unreachable]
                or not (isinstance(nargs[1], int) or nargs[1] == constants.INFINITY)  # type: ignore[misc]
            ):
                raise ValueError('Ranged values for nargs must be a tuple of 1 or 2 integers')
            if nargs[0] >= nargs[1]:  # type: ignore[misc]
                raise ValueError('Invalid nargs range. The first value must be less than the second')
            if nargs[0] < 0:
                raise ValueError('Negative numbers are invalid for nargs range')

            # Save the nargs tuple as our range setting
            nargs_range = nargs
            range_min = nargs_range[0]
            range_max = nargs_range[1]  # type: ignore[misc]

            # Convert nargs into a format argparse recognizes
            if range_min == 0:
                if range_max == 1:
                    nargs_adjusted = argparse.OPTIONAL

                    # No range needed since (0, 1) is just argparse.OPTIONAL
                    nargs_range = None
                else:
                    nargs_adjusted = argparse.ZERO_OR_MORE
                    if range_max == constants.INFINITY:
                        # No range needed since (0, INFINITY) is just argparse.ZERO_OR_MORE
                        nargs_range = None
            elif range_min == 1 and range_max == constants.INFINITY:
                nargs_adjusted = argparse.ONE_OR_MORE

                # No range needed since (1, INFINITY) is just argparse.ONE_OR_MORE
                nargs_range = None
            else:
                nargs_adjusted = argparse.ONE_OR_MORE
        else:
            nargs_adjusted = nargs

        # Add the argparse-recognized version of nargs to kwargs
        kwargs['nargs'] = nargs_adjusted

    # Extract registered custom keyword arguments
    custom_attribs: Dict[str, Any] = {}
    for keyword, value in kwargs.items():
        if keyword in CUSTOM_ACTION_ATTRIBS:
            custom_attribs[keyword] = value
    for keyword in custom_attribs:
        del kwargs[keyword]

    # Create the argument using the original add_argument function
    new_arg = orig_actions_container_add_argument(self, *args, **kwargs)

    # Set the custom attributes
    new_arg.set_nargs_range(nargs_range)  # type: ignore[arg-type, attr-defined]

    if choices_provider:
        new_arg.set_choices_provider(choices_provider)  # type: ignore[attr-defined]
    elif completer:
        new_arg.set_completer(completer)  # type: ignore[attr-defined]

    new_arg.set_suppress_tab_hint(suppress_tab_hint)  # type: ignore[attr-defined]
    new_arg.set_descriptive_header(descriptive_header)  # type: ignore[attr-defined]

    for keyword, value in custom_attribs.items():
        attr_setter = getattr(new_arg, f'set_{keyword}', None)
        if attr_setter is not None:
            attr_setter(value)

    return new_arg


# Overwrite _ActionsContainer.add_argument with our wrapper
# noinspection PyProtectedMember
setattr(argparse._ActionsContainer, 'add_argument', _add_argument_wrapper)

############################################################################################################
# Patch ArgumentParser._get_nargs_pattern with our wrapper to support nargs ranges
############################################################################################################

# Save original ArgumentParser._get_nargs_pattern so we can call it in our wrapper
# noinspection PyProtectedMember
orig_argument_parser_get_nargs_pattern = argparse.ArgumentParser._get_nargs_pattern


# noinspection PyProtectedMember
def _get_nargs_pattern_wrapper(self: argparse.ArgumentParser, action: argparse.Action) -> str:
    # Wrapper around ArgumentParser._get_nargs_pattern behavior to support nargs ranges
    nargs_range = action.get_nargs_range()  # type: ignore[attr-defined]
    if nargs_range is not None:
        if nargs_range[1] == constants.INFINITY:
            range_max = ''
        else:
            range_max = nargs_range[1]  # type: ignore[assignment]

        nargs_pattern = f'(-*A{{{nargs_range[0]},{range_max}}}-*)'

        # if this is an optional action, -- is not allowed
        if action.option_strings:
            nargs_pattern = nargs_pattern.replace('-*', '')
            nargs_pattern = nargs_pattern.replace('-', '')
        return nargs_pattern

    return orig_argument_parser_get_nargs_pattern(self, action)


# Overwrite ArgumentParser._get_nargs_pattern with our wrapper
# noinspection PyProtectedMember
setattr(argparse.ArgumentParser, '_get_nargs_pattern', _get_nargs_pattern_wrapper)


############################################################################################################
# Patch ArgumentParser._match_argument with our wrapper to support nargs ranges
############################################################################################################
# noinspection PyProtectedMember
orig_argument_parser_match_argument = argparse.ArgumentParser._match_argument


# noinspection PyProtectedMember
def _match_argument_wrapper(self: argparse.ArgumentParser, action: argparse.Action, arg_strings_pattern: str) -> int:
    # Wrapper around ArgumentParser._match_argument behavior to support nargs ranges
    nargs_pattern = self._get_nargs_pattern(action)
    match = re.match(nargs_pattern, arg_strings_pattern)

    # raise an exception if we weren't able to find a match
    if match is None:
        nargs_range = action.get_nargs_range()  # type: ignore[attr-defined]
        if nargs_range is not None:
            raise ArgumentError(action, generate_range_error(nargs_range[0], nargs_range[1]))

    return orig_argument_parser_match_argument(self, action, arg_strings_pattern)


# Overwrite ArgumentParser._match_argument with our wrapper
# noinspection PyProtectedMember
setattr(argparse.ArgumentParser, '_match_argument', _match_argument_wrapper)


############################################################################################################
# Patch argparse.ArgumentParser with accessors for ap_completer_type attribute
############################################################################################################

# An ArgumentParser attribute which specifies a subclass of ArgparseCompleter for custom tab completion behavior on a
# given parser. If this is None or not present, then cmd2 will use argparse_completer.DEFAULT_AP_COMPLETER when tab
# completing a parser's arguments
ATTR_AP_COMPLETER_TYPE = 'ap_completer_type'


# noinspection PyPep8Naming
def _ArgumentParser_get_ap_completer_type(self: argparse.ArgumentParser) -> Optional[Type['ArgparseCompleter']]:
    """
    Get the ap_completer_type attribute of an argparse ArgumentParser.

    This function is added by cmd2 as a method called ``get_ap_completer_type()`` to ``argparse.ArgumentParser`` class.

    To call: ``parser.get_ap_completer_type()``

    :param self: ArgumentParser being queried
    :return: An ArgparseCompleter-based class or None if attribute does not exist
    """
    return cast(Optional[Type['ArgparseCompleter']], getattr(self, ATTR_AP_COMPLETER_TYPE, None))


setattr(argparse.ArgumentParser, 'get_ap_completer_type', _ArgumentParser_get_ap_completer_type)


# noinspection PyPep8Naming
def _ArgumentParser_set_ap_completer_type(self: argparse.ArgumentParser, ap_completer_type: Type['ArgparseCompleter']) -> None:
    """
    Set the ap_completer_type attribute of an argparse ArgumentParser.

    This function is added by cmd2 as a method called ``set_ap_completer_type()`` to ``argparse.ArgumentParser`` class.

    To call: ``parser.set_ap_completer_type(ap_completer_type)``

    :param self: ArgumentParser being edited
    :param ap_completer_type: the custom ArgparseCompleter-based class to use when tab completing arguments for this parser
    """
    setattr(self, ATTR_AP_COMPLETER_TYPE, ap_completer_type)


setattr(argparse.ArgumentParser, 'set_ap_completer_type', _ArgumentParser_set_ap_completer_type)


############################################################################################################
# Patch ArgumentParser._check_value to support CompletionItems as choices
############################################################################################################
# noinspection PyPep8Naming
def _ArgumentParser_check_value(self: argparse.ArgumentParser, action: argparse.Action, value: Any) -> None:
    """
    Custom override of ArgumentParser._check_value that supports CompletionItems as choices.
    When evaluating choices, input is compared to CompletionItem.orig_value instead of the
    CompletionItem instance.

    :param self: ArgumentParser instance
    :param action: the action being populated
    :param value: value from command line already run through conversion function by argparse
    """
    # Import gettext like argparse does
    from gettext import (
        gettext as _,
    )

    # converted value must be one of the choices (if specified)
    if action.choices is not None:
        # If any choice is a CompletionItem, then use its orig_value property.
        choices = [c.orig_value if isinstance(c, CompletionItem) else c for c in action.choices]
        if value not in choices:
            args = {'value': value, 'choices': ', '.join(map(repr, choices))}
            msg = _('invalid choice: %(value)r (choose from %(choices)s)')
            raise ArgumentError(action, msg % args)


setattr(argparse.ArgumentParser, '_check_value', _ArgumentParser_check_value)


############################################################################################################
# Patch argparse._SubParsersAction to add remove_parser function
############################################################################################################

# noinspection PyPep8Naming,PyProtectedMember
def _SubParsersAction_remove_parser(self: argparse._SubParsersAction, name: str) -> None:  # type: ignore
    """
    Removes a sub-parser from a sub-parsers group. Used to remove subcommands from a parser.

    This function is added by cmd2 as a method called ``remove_parser()`` to ``argparse._SubParsersAction`` class.

    To call: ``action.remove_parser(name)``

    :param self: instance of the _SubParsersAction being edited
    :param name: name of the subcommand for the sub-parser to remove
    """
    # Remove this subcommand from its base command's help text
    for choice_action in self._choices_actions:
        if choice_action.dest == name:
            self._choices_actions.remove(choice_action)
            break

    # Remove this subcommand and all its aliases from the base command
    subparser = self._name_parser_map.get(name)
    if subparser is not None:
        to_remove = []
        for cur_name, cur_parser in self._name_parser_map.items():
            if cur_parser is subparser:
                to_remove.append(cur_name)
        for cur_name in to_remove:
            del self._name_parser_map[cur_name]


# noinspection PyProtectedMember
setattr(argparse._SubParsersAction, 'remove_parser', _SubParsersAction_remove_parser)


############################################################################################################
# Unless otherwise noted, everything below this point are copied from Python's
# argparse implementation with minor tweaks to adjust output.
# Changes are noted if it's buried in a block of copied code. Otherwise the
# function will check for a special case and fall back to the parent function
############################################################################################################


# noinspection PyCompatibility,PyShadowingBuiltins
class Cmd2HelpFormatter(argparse.RawTextHelpFormatter):
    """Custom help formatter to configure ordering of help text"""

    # noinspection PyProtectedMember
    def _format_usage(
        self,
        usage: Optional[str],
        actions: Iterable[argparse.Action],
        groups: Iterable[argparse._ArgumentGroup],
        prefix: Optional[str] = None,
    ) -> str:
        if prefix is None:
            prefix = gettext('Usage: ')

        # if usage is specified, use that
        if usage is not None:
            usage %= dict(prog=self._prog)

        # if no optionals or positionals are available, usage is just prog
        elif not actions:
            usage = '%(prog)s' % dict(prog=self._prog)

        # if optionals and positionals are available, calculate usage
        else:
            prog = '%(prog)s' % dict(prog=self._prog)

            # split optionals from positionals
            optionals = []
            positionals = []
            # Begin cmd2 customization (separates required and optional, applies to all changes in this function)
            required_options = []
            for action in actions:
                if action.option_strings:
                    if action.required:
                        required_options.append(action)
                    else:
                        optionals.append(action)
                else:
                    positionals.append(action)
            # End cmd2 customization

            # build full usage string
            format = self._format_actions_usage
            action_usage = format(required_options + optionals + positionals, groups)
            usage = ' '.join([s for s in [prog, action_usage] if s])

            # wrap the usage parts if it's too long
            text_width = self._width - self._current_indent
            if len(prefix) + len(usage) > text_width:

                # Begin cmd2 customization

                # break usage into wrappable parts
                part_regexp = r'\(.*?\)+|\[.*?\]+|\S+'
                req_usage = format(required_options, groups)
                opt_usage = format(optionals, groups)
                pos_usage = format(positionals, groups)
                req_parts = re.findall(part_regexp, req_usage)
                opt_parts = re.findall(part_regexp, opt_usage)
                pos_parts = re.findall(part_regexp, pos_usage)
                assert ' '.join(req_parts) == req_usage
                assert ' '.join(opt_parts) == opt_usage
                assert ' '.join(pos_parts) == pos_usage

                # End cmd2 customization

                # helper for wrapping lines
                # noinspection PyMissingOrEmptyDocstring,PyShadowingNames
                def get_lines(parts: List[str], indent: str, prefix: Optional[str] = None) -> List[str]:
                    lines: List[str] = []
                    line: List[str] = []
                    if prefix is not None:
                        line_len = len(prefix) - 1
                    else:
                        line_len = len(indent) - 1
                    for part in parts:
                        if line_len + 1 + len(part) > text_width and line:
                            lines.append(indent + ' '.join(line))
                            line = []
                            line_len = len(indent) - 1
                        line.append(part)
                        line_len += len(part) + 1
                    if line:
                        lines.append(indent + ' '.join(line))
                    if prefix is not None:
                        lines[0] = lines[0][len(indent) :]
                    return lines

                # if prog is short, follow it with optionals or positionals
                if len(prefix) + len(prog) <= 0.75 * text_width:
                    indent = ' ' * (len(prefix) + len(prog) + 1)
                    # Begin cmd2 customization
                    if req_parts:
                        lines = get_lines([prog] + req_parts, indent, prefix)
                        lines.extend(get_lines(opt_parts, indent))
                        lines.extend(get_lines(pos_parts, indent))
                    elif opt_parts:
                        lines = get_lines([prog] + opt_parts, indent, prefix)
                        lines.extend(get_lines(pos_parts, indent))
                    elif pos_parts:
                        lines = get_lines([prog] + pos_parts, indent, prefix)
                    else:
                        lines = [prog]
                    # End cmd2 customization

                # if prog is long, put it on its own line
                else:
                    indent = ' ' * len(prefix)
                    # Begin cmd2 customization
                    parts = req_parts + opt_parts + pos_parts
                    lines = get_lines(parts, indent)
                    if len(lines) > 1:
                        lines = []
                        lines.extend(get_lines(req_parts, indent))
                        lines.extend(get_lines(opt_parts, indent))
                        lines.extend(get_lines(pos_parts, indent))
                    # End cmd2 customization
                    lines = [prog] + lines

                # join lines into usage
                usage = '\n'.join(lines)

        # prefix with 'Usage:'
        return '%s%s\n\n' % (prefix, usage)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            (metavar,) = self._metavar_formatter(action, default)(1)
            return metavar

        else:
            parts: List[str] = []

            # if the Optional doesn't take a value, format is:
            #    -s, --long
            if action.nargs == 0:
                parts.extend(action.option_strings)
                return ', '.join(parts)

            # Begin cmd2 customization (less verbose)
            # if the Optional takes a value, format is:
            #    -s, --long ARGS
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)

                return ', '.join(action.option_strings) + ' ' + args_string
            # End cmd2 customization

    # noinspection PyMethodMayBeStatic
    def _determine_metavar(
        self,
        action: argparse.Action,
        default_metavar: Union[str, Tuple[str, ...]],
    ) -> Union[str, Tuple[str, ...]]:
        """Custom method to determine what to use as the metavar value of an action"""
        if action.metavar is not None:
            result = action.metavar
        elif action.choices is not None:
            choice_strs = [str(choice) for choice in action.choices]
            # Begin cmd2 customization (added space after comma)
            result = '{%s}' % ', '.join(choice_strs)
            # End cmd2 customization
        else:
            result = default_metavar
        return result

    def _metavar_formatter(
        self,
        action: argparse.Action,
        default_metavar: Union[str, Tuple[str, ...]],
    ) -> Callable[[int], Tuple[str, ...]]:
        metavar = self._determine_metavar(action, default_metavar)

        # noinspection PyMissingOrEmptyDocstring
        def format(tuple_size: int) -> Tuple[str, ...]:
            if isinstance(metavar, tuple):
                return metavar
            else:
                return (metavar,) * tuple_size

        return format

    # noinspection PyProtectedMember
    def _format_args(self, action: argparse.Action, default_metavar: Union[str, Tuple[str, ...]]) -> str:
        """Customized to handle ranged nargs and make other output less verbose"""
        metavar = self._determine_metavar(action, default_metavar)
        metavar_formatter = self._metavar_formatter(action, default_metavar)

        # Handle nargs specified as a range
        nargs_range = action.get_nargs_range()  # type: ignore[attr-defined]
        if nargs_range is not None:
            if nargs_range[1] == constants.INFINITY:
                range_str = f'{nargs_range[0]}+'
            else:
                range_str = f'{nargs_range[0]}..{nargs_range[1]}'

            return '{}{{{}}}'.format('%s' % metavar_formatter(1), range_str)

        # Make this output less verbose. Do not customize the output when metavar is a
        # tuple of strings. Allow argparse's formatter to handle that instead.
        elif isinstance(metavar, str):
            if action.nargs == ZERO_OR_MORE:
                return '[%s [...]]' % metavar_formatter(1)
            elif action.nargs == ONE_OR_MORE:
                return '%s [...]' % metavar_formatter(1)
            elif isinstance(action.nargs, int) and action.nargs > 1:
                return '{}{{{}}}'.format('%s' % metavar_formatter(1), action.nargs)

        return super()._format_args(action, default_metavar)  # type: ignore[arg-type]


# noinspection PyCompatibility
class Cmd2ArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser class that improves error and help output"""

    def __init__(
        self,
        prog: Optional[str] = None,
        usage: Optional[str] = None,
        description: Optional[str] = None,
        epilog: Optional[str] = None,
        parents: Sequence[argparse.ArgumentParser] = (),
        formatter_class: Type[argparse.HelpFormatter] = Cmd2HelpFormatter,
        prefix_chars: str = '-',
        fromfile_prefix_chars: Optional[str] = None,
        argument_default: Optional[str] = None,
        conflict_handler: str = 'error',
        add_help: bool = True,
        allow_abbrev: bool = True,
        *,
        ap_completer_type: Optional[Type['ArgparseCompleter']] = None,
    ) -> None:
        """
        # Custom parameter added by cmd2

        :param ap_completer_type: optional parameter which specifies a subclass of ArgparseCompleter for custom tab completion
                                  behavior on this parser. If this is None or not present, then cmd2 will use
                                  argparse_completer.DEFAULT_AP_COMPLETER when tab completing this parser's arguments
        """
        super(Cmd2ArgumentParser, self).__init__(
            prog=prog,
            usage=usage,
            description=description,
            epilog=epilog,
            parents=parents if parents else [],
            formatter_class=formatter_class,  # type: ignore[arg-type]
            prefix_chars=prefix_chars,
            fromfile_prefix_chars=fromfile_prefix_chars,
            argument_default=argument_default,
            conflict_handler=conflict_handler,
            add_help=add_help,
            allow_abbrev=allow_abbrev,
        )

        self.set_ap_completer_type(ap_completer_type)  # type: ignore[attr-defined]

    # noinspection PyProtectedMember
    def add_subparsers(self, **kwargs: Any) -> argparse._SubParsersAction:  # type: ignore
        """
        Custom override. Sets a default title if one was not given.

        :param kwargs: additional keyword arguments
        :return: argparse Subparser Action
        """
        if 'title' not in kwargs:
            kwargs['title'] = 'subcommands'

        return super().add_subparsers(**kwargs)

    def error(self, message: str) -> NoReturn:
        """Custom override that applies custom formatting to the error message"""
        lines = message.split('\n')
        linum = 0
        formatted_message = ''
        for line in lines:
            if linum == 0:
                formatted_message = 'Error: ' + line
            else:
                formatted_message += '\n       ' + line
            linum += 1

        self.print_usage(sys.stderr)
        formatted_message = ansi.style_error(formatted_message)
        self.exit(2, f'{formatted_message}\n\n')

    # noinspection PyProtectedMember
    def format_help(self) -> str:
        """Copy of format_help() from argparse.ArgumentParser with tweaks to separately display required parameters"""
        formatter = self._get_formatter()

        # usage
        formatter.add_usage(self.usage, self._actions, self._mutually_exclusive_groups)  # type: ignore[arg-type]

        # description
        formatter.add_text(self.description)

        # Begin cmd2 customization (separate required and optional arguments)

        # positionals, optionals and user-defined groups
        for action_group in self._action_groups:
            if sys.version_info >= (3, 10):
                default_options_group = action_group.title == 'options'
            else:
                default_options_group = action_group.title == 'optional arguments'

            if default_options_group:
                # check if the arguments are required, group accordingly
                req_args = []
                opt_args = []
                for action in action_group._group_actions:
                    if action.required:
                        req_args.append(action)
                    else:
                        opt_args.append(action)

                # separately display required arguments
                formatter.start_section('required arguments')
                formatter.add_text(action_group.description)
                formatter.add_arguments(req_args)
                formatter.end_section()

                # now display truly optional arguments
                formatter.start_section('optional arguments')
                formatter.add_text(action_group.description)
                formatter.add_arguments(opt_args)
                formatter.end_section()
            else:
                formatter.start_section(action_group.title)
                formatter.add_text(action_group.description)
                formatter.add_arguments(action_group._group_actions)
                formatter.end_section()

        # End cmd2 customization

        # epilog
        formatter.add_text(self.epilog)

        # determine help from format above
        return formatter.format_help() + '\n'

    def _print_message(self, message: str, file: Optional[IO[str]] = None) -> None:
        # Override _print_message to use style_aware_write() since we use ANSI escape characters to support color
        if message:
            if file is None:
                file = sys.stderr
            ansi.style_aware_write(file, message)


class Cmd2AttributeWrapper:
    """
    Wraps a cmd2-specific attribute added to an argparse Namespace.
    This makes it easy to know which attributes in a Namespace are
    arguments from a parser and which were added by cmd2.
    """

    def __init__(self, attribute: Any) -> None:
        self.__attribute = attribute

    def get(self) -> Any:
        """Get the value of the attribute"""
        return self.__attribute

    def set(self, new_val: Any) -> None:
        """Set the value of the attribute"""
        self.__attribute = new_val


# The default ArgumentParser class for a cmd2 app
DEFAULT_ARGUMENT_PARSER: Type[argparse.ArgumentParser] = Cmd2ArgumentParser


def set_default_argument_parser_type(parser_type: Type[argparse.ArgumentParser]) -> None:
    """
    Set the default ArgumentParser class for a cmd2 app. This must be called prior to loading cmd2.py if
    you want to override the parser for cmd2's built-in commands. See examples/override_parser.py.
    """
    global DEFAULT_ARGUMENT_PARSER
    DEFAULT_ARGUMENT_PARSER = parser_type
