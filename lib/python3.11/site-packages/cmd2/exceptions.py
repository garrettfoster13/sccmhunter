# coding=utf-8
"""Custom exceptions for cmd2"""

from typing import (
    Any,
)

############################################################################################################
# The following exceptions are part of the public API
############################################################################################################


class SkipPostcommandHooks(Exception):
    """
    Custom exception class for when a command has a failure bad enough to skip post command
    hooks, but not bad enough to print the exception to the user.
    """

    pass


class Cmd2ArgparseError(SkipPostcommandHooks):
    """
    A ``SkipPostcommandHooks`` exception for when a command fails to parse its arguments.
    Normally argparse raises a SystemExit exception in these cases. To avoid stopping the command
    loop, catch the SystemExit and raise this instead. If you still need to run post command hooks
    after parsing fails, just return instead of raising an exception.
    """

    pass


class CommandSetRegistrationError(Exception):
    """
    Exception that can be thrown when an error occurs while a CommandSet is being added or removed
    from a cmd2 application.
    """

    pass


class CompletionError(Exception):
    """
    Raised during tab completion operations to report any sort of error you want printed. This can also be used
    just to display a message, even if it's not an error. For instance, ArgparseCompleter raises CompletionErrors
    to display tab completion hints and sets apply_style to False so hints aren't colored like error text.

    Example use cases

    - Reading a database to retrieve a tab completion data set failed
    - A previous command line argument that determines the data set being completed is invalid
    - Tab completion hints
    """

    def __init__(self, *args: Any, apply_style: bool = True) -> None:
        """
        Initializer for CompletionError
        :param apply_style: If True, then ansi.style_error will be applied to the message text when printed.
                            Set to False in cases where the message text already has the desired style.
                            Defaults to True.
        """
        self.apply_style = apply_style

        # noinspection PyArgumentList
        super().__init__(*args)


class PassThroughException(Exception):
    """
    Normally all unhandled exceptions raised during commands get printed to the user.
    This class is used to wrap an exception that should be raised instead of printed.
    """

    def __init__(self, *args: Any, wrapped_ex: BaseException) -> None:
        """
        Initializer for PassThroughException
        :param wrapped_ex: the exception that will be raised
        """
        self.wrapped_ex = wrapped_ex
        super().__init__(*args)


############################################################################################################
# The following exceptions are NOT part of the public API and are intended for internal use only.
############################################################################################################


class Cmd2ShlexError(Exception):
    """Raised when shlex fails to parse a command line string in StatementParser"""

    pass


class EmbeddedConsoleExit(SystemExit):
    """Custom exception class for use with the py command."""

    pass


class EmptyStatement(Exception):
    """Custom exception class for handling behavior when the user just presses <Enter>."""

    pass


class RedirectionError(Exception):
    """Custom exception class for when redirecting or piping output fails"""

    pass
