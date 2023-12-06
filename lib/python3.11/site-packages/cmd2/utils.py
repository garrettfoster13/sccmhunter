# coding=utf-8
"""Shared utility functions"""
import argparse
import collections
import functools
import glob
import inspect
import itertools
import os
import re
import subprocess
import sys
import threading
import unicodedata
from enum import (
    Enum,
)
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    TextIO,
    Type,
    TypeVar,
    Union,
    cast,
)

from . import (
    constants,
)
from .argparse_custom import (
    ChoicesProviderFunc,
    CompleterFunc,
)

if TYPE_CHECKING:  # pragma: no cover
    import cmd2  # noqa: F401

    PopenTextIO = subprocess.Popen[str]
else:
    PopenTextIO = subprocess.Popen

_T = TypeVar('_T')


def is_quoted(arg: str) -> bool:
    """
    Checks if a string is quoted

    :param arg: the string being checked for quotes
    :return: True if a string is quoted
    """
    return len(arg) > 1 and arg[0] == arg[-1] and arg[0] in constants.QUOTES


def quote_string(arg: str) -> str:
    """Quote a string"""
    if '"' in arg:
        quote = "'"
    else:
        quote = '"'

    return quote + arg + quote


def quote_string_if_needed(arg: str) -> str:
    """Quote a string if it contains spaces and isn't already quoted"""
    if is_quoted(arg) or ' ' not in arg:
        return arg

    return quote_string(arg)


def strip_quotes(arg: str) -> str:
    """Strip outer quotes from a string.

     Applies to both single and double quotes.

    :param arg:  string to strip outer quotes from
    :return: same string with potentially outer quotes stripped
    """
    if is_quoted(arg):
        arg = arg[1:-1]
    return arg


def to_bool(val: Any) -> bool:
    """Converts anything to a boolean based on its value.

    Strings like "True", "true", "False", and "false" return True, True, False, and False
    respectively. All other values are converted using bool()

    :param val: value being converted
    :return: boolean value expressed in the passed in value
    :raises: ValueError if the string does not contain a value corresponding to a boolean value
    """
    if isinstance(val, str):
        if val.capitalize() == str(True):
            return True
        elif val.capitalize() == str(False):
            return False
        raise ValueError("must be True or False (case-insensitive)")
    elif isinstance(val, bool):
        return val
    else:
        return bool(val)


class Settable:
    """Used to configure an attribute to be settable via the set command in the CLI"""

    def __init__(
        self,
        name: str,
        val_type: Union[Type[Any], Callable[[Any], Any]],
        description: str,
        settable_object: object,
        *,
        settable_attrib_name: Optional[str] = None,
        onchange_cb: Optional[Callable[[str, _T, _T], Any]] = None,
        choices: Optional[Iterable[Any]] = None,
        choices_provider: Optional[ChoicesProviderFunc] = None,
        completer: Optional[CompleterFunc] = None,
    ) -> None:
        """
        Settable Initializer

        :param name: name of the instance attribute being made settable
        :param val_type: callable used to cast the string value from the command line into its proper type and
                         even validate its value. Setting this to bool provides tab completion for true/false and
                         validation using to_bool(). The val_type function should raise an exception if it fails.
                         This exception will be caught and printed by Cmd.do_set().
        :param description: string describing this setting
        :param settable_object: object to which the instance attribute belongs (e.g. self)
        :param settable_attrib_name: name which displays to the user in the output of the set command.
                                     Defaults to `name` if not specified.
        :param onchange_cb: optional function or method to call when the value of this settable is altered
                            by the set command. (e.g. onchange_cb=self.debug_changed)

                            Cmd.do_set() passes the following 3 arguments to onchange_cb:
                                param_name: str - name of the changed parameter
                                old_value: Any - the value before being changed
                                new_value: Any - the value after being changed

        The following optional settings provide tab completion for a parameter's values. They correspond to the
        same settings in argparse-based tab completion. A maximum of one of these should be provided.

        :param choices: iterable of accepted values
        :param choices_provider: function that provides choices for this argument
        :param completer: tab completion function that provides choices for this argument
        """
        if val_type == bool:

            def get_bool_choices(_) -> List[str]:  # type: ignore[no-untyped-def]
                """Used to tab complete lowercase boolean values"""
                return ['true', 'false']

            val_type = to_bool
            choices_provider = cast(ChoicesProviderFunc, get_bool_choices)

        self.name = name
        self.val_type = val_type
        self.description = description
        self.settable_obj = settable_object
        self.settable_attrib_name = settable_attrib_name if settable_attrib_name is not None else name
        self.onchange_cb = onchange_cb
        self.choices = choices
        self.choices_provider = choices_provider
        self.completer = completer

    def get_value(self) -> Any:
        """
        Get the value of the settable attribute
        :return:
        """
        return getattr(self.settable_obj, self.settable_attrib_name)

    def set_value(self, value: Any) -> Any:
        """
        Set the settable attribute on the specified destination object
        :param value: New value to set
        :return: New value that the attribute was set to
        """
        # Run the value through its type function to handle any conversion or validation
        new_value = self.val_type(value)

        # Make sure new_value is a valid choice
        if self.choices is not None and new_value not in self.choices:
            choices_str = ', '.join(map(repr, self.choices))
            raise ValueError(f"invalid choice: {new_value!r} (choose from {choices_str})")

        # Try to update the settable's value
        orig_value = self.get_value()
        setattr(self.settable_obj, self.settable_attrib_name, new_value)

        # Check if we need to call an onchange callback
        if orig_value != new_value and self.onchange_cb:
            self.onchange_cb(self.name, orig_value, new_value)
        return new_value


def is_text_file(file_path: str) -> bool:
    """Returns if a file contains only ASCII or UTF-8 encoded text and isn't empty.

    :param file_path: path to the file being checked
    :return: True if the file is a non-empty text file, otherwise False
    :raises OSError if file can't be read
    """
    import codecs

    expanded_path = os.path.abspath(os.path.expanduser(file_path.strip()))
    valid_text_file = False

    # Only need to check for utf-8 compliance since that covers ASCII, too
    try:
        with codecs.open(expanded_path, encoding='utf-8', errors='strict') as f:
            # Make sure the file has only utf-8 text and is not empty
            if sum(1 for _ in f) > 0:
                valid_text_file = True
    except OSError:
        raise
    except UnicodeDecodeError:
        # Not UTF-8
        pass

    return valid_text_file


def remove_duplicates(list_to_prune: List[_T]) -> List[_T]:
    """Removes duplicates from a list while preserving order of the items.

    :param list_to_prune: the list being pruned of duplicates
    :return: The pruned list
    """
    temp_dict: collections.OrderedDict[_T, Any] = collections.OrderedDict()
    for item in list_to_prune:
        temp_dict[item] = None

    return list(temp_dict.keys())


def norm_fold(astr: str) -> str:
    """Normalize and casefold Unicode strings for saner comparisons.

    :param astr: input unicode string
    :return: a normalized and case-folded version of the input string
    """
    return unicodedata.normalize('NFC', astr).casefold()


def alphabetical_sort(list_to_sort: Iterable[str]) -> List[str]:
    """Sorts a list of strings alphabetically.

    For example: ['a1', 'A11', 'A2', 'a22', 'a3']

    To sort a list in place, don't call this method, which makes a copy. Instead, do this:

    my_list.sort(key=norm_fold)

    :param list_to_sort: the list being sorted
    :return: the sorted list
    """
    return sorted(list_to_sort, key=norm_fold)


def try_int_or_force_to_lower_case(input_str: str) -> Union[int, str]:
    """
    Tries to convert the passed-in string to an integer. If that fails, it converts it to lower case using norm_fold.
    :param input_str: string to convert
    :return: the string as an integer or a lower case version of the string
    """
    try:
        return int(input_str)
    except ValueError:
        return norm_fold(input_str)


def natural_keys(input_str: str) -> List[Union[int, str]]:
    """
    Converts a string into a list of integers and strings to support natural sorting (see natural_sort).

    For example: natural_keys('abc123def') -> ['abc', '123', 'def']
    :param input_str: string to convert
    :return: list of strings and integers
    """
    return [try_int_or_force_to_lower_case(substr) for substr in re.split(r'(\d+)', input_str)]


def natural_sort(list_to_sort: Iterable[str]) -> List[str]:
    """
    Sorts a list of strings case insensitively as well as numerically.

    For example: ['a1', 'A2', 'a3', 'A11', 'a22']

    To sort a list in place, don't call this method, which makes a copy. Instead, do this:

    my_list.sort(key=natural_keys)

    :param list_to_sort: the list being sorted
    :return: the list sorted naturally
    """
    return sorted(list_to_sort, key=natural_keys)


def quote_specific_tokens(tokens: List[str], tokens_to_quote: List[str]) -> None:
    """
    Quote specific tokens in a list

    :param tokens: token list being edited
    :param tokens_to_quote: the tokens, which if present in tokens, to quote
    """
    for i, token in enumerate(tokens):
        if token in tokens_to_quote:
            tokens[i] = quote_string(token)


def unquote_specific_tokens(tokens: List[str], tokens_to_unquote: List[str]) -> None:
    """
    Unquote specific tokens in a list

    :param tokens: token list being edited
    :param tokens_to_unquote: the tokens, which if present in tokens, to unquote
    """
    for i, token in enumerate(tokens):
        unquoted_token = strip_quotes(token)
        if unquoted_token in tokens_to_unquote:
            tokens[i] = unquoted_token


def expand_user(token: str) -> str:
    """
    Wrap os.expanduser() to support expanding ~ in quoted strings
    :param token: the string to expand
    """
    if token:
        if is_quoted(token):
            quote_char = token[0]
            token = strip_quotes(token)
        else:
            quote_char = ''

        token = os.path.expanduser(token)

        # Restore the quotes even if not needed to preserve what the user typed
        if quote_char:
            token = quote_char + token + quote_char

    return token


def expand_user_in_tokens(tokens: List[str]) -> None:
    """
    Call expand_user() on all tokens in a list of strings
    :param tokens: tokens to expand
    """
    for index, _ in enumerate(tokens):
        tokens[index] = expand_user(tokens[index])


def find_editor() -> Optional[str]:
    """
    Used to set cmd2.Cmd.DEFAULT_EDITOR. If EDITOR env variable is set, that will be used.
    Otherwise the function will look for a known editor in directories specified by PATH env variable.
    :return: Default editor or None
    """
    editor = os.environ.get('EDITOR')
    if not editor:
        if sys.platform[:3] == 'win':
            editors = ['code.cmd', 'notepad++.exe', 'notepad.exe']
        else:
            editors = ['vim', 'vi', 'emacs', 'nano', 'pico', 'joe', 'code', 'subl', 'atom', 'gedit', 'geany', 'kate']

        # Get a list of every directory in the PATH environment variable and ignore symbolic links
        env_path = os.getenv('PATH')
        if env_path is None:
            paths = []
        else:
            paths = [p for p in env_path.split(os.path.pathsep) if not os.path.islink(p)]

        for editor, path in itertools.product(editors, paths):
            editor_path = os.path.join(path, editor)
            if os.path.isfile(editor_path) and os.access(editor_path, os.X_OK):
                if sys.platform[:3] == 'win':
                    # Remove extension from Windows file names
                    editor = os.path.splitext(editor)[0]
                break
        else:
            editor = None

    return editor


def files_from_glob_pattern(pattern: str, access: int = os.F_OK) -> List[str]:
    """Return a list of file paths based on a glob pattern.

    Only files are returned, not directories, and optionally only files for which the user has a specified access to.

    :param pattern: file name or glob pattern
    :param access: file access type to verify (os.* where * is F_OK, R_OK, W_OK, or X_OK)
    :return: list of files matching the name or glob pattern
    """
    return [f for f in glob.glob(pattern) if os.path.isfile(f) and os.access(f, access)]


def files_from_glob_patterns(patterns: List[str], access: int = os.F_OK) -> List[str]:
    """Return a list of file paths based on a list of glob patterns.

    Only files are returned, not directories, and optionally only files for which the user has a specified access to.

    :param patterns: list of file names and/or glob patterns
    :param access: file access type to verify (os.* where * is F_OK, R_OK, W_OK, or X_OK)
    :return: list of files matching the names and/or glob patterns
    """
    files = []
    for pattern in patterns:
        matches = files_from_glob_pattern(pattern, access=access)
        files.extend(matches)
    return files


def get_exes_in_path(starts_with: str) -> List[str]:
    """Returns names of executables in a user's path

    :param starts_with: what the exes should start with. leave blank for all exes in path.
    :return: a list of matching exe names
    """
    # Purposely don't match any executable containing wildcards
    wildcards = ['*', '?']
    for wildcard in wildcards:
        if wildcard in starts_with:
            return []

    # Get a list of every directory in the PATH environment variable and ignore symbolic links
    env_path = os.getenv('PATH')
    if env_path is None:
        paths = []
    else:
        paths = [p for p in env_path.split(os.path.pathsep) if not os.path.islink(p)]

    # Use a set to store exe names since there can be duplicates
    exes_set = set()

    # Find every executable file in the user's path that matches the pattern
    for path in paths:
        full_path = os.path.join(path, starts_with)
        matches = files_from_glob_pattern(full_path + '*', access=os.X_OK)

        for match in matches:
            exes_set.add(os.path.basename(match))

    return list(exes_set)


class StdSim:
    """
    Class to simulate behavior of sys.stdout or sys.stderr.
    Stores contents in internal buffer and optionally echos to the inner stream it is simulating.
    """

    def __init__(
        self,
        inner_stream: Union[TextIO, 'StdSim'],
        *,
        echo: bool = False,
        encoding: str = 'utf-8',
        errors: str = 'replace',
    ) -> None:
        """
        StdSim Initializer

        :param inner_stream: the wrapped stream. Should be a TextIO or StdSim instance.
        :param echo: if True, then all input will be echoed to inner_stream
        :param encoding: codec for encoding/decoding strings (defaults to utf-8)
        :param errors: how to handle encoding/decoding errors (defaults to replace)
        """
        self.inner_stream = inner_stream
        self.echo = echo
        self.encoding = encoding
        self.errors = errors
        self.pause_storage = False
        self.buffer = ByteBuf(self)

    def write(self, s: str) -> None:
        """
        Add str to internal bytes buffer and if echo is True, echo contents to inner stream

        :param s: String to write to the stream
        """
        if not isinstance(s, str):
            raise TypeError(f'write() argument must be str, not {type(s)}')

        if not self.pause_storage:
            self.buffer.byte_buf += s.encode(encoding=self.encoding, errors=self.errors)
        if self.echo:
            self.inner_stream.write(s)

    def getvalue(self) -> str:
        """Get the internal contents as a str"""
        return self.buffer.byte_buf.decode(encoding=self.encoding, errors=self.errors)

    def getbytes(self) -> bytes:
        """Get the internal contents as bytes"""
        return bytes(self.buffer.byte_buf)

    def read(self, size: Optional[int] = -1) -> str:
        """
        Read from the internal contents as a str and then clear them out

        :param size: Number of bytes to read from the stream
        """
        if size is None or size == -1:
            result = self.getvalue()
            self.clear()
        else:
            result = self.buffer.byte_buf[:size].decode(encoding=self.encoding, errors=self.errors)
            self.buffer.byte_buf = self.buffer.byte_buf[size:]

        return result

    def readbytes(self) -> bytes:
        """Read from the internal contents as bytes and then clear them out"""
        result = self.getbytes()
        self.clear()
        return result

    def clear(self) -> None:
        """Clear the internal contents"""
        self.buffer.byte_buf.clear()

    def isatty(self) -> bool:
        """StdSim only considered an interactive stream if `echo` is True and `inner_stream` is a tty."""
        if self.echo:
            return self.inner_stream.isatty()
        else:
            return False

    @property
    def line_buffering(self) -> bool:
        """
        Handle when the inner stream doesn't have a line_buffering attribute which is the case
        when running unit tests because pytest sets stdout to a pytest EncodedFile object.
        """
        try:
            return bool(self.inner_stream.line_buffering)
        except AttributeError:
            return False

    def __getattr__(self, item: str) -> Any:
        if item in self.__dict__:
            return self.__dict__[item]
        else:
            return getattr(self.inner_stream, item)


class ByteBuf:
    """
    Used by StdSim to write binary data and stores the actual bytes written
    """

    # Used to know when to flush the StdSim
    NEWLINES = [b'\n', b'\r']

    def __init__(self, std_sim_instance: StdSim) -> None:
        self.byte_buf = bytearray()
        self.std_sim_instance = std_sim_instance

    def write(self, b: bytes) -> None:
        """Add bytes to internal bytes buffer and if echo is True, echo contents to inner stream."""
        if not isinstance(b, bytes):
            raise TypeError(f'a bytes-like object is required, not {type(b)}')
        if not self.std_sim_instance.pause_storage:
            self.byte_buf += b
        if self.std_sim_instance.echo:
            self.std_sim_instance.inner_stream.buffer.write(b)

            # Since StdSim wraps TextIO streams, we will flush the stream if line buffering is on
            # and the bytes being written contain a new line character. This is helpful when StdSim
            # is being used to capture output of a shell command because it causes the output to print
            # to the screen more often than if we waited for the stream to flush its buffer.
            if self.std_sim_instance.line_buffering:
                if any(newline in b for newline in ByteBuf.NEWLINES):
                    self.std_sim_instance.flush()


class ProcReader:
    """
    Used to capture stdout and stderr from a Popen process if any of those were set to subprocess.PIPE.
    If neither are pipes, then the process will run normally and no output will be captured.
    """

    def __init__(self, proc: PopenTextIO, stdout: Union[StdSim, TextIO], stderr: Union[StdSim, TextIO]) -> None:
        """
        ProcReader initializer
        :param proc: the Popen process being read from
        :param stdout: the stream to write captured stdout
        :param stderr: the stream to write captured stderr
        """
        self._proc = proc
        self._stdout = stdout
        self._stderr = stderr

        self._out_thread = threading.Thread(name='out_thread', target=self._reader_thread_func, kwargs={'read_stdout': True})

        self._err_thread = threading.Thread(name='err_thread', target=self._reader_thread_func, kwargs={'read_stdout': False})

        # Start the reader threads for pipes only
        if self._proc.stdout is not None:
            self._out_thread.start()
        if self._proc.stderr is not None:
            self._err_thread.start()

    def send_sigint(self) -> None:
        """Send a SIGINT to the process similar to if <Ctrl>+C were pressed"""
        import signal

        if sys.platform.startswith('win'):
            # cmd2 started the Windows process in a new process group. Therefore we must send
            # a CTRL_BREAK_EVENT since CTRL_C_EVENT signals cannot be generated for process groups.
            self._proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            # Since cmd2 uses shell=True in its Popen calls, we need to send the SIGINT to
            # the whole process group to make sure it propagates further than the shell
            try:
                group_id = os.getpgid(self._proc.pid)
                os.killpg(group_id, signal.SIGINT)
            except ProcessLookupError:
                return

    def terminate(self) -> None:
        """Terminate the process"""
        self._proc.terminate()

    def wait(self) -> None:
        """Wait for the process to finish"""
        if self._out_thread.is_alive():
            self._out_thread.join()
        if self._err_thread.is_alive():
            self._err_thread.join()

        # Handle case where the process ended before the last read could be done.
        # This will return None for the streams that weren't pipes.
        out, err = self._proc.communicate()

        if out:
            self._write_bytes(self._stdout, out)
        if err:
            self._write_bytes(self._stderr, err)

    def _reader_thread_func(self, read_stdout: bool) -> None:
        """
        Thread function that reads a stream from the process
        :param read_stdout: if True, then this thread deals with stdout. Otherwise it deals with stderr.
        """
        if read_stdout:
            read_stream = self._proc.stdout
            write_stream = self._stdout
        else:
            read_stream = self._proc.stderr
            write_stream = self._stderr

        # The thread should have been started only if this stream was a pipe
        assert read_stream is not None

        # Run until process completes
        while self._proc.poll() is None:
            # noinspection PyUnresolvedReferences
            available = read_stream.peek()  # type: ignore[attr-defined]
            if available:
                read_stream.read(len(available))
                self._write_bytes(write_stream, available)

    @staticmethod
    def _write_bytes(stream: Union[StdSim, TextIO], to_write: Union[bytes, str]) -> None:
        """
        Write bytes to a stream
        :param stream: the stream being written to
        :param to_write: the bytes being written
        """
        if isinstance(to_write, str):
            to_write = to_write.encode()

        try:
            stream.buffer.write(to_write)
        except BrokenPipeError:
            # This occurs if output is being piped to a process that closed
            pass


class ContextFlag:
    """A context manager which is also used as a boolean flag value within the default sigint handler.

    Its main use is as a flag to prevent the SIGINT handler in cmd2 from raising a KeyboardInterrupt
    while a critical code section has set the flag to True. Because signal handling is always done on the
    main thread, this class is not thread-safe since there is no need.
    """

    def __init__(self) -> None:
        # When this flag has a positive value, it is considered set.
        # When it is 0, it is not set. It should never go below 0.
        self.__count = 0

    def __bool__(self) -> bool:
        return self.__count > 0

    def __enter__(self) -> None:
        self.__count += 1

    def __exit__(self, *args: Any) -> None:
        self.__count -= 1
        if self.__count < 0:
            raise ValueError("count has gone below 0")


class RedirectionSavedState:
    """Created by each command to store information required to restore state after redirection"""

    def __init__(
        self,
        self_stdout: Union[StdSim, TextIO],
        sys_stdout: Union[StdSim, TextIO],
        pipe_proc_reader: Optional[ProcReader],
        saved_redirecting: bool,
    ) -> None:
        """
        RedirectionSavedState initializer
        :param self_stdout: saved value of Cmd.stdout
        :param sys_stdout: saved value of sys.stdout
        :param pipe_proc_reader: saved value of Cmd._cur_pipe_proc_reader
        :param saved_redirecting: saved value of Cmd._redirecting
        """
        # Tells if command is redirecting
        self.redirecting = False

        # Used to restore values after redirection ends
        self.saved_self_stdout = self_stdout
        self.saved_sys_stdout = sys_stdout

        # Used to restore values after command ends regardless of whether the command redirected
        self.saved_pipe_proc_reader = pipe_proc_reader
        self.saved_redirecting = saved_redirecting


def _remove_overridden_styles(styles_to_parse: List[str]) -> List[str]:
    """
    Utility function for align_text() / truncate_line() which filters a style list down
    to only those which would still be in effect if all were processed in order.

    This is mainly used to reduce how many style strings are stored in memory when
    building large multiline strings with ANSI styles. We only need to carry over
    styles from previous lines that are still in effect.

    :param styles_to_parse: list of styles to evaluate.
    :return: list of styles that are still in effect.
    """
    from . import (
        ansi,
    )

    class StyleState:
        """Keeps track of what text styles are enabled"""

        def __init__(self) -> None:
            # Contains styles still in effect, keyed by their index in styles_to_parse
            self.style_dict: Dict[int, str] = dict()

            # Indexes into style_dict
            self.reset_all: Optional[int] = None
            self.fg: Optional[int] = None
            self.bg: Optional[int] = None
            self.intensity: Optional[int] = None
            self.italic: Optional[int] = None
            self.overline: Optional[int] = None
            self.strikethrough: Optional[int] = None
            self.underline: Optional[int] = None

    # Read the previous styles in order and keep track of their states
    style_state = StyleState()

    for index, style in enumerate(styles_to_parse):
        # For styles types that we recognize, only keep their latest value from styles_to_parse.
        # All unrecognized style types will be retained and their order preserved.
        if style in (str(ansi.TextStyle.RESET_ALL), str(ansi.TextStyle.ALT_RESET_ALL)):
            style_state = StyleState()
            style_state.reset_all = index
        elif ansi.STD_FG_RE.match(style) or ansi.EIGHT_BIT_FG_RE.match(style) or ansi.RGB_FG_RE.match(style):
            if style_state.fg is not None:
                style_state.style_dict.pop(style_state.fg)
            style_state.fg = index
        elif ansi.STD_BG_RE.match(style) or ansi.EIGHT_BIT_BG_RE.match(style) or ansi.RGB_BG_RE.match(style):
            if style_state.bg is not None:
                style_state.style_dict.pop(style_state.bg)
            style_state.bg = index
        elif style in (
            str(ansi.TextStyle.INTENSITY_BOLD),
            str(ansi.TextStyle.INTENSITY_DIM),
            str(ansi.TextStyle.INTENSITY_NORMAL),
        ):
            if style_state.intensity is not None:
                style_state.style_dict.pop(style_state.intensity)
            style_state.intensity = index
        elif style in (str(ansi.TextStyle.ITALIC_ENABLE), str(ansi.TextStyle.ITALIC_DISABLE)):
            if style_state.italic is not None:
                style_state.style_dict.pop(style_state.italic)
            style_state.italic = index
        elif style in (str(ansi.TextStyle.OVERLINE_ENABLE), str(ansi.TextStyle.OVERLINE_DISABLE)):
            if style_state.overline is not None:
                style_state.style_dict.pop(style_state.overline)
            style_state.overline = index
        elif style in (str(ansi.TextStyle.STRIKETHROUGH_ENABLE), str(ansi.TextStyle.STRIKETHROUGH_DISABLE)):
            if style_state.strikethrough is not None:
                style_state.style_dict.pop(style_state.strikethrough)
            style_state.strikethrough = index
        elif style in (str(ansi.TextStyle.UNDERLINE_ENABLE), str(ansi.TextStyle.UNDERLINE_DISABLE)):
            if style_state.underline is not None:
                style_state.style_dict.pop(style_state.underline)
            style_state.underline = index

        # Store this style and its location in the dictionary
        style_state.style_dict[index] = style

    return list(style_state.style_dict.values())


class TextAlignment(Enum):
    """Horizontal text alignment"""

    LEFT = 1
    CENTER = 2
    RIGHT = 3


def align_text(
    text: str,
    alignment: TextAlignment,
    *,
    fill_char: str = ' ',
    width: Optional[int] = None,
    tab_width: int = 4,
    truncate: bool = False,
) -> str:
    """
    Align text for display within a given width. Supports characters with display widths greater than 1.
    ANSI style sequences do not count toward the display width. If text has line breaks, then each line is aligned
    independently.

    There are convenience wrappers around this function: align_left(), align_center(), and align_right()

    :param text: text to align (can contain multiple lines)
    :param alignment: how to align the text
    :param fill_char: character that fills the alignment gap. Defaults to space. (Cannot be a line breaking character)
    :param width: display width of the aligned text. Defaults to width of the terminal.
    :param tab_width: any tabs in the text will be replaced with this many spaces. if fill_char is a tab, then it will
                      be converted to one space.
    :param truncate: if True, then each line will be shortened to fit within the display width. The truncated
                     portions are replaced by a '…' character. Defaults to False.
    :return: aligned text
    :raises: TypeError if fill_char is more than one character (not including ANSI style sequences)
    :raises: ValueError if text or fill_char contains an unprintable character
    :raises: ValueError if width is less than 1
    """
    import io
    import shutil

    from . import (
        ansi,
    )

    if width is None:
        width = shutil.get_terminal_size().columns

    if width < 1:
        raise ValueError("width must be at least 1")

    # Convert tabs to spaces
    text = text.replace('\t', ' ' * tab_width)
    fill_char = fill_char.replace('\t', ' ')

    # Save fill_char with no styles for use later
    stripped_fill_char = ansi.strip_style(fill_char)
    if len(stripped_fill_char) != 1:
        raise TypeError("Fill character must be exactly one character long")

    fill_char_width = ansi.style_aware_wcswidth(fill_char)
    if fill_char_width == -1:
        raise (ValueError("Fill character is an unprintable character"))

    # Isolate the style chars before and after the fill character. We will use them when building sequences of
    # fill characters. Instead of repeating the style characters for each fill character, we'll wrap each sequence.
    fill_char_style_begin, fill_char_style_end = fill_char.split(stripped_fill_char)

    if text:
        lines = text.splitlines()
    else:
        lines = ['']

    text_buf = io.StringIO()

    # ANSI style sequences that may affect subsequent lines will be cancelled by the fill_char's style.
    # To avoid this, we save styles which are still in effect so we can restore them when beginning the next line.
    # This also allows lines to be used independently and still have their style. TableCreator does this.
    previous_styles: List[str] = []

    for index, line in enumerate(lines):
        if index > 0:
            text_buf.write('\n')

        if truncate:
            line = truncate_line(line, width)

        line_width = ansi.style_aware_wcswidth(line)
        if line_width == -1:
            raise (ValueError("Text to align contains an unprintable character"))

        # Get list of styles in this line
        line_styles = list(get_styles_dict(line).values())

        # Calculate how wide each side of filling needs to be
        if line_width >= width:
            # Don't return here even though the line needs no fill chars.
            # There may be styles sequences to restore.
            total_fill_width = 0
        else:
            total_fill_width = width - line_width

        if alignment == TextAlignment.LEFT:
            left_fill_width = 0
            right_fill_width = total_fill_width
        elif alignment == TextAlignment.CENTER:
            left_fill_width = total_fill_width // 2
            right_fill_width = total_fill_width - left_fill_width
        else:
            left_fill_width = total_fill_width
            right_fill_width = 0

        # Determine how many fill characters are needed to cover the width
        left_fill = (left_fill_width // fill_char_width) * stripped_fill_char
        right_fill = (right_fill_width // fill_char_width) * stripped_fill_char

        # In cases where the fill character display width didn't divide evenly into
        # the gap being filled, pad the remainder with space.
        left_fill += ' ' * (left_fill_width - ansi.style_aware_wcswidth(left_fill))
        right_fill += ' ' * (right_fill_width - ansi.style_aware_wcswidth(right_fill))

        # Don't allow styles in fill characters and text to affect one another
        if fill_char_style_begin or fill_char_style_end or previous_styles or line_styles:
            if left_fill:
                left_fill = ansi.TextStyle.RESET_ALL + fill_char_style_begin + left_fill + fill_char_style_end
            left_fill += ansi.TextStyle.RESET_ALL

            if right_fill:
                right_fill = ansi.TextStyle.RESET_ALL + fill_char_style_begin + right_fill + fill_char_style_end
            right_fill += ansi.TextStyle.RESET_ALL

        # Write the line and restore styles from previous lines which are still in effect
        text_buf.write(left_fill + ''.join(previous_styles) + line + right_fill)

        # Update list of styles that are still in effect for the next line
        previous_styles.extend(line_styles)
        previous_styles = _remove_overridden_styles(previous_styles)

    return text_buf.getvalue()


def align_left(
    text: str, *, fill_char: str = ' ', width: Optional[int] = None, tab_width: int = 4, truncate: bool = False
) -> str:
    """
    Left align text for display within a given width. Supports characters with display widths greater than 1.
    ANSI style sequences do not count toward the display width. If text has line breaks, then each line is aligned
    independently.

    :param text: text to left align (can contain multiple lines)
    :param fill_char: character that fills the alignment gap. Defaults to space. (Cannot be a line breaking character)
    :param width: display width of the aligned text. Defaults to width of the terminal.
    :param tab_width: any tabs in the text will be replaced with this many spaces. if fill_char is a tab, then it will
                      be converted to one space.
    :param truncate: if True, then text will be shortened to fit within the display width. The truncated portion is
                     replaced by a '…' character. Defaults to False.
    :return: left-aligned text
    :raises: TypeError if fill_char is more than one character (not including ANSI style sequences)
    :raises: ValueError if text or fill_char contains an unprintable character
    :raises: ValueError if width is less than 1
    """
    return align_text(text, TextAlignment.LEFT, fill_char=fill_char, width=width, tab_width=tab_width, truncate=truncate)


def align_center(
    text: str, *, fill_char: str = ' ', width: Optional[int] = None, tab_width: int = 4, truncate: bool = False
) -> str:
    """
    Center text for display within a given width. Supports characters with display widths greater than 1.
    ANSI style sequences do not count toward the display width. If text has line breaks, then each line is aligned
    independently.

    :param text: text to center (can contain multiple lines)
    :param fill_char: character that fills the alignment gap. Defaults to space. (Cannot be a line breaking character)
    :param width: display width of the aligned text. Defaults to width of the terminal.
    :param tab_width: any tabs in the text will be replaced with this many spaces. if fill_char is a tab, then it will
                      be converted to one space.
    :param truncate: if True, then text will be shortened to fit within the display width. The truncated portion is
                     replaced by a '…' character. Defaults to False.
    :return: centered text
    :raises: TypeError if fill_char is more than one character (not including ANSI style sequences)
    :raises: ValueError if text or fill_char contains an unprintable character
    :raises: ValueError if width is less than 1
    """
    return align_text(text, TextAlignment.CENTER, fill_char=fill_char, width=width, tab_width=tab_width, truncate=truncate)


def align_right(
    text: str, *, fill_char: str = ' ', width: Optional[int] = None, tab_width: int = 4, truncate: bool = False
) -> str:
    """
    Right align text for display within a given width. Supports characters with display widths greater than 1.
    ANSI style sequences do not count toward the display width. If text has line breaks, then each line is aligned
    independently.

    :param text: text to right align (can contain multiple lines)
    :param fill_char: character that fills the alignment gap. Defaults to space. (Cannot be a line breaking character)
    :param width: display width of the aligned text. Defaults to width of the terminal.
    :param tab_width: any tabs in the text will be replaced with this many spaces. if fill_char is a tab, then it will
                      be converted to one space.
    :param truncate: if True, then text will be shortened to fit within the display width. The truncated portion is
                     replaced by a '…' character. Defaults to False.
    :return: right-aligned text
    :raises: TypeError if fill_char is more than one character (not including ANSI style sequences)
    :raises: ValueError if text or fill_char contains an unprintable character
    :raises: ValueError if width is less than 1
    """
    return align_text(text, TextAlignment.RIGHT, fill_char=fill_char, width=width, tab_width=tab_width, truncate=truncate)


def truncate_line(line: str, max_width: int, *, tab_width: int = 4) -> str:
    """
    Truncate a single line to fit within a given display width. Any portion of the string that is truncated
    is replaced by a '…' character. Supports characters with display widths greater than 1. ANSI style sequences
    do not count toward the display width.

    If there are ANSI style sequences in the string after where truncation occurs, this function will append them
    to the returned string.

    This is done to prevent issues caused in cases like: truncate_line(Fg.BLUE + hello + Fg.RESET, 3)
    In this case, "hello" would be truncated before Fg.RESET resets the color from blue. Appending the remaining style
    sequences makes sure the style is in the same state had the entire string been printed. align_text() relies on this
    behavior when preserving style over multiple lines.

    :param line: text to truncate
    :param max_width: the maximum display width the resulting string is allowed to have
    :param tab_width: any tabs in the text will be replaced with this many spaces
    :return: line that has a display width less than or equal to width
    :raises: ValueError if text contains an unprintable character like a newline
    :raises: ValueError if max_width is less than 1
    """
    import io

    from . import (
        ansi,
    )

    # Handle tabs
    line = line.replace('\t', ' ' * tab_width)

    if ansi.style_aware_wcswidth(line) == -1:
        raise (ValueError("text contains an unprintable character"))

    if max_width < 1:
        raise ValueError("max_width must be at least 1")

    if ansi.style_aware_wcswidth(line) <= max_width:
        return line

    # Find all style sequences in the line
    styles_dict = get_styles_dict(line)

    # Add characters one by one and preserve all style sequences
    done = False
    index = 0
    total_width = 0
    truncated_buf = io.StringIO()

    while not done:
        # Check if a style sequence is at this index. These don't count toward display width.
        if index in styles_dict:
            truncated_buf.write(styles_dict[index])
            style_len = len(styles_dict[index])
            styles_dict.pop(index)
            index += style_len
            continue

        char = line[index]
        char_width = ansi.style_aware_wcswidth(char)

        # This char will make the text too wide, add the ellipsis instead
        if char_width + total_width >= max_width:
            char = constants.HORIZONTAL_ELLIPSIS
            char_width = ansi.style_aware_wcswidth(char)
            done = True

        total_width += char_width
        truncated_buf.write(char)
        index += 1

    # Filter out overridden styles from the remaining ones
    remaining_styles = _remove_overridden_styles(list(styles_dict.values()))

    # Append the remaining styles to the truncated text
    truncated_buf.write(''.join(remaining_styles))

    return truncated_buf.getvalue()


def get_styles_dict(text: str) -> Dict[int, str]:
    """
    Return an OrderedDict containing all ANSI style sequences found in a string

    The structure of the dictionary is:
        key: index where sequences begins
        value: ANSI style sequence found at index in text

    Keys are in ascending order

    :param text: text to search for style sequences
    """
    from . import (
        ansi,
    )

    start = 0
    styles = collections.OrderedDict()

    while True:
        match = ansi.ANSI_STYLE_RE.search(text, start)
        if match is None:
            break
        styles[match.start()] = match.group()
        start += len(match.group())

    return styles


def categorize(func: Union[Callable[..., Any], Iterable[Callable[..., Any]]], category: str) -> None:
    """Categorize a function.

    The help command output will group the passed function under the
    specified category heading

    :param func: function or list of functions to categorize
    :param category: category to put it in

    :Example:

    >>> import cmd2
    >>> class MyApp(cmd2.Cmd):
    >>>   def do_echo(self, arglist):
    >>>     self.poutput(' '.join(arglist)
    >>>
    >>>   cmd2.utils.categorize(do_echo, "Text Processing")

    For an alternative approach to categorizing commands using a decorator, see
    :func:`~cmd2.decorators.with_category`
    """
    if isinstance(func, Iterable):
        for item in func:
            setattr(item, constants.CMD_ATTR_HELP_CATEGORY, category)
    else:
        if inspect.ismethod(func):
            setattr(func.__func__, constants.CMD_ATTR_HELP_CATEGORY, category)  # type: ignore[attr-defined]
        else:
            setattr(func, constants.CMD_ATTR_HELP_CATEGORY, category)


def get_defining_class(meth: Callable[..., Any]) -> Optional[Type[Any]]:
    """
    Attempts to resolve the class that defined a method.

    Inspired by implementation published here:
        https://stackoverflow.com/a/25959545/1956611

    :param meth: method to inspect
    :return: class type in which the supplied method was defined. None if it couldn't be resolved.
    """
    if isinstance(meth, functools.partial):
        return get_defining_class(meth.func)
    if inspect.ismethod(meth) or (
        inspect.isbuiltin(meth)
        and getattr(meth, '__self__') is not None
        and getattr(meth.__self__, '__class__')  # type: ignore[attr-defined]
    ):
        for cls in inspect.getmro(meth.__self__.__class__):  # type: ignore[attr-defined]
            if meth.__name__ in cls.__dict__:
                return cls
        meth = getattr(meth, '__func__', meth)  # fallback to __qualname__ parsing
    if inspect.isfunction(meth):
        cls = getattr(inspect.getmodule(meth), meth.__qualname__.split('.<locals>', 1)[0].rsplit('.', 1)[0])
        if isinstance(cls, type):
            return cls
    return cast(type, getattr(meth, '__objclass__', None))  # handle special descriptor objects


class CompletionMode(Enum):
    """Enum for what type of tab completion to perform in cmd2.Cmd.read_input()"""

    # Tab completion will be disabled during read_input() call
    # Use of custom up-arrow history supported
    NONE = 1

    # read_input() will tab complete cmd2 commands and their arguments
    # cmd2's command line history will be used for up arrow if history is not provided.
    # Otherwise use of custom up-arrow history supported.
    COMMANDS = 2

    # read_input() will tab complete based on one of its following parameters:
    #     choices, choices_provider, completer, parser
    # Use of custom up-arrow history supported
    CUSTOM = 3


class CustomCompletionSettings:
    """Used by cmd2.Cmd.complete() to tab complete strings other than command arguments"""

    def __init__(self, parser: argparse.ArgumentParser, *, preserve_quotes: bool = False) -> None:
        """
        Initializer

        :param parser: arg parser defining format of string being tab completed
        :param preserve_quotes: if True, then quoted tokens will keep their quotes when processed by
                                ArgparseCompleter. This is helpful in cases when you're tab completing
                                flag-like tokens (e.g. -o, --option) and you don't want them to be
                                treated as argparse flags when quoted. Set this to True if you plan
                                on passing the string to argparse with the tokens still quoted.
        """
        self.parser = parser
        self.preserve_quotes = preserve_quotes


def strip_doc_annotations(doc: str) -> str:
    """
    Strip annotations from a docstring leaving only the text description

    :param doc: documentation string
    """
    # Attempt to locate the first documentation block
    cmd_desc = ''
    found_first = False
    for doc_line in doc.splitlines():
        stripped_line = doc_line.strip()

        # Don't include :param type lines
        if stripped_line.startswith(':'):
            if found_first:
                break
        elif stripped_line:
            if found_first:
                cmd_desc += "\n"
            cmd_desc += stripped_line
            found_first = True
        elif found_first:
            break
    return cmd_desc
