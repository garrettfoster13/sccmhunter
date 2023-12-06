# coding=utf-8
"""
This module provides basic ability to copy from and paste to the clipboard/pastebuffer.
"""
from typing import (
    cast,
)

import pyperclip  # type: ignore[import]

# noinspection PyProtectedMember

# Can we access the clipboard?  Should always be true on Windows and Mac, but only sometimes on Linux
# noinspection PyBroadException
try:
    # Try getting the contents of the clipboard
    _ = pyperclip.paste()

# pyperclip raises at least the following types of exceptions. To be safe, just catch all Exceptions.
#   FileNotFoundError on Windows Subsystem for Linux (WSL) when Windows paths are removed from $PATH
#   ValueError for headless Linux systems without Gtk installed
#   AssertionError can be raised by paste_klipper().
#   PyperclipException for pyperclip-specific exceptions
except Exception:
    can_clip = False
else:
    can_clip = True


def get_paste_buffer() -> str:
    """Get the contents of the clipboard / paste buffer.

    :return: contents of the clipboard
    """
    pb_str = cast(str, pyperclip.paste())
    return pb_str


def write_to_paste_buffer(txt: str) -> None:
    """Copy text to the clipboard / paste buffer.

    :param txt: text to copy to the clipboard
    """
    pyperclip.copy(txt)
