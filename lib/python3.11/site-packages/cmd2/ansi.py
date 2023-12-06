# coding=utf-8
"""
Support for ANSI escape sequences which are used for things like applying style to text,
setting the window title, and asynchronous alerts.
 """
import functools
import re
from enum import (
    Enum,
)
from typing import (
    IO,
    Any,
    List,
    Optional,
    cast,
)

from wcwidth import (  # type: ignore[import]
    wcswidth,
)

#######################################################
# Common ANSI escape sequence constants
#######################################################
ESC = '\x1b'
CSI = f'{ESC}['
OSC = f'{ESC}]'
BEL = '\a'


class AllowStyle(Enum):
    """Values for ``cmd2.ansi.allow_style``"""

    ALWAYS = 'Always'  # Always output ANSI style sequences
    NEVER = 'Never'  # Remove ANSI style sequences from all output
    TERMINAL = 'Terminal'  # Remove ANSI style sequences if the output is not going to the terminal

    def __str__(self) -> str:
        """Return value instead of enum name for printing in cmd2's set command"""
        return str(self.value)

    def __repr__(self) -> str:
        """Return quoted value instead of enum description for printing in cmd2's set command"""
        return repr(self.value)


# Controls when ANSI style sequences are allowed in output
allow_style = AllowStyle.TERMINAL
"""When using outside of a cmd2 app, set this variable to one of:

- ``AllowStyle.ALWAYS`` - always output ANSI style sequences
- ``AllowStyle.NEVER`` - remove ANSI style sequences from all output
- ``AllowStyle.TERMINAL`` - remove ANSI style sequences if the output is not going to the terminal

to control how ANSI style sequences are handled by ``style_aware_write()``.

``style_aware_write()`` is called by cmd2 methods like ``poutput()``, ``perror()``,
``pwarning()``, etc.

The default is ``AllowStyle.TERMINAL``.
"""

# Regular expression to match ANSI style sequence
ANSI_STYLE_RE = re.compile(fr'{ESC}\[[^m]*m')

# Matches standard foreground colors: CSI(30-37|90-97|39)m
STD_FG_RE = re.compile(fr'{ESC}\[(?:[39][0-7]|39)m')

# Matches standard background colors: CSI(40-47|100-107|49)m
STD_BG_RE = re.compile(fr'{ESC}\[(?:(?:4|10)[0-7]|49)m')

# Matches eight-bit foreground colors: CSI38;5;(0-255)m
EIGHT_BIT_FG_RE = re.compile(fr'{ESC}\[38;5;(?:1?[0-9]?[0-9]?|2[0-4][0-9]|25[0-5])m')

# Matches eight-bit background colors: CSI48;5;(0-255)m
EIGHT_BIT_BG_RE = re.compile(fr'{ESC}\[48;5;(?:1?[0-9]?[0-9]?|2[0-4][0-9]|25[0-5])m')

# Matches RGB foreground colors: CSI38;2;(0-255);(0-255);(0-255)m
RGB_FG_RE = re.compile(fr'{ESC}\[38;2(?:;(?:1?[0-9]?[0-9]?|2[0-4][0-9]|25[0-5])){{3}}m')

# Matches RGB background colors: CSI48;2;(0-255);(0-255);(0-255)m
RGB_BG_RE = re.compile(fr'{ESC}\[48;2(?:;(?:1?[0-9]?[0-9]?|2[0-4][0-9]|25[0-5])){{3}}m')


def strip_style(text: str) -> str:
    """
    Strip ANSI style sequences from a string.

    :param text: string which may contain ANSI style sequences
    :return: the same string with any ANSI style sequences removed
    """
    return ANSI_STYLE_RE.sub('', text)


def style_aware_wcswidth(text: str) -> int:
    """
    Wrap wcswidth to make it compatible with strings that contain ANSI style sequences.
    This is intended for single line strings. If text contains a newline, this
    function will return -1. For multiline strings, call widest_line() instead.

    :param text: the string being measured
    :return: The width of the string when printed to the terminal if no errors occur.
             If text contains characters with no absolute width (i.e. tabs),
             then this function returns -1. Replace tabs with spaces before calling this.
    """
    # Strip ANSI style sequences since they cause wcswidth to return -1
    return cast(int, wcswidth(strip_style(text)))


def widest_line(text: str) -> int:
    """
    Return the width of the widest line in a multiline string. This wraps style_aware_wcswidth()
    so it handles ANSI style sequences and has the same restrictions on non-printable characters.

    :param text: the string being measured
    :return: The width of the string when printed to the terminal if no errors occur.
             If text contains characters with no absolute width (i.e. tabs),
             then this function returns -1. Replace tabs with spaces before calling this.
    """
    if not text:
        return 0

    lines_widths = [style_aware_wcswidth(line) for line in text.splitlines()]
    if -1 in lines_widths:
        return -1

    return max(lines_widths)


def style_aware_write(fileobj: IO[str], msg: str) -> None:
    """
    Write a string to a fileobject and strip its ANSI style sequences if required by allow_style setting

    :param fileobj: the file object being written to
    :param msg: the string being written
    """
    if allow_style == AllowStyle.NEVER or (allow_style == AllowStyle.TERMINAL and not fileobj.isatty()):
        msg = strip_style(msg)
    fileobj.write(msg)


####################################################################################
# Utility functions which create various ANSI sequences
####################################################################################
def set_title(title: str) -> str:
    """
    Generate a string that, when printed, sets a terminal's window title.

    :param title: new title for the window
    :return: the set title string
    """
    return f"{OSC}2;{title}{BEL}"


def clear_screen(clear_type: int = 2) -> str:
    """
    Generate a string that, when printed, clears a terminal screen based on value of clear_type.

    :param clear_type: integer which specifies how to clear the screen (Defaults to 2)
                       Possible values:
                       0 - clear from cursor to end of screen
                       1 - clear from cursor to beginning of the screen
                       2 - clear entire screen
                       3 - clear entire screen and delete all lines saved in the scrollback buffer
    :return: the clear screen string
    :raises: ValueError if clear_type is not a valid value
    """
    if 0 <= clear_type <= 3:
        return f"{CSI}{clear_type}J"
    raise ValueError("clear_type must in an integer from 0 to 3")


def clear_line(clear_type: int = 2) -> str:
    """
    Generate a string that, when printed, clears a line based on value of clear_type.

    :param clear_type: integer which specifies how to clear the line (Defaults to 2)
                       Possible values:
                       0 - clear from cursor to the end of the line
                       1 - clear from cursor to beginning of the line
                       2 - clear entire line
    :return: the clear line string
    :raises: ValueError if clear_type is not a valid value
    """
    if 0 <= clear_type <= 2:
        return f"{CSI}{clear_type}K"
    raise ValueError("clear_type must in an integer from 0 to 2")


####################################################################################
# Base classes which are not intended to be used directly
####################################################################################
class AnsiSequence:
    """Base class to create ANSI sequence strings"""

    def __add__(self, other: Any) -> str:
        """
        Support building an ANSI sequence string when self is the left operand
        e.g. Fg.LIGHT_MAGENTA + "hello"
        """
        return str(self) + str(other)

    def __radd__(self, other: Any) -> str:
        """
        Support building an ANSI sequence string when self is the right operand
        e.g. "hello" + Fg.RESET
        """
        return str(other) + str(self)


class FgColor(AnsiSequence):
    """Base class for ANSI Sequences which set foreground text color"""

    pass


class BgColor(AnsiSequence):
    """Base class for ANSI Sequences which set background text color"""

    pass


####################################################################################
# Implementations intended for direct use
####################################################################################
# noinspection PyPep8Naming
class Cursor:
    """Create ANSI sequences to alter the cursor position"""

    @staticmethod
    def UP(count: int = 1) -> str:
        """Move the cursor up a specified amount of lines (Defaults to 1)"""
        return f"{CSI}{count}A"

    @staticmethod
    def DOWN(count: int = 1) -> str:
        """Move the cursor down a specified amount of lines (Defaults to 1)"""
        return f"{CSI}{count}B"

    @staticmethod
    def FORWARD(count: int = 1) -> str:
        """Move the cursor forward a specified amount of lines (Defaults to 1)"""
        return f"{CSI}{count}C"

    @staticmethod
    def BACK(count: int = 1) -> str:
        """Move the cursor back a specified amount of lines (Defaults to 1)"""
        return f"{CSI}{count}D"

    @staticmethod
    def SET_POS(x: int, y: int) -> str:
        """Set the cursor position to coordinates which are 1-based"""
        return f"{CSI}{y};{x}H"


class TextStyle(AnsiSequence, Enum):
    """Create text style ANSI sequences"""

    # Resets all styles and colors of text
    RESET_ALL = 0
    ALT_RESET_ALL = ''

    INTENSITY_BOLD = 1
    INTENSITY_DIM = 2
    INTENSITY_NORMAL = 22

    ITALIC_ENABLE = 3
    ITALIC_DISABLE = 23

    OVERLINE_ENABLE = 53
    OVERLINE_DISABLE = 55

    STRIKETHROUGH_ENABLE = 9
    STRIKETHROUGH_DISABLE = 29

    UNDERLINE_ENABLE = 4
    UNDERLINE_DISABLE = 24

    def __str__(self) -> str:
        """
        Return ANSI text style sequence instead of enum name
        This is helpful when using a TextStyle in an f-string or format() call
        e.g. my_str = f"{TextStyle.UNDERLINE_ENABLE}hello{TextStyle.UNDERLINE_DISABLE}"
        """
        return f"{CSI}{self.value}m"


class Fg(FgColor, Enum):
    """
    Create ANSI sequences for the 16 standard terminal foreground text colors.
    A terminal's color settings affect how these colors appear.
    To reset any foreground color, use Fg.RESET.
    """

    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    LIGHT_GRAY = 37
    DARK_GRAY = 90
    LIGHT_RED = 91
    LIGHT_GREEN = 92
    LIGHT_YELLOW = 93
    LIGHT_BLUE = 94
    LIGHT_MAGENTA = 95
    LIGHT_CYAN = 96
    WHITE = 97

    RESET = 39

    def __str__(self) -> str:
        """
        Return ANSI color sequence instead of enum name
        This is helpful when using an Fg in an f-string or format() call
        e.g. my_str = f"{Fg.BLUE}hello{Fg.RESET}"
        """
        return f"{CSI}{self.value}m"


class Bg(BgColor, Enum):
    """
    Create ANSI sequences for the 16 standard terminal background text colors.
    A terminal's color settings affect how these colors appear.
    To reset any background color, use Bg.RESET.
    """

    BLACK = 40
    RED = 41
    GREEN = 42
    YELLOW = 43
    BLUE = 44
    MAGENTA = 45
    CYAN = 46
    LIGHT_GRAY = 47
    DARK_GRAY = 100
    LIGHT_RED = 101
    LIGHT_GREEN = 102
    LIGHT_YELLOW = 103
    LIGHT_BLUE = 104
    LIGHT_MAGENTA = 105
    LIGHT_CYAN = 106
    WHITE = 107

    RESET = 49

    def __str__(self) -> str:
        """
        Return ANSI color sequence instead of enum name
        This is helpful when using a Bg in an f-string or format() call
        e.g. my_str = f"{Bg.BLACK}hello{Bg.RESET}"
        """
        return f"{CSI}{self.value}m"


class EightBitFg(FgColor, Enum):
    """
    Create ANSI sequences for 8-bit terminal foreground text colors. Most terminals support 8-bit/256-color mode.
    The first 16 colors correspond to the 16 colors from Fg and behave the same way.
    To reset any foreground color, including 8-bit, use Fg.RESET.
    """

    BLACK = 0
    RED = 1
    GREEN = 2
    YELLOW = 3
    BLUE = 4
    MAGENTA = 5
    CYAN = 6
    LIGHT_GRAY = 7
    DARK_GRAY = 8
    LIGHT_RED = 9
    LIGHT_GREEN = 10
    LIGHT_YELLOW = 11
    LIGHT_BLUE = 12
    LIGHT_MAGENTA = 13
    LIGHT_CYAN = 14
    WHITE = 15
    GRAY_0 = 16
    NAVY_BLUE = 17
    DARK_BLUE = 18
    BLUE_3A = 19
    BLUE_3B = 20
    BLUE_1 = 21
    DARK_GREEN = 22
    DEEP_SKY_BLUE_4A = 23
    DEEP_SKY_BLUE_4B = 24
    DEEP_SKY_BLUE_4C = 25
    DODGER_BLUE_3 = 26
    DODGER_BLUE_2 = 27
    GREEN_4 = 28
    SPRING_GREEN_4 = 29
    TURQUOISE_4 = 30
    DEEP_SKY_BLUE_3A = 31
    DEEP_SKY_BLUE_3B = 32
    DODGER_BLUE_1 = 33
    GREEN_3A = 34
    SPRING_GREEN_3A = 35
    DARK_CYAN = 36
    LIGHT_SEA_GREEN = 37
    DEEP_SKY_BLUE_2 = 38
    DEEP_SKY_BLUE_1 = 39
    GREEN_3B = 40
    SPRING_GREEN_3B = 41
    SPRING_GREEN_2A = 42
    CYAN_3 = 43
    DARK_TURQUOISE = 44
    TURQUOISE_2 = 45
    GREEN_1 = 46
    SPRING_GREEN_2B = 47
    SPRING_GREEN_1 = 48
    MEDIUM_SPRING_GREEN = 49
    CYAN_2 = 50
    CYAN_1 = 51
    DARK_RED_1 = 52
    DEEP_PINK_4A = 53
    PURPLE_4A = 54
    PURPLE_4B = 55
    PURPLE_3 = 56
    BLUE_VIOLET = 57
    ORANGE_4A = 58
    GRAY_37 = 59
    MEDIUM_PURPLE_4 = 60
    SLATE_BLUE_3A = 61
    SLATE_BLUE_3B = 62
    ROYAL_BLUE_1 = 63
    CHARTREUSE_4 = 64
    DARK_SEA_GREEN_4A = 65
    PALE_TURQUOISE_4 = 66
    STEEL_BLUE = 67
    STEEL_BLUE_3 = 68
    CORNFLOWER_BLUE = 69
    CHARTREUSE_3A = 70
    DARK_SEA_GREEN_4B = 71
    CADET_BLUE_2 = 72
    CADET_BLUE_1 = 73
    SKY_BLUE_3 = 74
    STEEL_BLUE_1A = 75
    CHARTREUSE_3B = 76
    PALE_GREEN_3A = 77
    SEA_GREEN_3 = 78
    AQUAMARINE_3 = 79
    MEDIUM_TURQUOISE = 80
    STEEL_BLUE_1B = 81
    CHARTREUSE_2A = 82
    SEA_GREEN_2 = 83
    SEA_GREEN_1A = 84
    SEA_GREEN_1B = 85
    AQUAMARINE_1A = 86
    DARK_SLATE_GRAY_2 = 87
    DARK_RED_2 = 88
    DEEP_PINK_4B = 89
    DARK_MAGENTA_1 = 90
    DARK_MAGENTA_2 = 91
    DARK_VIOLET_1A = 92
    PURPLE_1A = 93
    ORANGE_4B = 94
    LIGHT_PINK_4 = 95
    PLUM_4 = 96
    MEDIUM_PURPLE_3A = 97
    MEDIUM_PURPLE_3B = 98
    SLATE_BLUE_1 = 99
    YELLOW_4A = 100
    WHEAT_4 = 101
    GRAY_53 = 102
    LIGHT_SLATE_GRAY = 103
    MEDIUM_PURPLE = 104
    LIGHT_SLATE_BLUE = 105
    YELLOW_4B = 106
    DARK_OLIVE_GREEN_3A = 107
    DARK_GREEN_SEA = 108
    LIGHT_SKY_BLUE_3A = 109
    LIGHT_SKY_BLUE_3B = 110
    SKY_BLUE_2 = 111
    CHARTREUSE_2B = 112
    DARK_OLIVE_GREEN_3B = 113
    PALE_GREEN_3B = 114
    DARK_SEA_GREEN_3A = 115
    DARK_SLATE_GRAY_3 = 116
    SKY_BLUE_1 = 117
    CHARTREUSE_1 = 118
    LIGHT_GREEN_2 = 119
    LIGHT_GREEN_3 = 120
    PALE_GREEN_1A = 121
    AQUAMARINE_1B = 122
    DARK_SLATE_GRAY_1 = 123
    RED_3A = 124
    DEEP_PINK_4C = 125
    MEDIUM_VIOLET_RED = 126
    MAGENTA_3A = 127
    DARK_VIOLET_1B = 128
    PURPLE_1B = 129
    DARK_ORANGE_3A = 130
    INDIAN_RED_1A = 131
    HOT_PINK_3A = 132
    MEDIUM_ORCHID_3 = 133
    MEDIUM_ORCHID = 134
    MEDIUM_PURPLE_2A = 135
    DARK_GOLDENROD = 136
    LIGHT_SALMON_3A = 137
    ROSY_BROWN = 138
    GRAY_63 = 139
    MEDIUM_PURPLE_2B = 140
    MEDIUM_PURPLE_1 = 141
    GOLD_3A = 142
    DARK_KHAKI = 143
    NAVAJO_WHITE_3 = 144
    GRAY_69 = 145
    LIGHT_STEEL_BLUE_3 = 146
    LIGHT_STEEL_BLUE = 147
    YELLOW_3A = 148
    DARK_OLIVE_GREEN_3 = 149
    DARK_SEA_GREEN_3B = 150
    DARK_SEA_GREEN_2 = 151
    LIGHT_CYAN_3 = 152
    LIGHT_SKY_BLUE_1 = 153
    GREEN_YELLOW = 154
    DARK_OLIVE_GREEN_2 = 155
    PALE_GREEN_1B = 156
    DARK_SEA_GREEN_5B = 157
    DARK_SEA_GREEN_5A = 158
    PALE_TURQUOISE_1 = 159
    RED_3B = 160
    DEEP_PINK_3A = 161
    DEEP_PINK_3B = 162
    MAGENTA_3B = 163
    MAGENTA_3C = 164
    MAGENTA_2A = 165
    DARK_ORANGE_3B = 166
    INDIAN_RED_1B = 167
    HOT_PINK_3B = 168
    HOT_PINK_2 = 169
    ORCHID = 170
    MEDIUM_ORCHID_1A = 171
    ORANGE_3 = 172
    LIGHT_SALMON_3B = 173
    LIGHT_PINK_3 = 174
    PINK_3 = 175
    PLUM_3 = 176
    VIOLET = 177
    GOLD_3B = 178
    LIGHT_GOLDENROD_3 = 179
    TAN = 180
    MISTY_ROSE_3 = 181
    THISTLE_3 = 182
    PLUM_2 = 183
    YELLOW_3B = 184
    KHAKI_3 = 185
    LIGHT_GOLDENROD_2A = 186
    LIGHT_YELLOW_3 = 187
    GRAY_84 = 188
    LIGHT_STEEL_BLUE_1 = 189
    YELLOW_2 = 190
    DARK_OLIVE_GREEN_1A = 191
    DARK_OLIVE_GREEN_1B = 192
    DARK_SEA_GREEN_1 = 193
    HONEYDEW_2 = 194
    LIGHT_CYAN_1 = 195
    RED_1 = 196
    DEEP_PINK_2 = 197
    DEEP_PINK_1A = 198
    DEEP_PINK_1B = 199
    MAGENTA_2B = 200
    MAGENTA_1 = 201
    ORANGE_RED_1 = 202
    INDIAN_RED_1C = 203
    INDIAN_RED_1D = 204
    HOT_PINK_1A = 205
    HOT_PINK_1B = 206
    MEDIUM_ORCHID_1B = 207
    DARK_ORANGE = 208
    SALMON_1 = 209
    LIGHT_CORAL = 210
    PALE_VIOLET_RED_1 = 211
    ORCHID_2 = 212
    ORCHID_1 = 213
    ORANGE_1 = 214
    SANDY_BROWN = 215
    LIGHT_SALMON_1 = 216
    LIGHT_PINK_1 = 217
    PINK_1 = 218
    PLUM_1 = 219
    GOLD_1 = 220
    LIGHT_GOLDENROD_2B = 221
    LIGHT_GOLDENROD_2C = 222
    NAVAJO_WHITE_1 = 223
    MISTY_ROSE1 = 224
    THISTLE_1 = 225
    YELLOW_1 = 226
    LIGHT_GOLDENROD_1 = 227
    KHAKI_1 = 228
    WHEAT_1 = 229
    CORNSILK_1 = 230
    GRAY_100 = 231
    GRAY_3 = 232
    GRAY_7 = 233
    GRAY_11 = 234
    GRAY_15 = 235
    GRAY_19 = 236
    GRAY_23 = 237
    GRAY_27 = 238
    GRAY_30 = 239
    GRAY_35 = 240
    GRAY_39 = 241
    GRAY_42 = 242
    GRAY_46 = 243
    GRAY_50 = 244
    GRAY_54 = 245
    GRAY_58 = 246
    GRAY_62 = 247
    GRAY_66 = 248
    GRAY_70 = 249
    GRAY_74 = 250
    GRAY_78 = 251
    GRAY_82 = 252
    GRAY_85 = 253
    GRAY_89 = 254
    GRAY_93 = 255

    def __str__(self) -> str:
        """
        Return ANSI color sequence instead of enum name
        This is helpful when using an EightBitFg in an f-string or format() call
        e.g. my_str = f"{EightBitFg.SLATE_BLUE_1}hello{Fg.RESET}"
        """
        return f"{CSI}38;5;{self.value}m"


class EightBitBg(BgColor, Enum):
    """
    Create ANSI sequences for 8-bit terminal background text colors. Most terminals support 8-bit/256-color mode.
    The first 16 colors correspond to the 16 colors from Bg and behave the same way.
    To reset any background color, including 8-bit, use Bg.RESET.
    """

    BLACK = 0
    RED = 1
    GREEN = 2
    YELLOW = 3
    BLUE = 4
    MAGENTA = 5
    CYAN = 6
    LIGHT_GRAY = 7
    DARK_GRAY = 8
    LIGHT_RED = 9
    LIGHT_GREEN = 10
    LIGHT_YELLOW = 11
    LIGHT_BLUE = 12
    LIGHT_MAGENTA = 13
    LIGHT_CYAN = 14
    WHITE = 15
    GRAY_0 = 16
    NAVY_BLUE = 17
    DARK_BLUE = 18
    BLUE_3A = 19
    BLUE_3B = 20
    BLUE_1 = 21
    DARK_GREEN = 22
    DEEP_SKY_BLUE_4A = 23
    DEEP_SKY_BLUE_4B = 24
    DEEP_SKY_BLUE_4C = 25
    DODGER_BLUE_3 = 26
    DODGER_BLUE_2 = 27
    GREEN_4 = 28
    SPRING_GREEN_4 = 29
    TURQUOISE_4 = 30
    DEEP_SKY_BLUE_3A = 31
    DEEP_SKY_BLUE_3B = 32
    DODGER_BLUE_1 = 33
    GREEN_3A = 34
    SPRING_GREEN_3A = 35
    DARK_CYAN = 36
    LIGHT_SEA_GREEN = 37
    DEEP_SKY_BLUE_2 = 38
    DEEP_SKY_BLUE_1 = 39
    GREEN_3B = 40
    SPRING_GREEN_3B = 41
    SPRING_GREEN_2A = 42
    CYAN_3 = 43
    DARK_TURQUOISE = 44
    TURQUOISE_2 = 45
    GREEN_1 = 46
    SPRING_GREEN_2B = 47
    SPRING_GREEN_1 = 48
    MEDIUM_SPRING_GREEN = 49
    CYAN_2 = 50
    CYAN_1 = 51
    DARK_RED_1 = 52
    DEEP_PINK_4A = 53
    PURPLE_4A = 54
    PURPLE_4B = 55
    PURPLE_3 = 56
    BLUE_VIOLET = 57
    ORANGE_4A = 58
    GRAY_37 = 59
    MEDIUM_PURPLE_4 = 60
    SLATE_BLUE_3A = 61
    SLATE_BLUE_3B = 62
    ROYAL_BLUE_1 = 63
    CHARTREUSE_4 = 64
    DARK_SEA_GREEN_4A = 65
    PALE_TURQUOISE_4 = 66
    STEEL_BLUE = 67
    STEEL_BLUE_3 = 68
    CORNFLOWER_BLUE = 69
    CHARTREUSE_3A = 70
    DARK_SEA_GREEN_4B = 71
    CADET_BLUE_2 = 72
    CADET_BLUE_1 = 73
    SKY_BLUE_3 = 74
    STEEL_BLUE_1A = 75
    CHARTREUSE_3B = 76
    PALE_GREEN_3A = 77
    SEA_GREEN_3 = 78
    AQUAMARINE_3 = 79
    MEDIUM_TURQUOISE = 80
    STEEL_BLUE_1B = 81
    CHARTREUSE_2A = 82
    SEA_GREEN_2 = 83
    SEA_GREEN_1A = 84
    SEA_GREEN_1B = 85
    AQUAMARINE_1A = 86
    DARK_SLATE_GRAY_2 = 87
    DARK_RED_2 = 88
    DEEP_PINK_4B = 89
    DARK_MAGENTA_1 = 90
    DARK_MAGENTA_2 = 91
    DARK_VIOLET_1A = 92
    PURPLE_1A = 93
    ORANGE_4B = 94
    LIGHT_PINK_4 = 95
    PLUM_4 = 96
    MEDIUM_PURPLE_3A = 97
    MEDIUM_PURPLE_3B = 98
    SLATE_BLUE_1 = 99
    YELLOW_4A = 100
    WHEAT_4 = 101
    GRAY_53 = 102
    LIGHT_SLATE_GRAY = 103
    MEDIUM_PURPLE = 104
    LIGHT_SLATE_BLUE = 105
    YELLOW_4B = 106
    DARK_OLIVE_GREEN_3A = 107
    DARK_GREEN_SEA = 108
    LIGHT_SKY_BLUE_3A = 109
    LIGHT_SKY_BLUE_3B = 110
    SKY_BLUE_2 = 111
    CHARTREUSE_2B = 112
    DARK_OLIVE_GREEN_3B = 113
    PALE_GREEN_3B = 114
    DARK_SEA_GREEN_3A = 115
    DARK_SLATE_GRAY_3 = 116
    SKY_BLUE_1 = 117
    CHARTREUSE_1 = 118
    LIGHT_GREEN_2 = 119
    LIGHT_GREEN_3 = 120
    PALE_GREEN_1A = 121
    AQUAMARINE_1B = 122
    DARK_SLATE_GRAY_1 = 123
    RED_3A = 124
    DEEP_PINK_4C = 125
    MEDIUM_VIOLET_RED = 126
    MAGENTA_3A = 127
    DARK_VIOLET_1B = 128
    PURPLE_1B = 129
    DARK_ORANGE_3A = 130
    INDIAN_RED_1A = 131
    HOT_PINK_3A = 132
    MEDIUM_ORCHID_3 = 133
    MEDIUM_ORCHID = 134
    MEDIUM_PURPLE_2A = 135
    DARK_GOLDENROD = 136
    LIGHT_SALMON_3A = 137
    ROSY_BROWN = 138
    GRAY_63 = 139
    MEDIUM_PURPLE_2B = 140
    MEDIUM_PURPLE_1 = 141
    GOLD_3A = 142
    DARK_KHAKI = 143
    NAVAJO_WHITE_3 = 144
    GRAY_69 = 145
    LIGHT_STEEL_BLUE_3 = 146
    LIGHT_STEEL_BLUE = 147
    YELLOW_3A = 148
    DARK_OLIVE_GREEN_3 = 149
    DARK_SEA_GREEN_3B = 150
    DARK_SEA_GREEN_2 = 151
    LIGHT_CYAN_3 = 152
    LIGHT_SKY_BLUE_1 = 153
    GREEN_YELLOW = 154
    DARK_OLIVE_GREEN_2 = 155
    PALE_GREEN_1B = 156
    DARK_SEA_GREEN_5B = 157
    DARK_SEA_GREEN_5A = 158
    PALE_TURQUOISE_1 = 159
    RED_3B = 160
    DEEP_PINK_3A = 161
    DEEP_PINK_3B = 162
    MAGENTA_3B = 163
    MAGENTA_3C = 164
    MAGENTA_2A = 165
    DARK_ORANGE_3B = 166
    INDIAN_RED_1B = 167
    HOT_PINK_3B = 168
    HOT_PINK_2 = 169
    ORCHID = 170
    MEDIUM_ORCHID_1A = 171
    ORANGE_3 = 172
    LIGHT_SALMON_3B = 173
    LIGHT_PINK_3 = 174
    PINK_3 = 175
    PLUM_3 = 176
    VIOLET = 177
    GOLD_3B = 178
    LIGHT_GOLDENROD_3 = 179
    TAN = 180
    MISTY_ROSE_3 = 181
    THISTLE_3 = 182
    PLUM_2 = 183
    YELLOW_3B = 184
    KHAKI_3 = 185
    LIGHT_GOLDENROD_2A = 186
    LIGHT_YELLOW_3 = 187
    GRAY_84 = 188
    LIGHT_STEEL_BLUE_1 = 189
    YELLOW_2 = 190
    DARK_OLIVE_GREEN_1A = 191
    DARK_OLIVE_GREEN_1B = 192
    DARK_SEA_GREEN_1 = 193
    HONEYDEW_2 = 194
    LIGHT_CYAN_1 = 195
    RED_1 = 196
    DEEP_PINK_2 = 197
    DEEP_PINK_1A = 198
    DEEP_PINK_1B = 199
    MAGENTA_2B = 200
    MAGENTA_1 = 201
    ORANGE_RED_1 = 202
    INDIAN_RED_1C = 203
    INDIAN_RED_1D = 204
    HOT_PINK_1A = 205
    HOT_PINK_1B = 206
    MEDIUM_ORCHID_1B = 207
    DARK_ORANGE = 208
    SALMON_1 = 209
    LIGHT_CORAL = 210
    PALE_VIOLET_RED_1 = 211
    ORCHID_2 = 212
    ORCHID_1 = 213
    ORANGE_1 = 214
    SANDY_BROWN = 215
    LIGHT_SALMON_1 = 216
    LIGHT_PINK_1 = 217
    PINK_1 = 218
    PLUM_1 = 219
    GOLD_1 = 220
    LIGHT_GOLDENROD_2B = 221
    LIGHT_GOLDENROD_2C = 222
    NAVAJO_WHITE_1 = 223
    MISTY_ROSE1 = 224
    THISTLE_1 = 225
    YELLOW_1 = 226
    LIGHT_GOLDENROD_1 = 227
    KHAKI_1 = 228
    WHEAT_1 = 229
    CORNSILK_1 = 230
    GRAY_100 = 231
    GRAY_3 = 232
    GRAY_7 = 233
    GRAY_11 = 234
    GRAY_15 = 235
    GRAY_19 = 236
    GRAY_23 = 237
    GRAY_27 = 238
    GRAY_30 = 239
    GRAY_35 = 240
    GRAY_39 = 241
    GRAY_42 = 242
    GRAY_46 = 243
    GRAY_50 = 244
    GRAY_54 = 245
    GRAY_58 = 246
    GRAY_62 = 247
    GRAY_66 = 248
    GRAY_70 = 249
    GRAY_74 = 250
    GRAY_78 = 251
    GRAY_82 = 252
    GRAY_85 = 253
    GRAY_89 = 254
    GRAY_93 = 255

    def __str__(self) -> str:
        """
        Return ANSI color sequence instead of enum name
        This is helpful when using an EightBitBg in an f-string or format() call
        e.g. my_str = f"{EightBitBg.KHAKI_3}hello{Bg.RESET}"
        """
        return f"{CSI}48;5;{self.value}m"


class RgbFg(FgColor):
    """
    Create ANSI sequences for 24-bit (RGB) terminal foreground text colors. The terminal must support 24-bit/true-color mode.
    To reset any foreground color, including 24-bit, use Fg.RESET.
    """

    def __init__(self, r: int, g: int, b: int) -> None:
        """
        RgbFg initializer

        :param r: integer from 0-255 for the red component of the color
        :param g: integer from 0-255 for the green component of the color
        :param b: integer from 0-255 for the blue component of the color
        :raises: ValueError if r, g, or b is not in the range 0-255
        """
        if any(c < 0 or c > 255 for c in [r, g, b]):
            raise ValueError("RGB values must be integers in the range of 0 to 255")

        self._sequence = f"{CSI}38;2;{r};{g};{b}m"

    def __str__(self) -> str:
        """
        Return ANSI color sequence instead of enum name
        This is helpful when using an RgbFg in an f-string or format() call
        e.g. my_str = f"{RgbFg(0, 55, 100)}hello{Fg.RESET}"
        """
        return self._sequence


class RgbBg(BgColor):
    """
    Create ANSI sequences for 24-bit (RGB) terminal background text colors. The terminal must support 24-bit/true-color mode.
    To reset any background color, including 24-bit, use Bg.RESET.
    """

    def __init__(self, r: int, g: int, b: int) -> None:
        """
        RgbBg initializer

        :param r: integer from 0-255 for the red component of the color
        :param g: integer from 0-255 for the green component of the color
        :param b: integer from 0-255 for the blue component of the color
        :raises: ValueError if r, g, or b is not in the range 0-255
        """
        if any(c < 0 or c > 255 for c in [r, g, b]):
            raise ValueError("RGB values must be integers in the range of 0 to 255")

        self._sequence = f"{CSI}48;2;{r};{g};{b}m"

    def __str__(self) -> str:
        """
        Return ANSI color sequence instead of enum name
        This is helpful when using an RgbBg in an f-string or format() call
        e.g. my_str = f"{RgbBg(100, 255, 27)}hello{Bg.RESET}"
        """
        return self._sequence


def style(
    value: Any,
    *,
    fg: Optional[FgColor] = None,
    bg: Optional[BgColor] = None,
    bold: Optional[bool] = None,
    dim: Optional[bool] = None,
    italic: Optional[bool] = None,
    overline: Optional[bool] = None,
    strikethrough: Optional[bool] = None,
    underline: Optional[bool] = None,
) -> str:
    """
    Apply ANSI colors and/or styles to a string and return it.
    The styling is self contained which means that at the end of the string reset code(s) are issued
    to undo whatever styling was done at the beginning.

    :param value: object whose text is to be styled
    :param fg: foreground color provided as any subclass of FgColor (e.g. Fg, EightBitFg, RgbFg)
               Defaults to no color.
    :param bg: foreground color provided as any subclass of BgColor (e.g. Bg, EightBitBg, RgbBg)
               Defaults to no color.
    :param bold: apply the bold style if True. Defaults to False.
    :param dim: apply the dim style if True. Defaults to False.
    :param italic: apply the italic style if True. Defaults to False.
    :param overline: apply the overline style if True. Defaults to False.
    :param strikethrough: apply the strikethrough style if True. Defaults to False.
    :param underline: apply the underline style if True. Defaults to False.
    :raises: TypeError if fg isn't None or a subclass of FgColor
    :raises: TypeError if bg isn't None or a subclass of BgColor
    :return: the stylized string
    """
    # List of strings that add style
    additions: List[AnsiSequence] = []

    # List of strings that remove style
    removals: List[AnsiSequence] = []

    # Process the style settings
    if fg is not None:
        if not isinstance(fg, FgColor):
            raise TypeError("fg must be a subclass of FgColor")
        additions.append(fg)
        removals.append(Fg.RESET)

    if bg is not None:
        if not isinstance(bg, BgColor):
            raise TypeError("bg must a subclass of BgColor")
        additions.append(bg)
        removals.append(Bg.RESET)

    if bold:
        additions.append(TextStyle.INTENSITY_BOLD)
        removals.append(TextStyle.INTENSITY_NORMAL)

    if dim:
        additions.append(TextStyle.INTENSITY_DIM)
        removals.append(TextStyle.INTENSITY_NORMAL)

    if italic:
        additions.append(TextStyle.ITALIC_ENABLE)
        removals.append(TextStyle.ITALIC_DISABLE)

    if overline:
        additions.append(TextStyle.OVERLINE_ENABLE)
        removals.append(TextStyle.OVERLINE_DISABLE)

    if strikethrough:
        additions.append(TextStyle.STRIKETHROUGH_ENABLE)
        removals.append(TextStyle.STRIKETHROUGH_DISABLE)

    if underline:
        additions.append(TextStyle.UNDERLINE_ENABLE)
        removals.append(TextStyle.UNDERLINE_DISABLE)

    # Combine the ANSI style sequences with the value's text
    return "".join(map(str, additions)) + str(value) + "".join(map(str, removals))


# Default styles for printing strings of various types.
# These can be altered to suit an application's needs and only need to be a
# function with the following structure: func(str) -> str
style_success = functools.partial(style, fg=Fg.GREEN)
"""Partial function supplying arguments to :meth:`cmd2.ansi.style()` which colors text to signify success"""

style_warning = functools.partial(style, fg=Fg.LIGHT_YELLOW)
"""Partial function supplying arguments to :meth:`cmd2.ansi.style()` which colors text to signify a warning"""

style_error = functools.partial(style, fg=Fg.LIGHT_RED)
"""Partial function supplying arguments to :meth:`cmd2.ansi.style()` which colors text to signify an error"""


def async_alert_str(*, terminal_columns: int, prompt: str, line: str, cursor_offset: int, alert_msg: str) -> str:
    """Calculate the desired string, including ANSI escape codes, for displaying an asynchronous alert message.

    :param terminal_columns: terminal width (number of columns)
    :param prompt: prompt that is displayed on the current line
    :param line: current contents of the Readline line buffer
    :param cursor_offset: the offset of the current cursor position within line
    :param alert_msg: the message to display to the user
    :return: the correct string so that the alert message appears to the user to be printed above the current line.
    """

    # Split the prompt lines since it can contain newline characters.
    prompt_lines = prompt.splitlines() or ['']

    # Calculate how many terminal lines are taken up by all prompt lines except for the last one.
    # That will be included in the input lines calculations since that is where the cursor is.
    num_prompt_terminal_lines = 0
    for line in prompt_lines[:-1]:
        line_width = style_aware_wcswidth(line)
        num_prompt_terminal_lines += int(line_width / terminal_columns) + 1

    # Now calculate how many terminal lines are take up by the input
    last_prompt_line = prompt_lines[-1]
    last_prompt_line_width = style_aware_wcswidth(last_prompt_line)

    input_width = last_prompt_line_width + style_aware_wcswidth(line)

    num_input_terminal_lines = int(input_width / terminal_columns) + 1

    # Get the cursor's offset from the beginning of the first input line
    cursor_input_offset = last_prompt_line_width + cursor_offset

    # Calculate what input line the cursor is on
    cursor_input_line = int(cursor_input_offset / terminal_columns) + 1

    # Create a string that when printed will clear all input lines and display the alert
    terminal_str = ''

    # Move the cursor down to the last input line
    if cursor_input_line != num_input_terminal_lines:
        terminal_str += Cursor.DOWN(num_input_terminal_lines - cursor_input_line)

    # Clear each line from the bottom up so that the cursor ends up on the first prompt line
    total_lines = num_prompt_terminal_lines + num_input_terminal_lines
    terminal_str += (clear_line() + Cursor.UP(1)) * (total_lines - 1)

    # Clear the first prompt line
    terminal_str += clear_line()

    # Move the cursor to the beginning of the first prompt line and print the alert
    terminal_str += '\r' + alert_msg
    return terminal_str
