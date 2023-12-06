# coding=utf-8
"""
History management classes
"""

import json
import re
from collections import (
    OrderedDict,
)
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Union,
    overload,
)

import attr

from . import (
    utils,
)
from .parsing import (
    Statement,
)


@attr.s(auto_attribs=True, frozen=True)
class HistoryItem:
    """Class used to represent one command in the history list"""

    _listformat = ' {:>4}  {}'
    _ex_listformat = ' {:>4}x {}'

    # Used in JSON dictionaries
    _statement_field = 'statement'

    statement: Statement = attr.ib(default=None, validator=attr.validators.instance_of(Statement))

    def __str__(self) -> str:
        """A convenient human readable representation of the history item"""
        return self.statement.raw

    @property
    def raw(self) -> str:
        """The raw input from the user for this item.

        Proxy property for ``self.statement.raw``
        """
        return self.statement.raw

    @property
    def expanded(self) -> str:
        """Return the command as run which includes shortcuts and aliases resolved
        plus any changes made in hooks

        Proxy property for ``self.statement.expanded_command_line``
        """
        return self.statement.expanded_command_line

    def pr(self, idx: int, script: bool = False, expanded: bool = False, verbose: bool = False) -> str:
        """Represent this item in a pretty fashion suitable for printing.

        If you pass verbose=True, script and expanded will be ignored

        :param idx: The 1-based index of this item in the history list
        :param script: True if formatting for a script (No item numbers)
        :param expanded: True if expanded command line should be printed
        :param verbose: True if expanded and raw should both appear when they are different
        :return: pretty print string version of a HistoryItem
        """
        if verbose:
            raw = self.raw.rstrip()
            expanded_command = self.expanded

            ret_str = self._listformat.format(idx, raw)
            if raw != expanded_command:
                ret_str += '\n' + self._ex_listformat.format(idx, expanded_command)
        else:
            if expanded:
                ret_str = self.expanded
            else:
                ret_str = self.raw.rstrip()

                # In non-verbose mode, display raw multiline commands on 1 line
                if self.statement.multiline_command:
                    # This is an approximation and not meant to be a perfect piecing together of lines.
                    # All newlines will be converted to spaces, including the ones in quoted strings that
                    # are considered literals. Also if the final line starts with a terminator, then the
                    # terminator will have an extra space before it in the 1 line version.
                    ret_str = ret_str.replace('\n', ' ')

            # Display a numbered list if not writing to a script
            if not script:
                ret_str = self._listformat.format(idx, ret_str)

        return ret_str

    def to_dict(self) -> Dict[str, Any]:
        """Utility method to convert this HistoryItem into a dictionary for use in persistent JSON history files"""
        return {HistoryItem._statement_field: self.statement.to_dict()}

    @staticmethod
    def from_dict(source_dict: Dict[str, Any]) -> 'HistoryItem':
        """
        Utility method to restore a HistoryItem from a dictionary

        :param source_dict: source data dictionary (generated using to_dict())
        :return: HistoryItem object
        :raises KeyError: if source_dict is missing required elements
        """
        statement_dict = source_dict[HistoryItem._statement_field]
        return HistoryItem(Statement.from_dict(statement_dict))


class History(List[HistoryItem]):
    """A list of :class:`~cmd2.history.HistoryItem` objects with additional methods
    for searching and managing the list.

    :class:`~cmd2.Cmd` instantiates this class into the :data:`~cmd2.Cmd.history`
    attribute, and adds commands to it as a user enters them.

    See :ref:`features/history:History` for information about the built-in command
    which allows users to view, search, run, and save previously entered commands.

    Developers interested in accessing previously entered commands can use this
    class to gain access to the historical record.
    """

    # Used in JSON dictionaries
    _history_version = '1.0.0'
    _history_version_field = 'history_version'
    _history_items_field = 'history_items'

    def __init__(self, seq: Iterable[HistoryItem] = ()) -> None:
        super(History, self).__init__(seq)
        self.session_start_index = 0

    def start_session(self) -> None:
        """Start a new session, thereby setting the next index as the first index in the new session."""
        self.session_start_index = len(self)

    # noinspection PyMethodMayBeStatic
    def _zero_based_index(self, onebased: Union[int, str]) -> int:
        """Convert a one-based index to a zero-based index."""
        result = int(onebased)
        if result > 0:
            result -= 1
        return result

    @overload
    def append(self, new: HistoryItem) -> None:
        ...  # pragma: no cover

    @overload
    def append(self, new: Statement) -> None:
        ...  # pragma: no cover

    def append(self, new: Union[Statement, HistoryItem]) -> None:
        """Append a new statement to the end of the History list.

        :param new: Statement object which will be composed into a HistoryItem
                    and added to the end of the list
        """
        history_item = HistoryItem(new) if isinstance(new, Statement) else new
        super(History, self).append(history_item)

    def clear(self) -> None:
        """Remove all items from the History list."""
        super().clear()
        self.start_session()

    def get(self, index: int) -> HistoryItem:
        """Get item from the History list using 1-based indexing.

        :param index: optional item to get
        :return: a single :class:`~cmd2.history.HistoryItem`
        """
        if index == 0:
            raise IndexError('The first command in history is command 1.')
        elif index < 0:
            return self[index]
        else:
            return self[index - 1]

    # This regular expression parses input for the span() method. There are five parts:
    #
    #    ^\s*                          matches any whitespace at the beginning of the
    #                                  input. This is here so you don't have to trim the input
    #
    #    (?P<start>-?[1-9]{1}\d*)?     create a capture group named 'start' which matches an
    #                                  optional minus sign, followed by exactly one non-zero
    #                                  digit, and as many other digits as you want. This group
    #                                  is optional so that we can match an input string like '..2'.
    #                                  This regex will match 1, -1, 10, -10, but not 0 or -0.
    #
    #    (?P<separator>:|(\.{2,}))?    create a capture group named 'separator' which matches either
    #                                  a colon or two periods.
    #
    #    (?P<end>-?[1-9]{1}\d*)?       create a capture group named 'end' which matches an
    #                                  optional minus sign, followed by exactly one non-zero
    #                                  digit, and as many other digits as you want. This group is
    #                                  optional so that we can match an input string like ':'
    #                                  or '5:'. This regex will match 1, -1, 10, -10, but not
    #                                  0 or -0.
    #
    #    \s*$                          match any whitespace at the end of the input. This is here so
    #                                  you don't have to trim the input
    #
    spanpattern = re.compile(r'^\s*(?P<start>-?[1-9]\d*)?(?P<separator>:|(\.{2,}))(?P<end>-?[1-9]\d*)?\s*$')

    def span(self, span: str, include_persisted: bool = False) -> 'OrderedDict[int, HistoryItem]':
        """Return a slice of the History list

        :param span: string containing an index or a slice
        :param include_persisted: if True, then retrieve full results including from persisted history
        :return: a dictionary of history items keyed by their 1-based index in ascending order,
                 or an empty dictionary if no results were found

        This method can accommodate input in any of these forms:

            a..b or a:b
            a.. or a:
            ..a or :a
            -a.. or -a:
            ..-a or :-a

        Different from native python indexing and slicing of arrays, this method
        uses 1-based array numbering. Users who are not programmers can't grok
        zero based numbering. Programmers can sometimes grok zero based numbering.
        Which reminds me, there are only two hard problems in programming:

        - naming
        - cache invalidation
        - off by one errors

        """
        results = self.spanpattern.search(span)
        if not results:
            # our regex doesn't match the input, bail out
            raise ValueError('History indices must be positive or negative integers, and may not be zero.')

        start_token = results.group('start')
        if start_token:
            start = min(self._zero_based_index(start_token), len(self) - 1)
            if start < 0:
                start = max(0, len(self) + start)
        else:
            start = 0 if include_persisted else self.session_start_index

        end_token = results.group('end')
        if end_token:
            end = min(int(end_token), len(self))
            if end < 0:
                end = max(0, len(self) + end + 1)
        else:
            end = len(self)

        return self._build_result_dictionary(start, end)

    def str_search(self, search: str, include_persisted: bool = False) -> 'OrderedDict[int, HistoryItem]':
        """Find history items which contain a given string

        :param search: the string to search for
        :param include_persisted: if True, then search full history including persisted history
        :return: a dictionary of history items keyed by their 1-based index in ascending order,
                 or an empty dictionary if the string was not found
        """

        def isin(history_item: HistoryItem) -> bool:
            """filter function for string search of history"""
            sloppy = utils.norm_fold(search)
            inraw = sloppy in utils.norm_fold(history_item.raw)
            inexpanded = sloppy in utils.norm_fold(history_item.expanded)
            return inraw or inexpanded

        start = 0 if include_persisted else self.session_start_index
        return self._build_result_dictionary(start, len(self), isin)

    def regex_search(self, regex: str, include_persisted: bool = False) -> 'OrderedDict[int, HistoryItem]':
        """Find history items which match a given regular expression

        :param regex: the regular expression to search for.
        :param include_persisted: if True, then search full history including persisted history
        :return: a dictionary of history items keyed by their 1-based index in ascending order,
                 or an empty dictionary if the regex was not matched
        """
        regex = regex.strip()
        if regex.startswith(r'/') and regex.endswith(r'/'):
            regex = regex[1:-1]
        finder = re.compile(regex, re.DOTALL | re.MULTILINE)

        def isin(hi: HistoryItem) -> bool:
            """filter function for doing a regular expression search of history"""
            return bool(finder.search(hi.raw) or finder.search(hi.expanded))

        start = 0 if include_persisted else self.session_start_index
        return self._build_result_dictionary(start, len(self), isin)

    def truncate(self, max_length: int) -> None:
        """Truncate the length of the history, dropping the oldest items if necessary

        :param max_length: the maximum length of the history, if negative, all history
                           items will be deleted
        :return: nothing
        """
        if max_length <= 0:
            # remove all history
            del self[:]
        elif len(self) > max_length:
            last_element = len(self) - max_length
            del self[0:last_element]

    def _build_result_dictionary(
        self, start: int, end: int, filter_func: Optional[Callable[[HistoryItem], bool]] = None
    ) -> 'OrderedDict[int, HistoryItem]':
        """
        Build history search results
        :param start: start index to search from
        :param end: end index to stop searching (exclusive)
        """
        results: OrderedDict[int, HistoryItem] = OrderedDict()
        for index in range(start, end):
            if filter_func is None or filter_func(self[index]):
                results[index + 1] = self[index]
        return results

    def to_json(self) -> str:
        """Utility method to convert this History into a JSON string for use in persistent history files"""
        json_dict = {
            History._history_version_field: History._history_version,
            History._history_items_field: [hi.to_dict() for hi in self],
        }
        return json.dumps(json_dict, ensure_ascii=False, indent=2)

    @staticmethod
    def from_json(history_json: str) -> 'History':
        """
        Utility method to restore History from a JSON string

        :param history_json: history data as JSON string (generated using to_json())
        :return: History object
        :raises json.JSONDecodeError: if passed invalid JSON string
        :raises KeyError: if JSON is missing required elements
        :raises ValueError: if history version in JSON isn't supported
        """
        json_dict = json.loads(history_json)
        version = json_dict[History._history_version_field]
        if version != History._history_version:
            raise ValueError(
                f"Unsupported history file version: {version}. This application uses version {History._history_version}."
            )

        items = json_dict[History._history_items_field]
        history = History()
        for hi_dict in items:
            history.append(HistoryItem.from_dict(hi_dict))

        return history
