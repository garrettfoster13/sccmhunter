#
# coding=utf-8
"""Classes for the cmd2 plugin system"""
from typing import (
    Optional,
)

import attr

from .parsing import (
    Statement,
)


@attr.s(auto_attribs=True)
class PostparsingData:
    """Data class containing information passed to postparsing hook methods"""

    stop: bool
    statement: Statement


@attr.s(auto_attribs=True)
class PrecommandData:
    """Data class containing information passed to precommand hook methods"""

    statement: Statement


@attr.s(auto_attribs=True)
class PostcommandData:
    """Data class containing information passed to postcommand hook methods"""

    stop: bool
    statement: Statement


@attr.s(auto_attribs=True)
class CommandFinalizationData:
    """Data class containing information passed to command finalization hook methods"""

    stop: bool
    statement: Optional[Statement]
