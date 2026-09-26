import unittest

import cmd2

from lib.parsers.parsers import PARSERS


def _parser_factories():
    for name in dir(PARSERS):
        if name.endswith("_parser") or name.endswith("_parsers"):
            yield name, getattr(PARSERS, name)


class ParserFactoryTests(unittest.TestCase):
    """cmd2 >=4.0 raises a TypeError if a parser factory used with
    @cmd2.with_argparser doesn't return a Cmd2ArgumentParser (see issue #124:
    every factory here used to return a plain argparse.ArgumentParser).
    These checks don't need cmd2 >=4.0 installed to catch a regression -- they
    assert the same thing cmd2's own runtime check enforces."""

    def test_every_parser_factory_returns_a_cmd2_argument_parser(self):
        factories = list(_parser_factories())
        self.assertGreater(len(factories), 0, "expected to find at least one *_parser factory")
        for name, factory in factories:
            parser = factory()
            self.assertIsInstance(
                parser, cmd2.Cmd2ArgumentParser,
                f"PARSERS.{name}() must return a Cmd2ArgumentParser, got {type(parser).__name__}",
            )


if __name__ == "__main__":
    unittest.main()
