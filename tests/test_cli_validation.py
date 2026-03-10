import unittest
from types import SimpleNamespace

from malwoverview.utils.cli_validation import should_print_help


def make_args(**overrides):
    defaults = {
        "config": ".malwapi.conf",
        "direct": "",
        "backg": 1,
        "virustotaloption": 0,
        "virustotalarg": "",
        "haoption": 0,
        "haarg": None,
        "vtpubpremium": 0,
        "malsharelist": 0,
        "malsharehash": None,
        "hausoption": 0,
        "hausarg": None,
        "polyoption": 0,
        "polyarg": None,
        "androidoption": 0,
        "androidarg": "",
        "alienvault": 0,
        "alienvaultargs": "",
        "malpedia": 0,
        "malpediaarg": "",
        "bazaar": 0,
        "bazaararg": None,
        "triage": 0,
        "triagearg": "",
        "output_dir": ".",
        "ipoption": 0,
        "iparg": None,
        "nistoption": 0,
        "nistarg": None,
        "nisttime": None,
        "nistrpp": 100,
        "niststartindex": 0,
        "nistncves": None,
        "vulncheckoption": 0,
        "vulncheckarg": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class CliValidationTests(unittest.TestCase):
    def test_rejects_argument_without_matching_flag(self):
        args = make_args(virustotalarg="foo")
        self.assertTrue(should_print_help(args))

    def test_rejects_flag_without_required_argument(self):
        args = make_args(ipoption=1)
        self.assertTrue(should_print_help(args))

    def test_accepts_valid_option_argument_pair(self):
        args = make_args(ipoption=1, iparg="8.8.8.8")
        self.assertFalse(should_print_help(args))


if __name__ == "__main__":
    unittest.main()
