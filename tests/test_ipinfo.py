import unittest
from unittest.mock import patch

from malwoverview.modules.ipinfo import IPInfoExtractor


class IPInfoExtractorTests(unittest.TestCase):
    @patch("malwoverview.modules.ipinfo.requests.get", side_effect=RuntimeError("network down"))
    def test_raw_ip_info_returns_string_error(self, mocked_get):
        extractor = IPInfoExtractor("")
        data = extractor._raw_ip_info("8.8.8.8")
        self.assertEqual(data, {"error": "network down"})
        mocked_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
