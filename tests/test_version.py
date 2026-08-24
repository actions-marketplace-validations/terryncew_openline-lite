from __future__ import annotations

from importlib.metadata import version
import unittest

import openline_lite


class VersionTests(unittest.TestCase):
    def test_package_and_runtime_versions_match(self):
        self.assertEqual(version("openline-lite"), "0.6.0")
        self.assertEqual(openline_lite.__version__, "0.6.0")
        self.assertEqual(version("openline-lite"), openline_lite.__version__)


if __name__ == "__main__":
    unittest.main()
