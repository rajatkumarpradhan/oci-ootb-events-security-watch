import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from oci_ootb_events_security_watch.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCli(unittest.TestCase):
    def test_missing_file_exits_1(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["/nonexistent/rules.json"]), 1)

    def test_invalid_json_exits_1(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main([os.path.join(ROOT, "pyproject.toml")]), 1)

    def test_gappy_sample_exits_2(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([os.path.join(ROOT, "samples", "gappy-rules.json")])
        self.assertEqual(code, 2)
        text = out.getvalue()
        self.assertIn("WAT001", text)
        self.assertIn("WAT004", text)
        self.assertIn("summary:", text)

    def test_complete_sample_exits_0(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([os.path.join(ROOT, "samples", "complete-rules.json")])
        self.assertEqual(code, 0)
        self.assertIn("0 high", out.getvalue())


if __name__ == "__main__":
    unittest.main()
