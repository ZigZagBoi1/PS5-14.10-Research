#!/usr/bin/env python3
"""Pin the generated progress artifacts to the rubric data."""

import unittest

from tools import render_progress


class RenderProgressTests(unittest.TestCase):
    def test_generated_artifacts_match_the_rendered_rubric(self):
        for path, content in render_progress.render().items():
            self.assertEqual(path.read_text(encoding="utf-8"), content,
                             str(path.relative_to(render_progress.ROOT)))


if __name__ == "__main__":
    unittest.main()
