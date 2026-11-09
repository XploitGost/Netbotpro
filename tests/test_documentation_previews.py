from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DocumentationPreviewTests(unittest.TestCase):
    def test_readme_uses_current_synthetic_images_with_valid_dimensions(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("synthetic", readme)
        for view in ("overview", "monitor", "inspect", "fleet"):
            name = f"docs/assets/netbotpro-{view}.png"
            self.assertIn(name, readme)
            data = (ROOT / name).read_bytes()
            self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(struct.unpack(">II", data[16:24]), (1672, 941))
            self.assertLess(len(data), 5 * 1024 * 1024)

    def test_current_limits_and_navigation_are_documented(self):
        for name in ("README.fa.md", "docs/ROADMAP.md", "docs/VALIDATION.md", "docs/SCREENSHOTS.md"):
            self.assertGreater((ROOT / name).stat().st_size, 100)
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn("no implemented Rust", architecture)
        self.assertIn("not a complete", architecture)
