"""Guard: every skill directory has a valid SKILL.md (frontmatter + layout).

Keeps the pack installable: a missing/broken SKILL.md is the kind of thing
that silently breaks agents installing via `npx skills add` or a plain copy.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

SKILLS = Path(__file__).resolve().parents[1] / "skills"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
NAME_RE = re.compile(r"^name:\s*(\S+)\s*$", re.MULTILINE)
DESCRIPTION_RE = re.compile(r"^description:\s*(.+)$", re.MULTILINE)


class SkillManifest(unittest.TestCase):
    def test_every_skill_has_valid_frontmatter(self):
        skills = sorted(p for p in SKILLS.iterdir() if p.is_dir())
        self.assertGreaterEqual(len(skills), 3)
        for skill_dir in skills:
            with self.subTest(skill=skill_dir.name):
                skill_md = skill_dir / "SKILL.md"
                self.assertTrue(skill_md.exists(), "SKILL.md missing")
                text = skill_md.read_text(encoding="utf-8")
                m = FRONTMATTER_RE.match(text)
                self.assertIsNotNone(m, "YAML frontmatter missing")
                frontmatter = m.group(1)
                name = NAME_RE.search(frontmatter)
                self.assertIsNotNone(name, "name: missing")
                self.assertEqual(name.group(1), skill_dir.name,
                                 "name: must match directory name")
                desc = DESCRIPTION_RE.search(frontmatter)
                self.assertIsNotNone(desc, "description: missing")
                self.assertLessEqual(len(desc.group(1)), 1024,
                                     "description: must be <= 1024 chars")
                self.assertLess(text.count("\n"), 300,
                                "SKILL.md should stay under 300 lines (progressive disclosure)")

    def test_referenced_files_exist(self):
        # SKILL.md must not point at files that are not shipped.
        for skill_md in SKILLS.glob("*/SKILL.md"):
            text = skill_md.read_text(encoding="utf-8")
            for rel in re.findall(r"`(scripts/[^`\s]+|references/[^`\s]+)`", text):
                target = skill_md.parent / rel
                self.assertTrue(target.exists(),
                                f"{skill_md.parent.name}: referenced {rel} missing")

    def test_no_real_pii_in_repo(self):
        """The pack must not ship real-looking personal data (synthetic only)."""
        forbidden = [
            # Real-looking private data would defeat the pack's purpose.
            # The sample IBAN DE89 3704 0044 0532 0130 00 is the canonical
            # public example and explicitly allowed.
        ]
        if not forbidden:
            self.skipTest("no forbidden values configured")
        for path in SKILLS.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="ignore")
                for value in forbidden:
                    self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
