"""Wiki contract refusal cases, using minimal independent temporary documents."""
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
TOOLS=runpy.run_path(str(ROOT/'scripts/wiki.py'))


class WikiTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        docs=self.root/'docs'; section=docs/'wiki.d/usage'; section.mkdir(parents=True)
        (docs/'index.md').write_text('# Wiki\n\n## Sommaire\n\n- [Usage](wiki.d/usage/index.md)\n',encoding='utf-8')
        self.index=section/'index.md'
        self.index.write_text('# Usage\n\nFil d’Ariane : Documentation / Usage\n\n[Retour au Parent](../../index.md)\n\n## Sommaire\n\n- [Page](page.md)\n',encoding='utf-8')
        self.page=section/'page.md'
        self.page.write_text('# Page\n\nFil d’Ariane : Documentation / Usage / Page\n\n[Retour au Parent](index.md)\n\n**Sommaire local**\n\n- [Section](#section)\n\n## Section\n\nTexte.\n',encoding='utf-8')

    def verify(self): return TOOLS['WikiVerifier'](self.root).verify()

    def test_complete_hierarchy_and_canonical_project(self):
        self.assertEqual(self.verify()['pages'],3)
        self.assertGreater(TOOLS['WikiVerifier'](ROOT).verify()['pages'],3)

    def test_missing_links_duplicate_parents_and_unmanaged_index_are_refused(self):
        original=self.page.read_text(encoding='utf-8')
        for addition,reason in (('\n[Missing](missing.md)\n','missing local target'),
                ('\n[Missing](#absent)\n','missing Markdown anchor'),
                ('\n[Retour au Parent](index.md)\n','one immediate parent'),
                ('\n[Unsafe](javascript:bad)\n','unsupported link scheme')):
            self.page.write_text(original+addition,encoding='utf-8')
            with self.assertRaisesRegex(ValueError,reason): self.verify()
        self.page.write_text(original,encoding='utf-8')
        self.index.write_text(self.index.read_text(encoding='utf-8')+'\n- [Duplicate](page.md)\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'exactly its direct children'): self.verify()

    def test_flat_root_extra_portal_and_incomplete_fences_are_refused(self):
        (self.root/'docs/extra.md').write_text('# Extra\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'docs root'): self.verify()
        (self.root/'docs/extra.md').unlink()
        (self.root/'docs/wiki.d/index.md').write_text('# Duplicate portal\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'container'): self.verify()
        (self.root/'docs/wiki.d/index.md').unlink()
        for source in ('```\ntext\n```','```python\ncode'):
            with self.assertRaises(ValueError): list(TOOLS['source_lines'](source))
