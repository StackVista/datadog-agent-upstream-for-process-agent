import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('check_owner_distributions.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class DistributionControls(unittest.TestCase):
    def test_negative_controls(self):
        for mutation in ('omit', 'license', 'mode', 'parser'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                shutil.copytree(guard.ROOT / 'third_party', root / 'third_party')
                p = root / 'third_party/goflow2/utils/utils.go'
                if mutation == 'omit':
                    p.unlink()
                elif mutation == 'license':
                    (root / 'third_party/goflow2/LICENSE').write_text('incorrect license')
                elif mutation == 'mode':
                    p.chmod(0o755)
                else:
                    p.write_text(p.read_text().replace('go.yaml.in/yaml/v2', 'gopkg.in/yaml.v2'))
                with self.assertRaises(AssertionError):
                    guard.verify(root)


if __name__ == '__main__':
    unittest.main()
