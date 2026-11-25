"""Runtime packaging may add only the reviewed missing library packages."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location('runtime_guest', Path(__file__).parents[1] / 'hyprland/runtime_guest.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class RuntimePackages(unittest.TestCase):
    def test_exact_addition_keeps_every_base_package(self):
        runtime.require_additive(['base\t1', 'mesa\t26'], ['base\t1', 'mesa\t26', 'library\t2'], ['library\t2'])

    def test_replacement_removal_extra_or_missing_package_is_refused(self):
        for after in [['base\t1', 'mesa\t25', 'library\t2'],
                      ['base\t1', 'library\t2'],
                      ['base\t1', 'mesa\t26', 'library\t2', 'unexpected\t1'],
                      ['base\t1', 'mesa\t26'],
                      ['base\t1', 'mesa\t26', 'library\t2', 'library\t2']]:
            with self.subTest(after=after), self.assertRaises(ValueError):
                runtime.require_additive(['base\t1', 'mesa\t26'], after, ['library\t2'])


if __name__ == '__main__':
    unittest.main()
