"""Keep the actual CTest class/name pair while checking the selected test."""
from pathlib import Path
import unittest

from image.portal.build_inputs import require_test_report


class PortalCTestReport(unittest.TestCase):
    def fixture(self):
        # Original output from hosted run 45770130727, portal 1.5.0.
        return (Path(__file__).parent / 'fixtures/portal-ctest-1.5.0.xml').read_bytes()

    def test_actual_ctest_class_and_name_are_accepted(self):
        expected = ['hyprland-share-picker-data.hyprland-share-picker-data']
        self.assertEqual(require_test_report(self.fixture(), expected_cases=expected), expected)

    def test_changed_selection_or_unsuccessful_ctest_is_refused(self):
        raw = self.fixture()
        expected = ['hyprland-share-picker-data.hyprland-share-picker-data']
        for changed in (
            raw.replace(b'name="hyprland-share-picker-data"', b'name="other-test"', 1),
            raw.replace(b'classname="hyprland-share-picker-data"', b'classname="other-suite"'),
            raw.replace(b'failures="0"', b'failures="1"'),
            raw.replace(b'skipped="0"', b'skipped="1"'),
            raw.replace(b'disabled="0"', b'disabled="1"'),
            raw.replace(b'status="run"', b'status="notrun"'),
            raw.replace(b'<properties/>', b'<failure message="failed"/>'),
            raw.replace(b'<properties/>', b'<skipped/>'),
        ):
            with self.subTest(report=changed), self.assertRaises(ValueError):
                require_test_report(changed, expected_cases=expected)
        with self.assertRaises(ValueError):
            require_test_report(raw, expected_cases=['hyprland-share-picker-data'])


if __name__ == '__main__':
    unittest.main()
