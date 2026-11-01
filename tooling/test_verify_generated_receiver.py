"""Pure evidence-parser controls; these fixtures are not generated SDK or JUnit execution proof."""
from pathlib import Path
import tempfile
import unittest
import verify_generated_receiver as verifier


class RequiredTestEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.module = Path(self.temporary.name)
        self.reports = self.module / 'target/surefire-reports'
        self.reports.mkdir(parents=True)

    def write(self, body, name='TEST-contract.xml'):
        (self.reports / name).write_text(body)

    def test_complete_unique_required_cases(self):
        self.write('<testsuite><testcase name="producer"/><testcase name="sdk"/></testsuite>')
        self.assertEqual(['producer', 'sdk'], verifier.passed_tests(self.module, {'producer', 'sdk'}))

    def test_no_report_is_not_success(self):
        with self.assertRaises(ValueError):
            verifier.passed_tests(self.module, {'producer'})

    def test_unrelated_test_does_not_satisfy_contract(self):
        self.write('<testsuite><testcase name="unrelated"/></testsuite>')
        with self.assertRaises(ValueError):
            verifier.passed_tests(self.module, {'producer'})

    def test_skips_failures_and_errors_are_refused(self):
        for status in ('skipped', 'failure', 'error'):
            with self.subTest(status=status):
                self.write('<testsuite><testcase name="producer"><' + status + '/></testcase></testsuite>')
                with self.assertRaises(ValueError):
                    verifier.passed_tests(self.module, {'producer'})

    def test_duplicate_report_cannot_inflate_required_execution(self):
        body = '<testsuite><testcase name="producer"/></testsuite>'
        self.write(body)
        self.write(body, 'TEST-duplicate.xml')
        with self.assertRaises(ValueError):
            verifier.passed_tests(self.module, {'producer'})

    def test_oversized_evidence_is_refused(self):
        path = self.module / 'oversized'
        path.write_bytes(b'12345')
        with self.assertRaises(ValueError):
            verifier.read(path, 4)


if __name__ == '__main__':
    unittest.main()
