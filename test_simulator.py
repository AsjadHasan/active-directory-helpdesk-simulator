"""Unit tests for the educational helpdesk simulator."""

import tempfile
import unittest
from pathlib import Path

from active_directory_simulator import DirectorySimulator


class DirectoryTests(unittest.TestCase):
    """Verify account lifecycle, access, and persistence."""

    def setUp(self) -> None:
        """Create an isolated directory file for each test."""
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'data.json'
        self.directory = DirectorySimulator(self.path)

    def tearDown(self) -> None:
        """Remove test data."""
        self.temp.cleanup()

    def test_create_and_persist(self) -> None:
        """Save a user without storing plaintext passwords."""
        self.assertEqual(self.directory.create_user('alice', 'Alice Example', 'TestPass123'), 'Created user: alice')
        self.assertNotIn('TestPass123', self.path.read_text())
        self.assertIn('alice', DirectorySimulator(self.path).data['users'])

    def test_lockout_and_reset(self) -> None:
        """Lock an account after three failures and reset it."""
        self.directory.create_user('alice', 'Alice Example', 'TestPass123')
        for _ in range(3):
            result = self.directory.authenticate('alice', 'wrongpass')
        self.assertIn('locked', result.lower())
        self.assertEqual(self.directory.authenticate('alice', 'TestPass123'), 'Account is locked.')
        self.directory.reset_password('alice', 'NewPass123')
        self.assertEqual(self.directory.authenticate('alice', 'NewPass123'), 'Login successful.')

    def test_group_access(self) -> None:
        """Grant only the simulated group-authorized resource."""
        self.directory.create_user('alice', 'Alice Example', 'TestPass123')
        self.assertIn('DENIED', self.directory.check_access('alice', 'IT-Share'))
        self.directory.add_to_group('alice', 'IT')
        self.assertIn('GRANTED', self.directory.check_access('alice', 'IT-Share'))
        self.assertIn('DENIED', self.directory.check_access('alice', 'HR-Share'))
        self.directory.set_enabled('alice', False)
        self.assertIn('DENIED', self.directory.check_access('alice', 'IT-Share'))


if __name__ == '__main__':
    unittest.main()
