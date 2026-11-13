"""Educational Active Directory-style helpdesk simulator (not Microsoft AD)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

DATA_FILE = Path(__file__).with_name('data.json')
MAX_FAILED_ATTEMPTS = 3


class DirectorySimulator:
    """Manage simulated accounts, groups, permissions and audit records."""

    def __init__(self, path: Path = DATA_FILE) -> None:
        """Load saved records or initialize a sample directory."""
        self.path = path
        self.data = self._load()

    def _load(self) -> dict:
        """Read JSON data or create a fresh directory."""
        if self.path.exists():
            return json.loads(self.path.read_text(encoding='utf-8'))
        return {'users': {}, 'groups': {'IT': [], 'HR': [], 'Finance': []},
                'resources': {'IT-Share': ['IT'], 'HR-Share': ['HR'],
                              'Finance-Share': ['Finance']}, 'audit': []}

    def _save(self) -> None:
        """Persist records in a local JSON file."""
        self.path.write_text(json.dumps(self.data, indent=2), encoding='utf-8')

    def _audit(self, action: str, details: str) -> None:
        """Record a timestamped administrative action without secrets."""
        self.data['audit'].append({'time': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                                   'action': action, 'details': details})
        self._save()

    @staticmethod
    def _hash_password(password: str, salt: bytes | None = None) -> str:
        """Hash a password with PBKDF2 and a random salt."""
        salt = salt or secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
        return f'{salt.hex()}:{digest.hex()}'

    @staticmethod
    def _verify_password(password: str, saved: str) -> bool:
        """Compare a password to its stored salted hash."""
        salt_hex, digest_hex = saved.split(':', 1)
        candidate = DirectorySimulator._hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(candidate, saved)

    def create_user(self, username: str, full_name: str, password: str) -> str:
        """Create a simulated user account."""
        username = username.strip().lower()
        if not username or not full_name.strip():
            return 'Username and full name are required.'
        if username in self.data['users']:
            return 'Account already exists.'
        if len(password) < 8:
            return 'Password must contain at least 8 characters.'
        self.data['users'][username] = {'full_name': full_name.strip(),
                                        'password_hash': self._hash_password(password),
                                        'enabled': True, 'locked': False, 'failed_attempts': 0}
        self._audit('CREATE_USER', username)
        return f'Created user: {username}'

    def list_users(self) -> str:
        """Show account names and their statuses."""
        if not self.data['users']:
            return 'No users found.'
        return '\n'.join(f"{name} | {record['full_name']} | "
                         f"{'Enabled' if record['enabled'] else 'Disabled'} | "
                         f"{'Locked' if record['locked'] else 'Unlocked'}"
                         for name, record in sorted(self.data['users'].items()))

    def set_enabled(self, username: str, enabled: bool) -> str:
        """Enable or disable a simulated account."""
        user = self.data['users'].get(username.lower())
        if user is None:
            return 'User not found.'
        user['enabled'] = enabled
        self._audit('ENABLE_USER' if enabled else 'DISABLE_USER', username.lower())
        return f"User {username.lower()} {'enabled' if enabled else 'disabled'}."

    def authenticate(self, username: str, password: str) -> str:
        """Simulate login and lock an account after repeated failures."""
        username = username.lower()
        user = self.data['users'].get(username)
        if user is None:
            return 'Authentication failed.'
        if not user['enabled']:
            return 'Account is disabled.'
        if user['locked']:
            return 'Account is locked.'
        if self._verify_password(password, user['password_hash']):
            user['failed_attempts'] = 0
            self._audit('LOGIN_SUCCESS', username)
            return 'Login successful.'
        user['failed_attempts'] += 1
        if user['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
            user['locked'] = True
            self._audit('ACCOUNT_LOCKED', username)
            return 'Account locked after repeated failed attempts.'
        self._audit('LOGIN_FAILED', username)
        return 'Authentication failed.'

    def reset_password(self, username: str, password: str) -> str:
        """Reset a password and clear the simulated lockout."""
        user = self.data['users'].get(username.lower())
        if user is None:
            return 'User not found.'
        if len(password) < 8:
            return 'Password must contain at least 8 characters.'
        user['password_hash'] = self._hash_password(password)
        user['failed_attempts'] = 0
        user['locked'] = False
        self._audit('RESET_PASSWORD', username.lower())
        return 'Password reset successfully; account unlocked.'

    def unlock_user(self, username: str) -> str:
        """Unlock an account without changing its password."""
        user = self.data['users'].get(username.lower())
        if user is None:
            return 'User not found.'
        user['locked'] = False
        user['failed_attempts'] = 0
        self._audit('UNLOCK_USER', username.lower())
        return f'Unlocked user: {username.lower()}'

    def add_to_group(self, username: str, group: str) -> str:
        """Add an existing user to an existing security group."""
        username = username.lower()
        if username not in self.data['users']:
            return 'User not found.'
        if group not in self.data['groups']:
            return 'Group not found.'
        if username in self.data['groups'][group]:
            return 'User is already in that group.'
        self.data['groups'][group].append(username)
        self._audit('ADD_TO_GROUP', f'{username} -> {group}')
        return f'Added {username} to {group}.'

    def show_groups(self) -> str:
        """List groups and their members."""
        return '\n'.join(f'{group}: {", ".join(members) or "(empty)"}'
                         for group, members in self.data['groups'].items())

    def check_access(self, username: str, resource: str) -> str:
        """Evaluate simulated resource access using group membership."""
        username = username.lower()
        user = self.data['users'].get(username)
        if user is None:
            return 'User not found.'
        if resource not in self.data['resources']:
            return 'Resource not found.'
        allowed_groups = self.data['resources'][resource]
        allowed = (user['enabled'] and not user['locked'] and
                   any(username in self.data['groups'].get(group, []) for group in allowed_groups))
        self._audit('CHECK_ACCESS', f'{username} -> {resource}: {"ALLOW" if allowed else "DENY"}')
        return f'{"ACCESS GRANTED" if allowed else "ACCESS DENIED"}: {username} -> {resource}'

    def recent_audit(self) -> str:
        """Return the ten most recent administrative events."""
        events = self.data['audit'][-10:]
        return '\n'.join(f"{item['time']} | {item['action']} | {item['details']}"
                         for item in events) or 'No audit records yet.'


def prompt_password(label: str = 'Password: ') -> str:
    """Read a password without echoing it to the terminal."""
    from getpass import getpass
    return getpass(label)


def main() -> None:
    """Run the interactive educational helpdesk menu."""
    directory = DirectorySimulator()
    actions = {
        '1': ('Create user', lambda: directory.create_user(input('Username: '), input('Full name: '), prompt_password())),
        '2': ('List users', directory.list_users),
        '3': ('Test login', lambda: directory.authenticate(input('Username: '), prompt_password())),
        '4': ('Reset password', lambda: directory.reset_password(input('Username: '), prompt_password('New password: '))),
        '5': ('Enable user', lambda: directory.set_enabled(input('Username: '), True)),
        '6': ('Disable user', lambda: directory.set_enabled(input('Username: '), False)),
        '7': ('Unlock user', lambda: directory.unlock_user(input('Username: '))),
        '8': ('Add user to group', lambda: directory.add_to_group(input('Username: '), input('Group (IT/HR/Finance): '))),
        '9': ('List groups', directory.show_groups),
        '10': ('Check resource access', lambda: directory.check_access(input('Username: '), input('Resource (IT-Share/HR-Share/Finance-Share): '))),
        '11': ('View audit log', directory.recent_audit),
    }
    while True:
        print('\n=== ACTIVE DIRECTORY HELP DESK SIMULATOR ===')
        for key, (label, _) in actions.items():
            print(f'{key}. {label}')
        print('0. Exit')
        choice = input('Select an option: ').strip()
        if choice == '0':
            print('Goodbye!')
            break
        action = actions.get(choice)
        if action is None:
            print('Invalid option.')
            continue
        try:
            print(action[1]())
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f'Operation failed: {error}')


if __name__ == '__main__':
    main()
