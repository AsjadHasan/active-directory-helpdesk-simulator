# Active Directory & IT Helpdesk Management Simulator

An **educational Python OOP simulator** of common identity-management and IT helpdesk workflows. This is **not Microsoft Active Directory**, does not connect to a domain controller, and does not replace hands-on Windows Server administration.

## Features
- Create, list, enable, and disable simulated employee accounts
- Test sign-in with password verification and three-attempt lockout
- Reset passwords and unlock accounts
- Assign users to IT, HR, and Finance groups
- Check simulated access to IT-Share, HR-Share, and Finance-Share
- Save records to local JSON and view recent audit actions

## Requirements
- Python 3.10+ (tested with Python 3.14)
- No third-party packages or Windows Server installation required

## Run
```powershell
python active_directory_simulator.py
```

## Suggested test scenario
1. Choose **1** and create `alice` with a password of at least eight characters.
2. Choose **2** to list accounts.
3. Choose **8** to add `alice` to `IT`.
4. Choose **10** to check `alice` access to `IT-Share` (granted).
5. Choose **10** to check `alice` access to `HR-Share` (denied).
6. Choose **3** and enter the wrong password three times to trigger lockout.
7. Choose **7** to unlock the account, or **4** to reset the password.
8. Choose **11** to review the audit log.

## Example output
```text
Created user: alice
alice | Alice Example | Enabled | Unlocked
Added alice to IT.
ACCESS GRANTED: alice -> IT-Share
ACCESS DENIED: alice -> HR-Share
Account locked after repeated failed attempts.
Unlocked user: alice
```

## Topics Covered
1. Python classes, methods, and encapsulation
2. Dictionaries, lists, JSON persistence, and file I/O
3. Password hashing with PBKDF2 and salts
4. Account lifecycle, authentication, and lockout concepts
5. Group membership and simulated access control
6. Audit logging and interactive CLI workflows

## Limitations and security
This is a **local learning project**, not production authentication software. There is no administrator authentication, role separation, encrypted database, or actual AD/LDAP integration. Password resets in this simulator assume an authorized helpdesk operator; real helpdesks must verify user identity and follow company policy. Do not use real employee data or passwords. `data.json` is excluded from Git.

## Portfolio relevance
Demonstrates understanding of identity-management and helpdesk workflows through a working Python simulation. Does **not** demonstrate hands-on Microsoft Active Directory administration.
