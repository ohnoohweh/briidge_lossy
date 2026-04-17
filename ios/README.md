# ObstacleBridge iOS Prototype (M1)

This directory contains the milestone-1 BeeWare companion-app prototype.

Current scope:

- briefcase-ready project metadata for an iOS app container
- shared ObstacleBridge import/preview logic wired into iOS-side helpers
- profile persistence that keeps plaintext secrets out of normal profile files
- focused tests for invite/config import preview and profile secret redaction

## Local developer checks

From repository root:

```bash
pytest -q ios/tests/test_invite_import.py ios/tests/test_ios_profile_config.py
```

## Briefcase bootstrap

From `ios/`:

```bash
python -m pip install briefcase
briefcase create iOS
briefcase build iOS
```

The app module is `obstacle_bridge_ios.app:main`.
