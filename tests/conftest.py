"""Pytest fixtures for the ocserv-sso unit tests.

Only portal-side tests remain (test_portal); the FreeRADIUS / PAT / TOTP
test suite was deleted with the freeradius service (refactor spec §3.5).
The portal reads its env at import time, so the test module itself
(tests/test_portal.py) sets SSO_* before importing portal/app.py —
nothing to do here.
"""
