# Screen Curtain Password for NVDA

This NVDA add-on adds password protection around Screen Curtain privacy actions.

It can:

- Require a password before Screen Curtain is disabled.
- Require a password before NVDA exits or restarts while Screen Curtain is active.
- Store only a salted PBKDF2-HMAC-SHA256 password hash, not the plain password.
- Keep password fields hidden by default, with a Show password checkbox beside them.
- Reset a forgotten password by entering `00000` at the password prompt and waiting five minutes.

Settings are available from NVDA menu, Preferences, Settings, Screen Curtain Password.

## Notes and known behaviour

- Requires NVDA 2026.1 or later (it hooks the Privacy and Security settings panel introduced in that version).
- Only a genuine, user-initiated NVDA **exit** is password protected. Restarting NVDA, and exits triggered by an update or add-on installation, are intentionally **not** blocked, so those flows are never interrupted.
- Cancelling a protected exit keeps NVDA running; NVDA may write a harmless "logic error" line to its log in that case.
- Protection covers the disable paths a user can reach: the toggle gesture (NVDA+control+escape) and the Screen Curtain checkbox in Privacy and Security settings. Code that calls the Screen Curtain controller's `disable()` directly (e.g. another add-on) is not intercepted.

The add-on is inspired by nvaccess/nvda issue #20335.
