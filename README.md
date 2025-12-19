## Tooling Scripts for IT Network & Security Production/Build

This repository contains **tooling and automation scripts** to support **IT network and security operations** in **production and build environments**.

The goal is to provide reusable helpers for:
- **Diagnostics and troubleshooting** (for example, Microsoft Teams diagnostics under `debug/teams`)
- **Operational efficiency** for network and security engineers
- **Repeatable runbooks** that can be executed safely in production

### Repository layout

- `debug/teams/` – Scripts for Microsoft Teams diagnostics and troubleshooting:
  - `START-TEAMS-DIAGNOSTIC.bat`
  - `teams-debug.ps1`

As you add more scripts, group them by **area** (e.g. `network/`, `security/`, `build/`) and keep each script **self-documenting** with comments and usage examples.

### Usage

1. **Review scripts before running**  
   Always inspect a script and understand what it does before executing it in production.

2. **Run from an elevated shell when required**  
   Some scripts may require administrative privileges (e.g. for advanced diagnostics or system changes).

3. **Environment notes**
   - Designed and tested primarily on **Windows** (PowerShell / batch).
   - Additional platforms or shells can be added as the toolkit grows.

### Contributing

- Keep scripts:
  - **Idempotent** where possible (safe to run multiple times)
  - **Well-commented** with clear input/output and side effects
  - **Non-destructive by default** (prefer read/diagnostic modes, with explicit flags for changes)
- Prefer **PowerShell** for new Windows-focused automation, unless there is a strong reason to use batch.

### License

This project is licensed under the **GNU General Public License v3.0**.  
See `LICENSE.md` for the full license text.


