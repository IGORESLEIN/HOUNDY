# Release Notes - Houndy Core v0.1.0

## Build & Environment Fixes
To achieve a successful compilation on Windows, the following critical changes were made:

1.  **Windows SDK Requirement**:
    - Identified missing `kernel32.lib` due to absent Windows SDK.
    - **Action**: User installed Windows 10/11 SDK via Visual Studio Installer.

2.  **Dependency Resolution (`ldap3` & `sspi`)**:
    - **Issue**: `ldap3` v0.11 lacked NTLM support. Upgrading to v0.12 with the `ntlm` feature caused a compilation failure in the transitive `sspi` dependency (due to `non-exhaustive patterns` in `picky-krb`).
    - **Fix**: 
        - Upgraded `ldap3` to **0.12**.
        - **Disabled** the `ntlm` feature to avoid the broken `sspi` crate.
        - Implemented **Simple Bind Fallback** using `User@Domain` (UPN) format in `ldap.rs`, replacing the broken `ntlm_bind` call.

3.  **Code Visibility & Traits**:
    - **Fix**: Added `#[derive(Clone)]` to `Node` and `Meta` structs in `houndy_output` to satisfy new usage requirements.
    - **Fix**: Changed visibility of helper functions `get_str` and `get_bin_entry` in `converter.rs` to `pub` so they can be accessed by `main.rs`.
    - **Fix**: Standardized imports of `SearchEntry` across crates to use the re-exported type from `houndy_protocol`.

## Feature Additions
-   **Group Member Resolution**: Implemented a two-pass logic.
    1.  First pass collects Users and Computers, mapping their `distinguishedName` to `objectSid`.
    2.  Second pass processes Groups, looking up `member` DNs in this map to resolve them to SIDs.
    -   **Result**: BloodHound can now correctly draw edges between Groups and their members.

## Usage
The binary `houndy_core.exe` is located in `target\release`.
Run with:
```cmd
houndy_core.exe --domain <DOMAIN> --dc <IP> --user <USER> --password <PASS>
```
