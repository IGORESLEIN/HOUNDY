# Houndy
**Stealthy Active Directory Enumeration Tool (Rust)**

## Status
*   **Architecture:** Modular Rust Workspace
*   **Current Phase:** Initialization

## Project Structure
*   `houndy_core`: Binary entry point & orchestration.
*   `houndy_evasion`: [Windows Only] Syscalls, Unhooking, AMSI Bypass.
*   `houndy_protocol`: ADWS (SOAP) & LDAPS clients.
*   `houndy_auth`: Kerberos/SSPI authentication.
*   `houndy_parser`: ACL, GPO, and Session parsing.
*   `houndy_output`: BloodHound JSON generation.

## Setup Instructions (Critical)

Since the environment lacks `cargo` and `git` in the PATH, you must perform these steps manually:

1.  **Install Rust:**
    *   Download `rustup-init.exe` from [rust-lang.org](https://www.rust-lang.org/tools/install).
    *   Run it and accept default settings.
    *   **Restart your terminal** to leverage `cargo`.

2.  **Initialize Git:**
    *   Navigate to this folder:
        ```powershell
        cd C:\Users\igor.uria\.gemini\antigravity\scratch\houndy
        ```
    *   Run:
        ```powershell
        git init
        git add .
        git commit -m "Initial commit"
        git branch -M main
        ```

3.  **GitHub Setup:**
    *   Create a **Private Repository** named `houndy` on GitHub.
    *   Link it:
        ```powershell
        git remote add origin https://github.com/<YOUR_USERNAME>/houndy.git
        git push -u origin main
        ```

4.  **Build:**
    *   To build the Windows implant:
        ```powershell
        cargo build --release
        ```
    *   To build the Linux scanner (from Linux):
        ```bash
        cargo build --release
        ```
