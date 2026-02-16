# Houndy Analysis & Validation Against Research Notebooks

## Executive Summary
**Verdict:** Houndy is currently a **valid, high-stealth "DCOnly" collector** that aligns with the core architectural recommendations found in your research.

It successfully implements the "RustHound" paradigm described in `IGGYHOUND_RESEARCH.md`—offering a native, cross-platform, memory-safe alternative to SharpHound that avoids the noise of endpoint connections. However, it currently lacks the "Next-Gen" features (ADWS, LAPS v2) identified in `FINAL_GAP_ANALYSIS.md`.

---

## 1. Architectural Validation
**Notebook Source:** `IGGYHOUND_RESEARCH.md` (Section: RustHound Architecture)

*   **Research Requirement:** The notebook highlights `RustHound` as a superior alternative for **stealth** and **evasion** because it is "cross-compiled" and prone to "no AV detection" compared to C# (SharpHound) or Python (BloodHound.py).
*   **Houndy Implementation:**
    *   ✅ **Written in Rust:** Leverages memory safety and speed.
    *   ✅ **Native Code:** compiles to a standalone binary, avoiding Python interpreter dependencies or .NET CLR hooks often monitored by EDR (AMSI).
    *   ✅ **Validation:** This aligns perfectly with the "Tool Choice and Compilation" evasion technique described in the Red Team Analysis.

## 2. Operational Stealth (DCOnly)
**Notebook Source:** `RED_TEAM_ANALYSIS.md` (Section: Detection Evasion) & `IGGYHOUND_RESEARCH.md`

*   **Research Requirement:** "DCOnly Collection" is cited as a primary stealth recommendation. It restricts enumeration to the Domain Controller, avoiding direct connections to member hosts which trigger "Logon" events and SIEM alerts.
*   **Houndy Implementation:**
    *   ✅ **Implicit DCOnly:** Houndy *only* implements LDAP/LDAPS queries. It does not contain code to connect to SMB (Port 445) or RPC on member servers.
    *   ✅ **Validation:** It effectively functions in the `--stealth` modes described for SharpHound, making it quieter than a default SharpHound scan.

## 3. Protocol & Authentication Security
**Notebook Source:** `IGGYHOUND_RESEARCH.md` (Section: Authentication)

*   **Research Requirement:**
    *   "Forcing the use of LDAPS (LDAP over SSL/TLS)... prevents network-based IDS from inspecting the query contents."
    *   Support for NTLM and Simple Bind.
*   **Houndy Implementation:**
    *   ✅ **LDAPS Priority:** The `connect_with_retry` logic prioritizes port 636 (LDAPS). This is a built-in security feature that aligns with the "Protocol Shifts" evasion technique.
    *   ✅ **Fallback Logic:** Implements the NTLM fallback described in the protocols section (`ldap3` with `ntlm` feature), ensuring functionality even when certificates are missing, matching established tool behaviors.

## 4. Collection Logic & attributes
**Notebook Source:** `FINAL_GAP_ANALYSIS.md` & `IGGYHOUND_RESEARCH.md`

*   **Research Requirement:** Standard tools use specific attributes to map the graph. `FINAL_GAP_ANALYSIS.md` warns against "Blind Attacks" and noisy scanning. `IGGYHOUND_RESEARCH` notes the importance of specific attributes like `nTSecurityDescriptor`.
*   **Houndy Implementation:**
    *   ✅ **Explicit Attribute Selection:** Instead of requesting `*` (all attributes), Houndy requests a hardcoded whitelist (e.g., `sAMAccountName`, `member`, `servicePrincipalName`, `nTSecurityDescriptor`). This reduces the traffic profile significantly compared to a full wildcard query.
    *   ✅ **ACL Support:** We implemented `nTSecurityDescriptor` parsing. As noted in the analysis, this is critical for identifying "Hidden Risks" like ACL-based admin rights (`AdminSDHolder` bypasses) that standard scanners miss.

## 5. Feature Gaps (Future Work)
**Notebook Source:** `FINAL_GAP_ANALYSIS.md`

*   **Critique:** While Houndy is good, it misses the "Advanced" features identified in your Gap Analysis:
    *   ❌ **No ADWS (SOAP):** Houndy uses `ldap3`. It does not support port 9389 (ADWS) to bypass LDAP monitoring.
    *   ❌ **No LDAP Obfuscation:** Queries are standard filters (e.g., `(objectClass=user)`). It does not implement the `Maldaptive` style casing/OID obfuscation.
    *   ❌ **No LAPS v2 Decryption:** It does not integrate with the KDS to decrypt `ms-Mcs-AdmPwd` blobs.

## Conclusion
Houndy is a robust **Foundation Level** tool. It replicates the core value proposition of RustHound (Speed, Safety, DCOnly Stealth) and validates positively against the "Stealth" and "Architecture" notebooks. It is "Good" for valid, quiet enumeration, but requires further development to hit the "Advanced/APT" criteria (ADWS, Obfuscation) found in the Gap Analysis.
