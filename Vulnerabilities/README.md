# Vulnerable AD (Defensive Lab)

Intentionally introduce common Active Directory misconfigurations so **defenders
can see — and practise detecting/remediating — what attackers do to a domain**.
Think BadBlood/GOAD-style, but config-driven, toggleable per vulnerability, and
**fully reversible**.

> ### ⚠️ Lab use only
> These scripts deliberately weaken Active Directory. Run them **only** on the
> disposable lab domain built by this repo, never against production or any
> internet-reachable domain. You are responsible for where you run them.

## Usage

Run on the DC (or any box with `RSAT-AD-Tools`) in an **elevated** PowerShell:

```powershell
# 1. Copy and edit the spec (domain + which vulns to enable).
Copy-Item config\vulns.example.json config\vulns.json

# 2. Preview everything, no changes:
.\Invoke-ADVulnerabilities.ps1 -Config config\vulns.json -DryRun

# 3. Apply the enabled vulnerabilities:
.\Invoke-ADVulnerabilities.ps1 -Config config\vulns.json

# 4. Reset the lab (revert everything):
.\Invoke-ADVulnerabilities.ps1 -Config config\vulns.json -Undo

# Apply/undo a single one (even if disabled in config):
.\Invoke-ADVulnerabilities.ps1 -Config config\vulns.json -Only dcsync
```

Each vulnerability prints a `[blue-team]` detection/remediation note as it runs.
Missing users referenced by the config are created automatically (tagged so
`-Undo` only deletes lab-created objects, never pre-existing accounts).

## Vulnerabilities

| Config key                | Attack                      | What it does                                                        | Module |
|---------------------------|-----------------------------|---------------------------------------------------------------------|--------|
| `kerberoasting`           | Kerberoasting               | Service accounts with an SPN + weak password                        | `Invoke-Kerberoastable.ps1` |
| `asrepRoasting`           | AS-REP roasting             | Users with Kerberos pre-auth disabled                               | `Invoke-ASREPRoastable.ps1` |
| `unconstrainedDelegation` | Delegation abuse            | Account trusted for unconstrained delegation                        | `Invoke-Delegation.ps1` |
| `constrainedDelegation`   | Delegation abuse (S4U)      | Account with constrained delegation + protocol transition           | `Invoke-Delegation.ps1` |
| `dangerousAcl`            | ACL abuse (BloodHound)      | GenericAll/WriteDacl/etc. from a low-priv user onto a target object | `Invoke-DangerousACL.ps1` |
| `dcsync`                  | DCSync                      | Replication rights (Get-Changes*) granted to a low-priv user        | `Invoke-DCSync.ps1` |
| `credentialExposure`      | Credential hunting          | Secrets in `description`, plus PasswordNeverExpires accounts         | `Invoke-CredentialExposure.ps1` |
| `dangerousGroups`         | Privileged group → DA       | Add a user to DnsAdmins (or another dangerous group)                | `Invoke-GroupMembership.ps1` |
| `adcs`                    | ADCS ESC1/2/3/4/6           | Vulnerable cert templates + weak template ACL + CA SAN flag         | `Invoke-ADCSVulns.ps1` |
| `adfs`                    | Golden SAML                 | Over-privileged AD FS service account + DKM key read access        | `Invoke-ADFSVulns.ps1` |
| `adws`                    | ADWS recon exposure         | Ensures ADWS (9389) is reachable for enumeration-detection practice | `Invoke-ADWSExposure.ps1` |

### ADCS ESC coverage (`adcs`)

| Type | Misconfiguration |
|------|------------------|
| ESC1 | Template: enrollee-supplies-subject + Client Authentication EKU, low-priv enroll |
| ESC2 | Template: Any Purpose EKU (usable for client auth and more) |
| ESC3 | Template: Certificate Request Agent EKU (enrollment agent) |
| ESC4 | Weak template ACL — a low-priv principal gets Write control over a template |
| ESC6 | CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` (SAN honoured from any request) |

> `adcs` requires the ADCS role and `adfs` requires the AD FS role (see
> `..\Domain Controller` → add `ADCS` / `ADFS` roles to your lab spec). Both are
> disabled by default. `adws` plants no privilege escalation — it just exposes
> the ADWS recon channel so you can build detections for tools like SOAPHound.

## Suggested blue-team workflow

1. Build the lab (`..\Domain Controller\Deploy-ADLab.ps1`) and populate users.
2. Apply vulnerabilities here, then hunt them:
   - Run **BloodHound** / **PingCastle** / **Certify|Certipy** and review the paths.
   - Review Windows Security logs for the events in each module's `[blue-team]` note.
3. Remediate in AD, then run with `-Undo` to confirm a clean baseline, and repeat.

## Adding a vulnerability

Drop an `Invoke-<X>.ps1` in `modules\` (follow the existing shape: `-Spec`,
`-Domain`, `-Undo`, `-DryRun`, a `[blue-team]` note) and add a row to the
`$registry` in `Invoke-ADVulnerabilities.ps1` mapping a new config key to it.
