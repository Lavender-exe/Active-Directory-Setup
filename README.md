# Active Directory Lab Setup

Scripts to stand up a throwaway Active Directory lab: build a new forest/DC from
a config file, install role services (ADCS, ADFS, RSAT/ADWS), populate the
domain with random users/groups, and join workstations. It doubles as a
**defensive lab**: optionally plant common attacker misconfigurations so blue
teamers can practise detection and remediation (see `Vulnerabilities\`).

> These scripts intentionally weaken security (e.g. password policy) for lab
> use. Run them only on disposable lab machines, never in production.

## Layout

| Folder                | Purpose |
|-----------------------|---------|
| `Domain Controller\`  | Build the forest/DC, install roles (ADCS/ADFS/RSAT), generate users |
| `Workstation\`        | Join a workstation/member server to the domain |
| `Vulnerabilities\`    | Plant (and undo) intentional AD misconfigurations for defensive practice |

## Quick start

On a fresh Windows **Server** VM (elevated PowerShell), from the `Domain Controller` folder:

```powershell
# 1. Copy config\lab.example.json to lab.json and edit it for your lab.
Copy-Item config\lab.example.json lab.json

# 2. See exactly what would happen, without changing anything:
.\Deploy-ADLab.ps1 -Config lab.json -DryRun

# 3. Provision for real:
.\Deploy-ADLab.ps1 -Config lab.json
```

`Deploy-ADLab.ps1` runs four stages in order and records progress in a state
file (`C:\Windows\Tasks\adlab.state.json`) so it can **resume after reboots**:

| Stage     | What it does                                            | Script                     |
|-----------|---------------------------------------------------------|----------------------------|
| `Network` | Set hostname, static IP, DNS (replaces `sconfig`)       | `modules\Set-DCNetwork.ps1`|
| `Promote` | Install AD DS, create the new forest/DC (**reboots**)   | `modules\Install-DC.ps1`   |
| `Roles`   | Install each role in `roles[]` (ADCS / ADFS / RSAT)     | `modules\Install-*.ps1`    |
| `Users`   | Optionally generate + import AD users/groups            | `generate_ad.ps1`          |

The DC promotion reboots the machine. A `RunOnce` entry re-launches the
orchestrator automatically after that reboot. If it doesn't fire, just re-run
the same command — completed stages are skipped and the rest continue.

Run a single stage or a single role:

```powershell
.\Deploy-ADLab.ps1 -Config lab.json -Stage Roles     # only (re)install roles
.\Deploy-ADLab.ps1 -Config lab.json -Role ADCS        # install one role locally, then exit
```

## Config file

See `config\lab.example.json`. Fields:

```jsonc
{
  "domain": {
    "fqdn": "moros.local",          // full domain name
    "netbios": "MOROS",             // short/NetBIOS name
    "safeModePassword": "...",      // DSRM (Directory Services Restore Mode) password
    "forestMode": "WinThreshold",   // forest functional level (optional)
    "domainMode": "WinThreshold"    // domain functional level (optional)
  },
  "network": {
    "hostname": "DC01",
    "ipAddress": "10.0.0.10",       // omit to leave IP/DNS as-is
    "prefixLength": 24,
    "gateway": "10.0.0.1",
    "dnsServer": "127.0.0.1"        // a DC should point DNS at itself
  },
  "roles": [
    { "type": "ADCS", "target": "local",
      "caType": "EnterpriseRootCA", "caCommonName": "moros-CA", "validityYears": 5 },
    { "type": "ADFS", "target": "local",
      "serviceFqdn": "adfs.moros.local", "displayName": "moros ADFS",
      "certThumbprint": null,       // null -> generate a self-signed cert (lab)
      "serviceAccount": "MOROS\\svc-adfs", "serviceAccountPassword": "..." },
    { "type": "RSAT", "target": "local" }
  ],
  "users": {                        // optional
    "schema": "ad-schema.json",
    "generate": { "count": 15, "groups": 5, "localAdmins": 3 }
  }
}
```

### Role placement (`target`)

Each role has a `target`: `"local"` installs it on the DC (the box running the
orchestrator). Set it to a **member server's hostname** instead to place the
role on its own machine. For a remote target the orchestrator prints a runbook:

1. Domain-join that server (`Workstation\Join-AD.ps1`).
2. Copy the `modules` folder to it.
3. Run the matching `modules\Install-<role>.ps1` there — each module is
   self-contained and runs standalone, e.g.:

```powershell
.\Install-ADCS.ps1 -CaType EnterpriseRootCA -CaCommonName moros-CA
.\Install-ADFS.ps1 -ServiceFqdn adfs.moros.local -ServiceAccount MOROS\svc-adfs -ServiceAccountPassword <pw>
.\Install-RSAT.ps1
```

> Note: an Enterprise CA and ADFS both require the server to be domain-joined
> first.

### Adding more roles

The orchestrator dispatches on `role.type` (`Invoke-SingleRole` in
`Deploy-ADLab.ps1`). To add a new role, drop an `Install-<X>.ps1` in `modules\`,
add its `type` to `$script:KnownRoleTypes` in `modules\Common.ps1`, and add a
branch to the dispatch `switch`.

## Verifying the result

```powershell
Get-ADForest                 # forest / domain
certutil -CAInfo             # ADCS CA
Get-AdfsProperties           # ADFS
Get-Service ADWS             # AD Web Services
```

## Joining a workstation to the domain

`Workstation\Join-AD.ps1` is self-contained (copy it to the workstation on its
own) and config-aware. It can point the machine's DNS at the DC for you, runs
pre-flight checks, is idempotent, and prompts securely for a password if you
don't pass one.

```powershell
# Using the same lab spec (pulls domain, NetBIOS and the DC IP for DNS):
.\Join-AD.ps1 -Config ..\"Domain Controller"\lab.json -Restart

# Or fully explicit:
.\Join-AD.ps1 -Domain moros.local -User MOROS\Administrator -DnsServer 10.0.0.10 -NewName WS01 -Restart

# Preview without changing anything:
.\Join-AD.ps1 -Domain moros.local -DnsServer 10.0.0.10 -DryRun
```

> If you don't pass `-DnsServer`, make sure the workstation's DNS already points
> at the DC's IP, or the join will fail to resolve the domain.

## Random user generation

`rand_users.ps1` builds an `ad-schema.json` of random users/groups;
`generate_ad.ps1` consumes it to create the objects (and weaken the password
policy). The `Users` stage of the orchestrator does both for you, but you can
also run them directly:

```powershell
.\rand_users.ps1 <OutputFile> <NumUsers> <NumGroups> <NumLocalAdmins> [-Domain <fqdn>]

# Example (domain defaults to moros.local):
.\rand_users.ps1 ad-schema.json 5 5 3 -Domain moros.local

.\generate_ad.ps1 ad-schema.json
# Undo all generated users/groups and restore the password policy:
.\generate_ad.ps1 ad-schema.json -Undo
```

> Max No. of Groups: 20 &nbsp;&nbsp; | &nbsp;&nbsp; Username format: first-initial + lastname (e.g. `dfriens`)

*Example `ad-schema.json`:*

```json
{
    "domain": "moros.local",
    "users": [
        { "groups": "Executives", "name": "Diaz Friens", "password": "elocin" },
        { "local_admin": true, "groups": "Developers", "name": "Atkins Marila", "password": "pooh123" }
    ],
    "groups": [
        { "name": "Executives" },
        { "name": "Developers" }
    ]
}
```

## Manual DC install (reference)

The orchestrator automates this, but for reference the manual path is:

```powershell
# sconfig: set hostname, static IP, and DNS (point DNS at self / 127.0.0.1), then:
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName moros.local -DomainNetbiosName MOROS -InstallDns
```
