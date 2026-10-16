<#
.SYNOPSIS
  Join this machine to the AD domain. Config-aware and hardened for lab use.

.DESCRIPTION
  Joins the local computer to a domain. It can read the same lab spec JSON used
  by Domain Controller\Deploy-ADLab.ps1 so the domain, NetBIOS name and DC IP
  stay consistent across the lab. Explicit parameters always override the config.

  Hardening over the original one-liner:
    * optionally points this machine's DNS at the DC first (the #1 join gotcha),
    * runs pre-flight checks (elevation, domain name resolves) before trying,
    * is idempotent (skips if already joined to the target domain),
    * prompts securely for a password when one isn't supplied,
    * supports -NewName / -OUPath / -Restart, with clear errors and -DryRun.

  This script is intentionally self-contained (no dependency on the modules\
  folder) so it can be copied to a workstation on its own.

.PARAMETER Config
  Optional path to the lab spec JSON (lab.json). Supplies defaults for -Domain,
  the NetBIOS prefix of -User, and -DnsServer (from network.ipAddress).

.PARAMETER Domain
  Domain FQDN to join (e.g. moros.local). Required unless supplied via -Config.

.PARAMETER User
  Join account. Defaults to "<NETBIOS>\Administrator".

.PARAMETER Password
  Join account password. If omitted you are prompted securely (Get-Credential).

.PARAMETER DnsServer
  Set this machine's DNS to this address (the DC's IP) before joining.

.PARAMETER NewName
  Rename the computer as part of the join.

.PARAMETER OUPath
  Distinguished name of the OU to create the computer object in.

.PARAMETER Restart
  Restart automatically after a successful join.

.PARAMETER DryRun
  Log what would happen without changing anything.

.EXAMPLE
  .\Join-AD.ps1 -Config ..\Domain Controller\lab.json

.EXAMPLE
  .\Join-AD.ps1 -Domain moros.local -User MOROS\Administrator -DnsServer 10.0.0.10 -NewName WS01 -Restart
#>
[CmdletBinding()]
param(
  [string]$Config,
  [string]$Domain,
  [string]$User,
  [string]$Password,
  [string]$DnsServer,
  [string]$InterfaceAlias,
  [string]$NewName,
  [string]$OUPath,
  [switch]$Restart,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# --- Minimal self-contained logging (matches the repo's [*]/[+]/[-] style) ---
function Write-Info { param([string]$m) Write-Host -ForegroundColor Yellow "[*] $m" }
function Write-Good { param([string]$m) Write-Host -ForegroundColor Green  "[+] $m" }
function Write-Warn { param([string]$m) Write-Host -ForegroundColor Red    "[-] $m" }

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Pull defaults from the lab spec, if given ------------------------------
$netbios = $null
if ($Config) {
  if (-not (Test-Path -LiteralPath $Config)) { throw "Config file not found: $Config" }
  try { $cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json }
  catch { throw "Config file is not valid JSON ($Config): $($_.Exception.Message)" }

  if (-not $Domain -and $cfg.domain.fqdn) { $Domain = $cfg.domain.fqdn }
  if ($cfg.domain.netbios) { $netbios = $cfg.domain.netbios }
  if (-not $DnsServer -and $cfg.network.ipAddress) { $DnsServer = $cfg.network.ipAddress }
}

if (-not $Domain) { throw "No domain specified. Pass -Domain or a -Config that sets domain.fqdn." }
if (-not $netbios) { $netbios = ($Domain.Split('.')[0]).ToUpper() }
if (-not $User) { $User = "$netbios\Administrator" }

Write-Info "Target domain : $Domain"
Write-Info "Join account  : $User"
if ($DnsServer) { Write-Info "DNS server    : $DnsServer" }

# --- Idempotency: already joined to the target domain? ----------------------
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain -eq $Domain) {
  Write-Good "This machine is already joined to '$Domain'. Nothing to do."
  return
}
if ($cs.PartOfDomain -and $cs.Domain -ne $Domain) {
  Write-Warn "Currently joined to a different domain ('$($cs.Domain)'). It must be unjoined first."
}

# --- Elevation --------------------------------------------------------------
if (-not $DryRun -and -not (Test-IsAdmin)) {
  throw "Joining a domain requires an elevated (Administrator) PowerShell session."
}

# --- Point DNS at the DC (the most common cause of join failures) -----------
if ($DnsServer) {
  if (-not $InterfaceAlias) {
    $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -First 1
    if (-not $adapter) { $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -First 1 }
    if ($adapter) { $InterfaceAlias = $adapter.Name }
  }
  if (-not $InterfaceAlias) {
    Write-Warn "Could not find an active network adapter to set DNS on; skipping (pass -InterfaceAlias)."
  }
  elseif ($DryRun) {
    Write-Host -ForegroundColor DarkGray "    [dry-run] would: set DNS on '$InterfaceAlias' -> $DnsServer"
  }
  else {
    Write-Info "Setting DNS on '$InterfaceAlias' -> $DnsServer"
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServer
    Clear-DnsClientCache -ErrorAction SilentlyContinue
  }
}

# --- Pre-flight: can we resolve the domain? ---------------------------------
$resolved = $true
try { Resolve-DnsName -Name $Domain -Type A -ErrorAction Stop | Out-Null }
catch { $resolved = $false }
if (-not $resolved) {
  $msg = "Cannot resolve domain '$Domain'. Point this machine's DNS at the DC (use -DnsServer <DC IP>) and ensure the DC is reachable."
  if ($DryRun) { Write-Warn "$msg (continuing: dry-run)" } else { throw $msg }
}
else {
  Write-Good "Domain '$Domain' resolves."
}

# --- Credentials ------------------------------------------------------------
if ($DryRun) {
  Write-Host -ForegroundColor DarkGray "    [dry-run] would: build credential for '$User'"
}
else {
  if ($Password) {
    $securePw = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($User, $securePw)
  }
  else {
    Write-Info "No -Password supplied; prompting for credentials."
    $Credential = Get-Credential -UserName $User -Message "Credentials to join '$Domain'"
  }
}

# --- Join -------------------------------------------------------------------
$join = @{ DomainName = $Domain; Force = $true }
if ($NewName) { $join['NewName'] = $NewName }
if ($OUPath)  { $join['OUPath']  = $OUPath }
if ($Restart) { $join['Restart'] = $true }

$desc = "Add-Computer -DomainName $Domain" + $(if ($NewName) { " -NewName $NewName" }) +
        $(if ($OUPath) { " -OUPath '$OUPath'" }) + $(if ($Restart) { " -Restart" })

if ($DryRun) {
  Write-Host -ForegroundColor DarkGray "    [dry-run] would: $desc"
  Write-Good "Dry-run complete."
  return
}

Write-Info "Joining domain '$Domain'..."
try {
  Add-Computer @join -Credential $Credential
}
catch {
  throw "Domain join failed: $($_.Exception.Message)"
}

Write-Good "Joined '$Domain' successfully."
if ($Restart) { Write-Info "Restarting to complete the join..." }
else { Write-Warn "Reboot required to complete the join. Re-run with -Restart or reboot manually." }
