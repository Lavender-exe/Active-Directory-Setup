<#
.SYNOPSIS
  Shared helpers for the AD vulnerability-lab scripts.

.DESCRIPTION
  Dot-sourced by Invoke-ADVulnerabilities.ps1 and the per-vulnerability modules.
  Provides logging, a dry-run wrapper, config loading/validation, the AD module
  import, and small AD helpers (SID lookup, ensure-user, ACL grant/revoke).

  Self-contained: it does not depend on the Domain Controller\modules helpers,
  so this whole folder can be copied to a DC on its own.
#>

function Write-Info { param([string]$m) Write-Host -ForegroundColor Yellow "[*] $m" }
function Write-Good { param([string]$m) Write-Host -ForegroundColor Green  "[+] $m" }
function Write-Warn { param([string]$m) Write-Host -ForegroundColor Red    "[-] $m" }
function Write-Step { param([string]$m) Write-Host -ForegroundColor Cyan   "`n==> $m" }
function Write-BlueTeam { param([string]$m) Write-Host -ForegroundColor DarkCyan "    [blue-team] $m" }

# Every state-changing action goes through this so -DryRun can log instead of run.
function Invoke-VulnAction {
  param(
    [Parameter(Mandatory)] [string]$Description,
    [Parameter(Mandatory)] [scriptblock]$Action,
    [switch]$DryRun
  )
  if ($DryRun) { Write-Host -ForegroundColor DarkGray "    [dry-run] would: $Description"; return }
  Write-Info $Description
  & $Action
}

function Import-ADModuleOrThrow {
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory PowerShell module is not available. Run this on the DC (or a box with RSAT-AD-Tools)."
  }
  Import-Module ActiveDirectory -ErrorAction Stop
}

# --- Config -----------------------------------------------------------------
function Get-VulnConfig {
  param([Parameter(Mandatory)] [string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "Config file not found: $Path" }
  try { $cfg = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
  catch { throw "Config file is not valid JSON ($Path): $($_.Exception.Message)" }
  if (-not $cfg.domain) { throw "Config is missing 'domain' (e.g. moros.local)." }
  if (-not $cfg.vulnerabilities) { throw "Config is missing the 'vulnerabilities' section." }
  return $cfg
}

# --- AD helpers -------------------------------------------------------------

# Marker written into the 'info' attribute of objects this lab creates, so Undo
# can safely delete only the objects it made (never pre-existing/real ones).
$script:VulnMarker = 'ADVULNLAB-CREATED'

function Get-DomainDN {
  return (Get-ADDomain).DistinguishedName
}

function Resolve-ADUserOrCreate {
  <#
    Return the SamAccountName of $Name, creating a basic enabled user if it does
    not already exist. Created users are tagged with the lab marker. Returns a
    hashtable: @{ Sam = ...; Created = $true/$false }.
  #>
  param(
    [Parameter(Mandatory)] [string]$Name,
    [string]$Password = 'Password123!',
    [switch]$DryRun
  )
  if ($DryRun) {
    Write-Host -ForegroundColor DarkGray "    [dry-run] would: ensure user '$Name' exists (create if missing)"
    return @{ Sam = $Name; Created = $false }
  }
  $existing = Get-ADUser -Filter "SamAccountName -eq '$Name'" -Properties info -ErrorAction SilentlyContinue
  if ($existing) { return @{ Sam = $existing.SamAccountName; Created = $false } }

  Invoke-VulnAction -DryRun:$DryRun -Description "create lab user '$Name'" -Action {
    New-ADUser -Name $Name -SamAccountName $Name `
      -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
      -Enabled $true -PasswordNeverExpires $true `
      -OtherAttributes @{ info = $script:VulnMarker } | Out-Null
  }
  return @{ Sam = $Name; Created = $true }
}

function Test-LabCreated {
  param([Parameter(Mandatory)] $ADObject)
  return ($ADObject.info -eq $script:VulnMarker)
}

function Get-ADObjectSid {
  param([Parameter(Mandatory)] [string]$Identity)
  $o = Get-ADObject -Filter "SamAccountName -eq '$Identity'" -Properties objectSid -ErrorAction SilentlyContinue
  if (-not $o) { $o = Get-ADObject -Filter "Name -eq '$Identity'" -Properties objectSid -ErrorAction SilentlyContinue }
  if (-not $o) { throw "Could not resolve identity '$Identity' to a SID." }
  return [System.Security.Principal.SecurityIdentifier]$o.objectSid
}

# Grant or revoke a right in an object's DACL.
#   -ObjectType [guid]::Empty  => a plain right (e.g. GenericAll)
#   -ObjectType <ext-right>    => an extended right (rights must be ExtendedRight)
function Set-ADAceForIdentity {
  param(
    [Parameter(Mandatory)] [string]$TargetDN,
    [Parameter(Mandatory)] [System.Security.Principal.SecurityIdentifier]$Sid,
    [Parameter(Mandatory)] [System.DirectoryServices.ActiveDirectoryRights]$Rights,
    [guid]$ObjectType = [guid]::Empty,
    [switch]$Remove,
    [switch]$DryRun
  )
  $verb = if ($Remove) { 'remove' } else { 'grant' }
  $rightName = if ($ObjectType -ne [guid]::Empty) { "$Rights {$ObjectType}" } else { "$Rights" }
  Invoke-VulnAction -DryRun:$DryRun -Description "$verb ACE [$rightName] for $Sid on $TargetDN" -Action {
    $path = "AD:\$TargetDN"
    $acl = Get-Acl -Path $path
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    if ($ObjectType -eq [guid]::Empty) {
      $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, $allow, $inherit)
    }
    else {
      $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, $allow, $ObjectType, $inherit)
    }
    if ($Remove) { [void]$acl.RemoveAccessRule($ace) } else { $acl.AddAccessRule($ace) }
    Set-Acl -Path $path -AclObject $acl
  }
}
