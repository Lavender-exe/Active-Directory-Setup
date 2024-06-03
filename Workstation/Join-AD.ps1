param ([string][ValidateNotNullOrEmpty()]$Password = "P@$$w0rd123",
       [string]$user = "Administrator",
       [string]$domain = "moros.local")

Write-Host -ForegroundColor Yellow "[*] Joining AD Domain"

# Change Password to secure string
$pass = ConvertTo-SecureString $Password -AsPlainText -Force

# Create Credential Object
$Credential = New-Object System.Management.Automation.PSCredential ($user, $pass)

# Join Domain
$Settings = @{
  DomainName = $domain
  DomainCredential = $Credential
}

Add-Computer @Settings