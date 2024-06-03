# Instructions:

1. Create a DC with domain name of `moros.local`
2. Run `rand_users.ps1` script to generate a list of users
3. Copy `generate_ad.ps1, ad-schema.json` to the DC @ `C:\Windows\Tasks`
4. Run `.\generate_ad.ps1 ad-schema.json`
5. You can undo all groups and users by running `.\generate_ad.ps1 ad-schema.json -Undo`

This will generate users and local admins on your AD forest.

## Install DC

1. Use `sconfig` to:
    - Change the hostname
    - Change the IP address to static
    - Change the DNS server to our own IP address (or 127.0.0.1)

2. Install the Active Directory Windows Feature

```shell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

```shell
Get-NetIPAddress
```

### Joining the Workstation to the domain

> Make sure the workstation's DNS is set to the DC IP

```shell
Add-Computer -Domainname moros.local -Credential moros\Administrator -Force -Restart
```

## Random User Generation

To generate a random user, run the following command:

```shell
.\rand_users.ps1 ad-schema.json <NUM Users> <NUM Groups> <NUM LocalAdmins>

Example:
.\rand_users.ps1 ad-schema.json 5 5 3
```

> Max No. of Groups: 20

> Username Format: First Initial+Lastname (dfriens)

*Output:*

```json
{
    "domain":  "moros.local",
    "users":  [
                  {
                      "groups":  "Executives",
                      "name":  "Diaz Friens",
                      "password":  "elocin"
                  },
                  {
                      "local_admin":  true,
                      "groups":  "Developers",
                      "name":  "Atkins Marila",
                      "password":  "pooh123"
                  },
                  {
                      "local_admin":  true,
                      "groups":  "Contractor",
                      "name":  "Sat Silvestri",
                      "password":  "marlboro"
                  },
                  {
                      "groups":  "Sales",
                      "name":  "Krauskopf Vecerril",
                      "password":  "softball22"
                  },
                  {
                      "local_admin":  true,
                      "groups":  "Developers",
                      "name":  "Randy Woolley",
                      "password":  "nextel"
                  }
              ],
    "groups":  [
                   {
                       "name":  "Executives"
                   },
                   {
                       "name":  "Security"
                   },
                   {
                       "name":  "Developers"
                   },
                   {
                       "name":  "Sales"
                   },
                   {
                       "name":  "Contractor"
                   }
               ]
}

```
