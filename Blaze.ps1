<#
  Setup-Blaze.ps1
  Purpose:
    - Align Active Directory with the Cisco Blaze model (City -> Department)
    - Create OUs, security groups (GG/DL), and map GG -> DL
    - Create department shares (E:\Blaze\<Dept>) with NTFS ACLs
    - Create per-user home folders under E:\BlazeUsers\USRS_<Dept>\First_Last
      and per-user SMB shares (NTFS controls the real permissions)
    - Assign users to GG based on Title (from JSON UserTitleMap)
    - Export a CSV report with all created/processed users

  Notes:
    - Local lab version (paths on E:\). In production replace paths with \\FS01\...
    - Requires RSAT / ActiveDirectory module, run as Domain Admin.
#>

param(
  [string]$ConfigPath = ".\blaze_config.local.json"
)

# ====== Preconditions ======
Import-Module ActiveDirectory -ErrorAction Stop

# ====== Load configuration ======
$config          = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$domainDNS       = $config.DomainDNS
$domainNetBIOS   = $config.DomainNetBIOS
$rootDN          = $config.RootDN
$parentOU        = $config.ParentOU
$parentOUPath    = "OU=$parentOU,$rootDN"

$foldersCfg      = $config.Folders
$basePath        = $foldersCfg.BasePath
$homeBasePath    = $foldersCfg.HomeFoldersBasePath
$deptPrefix      = if ($foldersCfg.DeptFolderPrefix) { $foldersCfg.DeptFolderPrefix } else { "USRS_" }

if (-not $basePath)     { throw "Folders.BasePath missing in JSON." }
if (-not $homeBasePath) { throw "Folders.HomeFoldersBasePath missing in JSON." }

# ====== Default password for new users ======
$pwd = Read-Host -Message "Enter the DEFAULT password for new users" -AsSecureString
if ($pwd.Length -eq 0) { throw "Password cannot be empty." }

# ====== Ensure base folders exist ======
foreach ($p in @($basePath, $homeBasePath)) {
  if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

# ====== Helpers ======
function New-IfMissingOU ($name, $path) {
  if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$name)" -SearchBase $path -EA 0)) {
    New-ADOrganizationalUnit -Name $name -Path $path | Out-Null
    Write-Host "[OU] $name" -ForegroundColor Green
  }
}
function New-IfMissingGroup ($name, $scope, $path) {
  if (-not (Get-ADGroup -LDAPFilter "(cn=$name)" -EA 0)) {
    New-ADGroup -Name $name -GroupScope $scope -GroupCategory Security -Path $path | Out-Null
    Write-Host "[$scope] $name" -ForegroundColor Cyan
  }
}

# ====== OU hierarchy (City -> Department) ======
New-IfMissingOU $parentOU $rootDN
# Container for groups
New-IfMissingOU -name "Groupen" -path $parentOUPath

# Derive City/Department from UsersByLocation (reflects Blaze VLAN org)
foreach ($city in $config.UsersByLocation.PSObject.Properties.Name) {
  $cityOU = "OU=$city,$parentOUPath"
  New-IfMissingOU $city $parentOUPath

  $departments = $config.UsersByLocation.$city.PSObject.Properties.Name
  foreach ($dept in $departments) {
    New-IfMissingOU $dept $cityOU
  }
}

# ====== Security groups (GG/DL) + mappings ======
$groupOU = "OU=Groupen,$parentOUPath"
foreach ($g in $config.GlobalGroups)      { New-IfMissingGroup $g 'Global'      $groupOU }
foreach ($g in $config.DomainLocalGroups) { New-IfMissingGroup $g 'DomainLocal' $groupOU }

# Map GG -> DL (role -> resource)
foreach ($ggProp in $config.GroupMap.PSObject.Properties) {
  $ggName = $ggProp.Name
  foreach ($dl in $ggProp.Value) {
    Add-ADGroupMember -Identity $dl -Members $ggName -EA 0
  }
}

# ====== Prepare USRS_* department roots ======
$deptMap = $config.DepartmentMap
$deptSet = [System.Collections.Generic.HashSet[string]]::new()
if ($deptMap) { foreach ($kv in $deptMap.PSObject.Properties) { [void]$deptSet.Add($kv.Value) } }
if ($deptSet.Count -eq 0 -and $foldersCfg.SubFolders) {
  foreach ($k in $foldersCfg.SubFolders.PSObject.Properties.Name) { [void]$deptSet.Add($k) }
}
if ($deptSet.Count -eq 0) { [void]$deptSet.Add("General") }

foreach ($dept in $deptSet) {
  $deptRoot = Join-Path $homeBasePath ($deptPrefix + $dept)
  if (-not (Test-Path $deptRoot)) {
    New-Item -ItemType Directory -Path $deptRoot | Out-Null
    Write-Host "[UsersRoot] $deptRoot" -ForegroundColor DarkCyan
  }
}

# ====== CSV export setup ======
$exportDir = Join-Path $PSScriptRoot "exports"
if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir | Out-Null }
$exportFile = Join-Path $exportDir ("Blaze-Users-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")
$report = @()

# ====== Users (City -> Department -> Users) ======
foreach ($cityProp in $config.UsersByLocation.PSObject.Properties) {
  $city = $cityProp.Name

  foreach ($deptProp in $cityProp.Value.PSObject.Properties) {
    $dept  = $deptProp.Name
    $ouPath = "OU=$dept,OU=$city,$parentOUPath"

    foreach ($u in $deptProp.Value) {
      if (-not $u.FirstName -or -not $u.LastName) {
        Write-Warning "Missing FirstName/LastName in $city/$dept"
        continue
      }

      # Build identifiers
      $rawSam   = ($u.FirstName.Substring(0,1) + $u.LastName).ToLower()
      $sam      = $rawSam.Substring(0, [Math]::Min(20, $rawSam.Length))
      $fullName = "$($u.FirstName) $($u.LastName)"
      $upn      = "$sam@$domainDNS"
      $folderName = "$($u.FirstName)_$($u.LastName)"

      # Resolve department for USRS_* root (Title -> DepartmentMap; fallback = OU dept)
      $deptName = $dept
      if ($config.DepartmentMap.PSObject.Properties[$u.Title]) {
        $deptName = $config.DepartmentMap.$($u.Title)
      }
      $deptRoot     = Join-Path $homeBasePath ($deptPrefix + $deptName)
      if (-not (Test-Path $deptRoot)) { New-Item -ItemType Directory -Path $deptRoot | Out-Null }

      $userHomePath  = Join-Path $deptRoot $folderName
      $homeShareName = $folderName
      $homeSharePath = "\\$env:COMPUTERNAME\$homeShareName"

      $created = $false

      # Create AD user if missing
      if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -EA 0)) {
        New-ADUser -Name $fullName `
                   -DisplayName $fullName `
                   -GivenName $u.FirstName -Surname $u.LastName `
                   -SamAccountName $sam -UserPrincipalName $upn `
                   -Title $u.Title -AccountPassword $pwd -Enabled $true `
                   -HomeDirectory $homeSharePath -HomeDrive "H:" `
                   -Path $ouPath | Out-Null
        $created = $true
        Write-Host "[User] $sam ($($u.Title)) $city/$dept" -ForegroundColor Yellow
      }

      # Assign GG by Title and collect DLs (via GroupMap)
      $gg = $null; $dls = @()
      if ($config.UserTitleMap.PSObject.Properties[$u.Title]) {
        $gg = [string]$config.UserTitleMap.$($u.Title)
        if ($gg) { Add-ADGroupMember -Identity $gg -Members $sam -EA 0 }
        if ($config.GroupMap.PSObject.Properties[$gg]) { $dls = $config.GroupMap.$gg }
      }

      # Create user home folder + NTFS ACL
      if (-not (Test-Path $userHomePath)) {
        New-Item -ItemType Directory -Path $userHomePath | Out-Null
        $acl = Get-Acl $userHomePath
        $acl.SetAccessRuleProtection($true, $false)  # break inheritance
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                      "$domainNetBIOS\$sam","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                      "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($userRule); $acl.AddAccessRule($adminRule)
        Set-Acl -Path $userHomePath -AclObject $acl
        Write-Host "[Home] $userHomePath secured" -ForegroundColor DarkGreen
      }

      # Create per-user SMB share (Everyone Full at share level; NTFS enforces real access)
      if (-not (Get-SmbShare -Name $homeShareName -EA 0)) {
        New-SmbShare -Name $homeShareName -Path $userHomePath -FullAccess "Everyone" | Out-Null
        Write-Host "[Share] $homeShareName → Everyone (NTFS enforced)" -ForegroundColor Cyan
      }

      # Append to report
      $report += [pscustomobject]@{
        City        = $city
        Department  = $dept
        FirstName   = $u.FirstName
        LastName    = $u.LastName
        Title       = $u.Title
        SamAccount  = $sam
        UPN         = $upn
        OUPath      = $ouPath
        HomeFolder  = $userHomePath
        HomeShare   = $homeSharePath
        GG          = $gg
        DLs         = ($dls -join ';')
        CreatedNow  = $created
      }
    }
  }
}

# ====== Department shares & NTFS ACLs (E:\Blaze\<Dept>) ======
if (-not (Test-Path $basePath)) { New-Item -ItemType Directory -Path $basePath | Out-Null }

foreach ($sub in $foldersCfg.SubFolders.PSObject.Properties) {
  $dept = $sub.Name
  $path = Join-Path $basePath $dept
  if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }

  # Reset and apply NTFS ACL
  $acl = Get-Acl $path
  $acl.SetAccessRuleProtection($true, $false)
  $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

  foreach ($perm in $sub.Value) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
              "$domainNetBIOS\$($perm.Group)", $perm.Right,
              "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
  }
  $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
  $acl.AddAccessRule($adminRule)
  Set-Acl $path $acl
  Write-Host "[ACL] $path set" -ForegroundColor DarkGreen

  # SMB share for department, if enabled
  if ($config.Shares -eq $true) {
    $shareName = "Blaze_$dept"
    if (-not (Get-SmbShare -Name $shareName -EA 0)) {
      New-SmbShare -Name $shareName -Path $path -FullAccess "Everyone" | Out-Null
      Write-Host "[Share] $shareName → Everyone FullAccess" -ForegroundColor Magenta
    }
  }
}

# ====== Export CSV report ======
$report | Export-Csv -Path $exportFile -NoTypeInformation -Encoding UTF8
Write-Host "`nReport saved to: $exportFile" -ForegroundColor Green
Write-Host "Setup complete." -ForegroundColor Green
