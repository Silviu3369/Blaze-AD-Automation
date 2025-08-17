<#
  Setup-Blaze-Hardcoded.ps1
  Local lab (E:\) – No JSON. Everything is defined below.

  What it does:
    - Create OUs aligned to Cisco Blaze (City -> Department)
    - Create security groups (GG/DL) and map GG -> DL
    - Create department folders (E:\Blaze\<Dept>) with NTFS ACLs + SMB shares
    - Create users (hardcoded) with per-user home on:
        E:\BlazeUsers\USRS_<Dept>\First_Last
      and per-user SMB share (NTFS enforces real access)
    - Add users to GG based on Title
    - Export a CSV report of processed users

  Requirements:
    - Run as Domain Admin on a DC or a domain-joined machine with RSAT (ActiveDirectory)
#>

# ===== Domain & Paths (edit if needed) =====
$DomainDNS       = "test.intra"
$DomainNetBIOS   = "TEST"
$RootDN          = "DC=test,DC=intra"
$ParentOU        = "Blaze"
$ParentOUPath    = "OU=$ParentOU,$RootDN"

$BasePath        = "E:\Blaze"        # department shares root
$HomeBasePath    = "E:\BlazeUsers"   # user homes root
$DeptPrefix      = "USRS_"           # USRS_<Dept>

# ===== Default password for new users (HARDCODED) =====
$DefaultPassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force

# ===== Blaze model (Cities / Departments) =====
$Cities = @(
  @{ Name = "City1"; Departments = @("Office","IT","HR","Managers") },
  @{ Name = "City2"; Departments = @("Sales","Marketing") }
)

# ===== Security Groups =====
$GlobalGroups = @(
  "GG_Office","GG_IT","GG_HR","GG_Managers",
  "GG_Sales","GG_Marketing","GG_Intern"
)
$DomainLocalGroups = @(
  "DL_Office_RW","DL_Office_R",
  "DL_IT_M","DL_IT_R",
  "DL_HR_M","DL_HR_R",
  "DL_Managers",
  "DL_Sales_M","DL_Sales_RW","DL_Sales_R",
  "DL_Marketing_M","DL_Marketing_RW","DL_Marketing_R",
  "DL_Intern_RW","DL_Intern_R"
)

# GG -> DL mapping (role -> resource access)
$GroupMap = @{
  "GG_Office"    = @("DL_Office_RW")
  "GG_IT"        = @("DL_IT_M","DL_Sales_R","DL_Office_R")
  "GG_HR"        = @("DL_HR_M","DL_Office_R")
  "GG_Managers"  = @("DL_Managers","DL_Sales_RW","DL_Office_RW","DL_Intern_R")
  "GG_Sales"     = @("DL_Sales_M","DL_IT_R")
  "GG_Marketing" = @("DL_Marketing_M")
  "GG_Intern"    = @("DL_Intern_RW")
}

# Title -> GG mapping
$TitleToGG = @{
  "Office"     = "GG_Office"
  "Technician" = "GG_IT"
  "Security"   = "GG_IT"
  "IT"         = "GG_IT"
  "HR"         = "GG_HR"
  "Manager"    = "GG_Managers"
  "Directeur"  = "GG_Managers"
  "Sales"      = "GG_Sales"
  "Marketing"  = "GG_Marketing"
  "Interim"    = "GG_Intern"
}

# Department NTFS ACL definitions (folder-level)
$DeptAcl = @{
  "Office"    = @(@{Group="DL_Office_RW";    Right="Modify"},
                  @{Group="DL_Office_R";     Right="Read"})
  "IT"        = @(@{Group="DL_IT_M";         Right="FullControl"},
                  @{Group="DL_IT_R";         Right="Read"})
  "HR"        = @(@{Group="DL_HR_M";         Right="FullControl"},
                  @{Group="DL_HR_R";         Right="Read"})
  "Managers"  = @(@{Group="DL_Managers";     Right="FullControl"})
  "Sales"     = @(@{Group="DL_Sales_M";      Right="FullControl"},
                  @{Group="DL_Sales_RW";     Right="Modify"},
                  @{Group="DL_Sales_R";      Right="Read"})
  "Marketing" = @(@{Group="DL_Marketing_M";  Right="FullControl"},
                  @{Group="DL_Marketing_RW"; Right="Modify"},
                  @{Group="DL_Marketing_R";  Right="Read"})
}

# ===== Hardcoded Users (City, Dept, First, Last, Title) =====
$Users = @(
  @{ City="City1"; Dept="Office";   First="Ana";     Last="Popescu"; Title="Office" },
  @{ City="City1"; Dept="Office";   First="Radu";    Last="Istrate"; Title="Office" },
  @{ City="City1"; Dept="IT";       First="Ion";     Last="Ionescu"; Title="Technician" },
  @{ City="City1"; Dept="IT";       First="Vasile";  Last="Stan";    Title="Security" },
  @{ City="City1"; Dept="HR";       First="Elena";   Last="Radu";    Title="HR" },
  @{ City="City1"; Dept="Managers"; First="Cristina";Last="Pop";     Title="Manager" },
  @{ City="City1"; Dept="Managers"; First="Ana";     Last="Marin";   Title="Directeur" },

  @{ City="City2"; Dept="Sales";    First="Rodica";  Last="Bacila";  Title="Sales" },
  @{ City="City2"; Dept="Sales";    First="George";  Last="Marin";   Title="Sales" },
  @{ City="City2"; Dept="Marketing";First="Ioana";   Last="Toma";    Title="Marketing" }
)

# ===== Utilities =====
Import-Module ActiveDirectory -ErrorAction Stop

function New-IfMissingOU ($Name, $Path) {
  if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$Name)" -SearchBase $Path -EA 0)) {
    New-ADOrganizationalUnit -Name $Name -Path $Path | Out-Null
    Write-Host "[OU] $Name" -ForegroundColor Green
  }
}

function New-IfMissingGroup ($Name, $Scope, $Path) {
  if (-not (Get-ADGroup -LDAPFilter "(cn=$Name)" -EA 0)) {
    New-ADGroup -Name $Name -GroupScope $Scope -GroupCategory Security -Path $Path | Out-Null
    Write-Host "[$Scope] $Name" -ForegroundColor Cyan
  }
}

function Normalize-Ascii([string]$s){
  $formD = $s.Normalize([Text.NormalizationForm]::FormD)
  -join ($formD.ToCharArray() | Where-Object { [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne 'NonSpacingMark' })
}

function Get-UniqueSam([string]$base){
  $sam = $base
  $i = 1
  while (Get-ADUser -Filter "SamAccountName -eq '$sam'" -EA 0) {
    $sam = ($base + $i); $i++
  }
  return $sam.Substring(0, [Math]::Min(20, $sam.Length))
}

# ===== Ensure base folders =====
foreach($p in @($BasePath,$HomeBasePath)){
  if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

# ===== Create OU tree =====
New-IfMissingOU $ParentOU $RootDN
New-IfMissingOU "Groupen" $ParentOUPath

foreach($c in $Cities){
  $cityName = $c.Name
  $cityOU = "OU=$cityName,$ParentOUPath"
  New-IfMissingOU $cityName $ParentOUPath
  foreach($d in $c.Departments){
    New-IfMissingOU $d $cityOU
  }
}

# ===== Create Groups and GG->DL mapping =====
$GroupOU = "OU=Groupen,$ParentOUPath"

foreach($g in $GlobalGroups){      New-IfMissingGroup $g 'Global'      $GroupOU }
foreach($g in $DomainLocalGroups){ New-IfMissingGroup $g 'DomainLocal' $GroupOU }

foreach($gg in $GroupMap.Keys){
  foreach($dl in $GroupMap[$gg]){
    Add-ADGroupMember -Identity $dl -Members $gg -EA 0
  }
}

# ===== Prepare USRS_<Dept> roots =====
$AllDepartments = ($Cities.Departments | ForEach-Object { $_ } | Select-Object -Unique)
foreach($dept in $AllDepartments){
  $deptRoot = Join-Path $HomeBasePath ($DeptPrefix + $dept)
  if (-not (Test-Path $deptRoot)){
    New-Item -ItemType Directory -Path $deptRoot | Out-Null
    Write-Host "[UsersRoot] $deptRoot" -ForegroundColor DarkCyan
  }
}

# ===== CSV report =====
$ExportDir  = Join-Path $PSScriptRoot "exports"
if (-not (Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir | Out-Null }
$ExportFile = Join-Path $ExportDir ("Blaze-Users-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")
$Report = @()

# ===== Create Users =====
foreach($u in $Users){
  $city = $u.City; $dept = $u.Dept
  $ouPath = "OU=$dept,OU=$city,$ParentOUPath"

  $first  = Normalize-Ascii $u.First
  $last   = Normalize-Ascii $u.Last
  $baseSam = ($first.Substring(0,1) + $last).ToLower()
  $sam    = Get-UniqueSam $baseSam
  $upn    = "$sam@$DomainDNS"
  $full   = "$($u.First) $($u.Last)"
  $folderName = "$($u.First)_$($u.Last)"

  $deptRoot    = Join-Path $HomeBasePath ($DeptPrefix + $dept)
  if (-not (Test-Path $deptRoot)){ New-Item -ItemType Directory -Path $deptRoot | Out-Null }

  $userHomePath  = Join-Path $deptRoot $folderName
  $homeShareName = $folderName
  $homeSharePath = "\\$env:COMPUTERNAME\$homeShareName"

  $created = $false

  if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -EA 0)) {
    New-ADUser -Name $full `
               -DisplayName $full `
               -GivenName $u.First -Surname $u.Last `
               -SamAccountName $sam -UserPrincipalName $upn `
               -Title $u.Title -AccountPassword $DefaultPassword -Enabled $true `
               -HomeDirectory $homeSharePath -HomeDrive "H:" `
               -Path $ouPath | Out-Null
    $created = $true
    Write-Host "[User] $sam ($($u.Title)) $city/$dept" -ForegroundColor Yellow
  }

  # Assign role (GG) by Title
  $gg = $null; $dls = @()
  if ($TitleToGG.ContainsKey($u.Title)){ $gg = [string]$TitleToGG[$u.Title] }
  if ($gg){ Add-ADGroupMember -Identity $gg -Members $sam -EA 0 }
  if ($gg -and $GroupMap.ContainsKey($gg)){ $dls = $GroupMap[$gg] }

  # Create home folder + NTFS ACL
  if (-not (Test-Path $userHomePath)){
    New-Item -ItemType Directory -Path $userHomePath | Out-Null
    $acl = Get-Acl $userHomePath
    $acl.SetAccessRuleProtection($true,$false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

    $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$DomainNetBIOS\$sam","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $adminRule= New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($userRule); $acl.AddAccessRule($adminRule)
    Set-Acl -Path $userHomePath -AclObject $acl
    Write-Host "[Home] $userHomePath secured" -ForegroundColor DarkGreen
  }

  # Per-user share (idempotent)
  $existing = Get-SmbShare -Name $homeShareName -EA 0
  if (-not $existing) {
    New-SmbShare -Name $homeShareName -Path $userHomePath -FullAccess "Everyone" | Out-Null
    Write-Host "[Share] $homeShareName → Everyone (NTFS enforced)" -ForegroundColor Cyan
  } elseif ($existing.Path -ne $userHomePath) {
    Write-Warning "Share $homeShareName already exists with different path ($($existing.Path)). Skipping."
  }

  # Report line
  $Report += [pscustomobject]@{
    City       = $city
    Department = $dept
    FirstName  = $u.First
    LastName   = $u.Last
    Title      = $u.Title
    SamAccount = $sam
    UPN        = $upn
    OUPath     = $ouPath
    HomeFolder = $userHomePath
    HomeShare  = $homeSharePath
    GG         = $gg
    DLs        = ($dls -join ';')
    CreatedNow = $created
  }
}

# ===== Department folders, ACLs, and shares =====
if (-not (Test-Path $BasePath)) { New-Item -ItemType Directory -Path $BasePath | Out-Null }

foreach($dept in $AllDepartments){
  $path = Join-Path $BasePath $dept
  if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }

  # Reset ACL
  $acl = Get-Acl $path
  $acl.SetAccessRuleProtection($true,$false)
  $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

  if ($DeptAcl.ContainsKey($dept)){
    foreach($perm in $DeptAcl[$dept]){
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$DomainNetBIOS\$($perm.Group)", $perm.Right, "ContainerInherit,ObjectInherit","None","Allow")
      $acl.AddAccessRule($rule)
    }
  }
  $adminRule= New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
  $acl.AddAccessRule($adminRule)
  Set-Acl $path $acl
  Write-Host "[ACL] $path set" -ForegroundColor DarkGreen

  # Department share (Everyone Full at share level; NTFS enforces)
  $shareName = "Blaze_$dept"
  $existing = Get-SmbShare -Name $shareName -EA 0
  if (-not $existing){
    New-SmbShare -Name $shareName -Path $path -FullAccess "Everyone" | Out-Null
    Write-Host "[Share] $shareName → Everyone FullAccess" -ForegroundColor Magenta
  } elseif ($existing.Path -ne $path) {
    Write-Warning "Share $shareName already exists with different path ($($existing.Path)). Skipping."
  }
}

# ===== Export report =====
$Report | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
Write-Host "`nReport saved to: $ExportFile" -ForegroundColor Green
Write-Host "Setup complete." -ForegroundColor Green
