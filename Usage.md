Usage
 Prerequisites

Before running the script, make sure you have:

A Windows Server joined to the domain

RSAT / ActiveDirectory PowerShell module installed

Run as Domain Admin (or equivalent delegated rights)

Script execution policy enabled:

Set-ExecutionPolicy RemoteSigned -Scope Process -Force

 Running the Script

Navigate to the scripts folder:

cd .\scripts\


Run the provisioning script with your configuration file:

.\Blaze.ps1 -ConfigPath ..\config\blaze_config.json


When prompted, enter the default password for new users.

 What the Script Does

During execution, the script will:

Create the OU hierarchy: OU=Blaze → OU=City → OU=Department

Create Global (GG) and Domain Local (DL) groups inside OU=Groupen

Apply GG → DL mappings for RBAC

Provision users into the correct OU, based on UsersByLocation

Assign users to their GG, according to UserTitleMap

Create home folders:

Path: E:\BlazeUsers\USRS_<Dept>\First_Last

NTFS ACLs: user + Administrators = FullControl

Publish SMB shares (if "Shares": true)

Department shares: Blaze_<Dept>

Per-user shares (same name as folder)

Export a CSV report under .\exports\

 Example Output
[OU] Blaze
[OU] Roeselare
[OU] IT
[OU] HR
[Global] GG_IT
[DomainLocal] DL_Sales_R
[User] ionionescu (Technician) Roeselare/IT
[Home] E:\BlazeUsers\USRS_IT\Ion_Ionescu secured
[Share] Ion_Ionescu → Everyone (NTFS enforced)

Report saved to: .\exports\Blaze-Users-20250817-113000.csv
Setup complete.

 Verifying the Results

After the script runs, verify:

In Active Directory Users and Computers (ADUC):

OU tree exists (Blaze → Cities → Departments)

Groups exist in OU=Groupen

Users are created in correct OUs

On the file system:

Department folders under E:\Blaze\ with correct ACLs

User folders under E:\BlazeUsers\USRS_<Dept>\

In Computer Management → Shared Folders:

Shares Blaze_<Dept> and per-user shares exist

Open the CSV report in .\exports\ to review created/processed users.

 Re-runs & Idempotency

The script is idempotent: running it multiple times is safe.

Existing OUs, groups, and users are skipped.

New entries from JSON are created automatically.

ACLs are re-applied for consistency.

 With this guide, any admin can clone the repo, edit blaze_config.json, run the script, and instantly provision a Blaze-aligned Active Directory.
