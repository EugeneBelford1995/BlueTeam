Function Get-ACLAudit {
param (
[parameter(Mandatory=$True)]
[ValidateNotNullOrEmpty()]$File
)

Try {
$CurrentPath = (Get-Location).Path
$Sheet = Import-Csv -Path $File
$OUs = (Get-Content $File | Select-Object -First 1).Split(",")

Import-Module ActiveDirectory
Set-Location AD:
$ADRoot = (Get-ADDomain).DistinguishedName
$DomainSID = (Get-ADDomain).DomainSID.Value

$Safe_Users = "Domain Admins|Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|$env:userdomain\\CERT Publishers|$env:userdomain\\Administrator|BUILTIN\\Account Operators|BUILTIN\\Terminal Server License Servers|NT AUTHORITY\\SELF|NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS|$env:userdomain\\Enterprise Read-only Domain Controllers|CREATOR OWNER|$env:userdomain\\DNSAdmins|$env:userdomain\\Key Admins|$env:userdomain\\Enterprise Key Admins|$env:userdomain\\Domain Computers|$env:userdomain\\Domain Controllers|$env:userdomain\\MSOL_06b14f1f684c|$env:userdomain\\BackupDC*|$env:userdomain\\TestDC|$DomainSID-519|S-1-5-32-548|$env:userdomain\\pGMSA_1b6a601e*"
$Safe_OU_Users = "$env:userdomain\\Domain Admins|Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|$env:userdomain\\Administrator|$env:userdomain\\Organization Management|$env:userdomain\\Exchange Trusted Subsystem|$env:userdomain\\Exchange Windows Permissions"
$DangerousOURights = "GenericAll|WriteDACL|WriteOwner"
$DangerousRights = "GenericAll|WriteDACL|WriteOwner|GenericWrite|WriteProperty|Self"
$DangerousGUIDs = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|00000000-0000-0000-0000-000000000000|00299570-246d-11d0-a768-00aa006e0529|33f04103-32fa-405f-95f8-037dd0a79827"
$FishyGUIDs = "ab721a56-1e2f-11d0-9819-00aa0040529b|ab721a54-1e2f-11d0-9819-00aa0040529b"
$SafeOUInheritance = "Descendents"

ForEach($OU in $OUs)
{
$OU_DN = (Get-ADOrganizationalUnit -Filter * -Properties * | Where-Object {$_.Name -eq "$OU"}).DistinguishedName
$Accounts = $Sheet.$OU
$MyGroups = $Accounts.ForEach{[regex]::Escape($_)} -join '|'
$SafeGroups = $MyGroups.Replace('\','')
While($SafeGroups.Substring($SafeGroups.Length-1) -eq "|"){$SafeGroups = $SafeGroups.Substring(0,$SafeGroups.Length-1)}

$ADCS_Objects = (Get-ADObject -Filter * -SearchBase "$OU_DN").DistinguishedName

Write-Host " "
Write-Host "Checking $OU_DN for non whitelisted groups or users who can abuse dMSAs"
$BadACE = (Get-Acl "$OU_DN").Access | Where-Object {($_.ActiveDirectoryRights -match $DangerousOURights) -or (($_.ActiveDirectoryRights -like "*CreateChild*") -and (($_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -or ($_.ObjectType -eq "33f04103-32fa-405f-95f8-037dd0a79827"))) -and ($_.IdentityReference -notmatch $Safe_OU_Users) -and ($_.InheritanceType -notmatch $SafeOUInheritance) -and ($_.AccessControlType -eq "Allow")}
If ($BadACE)
{
Write-Host "Object: $object" -ForegroundColor Red 
$BadACE
}


Write-Host " "
Write-Host "Checking $ADCS_Objects"
Write-Host " "

ForEach ($object in $ADCS_Objects)
{
$BadACE = (Get-Acl $object -ErrorAction SilentlyContinue).Access | Where-Object {(($_.IdentityReference -notmatch $Safe_Users) -and ($_.IdentityReference -notmatch $SafeGroups)) -and (($_.ActiveDirectoryRights -match $DangerousRights) -or ((($_.ActiveDirectoryRights -like "*ExtendedRight*") -and (($_.ObjectType -match $DangerousGUIDs) -or ($_.ObjectType -match $FishyGUIDs))))) -and ($_.AccessControlType -eq "Allow")}

If ($BadACE)
{
Write-Host "Object: $object" -ForegroundColor Red 
$BadACE
$object | Out-File "$CurrentPath\$OU Offenders.txt" -Append
$BadACE | Out-File "$CurrentPath\$OU Offenders.txt" -Append

If($BadACE.ObjectType.Guid -ne "00000000-0000-0000-0000-000000000000")
{$GUID = $BadACE.ObjectType.Guid
Get-Content "$CurrentPath\GUID_List.txt" | Select-String "$GUID" | Out-File "$CurrentPath\$OU Offenders.txt" -Append}

If($BadACE.InheritedObjectType.Guid -ne "00000000-0000-0000-0000-000000000000")
{$GUID = $BadACE.ObjectType.Guid
Get-Content "$CurrentPath\GUID_List.txt" | Select-String "$GUID" | Out-File "$CurrentPath\$OU Offenders.txt" -Append}

} #Close If ($BadACE)
} #Close ForEach ($object in $ADCS_Objects)
} #Close ForEach($OUs in $OUs)

} #Close the Try
Catch {Write-Host "Error, check the file name & path"}

Write-Host "Anything found was written to text files, named by OU, in your present working directory."
Set-Location $CurrentPath

} #Close the function

#. .\BadOwner_OU.ps1
#Get-BadOUOwner

Function Get-GUID {
param (
[parameter(Mandatory=$False)]
[ValidateNotNullOrEmpty()]$GUID
)
Get-Content "$CurrentPath\GUID_List.txt" | Select-String "$GUID"
Write-Host " "
Write-Host "If you need more information, please see https://medium.com/@happycamper84/dangerous-rights-cheatsheet-33e002660c1d and Ctrl + F the GUID"
}

Function Get-BadOUOwner {
Import-Module ActiveDirectory
Set-Location AD:
$ADRoot = (Get-ADDomain).DistinguishedName
$ADCS_Objects = (Get-ADOrganizationalUnit -Filter * -SearchBase $ADRoot).DistinguishedName
$Safe_Users = “Domain Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM”
ForEach ($object in $ADCS_Objects)
{
$BadOwner = (Get-Acl $object -ErrorAction SilentlyContinue).Owner -notmatch $Safe_Users
If ($BadOwner)
{
Write-Host “Object: $object” -ForegroundColor Red
Write-Host "is owned by the non whitelisted user or group listed below:"
(Get-Acl $object -ErrorAction SilentlyContinue).Owner
} #Close the If statement
} #Close the ForEach loop
} #Close the function

Function Audit-AllOUs {
Import-Module ActiveDirectory
Set-Location AD:
$ADRoot = (Get-ADDomain).DistinguishedName

$Safe_Users = "Domain Admins|Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|$env:userdomain\\CERT Publishers|$env:userdomain\\Administrator|BUILTIN\\Account Operators|BUILTIN\\Terminal Server License Servers|NT AUTHORITY\\SELF|NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS|$env:userdomain\\Enterprise Read-only Domain Controllers|CREATOR OWNER|$env:userdomain\\DNSAdmins|$env:userdomain\\Key Admins|$env:userdomain\\Enterprise Key Admins|$env:userdomain\\Domain Computers|$env:userdomain\\Domain Controllers|$env:userdomain\\MSOL_06b14f1f684c|$env:userdomain\\BackupDC*|$env:userdomain\\TestDC|$DomainSID-519|S-1-5-32-548|$env:userdomain\\pGMSA_1b6a601e*"
$Safe_OU_Users = "$env:userdomain\\Domain Admins|Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|$env:userdomain\\Administrator|$env:userdomain\\Organization Management|$env:userdomain\\Exchange Trusted Subsystem|$env:userdomain\\Exchange Windows Permissions"
$DangerousOURights = "GenericAll|WriteDACL|WriteOwner"
$DangerousRights = "GenericAll|WriteDACL|WriteOwner|GenericWrite|WriteProperty|Self"
$DangerousGUIDs = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|00000000-0000-0000-0000-000000000000|00299570-246d-11d0-a768-00aa006e0529|33f04103-32fa-405f-95f8-037dd0a79827"
$FishyGUIDs = "ab721a56-1e2f-11d0-9819-00aa0040529b|ab721a54-1e2f-11d0-9819-00aa0040529b"
$SafeOUInheritance = "Descendents"

$OUs = (Get-ADOrganizationalUnit -Filter * -SearchBase $ADRoot).DistinguishedName
ForEach($OU in $OUs)
{
$BadACE = (Get-Acl "$OU").Access | Where-Object {($_.ActiveDirectoryRights -match $DangerousOURights) -or (($_.ActiveDirectoryRights -like "*CreateChild*") -and (($_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -or ($_.ObjectType -eq "33f04103-32fa-405f-95f8-037dd0a79827"))) -and ($_.IdentityReference -notmatch $Safe_OU_Users) -and ($_.InheritanceType -notmatch $SafeOUInheritance) -and ($_.AccessControlType -eq "Allow")}
If ($BadACE)
{
Write-Host "Object: $OU" -ForegroundColor Red 
$BadACE
}
}
}