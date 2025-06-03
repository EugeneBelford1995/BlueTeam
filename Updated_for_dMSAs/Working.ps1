$ADRoot = (Get-ADDomain).DistinguishedName
Set-Location AD:

#Find all users/groups who hold Dangerous Rights on OUs
(Get-Acl "ou=domain controllers,$ADRoot").Access | Where-Object {(($_.ActiveDirectoryRights -like "*GenericAll*") -or ($_.ActiveDirectoryRights -like "*WriteOwner*") -or ($_.ActiveDirectoryRights -like "*WriteDACL*")) -or (($_.ActiveDirectoryRights -like "*CreateChild*") -and (($_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -or ($_.ObjectType -eq "33f04103-32fa-405f-95f8-037dd0a79827")))}


$Safe_OU_Users = "$env:userdomain\\Domain Admins|Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|$env:userdomain\\Administrator|$env:userdomain\\Organization Management|$env:userdomain\\Exchange Trusted Subsystem|$env:userdomain\\Exchange Windows Permissions"
$DangerousOURights = "GenericAll|WriteDACL|WriteOwner"
$DangerousGUIDs = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|00000000-0000-0000-0000-000000000000|00299570-246d-11d0-a768-00aa006e0529|33f04103-32fa-405f-95f8-037dd0a79827"
$SafeOUInheritance = "Descendents"

$OU_DN = Get-ADOrganizationalUnit "ou=User_Accounts,$ADRoot"
$BadACE = (Get-Acl "$OU_DN").Access | Where-Object {($_.ActiveDirectoryRights -match $DangerousOURights) -or (($_.ActiveDirectoryRights -like "*CreateChild*") -and (($_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -or ($_.ObjectType -eq "33f04103-32fa-405f-95f8-037dd0a79827"))) -and ($_.IdentityReference -notmatch $Safe_OU_Users) -and ($_.InheritanceType -notmatch $SafeOUInheritance) -and ($_.AccessControlType -eq "Allow")}
If ($BadACE)
{
Write-Host "Object: $object" -ForegroundColor Red 
$BadACE
}


(Get-Acl "ou=VIPs,$ADRoot").Access | Where-Object {($_.ActiveDirectoryRights -match $DangerousOURights) -or (($_.ActiveDirectoryRights -like "*CreateChild*") -and ($_.ObjectType -match $DangerousGUIDs)) -and ($_.InheritanceType -ne $SafeOUInheritance) -and ($_.IdentityReference -notmatch $Safe_OU_Users) -and ($_.AccessControlType -eq "Allow")}