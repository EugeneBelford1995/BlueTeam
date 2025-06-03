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