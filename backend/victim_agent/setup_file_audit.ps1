<#
Enable Windows Success auditing for read access to one explicitly chosen lab
folder. Run once in an elevated PowerShell on the endpoint you own.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell window."
}

# Enable only File System success auditing. This does not audit every folder;
# the SACL below limits auditing to the selected lab folder and its children.
auditpol /set /subcategory:"File System" /success:enable /failure:disable | Out-Null
$acl = Get-Acl -LiteralPath $resolvedPath
$rights = [System.Security.AccessControl.FileSystemRights]::ReadData -bor
          [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
          [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes
$inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
               [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
    "Everyone", $rights, $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AuditFlags]::Success
)
$acl.AddAuditRule($rule)
Set-Acl -LiteralPath $resolvedPath -AclObject $acl
Write-Host "Success auditing enabled for: $resolvedPath"
Write-Host "Add or enable this path in protected_paths.json, then start agent.py."
