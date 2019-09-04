# ToDo
# Comment the file
<#
.SYNOPSIS
    Allows modification of the User Rights Assignment in the Local Security Policy using PowerShell.
.DESCRIPTION
    All of these things are doable by using GPO but sometimes you might need to set settings quickly.
    These two functions enables you to modify the local security policy on the local host.
    List of all settings and Constant names are avaliable at https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment

.EXAMPLE
    Add-UserToPolicy -Principal 'domain\group of users' -ConstantName SeDenyInteractiveLogonRight
    Adds the group 'domain\group of users' to the Constant SeDenyInteractiveLogonRight to Deny log on locally

.EXAMPLE
    Remove-UserFromPolicy -Principal $env:username -Constant SeShutdownPrivilege
    Removes the user from the Constant SeShutdownPrivilege to allow to Shutdown the System 

.INPUTS
    Remove-UserFromPolicy -Principal [username or group] -Constant [Constant Name]

.PARAMETER Principal
    Username or groupname of the principal to add/remove from the right.

.PARAMETER Constant
    Specifies what Constant Name to modify.

.NOTES
    FileName: ModifyLocalPolicy.ps1
    Version: 1.1
    Author: Joseph Ginstmark
    Blog: www.fjml.se
    Twitter: @josephginstmark

    Version history:
    1.0 - Script created

    1.1 - Script modified to add all constants to be avaliable.

.LINKS 
    https://github.com/JosephGinstmark/ModifyLocalPolicy
#>
function Add-UserToPolicy  {
    Param(
        [parameter(Mandatory=$true)]
        [String]
        $Principal,
        [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
        [validateSet('SeTrustedCredManAccessPrivilege',
        'SeNetworkLogonRight',
        'SeTcbPrivilege',
        'SeMachineAccountPrivilege',
        'SeIncreaseQuotaPrivilege',
        'SeInteractiveLogonRight',
        'SeRemoteInteractiveLogonRight',
        'SeBackupPrivilege',
        'SeChangeNotifyPrivilege',
        'SeSystemtimePrivilege',
        'SeTimeZonePrivilege',
        'SeCreatePagefilePrivilege',
        'SeCreateTokenPrivilege',
        'SeCreateGlobalPrivilege',
        'SeCreatePermanentPrivilege',
        'SeCreateSymbolicLinkPrivilege',
        'SeDebugPrivilege',
        'SeDenyNetworkLogonRight',
        'SeDenyBatchLogonRight',
        'SeDenyServiceLogonRight',
        'SeDenyInteractiveLogonRight',
        'SeDenyRemoteInteractiveLogonRight',
        'SeEnableDelegationPrivilege',
        'SeRemoteShutdownPrivilege',
        'SeAuditPrivilege',
        'SeImpersonatePrivilege',
        'SeIncreaseWorkingSetPrivilege',
        'SeIncreaseBasePriorityPrivilege',
        'SeLoadDriverPrivilege',
        'SeLockMemoryPrivilege',
        'SeBatchLogonRight',
        'SeServiceLogonRight',
        'SeSecurityPrivilege',
        'SeRelabelPrivilege',
        'SeSystemEnvironmentPrivilege',
        'SeManageVolumePrivilege',
        'SeProfileSingleProcessPrivilege',
        'SeSystemProfilePrivilege',
        'SeUndockPrivilege',
        'SeAssignPrimaryTokenPrivilege',
        'SeRestorePrivilege',
        'SeShutdownPrivilege',
        'SeSyncAgentPrivilege',
        'SeTakeOwnershipPrivilege')]
        [string]$ConstantName
    ) 
    $AdObj = New-Object System.Security.Principal.NTAccount($Principal)
    $strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
    $SID = $strSID.Value
    $Principals = $null
    $NewPrinicpals = $null
    $PolicyFile = "$env:TEMP\policies.inf"
    $NewPolicyFile = "$env:TEMP\Newpolicies.inf"
    $PolicyLog = "$env:TEMP\policies.log"
    $SecDB = "$env:TEMP\secedit.sdb"
    #$SID =  (Get-CimInstance -ClassName "Win32_Account" -Filter "Name='$Username'").SID
    
    $ExitCode = (Start-Process secedit -ArgumentList "/export /areas USER_RIGHTS /cfg $PolicyFile /Log $PolicyLog" -Wait -PassThru).ExitCode
        if ($ExitCode -eq 0)
        {
            Write-Output "security template exported successfully exit code $ExitCode"
        }
    else
        {
            Write-Output "security template export failed exit code $ExitCode"
        }

    $file = Select-String '^(Se\S+) = (\S+)' "$PolicyFile" | Where-Object {$_ -match $ConstantName}
    if([string]::IsNullOrEmpty($file) )
        {
            $file = Select-String '^(Se\S+) = (\S+)' "$PolicyFile" | Where-Object {$_ -match $ConstantName}
            $LineNumber = $file.LineNumber
            $FullFile = get-content $PolicyFile
            $Principals = $SID
            $NewPrinicpals = "$ConstantName  = $Principals"
            $NewRights = "$ConstantName = $NewPrinicpals"
            $FullFile = $NewRights
        }
        else
        {
              $file     | Foreach-Object {
                    $LineNumber = $file.LineNumber
                    $Principals = $null
                    $ConstantName = $_.Matches[0].Groups[1].Value
                    $Principals += $_.Matches[0].Groups[2].Value -split ','
                    $collection = {$Principals}.Invoke()
                    $collection.Add("*$SID")
                    $NewPrinicpals = [String]::Join(",",$collection)
         }
            $FullFile = get-content $PolicyFile 
    
            # Get the full file and replace the line number -1 (since it's an array) that we are importing to. Arrays starts at 0 and the file starts at 1
            $NewRights = "$ConstantName = $NewPrinicpals"
            $FullFile[$LineNumber -1] = $NewRights
            
        }


    
    $fullFile | set-content $NewPolicyFile
    $ExitCode = (Start-Process secedit -ArgumentList "/configure /db $SecDB /cfg  $NewPolicyFile /areas USER_RIGHTS /log $PolicyLog " -NoNewWindow -Wait -PassThru).ExitCode
        if ($ExitCode -eq 0)
        {
            Write-Output "security template imported successfully exit code $ExitCode"
        }
    else
        {
            Write-Output "security template import failed exit code $ExitCode"
        }
    $Principals = $null
    $NewPrinicpals = $null
    Remove-Item -force $PolicyFile
    Remove-Item -force $NewPolicyFile
    Remove-Item -force $PolicyLog
    Remove-Item -force $SecDB
}
function Remove-UserFromPolicy  {
    Param(
        [parameter(Mandatory=$true)]
        [String]
        $Principal,
        [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
        [validateSet('SeTrustedCredManAccessPrivilege',
        'SeNetworkLogonRight',
        'SeTcbPrivilege',
        'SeMachineAccountPrivilege',
        'SeIncreaseQuotaPrivilege',
        'SeInteractiveLogonRight',
        'SeRemoteInteractiveLogonRight',
        'SeBackupPrivilege',
        'SeChangeNotifyPrivilege',
        'SeSystemtimePrivilege',
        'SeTimeZonePrivilege',
        'SeCreatePagefilePrivilege',
        'SeCreateTokenPrivilege',
        'SeCreateGlobalPrivilege',
        'SeCreatePermanentPrivilege',
        'SeCreateSymbolicLinkPrivilege',
        'SeDebugPrivilege',
        'SeDenyNetworkLogonRight',
        'SeDenyBatchLogonRight',
        'SeDenyServiceLogonRight',
        'SeDenyInteractiveLogonRight',
        'SeDenyRemoteInteractiveLogonRight',
        'SeEnableDelegationPrivilege',
        'SeRemoteShutdownPrivilege',
        'SeAuditPrivilege',
        'SeImpersonatePrivilege',
        'SeIncreaseWorkingSetPrivilege',
        'SeIncreaseBasePriorityPrivilege',
        'SeLoadDriverPrivilege',
        'SeLockMemoryPrivilege',
        'SeBatchLogonRight',
        'SeServiceLogonRight',
        'SeSecurityPrivilege',
        'SeRelabelPrivilege',
        'SeSystemEnvironmentPrivilege',
        'SeManageVolumePrivilege',
        'SeProfileSingleProcessPrivilege',
        'SeSystemProfilePrivilege',
        'SeUndockPrivilege',
        'SeAssignPrimaryTokenPrivilege',
        'SeRestorePrivilege',
        'SeShutdownPrivilege',
        'SeSyncAgentPrivilege',
        'SeTakeOwnershipPrivilege')]
        [string]$ConstantName
    ) 
    
    $Principals = $null
    $NewPrinicpals = $null
    $PolicyFile = "$env:TEMP\policies.inf"
    $NewPolicyFile = "$env:TEMP\Newpolicies.inf"
    $PolicyLog = "$env:TEMP\policies.log"
    $SecDB = "$env:TEMP\secedit.sdb"
    $AdObj = New-Object System.Security.Principal.NTAccount($Principal)
    $strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
    $SID = $strSID.Value

    $ExitCode = (Start-Process secedit -ArgumentList "/export /areas USER_RIGHTS /cfg $PolicyFile /Log $PolicyLog" -Wait -PassThru).ExitCode
    if ($ExitCode -eq 0)
        {
            Write-Output "security template exported successfully exit code $ExitCode"
        }
    else
        {
            Write-Output "security template export failed exit code $ExitCode"
        }
    $file = Select-String '^(Se\S+) = (\S+)' "$PolicyFile" | Where-Object {$_ -match "$ConstantName"}
    $LineNumber = $file.LineNumber
    $FullFile = get-content $PolicyFile
    $SecDB = "Security.sdb"
    $file     | Foreach-Object {
                     
                    $ConstantName = $_.Matches[0].Groups[1].Value
                    $Principals += $_.Matches[0].Groups[2].Value -split ','
                    $collection = {$Principals}.Invoke()
                    $collection.Remove("*$SID")
                    $NewPrinicpals = [String]::Join(",",$collection)
        } |Out-Null
    
    # Get the full file and replace the line number -1 (since it's an array) that we are importing to. Arrays starts at 0 and the file starts at 1
    $NewRights = "$ConstantName = $NewPrinicpals"
    $FullFile[$LineNumber -1] = $NewRights
    
    $FullFile | Set-Content $env:TEMP\$SecDB
    $fullFile | set-content $NewPolicyFile
    $ExitCode = (Start-Process secedit -ArgumentList "/configure /db $SecDB /cfg  $NewPolicyFile /areas USER_RIGHTS /log $PolicyLog " -NoNewWindow -Wait -PassThru).ExitCode
    if ($ExitCode -eq 0)
        {
            Write-Output "security template imported successfully exit code $ExitCode"
        }
    else
        {
            Write-Output "security template import failed exit code $ExitCode"
        }
    $Principals = $null
    $NewPrinicpals = $null
    Remove-Item -force $PolicyFile
    Remove-Item -force $NewPolicyFile
    Remove-Item -force $PolicyLog
    Remove-Item -force $SecDB
}
