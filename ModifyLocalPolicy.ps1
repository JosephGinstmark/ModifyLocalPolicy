# ToDo
# Comment the file
function Add-DenyLocalLogon  {
    Param(
        [parameter(Mandatory=$true)]
        [String]
        $Username 
    )
    
    $PolicyFile = "$env:TEMP\policies.inf"
    $NewPolicyFile = "$env:TEMP\Newpolicies.inf"
    $PolicyLog = "$env:TEMP\policies.log"
    $SecDB = "$env:TEMP\secedit.sdb"
    $SID =  (Get-CimInstance -ClassName "Win32_Account" -Filter "Name='$Username'").SID
    
    $ExitCode = (Start-Process secedit -ArgumentList "/export /areas USER_RIGHTS /cfg $PolicyFile /Log $PolicyLog" -Wait -PassThru).ExitCode
        if ($ExitCode -eq 0)
        {
            Write-Output "security template exported successfully exit code $ExitCode"
        }
    else
        {
            Write-Output "security template export failed exit code $ExitCode"
        }

    $file = Select-String '^(Se\S+) = (\S+)' "$PolicyFile" | Where-Object {$_ -match "SeDenyInteractiveLogonRight"}
    if([string]::IsNullOrEmpty($file) )
        {
            $file = Select-String '^(Se\S+) = (\S+)' "$PolicyFile" | Where-Object {$_ -match "SeDelegateSessionUserImpersonatePrivilege"}
            $LineNumber = $file.LineNumber
            $FullFile = get-content $PolicyFile
            $Privilege = "SeDenyInteractiveLogonRight"
            $Principals = $SID
            $NewPrinicpals = "$Privilege = $Principals"
            #$Privilege
            $NewRights = "$Privilege = $NewPrinicpals"
            $FullFile = $NewRights
        }
        else
        {
              $file     | Foreach-Object {
                    $LineNumber = $file.LineNumber
                    $Privilege = $null
                    $Principals = $null
                    $Privilege = $_.Matches[0].Groups[1].Value
                    $Principals += $_.Matches[0].Groups[2].Value -split ','
                    $collection = {$Principals}.Invoke()
                    $collection.Add("*$SID")
                    $NewPrinicpals = [String]::Join(",",$collection)
                }
            $FullFile = get-content $PolicyFile 
    
            # Get the full file and replace the line number -1 (since it's an array) that we are importing to. Arrays starts at 0 and the file starts at 1
            $NewRights = "$Privilege = $NewPrinicpals"
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
    
    Remove-Item -force $PolicyFile
    Remove-Item -force $NewPolicyFile
    Remove-Item -force $PolicyLog
    Remove-Item -force $SecDB
}
# ToDo
# Clean up Variables and do not use static paths 
# Create a function instead 
# Clean up when done
function Remove-DenyLocalLogon  {
    Param(
        [parameter(Mandatory=$true)]
        [String]
        $Username 
    )
    
    $PolicyFile = "$env:TEMP\policies.inf"
    $NewPolicyFile = "$env:TEMP\Newpolicies.inf"
    $PolicyLog = "$env:TEMP\policies.log"
    $SecDB = "$env:TEMP\secedit.sdb"
    $SidString =  (Get-CimInstance -ClassName "Win32_Account" -Filter "Name='$Username'").SID
    
    $ExitCode = (Start-Process secedit -ArgumentList "/export /areas USER_RIGHTS /cfg $PolicyFile /Log $PolicyLog" -Wait -PassThru).ExitCode
    if ($ExitCode -eq 0)
        {
            Write-Output "security template exported successfully exit code $ExitCode"
        }
    else
        {
            Write-Output "security template export failed exit code $ExitCode"
        }
    $file = Select-String '^(Se\S+) = (\S+)' "$PolicyFile" | Where-Object {$_ -match "SeDenyInteractiveLogonRight"}
    $LineNumber = $file.LineNumber
    $FullFile = get-content $PolicyFile
    
    # SID to remove 
    
    $SecDB = "Security.sdb"
    
    $file     | Foreach-Object {
                     
                    $Privilege = $null
                    $Principals = $null
                    $Privilege = $_.Matches[0].Groups[1].Value
                    $Principals += $_.Matches[0].Groups[2].Value -split ','
                    $collection = {$Principals}.Invoke()
                    $collection.Remove("*$SIDString")
                    $NewPrinicpals = [String]::Join(",",$collection)
                    $Privilege
        }
    
    # Get the full file and replace the line number -1 (since it's an array) that we are importing to. Arrays starts at 0 and the file starts at 1
    $NewRights = "$Privilege = $NewPrinicpals"
    $FullFile[$LineNumber -1] = $NewRights
    
    $FullFile | Set-Content $env:TEMP\$SecDB
    $fullFile | set-content $NewPolicyFile
    $ExitCode = (Start-Process secedit -ArgumentList "/configure /db $SecDB /cfg  $NewPolicyFile /areas USER_RIGHTS /log $PolicyLog " -NoNewWindow -Wait -PassThru).ExitCode
    
    Remove-Item -force $PolicyFile
    Remove-Item -force $NewPolicyFile
    Remove-Item -force $PolicyLog
    Remove-Item -force $SecDB
}
