# ModifyLocalPolicy
A short script that modifies the SeDenyInteractiveLogonRight to use for direct restriction for local logon

A short script that enables the adding/removing of ADUsers to the Local Security Policy "Deny log on locally".

The script has two functions, Add-DenyLocalLogon and Remove-DenyLocalLogon, that does what it says.

Add-DenyLocalLogon <ADUser> will lookup the SID of the user and add it to the list of people that is denied to logon localy
Remove-DenyLocalLogon <ADUser> will lookup the SID of the user and remove it from the list of people that is denied to logon localy.
