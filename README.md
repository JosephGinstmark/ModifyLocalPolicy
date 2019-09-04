# ModifyLocalPolicy

Created two functions to modify the User Rights Assignmnet on a local computer.

Add-UserToPolicy -Privilege <username/groupname> -Constant <constant>
Remove-UserFromPolicy -Privilege <username/groupname> -Constant <constant>
  
  Adds or Removes a group or user to the specifed Policy using it's constant name.
  A list of constants that can be modified can be located over at Microsoft https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
  
  
