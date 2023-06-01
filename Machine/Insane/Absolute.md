![|center|400](img/Absolute.png)

# Synopsis

Absolute is an Insane Windows Active Directory machine that starts with a webpage displaying some images, whose metadata is used to create a wordlist of possible usernames that may exits on the machine. It turns out that one of these users doesn't require Pre-authentication, therefore posing a valuable target for an `ASREP` roast attack. The discovered credentials are then used to enumerate `LDAP` and discover credentials for the user `svc_smb`, who has access to an `SMB` share containing a Windows binary. Performing dynamic analysis on the binary reveals that it tries to perform an `LDAP` connection to the Domain Controller with clear text credentials for the `m.lovegod` user, who owns the `Network Audit` group, which in turn has `Generic Write` over the `winrm_user`. Following this attack path and performing a shadow credential attack on the `winrm_user`, one can then `WinRM` and access the machine. Finally, the `KrbRelay` tool is used to add the `winrm_user` user to the Administrators group, leading to fully elevated privileges.

## Skills Required

- Enumeration
- Windows Active Directory
- Dynamic Analysis

## Skills Learned

- Kerberos Authentication
- Access Control Lists (ACLs) Modification
- KrbRelay
- Interactive Sessions

# Enumeration

aa
