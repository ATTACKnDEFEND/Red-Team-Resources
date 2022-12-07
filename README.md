# Red Team Free Resources

## Enumeration
- AutoRecon: Network reconnaissance tool. https://github.com/Tib3rius/AutoRecon
- Nmap: Network discovery and security auditing. https://nmap.org/
- SauronEye: Assembly search tool built to find files containing specific keywords. https://github.com/vivami/SauronEye
- ADRecon: PowerShell script extracts & combines various artefacts out of an AD env. https://github.com/sense-of-security/ADRecon
- ADModule: Microsoft signed DLL for the ActiveDirectory PowerShell module. https://github.com/samratashok/ADModule
- PowerView: AD enumeration tool. https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1
- SharpView: .NET Assemlbly port of PowerView. https://github.com/tevora-threat/SharpView
- ldapdomaindump: Active Directory information dumper via LDAP. https://github.com/dirkjanm/ldapdomaindump
- ADfind: Find various types of information from Active Directory. https://www.joeware.net/freetools/tools/adfind/index.htm
- GetUserSPNs: Find SPNs that use User accounts https://raw.githubusercontent.com/nidem/kerberoast/master/GetUserSPNs.ps1
- BloodHound: Identity AD attack paths. https://github.com/BloodHoundAD/BloodHound
- SharpHound: BloodHound Ingestor. https://github.com/BloodHoundAD/SharpHound
- SharpHound.ps1: BloodHound Ingestor using reflection. https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1

## Network utility
- Netcat: Networking utility for reading from and writing to network connections. https://eternallybored.org/misc/netcat/
- Impacket: Collection of Python classes working with network protocols. https://www.secureauth.com/labs/open-source-tools/impacket/

## C2
- Sliver: Command and Control (C2) system. https://github.com/BishopFox/slivern
- Metasploit: Command and Control (C2) system. https://www.metasploit.com/
- Covenant: Command and Control (C2) system. https://github.com/cobbr/Covenant/
- Covenant randomizer: Obfuscate Covenant. https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/Covenant%20Randomizer
- Cobaltstrike: Command and Control (C2) system. https://www.cobaltstrike.com/

## Shells+
- Evil-WinRM: Ultimate WinRM shell for hacking/pentesting. https://github.com/Hackplayers/evil-winrm 
- Villian: A Windows & Linux backdoor generator.  https://github.com/t3l3machus/Villain
- DotNetToJScript: Generate JScript bootstraps arbitrary .NET Assembly & class. https://github.com/tyranid/DotNetToJScript

## Packers+
- ConfuserEx: Open-source protector for .NET applications. https://github.com/mkaring/ConfuserEx

## Bypasses+
- Bypass-CLM: CLM bypass. https://github.com/calebstewart/bypass-clm
- AntiScan.Me: Online Virus Scanner without result distribution. https://antiscan.me/
- AMSI PowerShell bypass: Oneliner. https://github.com/ZemarKhos/AMSI-BYPASS-ONELINER/blob/main/amsi-bypass-onliner.ps1
- Amsi bypass: PowerShell AMSI bypass. https://notes.vulndev.io/notes/redteam/payloads/windows/amsi
- Amsitrigger: Hunting for Malicious Strings. https://www.rythmstick.net/posts/amsitrigger/
- ISESteroids: Extends built-in ISE PowerShell editor (inc obfuscation). https://www.powershellgallery.com/packages/ISESteroids/2.7.1.7
- Invoke-Obfuscation: PowerShell command and script obfuscator. https://github.com/danielbohannon/Invoke-Obfuscation
- amsi.fail: Generates obfuscated PowerShell snippets that break or disable AMSI for the current process. https://amsi.fail/

## Privilege Escalation and Post-Exploitation

### Linux
- LinPEAS: Linux Privilege Escalation Awesome Script. https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- GTFOBins: curated list of Unix binaries to bypass local security restrictions in misconfigured systems. https://gtfobins.github.io/
 
### Windows/AD
- WinPEAS: Windows Privilege Escalation Awesome Scripts. https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- PrivescCheck: Enumerate common Windows configuration issues. https://github.com/itm4n/PrivescCheck
- WinPwn: Powershell Recon/Exploit script with automatic proxy support. https://github.com/S3cur3Th1sSh1t/WinPwn
- HostRecon: PowerShell script host enumeration. https://github.com/dafthack/HostRecon/blob/master/HostRecon.ps1
- PowerUp: Clearinghouse of common Windows PE due to misconfiguration. https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1
- PowerShellMafia: PowerShell post-exploitation PowerSCCM and PowerSploit (includes PowerView). https://github.com/PowerShellMafia
- LOLBAS: Living Off The land Binaries, Scripts and Libraries. https://lolbas-project.github.io/

## Active Directory
- adPEAS: Powershell tool to automate Active Directory enumeration. https://github.com/61106960/adPEAS
- PowerMad: PowerShell MachineAccountQuota and DNS exploit tools.  https://github.com/Kevin-Robertson/Powermad
- Responder: Responder an LLMNR, NBT-NS and MDNS poisoner. https://github.com/SpiderLabs/Responder
- SpoolSample: coerce Windows hosts authenticate via the MS-RPRN RPC interface. https://github.com/leechristensen/SpoolSample
- Kerberoast: Kerberoast is a series of tools for attacking MS Kerberos implementations. https://github.com/nidem/kerberoast
- CrackMapExec(CME): Automate assessing the security of large AD networks. https://github.com/Porchetta-Industries/CrackMapExec
- Rubeus: C# toolset for raw Kerberos interaction and abuses. https://github.com/GhostPack/Rubeus
- Kekeo: Toolbox to manipulate Microsoft Kerberos in C. https://github.com/gentilkiwi/kekeo

## Credentials
- Mimikatz: Credential-dumping application. https://github.com/ParrotSec/mimikatz
- Pypykatz: Mimikatz implementation in pure Python. https://github.com/skelsec/pypykatz
- Lsassy: Python tool to remotely extract credentials on a set of hosts. https://github.com/Hackndo/lsassy
- LaZagne: Retrieve lots of passwords stored on a local computer. https://github.com/AlessandroZ/LaZagne
- crackstation: Free Password Hash Cracker. https://crackstation.net/

### MSSQL
- PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server. https://github.com/NetSPI/PowerUpSQL
- SharpSQLPwn: C# tool to identify and exploit weaknesses with MSSQL instances in AD env. https://github.com/lefayjey/SharpSQLPwn

## Proxy/Tunnel
- Sshuttle: Where transparent proxy meets VPN meets ssh. https://github.com/sshuttle/sshuttle
- Chisel: Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. https://github.com/jpillora/chisel

## Lateral Movement
- SharpMove: .NET authenticated execution for remote hosts. https://github.com/0xthirteen/SharpMove

## Home Labs
- Vulnerable-AD: Test most of active directory attacks in local lab. https://github.com/WazeHell/vulnerable-AD
- BadBlood: Outputs a domain to practice privileged identity threat hunting. https://github.com/davidprowe/BadBlood
- Windows & AD Hacking: Create your own vulnerable lab. https://redteamtechniques.github.io/Windows%20%26%20AD%20Hacking/

## Mind Maps/Flow Charts
- Orange Cyberdefense: Pentest AD. https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/img/pentest_ad_2022_04.svg
- Active Directory attacking: Useful for OSEP by Youssef Saeed. https://xmind.app/m/874LNH/#

## Other useful repositories
- S3cur3Th1sSh1t https://github.com/S3cur3Th1sSh1t
- Rasta Mouse https://github.com/rasta-mouse
- OSEP Code Snippets: Cas van Cooten. https://github.com/chvancooten/OSEP-Code-Snippets
- OSEP payloads and tools: Octoberfest7. https://github.com/Octoberfest7/OSEP-Tools
 
## References/Guides
- Test antivirus is working without any malware: https://www.blackhillsinfosec.com/is-this-thing-on/
- HackTricks: Comprehensive list of PT techniques. https://book.hacktricks.xyz
- Rubeus. A detailed guide on Rubeus. https://www.hackingarticles.in/a-detailed-guide-on-rubeus/
- Meterpreter Basics. https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/
- AD Domain Enumeration With Powerview: https://nored0x.github.io/red-teaming/active-directory-domain-enumeration-part-1/
- PowerView: https://academy.hackthebox.com/course/preview/active-directory-powerview/powerviewsharpview-overview--usage
- CertCube Labs: Blog on Advance InfoSec Concepts: https://blog.certcube.com/ad-exploitation-post-exploitation/
- ired.team notes about all things focusing on, but not limited to, red teaming and offensive security: https://www.ired.team/
- thehacker.recipes: technical guides on various hacking topics. https://www.thehacker.recipes/
- Kerberoast: how-to-kerberoast-like-a-boss. https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/
- Lateral moment on Active Directory crackmapexec: https://www.hackingarticles.in/lateral-moment-on-active-directory-crackmapexec/
