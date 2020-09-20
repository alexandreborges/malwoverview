/*
    VALHALLA YARA RULE SET
    Retrieved: 2020-09-20 09:19
    Generated for User: demo
    Number of Rules: 45
    
    This is the VALHALLA demo rule set. The content represents the 'signature-base' repository in a streamlined format but lacks the rules provided by 3rd parties. All rules are licensed under CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/.
*/

import "pe"

rule APT_APT41_CN_ELF_Speculoos_Backdoor_RID3365 : APT DEMO FILE G0096 LINUX MAL T1136 {
   meta:
      description = "Detects Speculoos Backdoor used by APT41"
      author = "Florian Roth"
      reference = "https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/"
      date = "2020-04-14 14:46:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0096, LINUX, MAL, T1136"
      minimum_yara = "1.7"
      
   strings:
      $xc1 = { 2F 70 72 69 76 61 74 65 2F 76 61 72 00 68 77 2E
               70 68 79 73 6D 65 6D 00 68 77 2E 75 73 65 72 6D
               65 6D 00 4E 41 2D 4E 41 2D 4E 41 2D 4E 41 2D 4E
               41 2D 4E 41 00 6C 6F 30 00 00 00 00 25 30 32 78
               2D 25 30 32 78 2D 25 30 32 78 2D 25 30 32 78 2D
               25 30 32 78 2D 25 30 32 78 0A 00 72 00 4E 41 00
               75 6E 61 6D 65 20 2D 76 } 
      $s1 = "badshell" ascii fullword
      $s2 = "hw.physmem" ascii fullword
      $s3 = "uname -v" ascii fullword
      $s4 = "uname -s" ascii fullword
      $s5 = "machdep.tsc_freq" ascii fullword
      $s6 = "/usr/sbin/config.bak" ascii fullword
      $s7 = "enter MessageLoop..." ascii fullword
      $s8 = "exit StartCBProcess..." ascii fullword
      $sc1 = { 72 6D 20 2D 72 66 20 22 25 73 22 00 2F 70 72 6F
               63 2F } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 600KB and 1 of ( $x* ) or 4 of them
}

rule APT_APT41_CRACKSHOT_RID2CA0 : APT DEMO EXE FILE G0096 T1136 {
   meta:
      description = "Detects APT41 malware CRACKSHOT"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 09:57:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, G0096, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = ";procmon64.exe;netmon.exe;tcpview.exe;MiniSniffer.exe;smsniff.exe" ascii
      $s1 = "RunUrlBinInMem" fullword ascii
      $s2 = "DownRunUrlFile" fullword ascii
      $s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36" fullword ascii
      $s4 = "%s|%s|%s|%s|%s|%s|%s|%dx%d|%04x|%08X|%s|%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and ( 1 of ( $x* ) or 2 of them )
}

rule APT_APT41_HIGHNOON_RID2C58 : APT DEMO EXE FILE G0096 T1136 {
   meta:
      description = "Detects APT41 malware HIGHNOON"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 09:45:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, G0096, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "workdll64.dll" fullword ascii
      $s1 = "\\Fonts\\Error.log" fullword ascii
      $s2 = "[%d/%d/%d/%d:%d:%d]" fullword ascii
      $s3 = "work_end" fullword ascii
      $s4 = "work_start" fullword ascii
      $s5 = "\\svchost.exe" fullword ascii
      $s6 = "LoadAppInit_DLLs" fullword ascii
      $s7 = "netsvcs" fullword ascii
      $s8 = "HookAPIs ...PID %d " fullword ascii
      $s9 = "SOFTWARE\\Microsoft\\HTMLHelp" fullword ascii
      $s0 = "DllMain_mem" fullword ascii
      $s10 = "%s\\NtKlRes.dat" fullword ascii
      $s11 = "Global\\%s-%d" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or 4 of them )
}

rule APT_APT41_HIGHNOON_BIN_RID2D90 : APT DEMO EXE FILE G0096 T1136 {
   meta:
      description = "Detects APT41 malware HIGHNOON.BIN"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 10:37:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, G0096, T1136"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $s1 = "PlusDll.dll" fullword ascii
      $s2 = "\\Device\\PORTLESS_DeviceName" fullword wide
      $s3 = "%s%s\\Security" fullword ascii
      $s4 = "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
      $s5 = "%s%s\\Enum" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "b70358b00dd0138566ac940d0da26a03" or 3 of them )
}

rule APT_APT41_HIGHNOON_BIN_2_RID2E21 : APT DEMO EXE FILE G0096 T1136 {
   meta:
      description = "Detects APT41 malware HIGHNOON.BIN"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 11:01:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, G0096, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\Double\\Door_wh\\" ascii
      $x2 = "[Stone] Config --> 2k3 TCP Positive Logout." fullword ascii
      $x3 = "\\RbDoorX64.pdb" ascii
      $x4 = "RbDoor, Version 1.0" fullword wide
      $x5 = "About RbDoor" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule MAL_CrypRAT_Jan19_1_RID2D41 : DEMO EXE FILE MAL T1136 {
   meta:
      description = "Detects CrypRAT"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-07 10:24:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "DEMO, EXE, FILE, MAL, T1136"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $x1 = "Cryp_RAT" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "2524e5e9fe04d7bfe5efb3a5e400fe4b" or 1 of them )
}

rule HKTL_Lazagne_PasswordDumper_Dec18_1_RID33E8 : DEMO EXE FILE HKTL T1003 T1136 {
   meta:
      description = "Detects password dumper Lazagne often used by middle eastern threat groups"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11 15:07:51"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "DEMO, EXE, FILE, HKTL, T1003, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "softwares.opera(" fullword ascii
      $s2 = "softwares.mozilla(" fullword ascii
      $s3 = "config.dico(" fullword ascii
      $s4 = "softwares.chrome(" fullword ascii
      $s5 = "softwares.outlook(" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and 1 of them
}

rule Crackmapexec_EXE_RID2D19 : DEMO EXE FILE HKTL T1136 {
   meta:
      description = "Detects CrackMapExec hack tool"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-04-06 10:17:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "DEMO, EXE, FILE, HKTL, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "core.scripts.secretsdump(" fullword ascii
      $s2 = "core.scripts.samrdump(" fullword ascii
      $s3 = "core.uacdump(" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 10000KB and 2 of them
}

rule GoldDragon_malware_Feb18_1_RID309F : APT CHINA DEMO EXE FILE {
   meta:
      description = "Detects malware from Gold Dragon report"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
      date = "2018-02-03 12:47:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, CHINA, DEMO, EXE, FILE"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "168c2f7752511dfd263a83d5d08a90db" or pe.imphash ( ) == "0606858bdeb129de33a2b095d7806e74" or pe.imphash ( ) == "51d992f5b9e01533eb1356323ed1cb0f" or pe.imphash ( ) == "bb801224abd8562f9ee8fb261b75e32a" )
}

rule GoldDragon_Aux_File_RID2E5E : APT CHINA DEMO T1136 {
   meta:
      description = "Detects export from Gold Dragon - February 2018"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
      date = "2018-02-03 11:11:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, CHINA, DEMO, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "/////////////////////regkeyenum////////////" ascii
   condition: 
      filesize < 500KB and 1 of them
}

rule Scarcruft_malware_Feb18_1_RID306B : APT DEMO EXE FILE G0067 T1136 {
   meta:
      description = "Detects Scarcruft malware - February 2018"
      author = "Florian Roth"
      reference = "https://twitter.com/craiu/status/959477129795731458"
      date = "2018-02-03 12:39:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, G0067, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "d:\\HighSchool\\version 13\\2ndBD\\T+M\\" ascii
      $x2 = "cmd.exe /C ping 0.1.1.2" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule WannCry_BAT_RID2B09 : CRIME DEMO FILE MAL RANSOM T1136 {
   meta:
      description = "Detects WannaCry Ransomware BATCH File"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12 08:49:21"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "CRIME, DEMO, FILE, MAL, RANSOM, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "@.exe\">> m.vbs" ascii
      $s2 = "cscript.exe //nologo m.vbs" fullword ascii
      $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
      $s4 = "echo om.Save>> m.vbs" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6540 and filesize < 1KB and 1 of them )
}

rule RottenPotato_Potato_RID2EDA : DEMO EXE FILE HKTL T1053 T1068 T1134 T1136 {
   meta:
      description = "Detects a component of privilege escalation tool Rotten Potato - file Potato.exe"
      author = "Florian Roth"
      reference = "https://github.com/foxglovesec/RottenPotato"
      date = "2017-02-07 11:32:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "DEMO, EXE, FILE, HKTL, T1053, T1068, T1134, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "Potato.exe -ip <ip>" fullword wide
      $x2 = "-enable_httpserver true -enable_spoof true" fullword wide
      $x3 = "/C schtasks.exe /Create /TN omg /TR" fullword wide
      $x4 = "-enable_token true -enable_dce true" fullword wide
      $x5 = "DNS lookup succeeds - UDP Exhaustion failed!" fullword wide
      $x6 = "DNS lookup fails - UDP Exhaustion worked!" fullword wide
      $x7 = "\\obj\\Release\\Potato.pdb" fullword ascii
      $x8 = "function FindProxyForURL(url,host){if (dnsDomainIs(host, \"localhost\")) return \"DIRECT\";" fullword wide
      $s1 = "\"C:\\Windows\\System32\\cmd.exe\" /K start" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of ( $x* ) ) or ( 2 of them )
}

rule APT_Stuxnet_Malware_4_RID2F0B : APT DEMO EXE FILE MAL T1136 {
   meta:
      description = "Stuxnet Sample"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-07-09 11:40:21"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, MAL, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
      $x2 = "MRxCls.sys" fullword wide
      $x3 = "MRXNET.Sys" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 1 of them ) or ( all of them )
}

rule IronGate_APT_Step7ProSim_Gen_RID3173 : APT DEMO EXE FILE GEN MAL T1136 {
   meta:
      description = "Detects IronGate APT Malware - Step7ProSim DLL"
      author = "Florian Roth"
      reference = "https://goo.gl/Mr6M2J"
      date = "2016-06-04 13:23:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, GEN, MAL, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\obj\\Release\\Step7ProSim.pdb" ascii
      $s1 = "Step7ProSim.Interfaces" fullword ascii
      $s2 = "payloadExecutionTimeInMilliSeconds" fullword ascii
      $s3 = "PackagingModule.Step7ProSim.dll" fullword wide
      $s4 = "<KillProcess>b__0" fullword ascii
      $s5 = "newDllFilename" fullword ascii
      $s6 = "PackagingModule.exe" fullword wide
      $s7 = "$863d8af0-cee6-4676-96ad-13e8540f4d47" fullword ascii
      $s8 = "RunPlcSim" fullword ascii
      $s9 = "$ccc64bc5-ef95-4217-adc4-5bf0d448c272" fullword ascii
      $s10 = "InstallProxy" fullword ascii
      $s11 = "DllProxyInstaller" fullword ascii
      $s12 = "FindFileInDrive" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and ( $x1 or 3 of ( $s* ) ) ) or ( 6 of them )
}

rule ONHAT_Proxy_Hacktool_RID2EA0 : APT CHINA DEMO EXE FILE HKTL T1020 T1090 T1136 {
   meta:
      description = "Detects ONHAT Proxy - Htran like SOCKS hack tool used by Chinese APT groups"
      author = "Florian Roth"
      reference = "https://goo.gl/p32Ozf"
      date = "2016-05-12 11:22:31"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, CHINA, DEMO, EXE, FILE, HKTL, T1020, T1090, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "INVALID PARAMETERS. TYPE ONHAT.EXE -h FOR HELP INFORMATION." fullword ascii
      $s2 = "[ONHAT] LISTENS (S, %d.%d.%d.%d, %d) ERROR." fullword ascii
      $s3 = "[ONHAT] CONNECTS (T, %d.%d.%d.%d, %d.%d.%d.%d, %d) ERROR." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and ( 1 of ( $s* ) ) ) or ( 2 of them )
}

rule BeepService_Hacktool_RID2EF2 : APT CHINA DEMO EXE FILE HKTL T1035 T1077 T1136 {
   meta:
      description = "Detects BeepService Hacktool used by Chinese APT groups"
      author = "Florian Roth"
      reference = "https://goo.gl/p32Ozf"
      date = "2016-05-12 11:36:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, CHINA, DEMO, EXE, FILE, HKTL, T1035, T1077, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\\\%s\\admin$\\system32\\%s" fullword ascii
      $s1 = "123.exe" fullword ascii
      $s2 = "regclean.exe" fullword ascii
      $s3 = "192.168.88.69" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and $x1 and 1 of ( $s* )
}

rule PoisonIvy_RAT_ssMUIDLL_RID2F13 : APT DEMO EXE FILE MAL T1136 {
   meta:
      description = "Detects PoisonIvy RAT DLL mentioned in Palo Alto Blog in April 2016"
      author = "Florian Roth"
      reference = "http://goo.gl/WiwtYT"
      date = "2016-04-22 11:41:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, MAL, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "ssMUIDLL.dll" fullword ascii
      $op1 = { 6a 00 c6 07 e9 ff d6 } 
      $op2 = { 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 } 
      $op3 = { 6a 00 88 7f 02 ff d6 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and ( all of ( $op* ) ) ) or ( all of them )
}

rule Nanocore_RAT_Gen_2_RID2D96 : APT DEMO EXE FILE GEN MAL T1136 {
   meta:
      description = "Detetcs the Nanocore RAT"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22 10:38:11"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, GEN, MAL, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "NanoCore.ClientPluginHost" fullword ascii
      $x2 = "IClientNetworkHost" fullword ascii
      $x3 = "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them ) or ( all of them )
}

rule PSAttack_ZIP_RID2B5E : DEMO FILE HKTL T1086 T1136 {
   meta:
      description = "PSAttack - Powershell attack tool - file PSAttack.zip"
      author = "Florian Roth"
      reference = "https://github.com/gdssecurity/PSAttack/releases/"
      date = "2016-03-09 09:03:31"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "DEMO, FILE, HKTL, T1086, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "PSAttack.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and all of them
}

rule PSAttack_EXE_RID2B4D : DEMO EXE FILE HKTL T1086 T1136 {
   meta:
      description = "PSAttack - Powershell attack tool - file PSAttack.exe"
      author = "Florian Roth"
      reference = "https://github.com/gdssecurity/PSAttack/releases/"
      date = "2016-03-09 09:00:41"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "DEMO, EXE, FILE, HKTL, T1086, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\Release\\PSAttack.pdb" fullword
      $s1 = "set-executionpolicy bypass -Scope process -Force" fullword wide
      $s2 = "PSAttack.Modules." ascii
      $s3 = "PSAttack.PSAttackProcessing" fullword ascii
      $s4 = "PSAttack.Modules.key.txt" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and ( $x1 or 2 of ( $s* ) ) ) or 3 of them
}

rule Sofacy_CollectorStealer_Gen2_RID31F7 : APT DEMO EXE FILE G0007 GEN RUSSIA T1136 {
   meta:
      description = "File collectors / USB stealers - Generic"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
      date = "2015-12-04 13:45:01"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, G0007, GEN, RUSSIA, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "msdetltemp.dll" fullword ascii
      $s2 = "msdeltemp.dll" fullword wide
      $s3 = "Delete Temp Folder Service" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Sofacy_CollectorStealer_Gen3_RID31F8 : APT DEMO EXE FILE G0007 GEN RUSSIA T1136 {
   meta:
      description = "File collectors / USB stealers - Generic"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
      date = "2015-12-04 13:45:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, G0007, GEN, RUSSIA, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "NvCpld.dll" fullword ascii
      $s4 = "NvStart" fullword ascii
      $s5 = "NvStop" fullword ascii
      $a1 = "%.4d%.2d%.2d%.2d%.2d%.2d%.2d%.4d" fullword wide
      $a2 = "IGFSRVC.dll" fullword wide
      $a3 = "Common User Interface" fullword wide
      $a4 = "igfsrvc Module" fullword wide
      $b1 = " Operating System                        " fullword wide
      $b2 = "Microsoft Corporation                                       " fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and ( all of ( $s* ) and ( all of ( $a* ) or all of ( $b* ) ) )
}

rule CheshireCat_Sample2_RID2E47 : APT DEMO EXE FILE T1136 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
      date = "2015-08-08 11:07:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "mpgvwr32.dll" fullword ascii
      $s1 = "Unexpected failure of wait! (%d)" fullword ascii
      $s2 = "\"%s\" /e%d /p%s" fullword ascii
      $s4 = "error in params!" fullword ascii
      $s5 = "sscanf" fullword ascii
      $s6 = "<>Param : 0x%x" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 4 of ( $s* )
}

rule CheshireCat_Gen2_RID2CFF : APT DEMO EXE FILE T1136 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
      date = "2015-08-08 10:13:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, T1136"
      minimum_yara = "1.7"
      
   strings:
      $a1 = "Interface\\%s\\info" fullword ascii
      $a2 = "Interface\\%s\\info\\%s" fullword ascii
      $a3 = "CLSID\\%s\\info\\%s" fullword ascii
      $a4 = "CLSID\\%s\\info" fullword ascii
      $b1 = "Windows Shell Icon Handler" fullword wide
      $b2 = "Microsoft Shell Icon Handler" fullword wide
      $s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
      $s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
      $s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
      $s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
      $s5 = "%sMutex" fullword ascii
      $s6 = "\\ShellIconCache" fullword ascii
      $s7 = "+6Service Pack " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 7 of ( $s* ) and 2 of ( $a* ) and 1 of ( $b* )
}

rule HttpBrowser_RAT_Gen_RID2E54 : APT DEMO EXE FILE GEN MAL T1038 T1136 {
   meta:
      description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
      author = "Florian Roth"
      reference = "http://snip.ly/giNB"
      date = "2015-08-06 11:09:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, EXE, FILE, GEN, MAL, T1038, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide
      $s1 = "HttpBrowser/1.0" fullword wide
      $s2 = "set cmd : %s" ascii fullword
      $s3 = "\\config.ini" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}

rule APT30_Generic_B_RID2C16 : APT DEMO FILE G0013 GEN T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, GEN, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "Moziea/4.0" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_H_RID2C1C : APT DEMO FILE G0013 GEN T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, GEN, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\\Temp1020.txt" fullword ascii
      $s1 = "Xmd.Txe" fullword ascii
      $s2 = "\\Internet Exp1orer" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_2_RID2BAB : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "ForZRLnkWordDlg.EXE" fullword wide
      $s1 = "ForZRLnkWordDlg Microsoft " fullword wide
      $s9 = "ForZRLnkWordDlg 1.0 " fullword wide
      $s11 = "ForZRLnkWordDlg" fullword wide
      $s12 = " (C) 2011" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_3_RID2BAC : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "Software\\Mic" ascii
      $s6 = "HHOSTR" ascii
      $s9 = "ThEugh" fullword ascii
      $s10 = "Moziea/" ascii
      $s12 = "%s%s(X-" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_9_RID2BB2 : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:17:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\\Windo" ascii
      $s2 = "oHHOSTR" ascii
      $s3 = "Softwa]\\Mic" ascii
      $s4 = "Startup'T" ascii
      $s6 = "Ora\\%^" ascii
      $s7 = "\\Ohttp=r" ascii
      $s17 = "help32Snapshot0L" ascii
      $s18 = "TimUmoveH" ascii
      $s20 = "WideChc[lobalAl" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_16_RID2BE0 : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\\Temp1020.txt" fullword ascii
      $s1 = "cmcbqyjs" fullword ascii
      $s2 = "SPVSWh\\" fullword ascii
      $s4 = "PSShxw@" fullword ascii
      $s5 = "VWhHw@" fullword ascii
      $s7 = "SVWhHw@" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_18_RID2BE2 : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:31"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "w.km-nyc.com" fullword ascii
      $s1 = "tscv.exe" fullword ascii
      $s2 = "Exit/app.htm" ascii
      $s3 = "UBD:\\D" ascii
      $s4 = "LastError" ascii
      $s5 = "MicrosoftHaveAck" ascii
      $s7 = "HHOSTR" ascii
      $s20 = "XPL0RE." ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_20_RID2BDB : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:21"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "dizhi.gif" fullword ascii
      $s2 = "Mozilla/u" ascii
      $s3 = "XicrosoftHaveAck" ascii
      $s4 = "flyeagles" ascii
      $s10 = "iexplore." ascii
      $s13 = "WindowsGV" fullword ascii
      $s16 = "CatePipe" fullword ascii
      $s17 = "'QWERTY:/webpage3" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_F_RID2C1A : APT DEMO FILE G0013 GEN T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:51"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, GEN, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\\~zlzl.exe" fullword ascii
      $s2 = "\\Internet Exp1orer" fullword ascii
      $s3 = "NodAndKabIsExcellent" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_24_RID2BDF : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:01"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "dizhi.gif" fullword ascii
      $s3 = "Mozilla/4.0" fullword ascii
      $s4 = "lyeagles" fullword ascii
      $s6 = "HHOSTR" ascii
      $s7 = "#MicrosoftHaveAck7" ascii
      $s8 = "iexplore." fullword ascii
      $s17 = "ModuleH" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_27_RID2BE2 : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:31"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Mozilla/4.0" fullword ascii
      $s1 = "dizhi.gif" fullword ascii
      $s5 = "oftHaveAck+" ascii
      $s10 = "HlobalAl" fullword ascii
      $s13 = "$NtRND1$" fullword ascii
      $s14 = "_NStartup" fullword ascii
      $s16 = "GXSYSTEM" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_28_RID2BE3 : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:41"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "www.flyeagles.com" fullword ascii
      $s1 = "iexplore.exe" fullword ascii
      $s2 = "www.km-nyc.com" fullword ascii
      $s3 = "cmdLine.exe" fullword ascii
      $s4 = "Software\\Microsoft\\CurrentNetInf" fullword ascii
      $s5 = "/dizhi.gif" ascii
      $s6 = "/connect.gif" ascii
      $s7 = "USBTest.sys" fullword ascii
      $s8 = "/ver.htm" fullword ascii
      $s11 = "\\netscv.exe" fullword ascii
      $s12 = "/app.htm" fullword ascii
      $s13 = "\\netsvc.exe" fullword ascii
      $s14 = "/exe.htm" fullword ascii
      $s18 = "MicrosoftHaveAck" fullword ascii
      $s19 = "MicrosoftHaveExit" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and 7 of them
}

rule APT30_Sample_34_RID2BE0 : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:11"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "dizhi.gif" ascii
      $s1 = "eagles.vip.nse" ascii
      $s4 = "o%S:S0" ascii
      $s5 = "la/4.0" ascii
      $s6 = "s#!<4!2>s02==<'s1" ascii
      $s7 = "HlobalAl" ascii
      $s9 = "vcMicrosoftHaveAck7" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_35_RID2BE1 : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:21"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "WhBoyIEXPLORE.EXE.exe" fullword ascii
      $s5 = "Startup>A" fullword ascii
      $s18 = "olhelp32Snapshot" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_1_RID2BAA : APT DEMO FILE G0013 T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:11"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "#hostid" fullword ascii
      $s1 = "\\Windows\\C" ascii
      $s5 = "TimUmove" fullword ascii
      $s6 = "Moziea/4.0 (c" fullword ascii
      $s7 = "StartupNA" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_4_RID2C08 : APT DEMO FILE G0013 GEN T1136 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:31:51"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, FILE, G0013, GEN, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "del NetEagle_Scout.bat" fullword
      $s1 = "NetEagle_Scout.bat" fullword
      $s2 = "\\visit.exe" fullword
      $s3 = "\\System.exe" fullword
      $s4 = "\\System.dat" fullword
      $s5 = "\\ieupdate.exe" fullword
      $s6 = "GOTO ERROR" fullword
      $s7 = ":ERROR" fullword
      $s9 = "IF EXIST " fullword
      $s10 = "ioiocn" fullword
      $s11 = "SetFileAttribute" fullword
      $s12 = "le_0*^il" fullword
      $s13 = "le_.*^il" fullword
      $s14 = "le_-*^il" fullword
   condition: 
      filesize < 250KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule WoolenGoldfish_Generic_2_RID3062 : APT DEMO GEN T1136 {
   meta:
      description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
      author = "Florian Roth"
      reference = "http://goo.gl/NpJpVZ"
      date = "2015-03-25 12:37:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, GEN, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii
   condition: 
      all of them
}

rule WoolenGoldfish_Generic_1_RID3061 : APT DEMO GEN T1136 {
   meta:
      description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
      author = "Florian Roth"
      reference = "http://goo.gl/NpJpVZ"
      date = "2015-03-25 12:37:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, DEMO, GEN, T1136"
      minimum_yara = "1.7"
      
   strings:
      $x0 = "Users\\Wool3n.H4t\\" 
      $x1 = "C-CPP\\CWoolger" 
      $x2 = "NTSuser.exe" fullword wide
      $s1 = "107.6.181.116" fullword wide
      $s2 = "oShellLink.Hotkey = \"CTRL+SHIFT+F\"" fullword
      $s3 = "set WshShell = WScript.CreateObject(\"WScript.Shell\")" fullword
      $s4 = "oShellLink.IconLocation = \"notepad.exe, 0\"" fullword
      $s5 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" fullword
      $s6 = "wlg.dat" fullword
      $s7 = "woolger" fullword wide
      $s8 = "[Enter]" fullword
      $s9 = "[Control]" fullword
   condition: 
      ( 1 of ( $x* ) and 2 of ( $s* ) ) or ( 6 of ( $s* ) )
}

rule DeepPanda_htran_exe_RID2E90 : APT CHINA DEMO G0009 T1020 T1090 T1136 {
   meta:
      description = "Hack Deep Panda - htran-exe"
      author = "Florian Roth"
      reference = "-"
      date = "2015-02-08 11:19:51"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      tags = "APT, CHINA, DEMO, G0009, T1020, T1090, T1136"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
      $s2 = "\\Release\\htran.pdb" ascii
      $s3 = "[SERVER]connection to %s:%d error" fullword ascii
      $s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $s8 = "======================== htran V%s =======================" fullword ascii
      $s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $s15 = "[+] OK! I Closed The Two Socket." fullword ascii
      $s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
   condition: 
      1 of them
}