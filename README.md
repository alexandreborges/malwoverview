# Malwoverview

[<img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/alexandreborges/malwoverview?color=red&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases/tag/5.3) [<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/alexandreborges/malwoverview?color=Yellow&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases) [<img alt="GitHub Release Date" src="https://img.shields.io/github/release-date/alexandreborges/malwoverview?label=Release%20Date&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases) [<img alt="GitHub" src="https://img.shields.io/github/license/alexandreborges/malwoverview?style=for-the-badge">](https://github.com/alexandreborges/malwoverview/blob/master/LICENSE) 
[<img alt="GitHub stars" src="https://img.shields.io/github/stars/alexandreborges/malwoverview?logoColor=Red&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/stargazers) [<img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/ale_sp_brazil?color=blueviolet&style=for-the-badge">](https://twitter.com/ale_sp_brazil)
[<img alt="PayPal" src="https://img.shields.io/badge/Donate-Paypal-brightgreen?style=for-the-badge&logo=appveyor">](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=M8F458EZH8UZE&source=url)
[<img alt="Downloads/Month" src="https://img.shields.io/pypi/dm/malwoverview?color=yellow&style=for-the-badge">](https://pypistats.org/packages/malwoverview)
[<img alt="Downloads/Total" src="https://static.pepy.tech/personalized-badge/malwoverview?period=total&units=international_system&left_color=grey&right_color=red&left_text=Total%20Downloads">](https://pepy.tech/project/malwoverview)

![Alt text](pictures/picture_1.jpg?raw=true "Title")
![Alt text](pictures/picture_2.jpg?raw=true "Title")
![Alt text](pictures/picture_3.jpg?raw=true "Title")
![Alt text](pictures/picture_4.jpg?raw=true "Title")
![Alt text](pictures/picture_5.jpg?raw=true "Title")
![Alt text](pictures/picture_6.jpg?raw=true "Title")
![Alt text](pictures/picture_7.jpg?raw=true "Title")
![Alt text](pictures/picture_8.jpg?raw=true "Title")
![Alt text](pictures/picture_9.jpg?raw=true "Title")
![Alt text](pictures/picture_10.jpg?raw=true "Title")
![Alt text](pictures/picture_11.jpg?raw=true "Title")
![Alt text](pictures/picture_12.jpg?raw=true "Title")
![Alt text](pictures/picture_13.jpg?raw=true "Title")
![Alt text](pictures/picture_14.jpg?raw=true "Title")
![Alt text](pictures/picture_15.jpg?raw=true "Title")
![Alt text](pictures/picture_16.jpg?raw=true "Title")
![Alt text](pictures/picture_17.jpg?raw=true "Title")
![Alt text](pictures/picture_18.jpg?raw=true "Title")
![Alt text](pictures/picture_19.jpg?raw=true "Title")
![Alt text](pictures/picture_20.jpg?raw=true "Title")
![Alt text](pictures/picture_21.jpg?raw=true "Title")
![Alt text](pictures/picture_22.jpg?raw=true "Title")
![Alt text](pictures/picture_23.jpg?raw=true "Title")
![Alt text](pictures/picture_24.jpg?raw=true "Title")
![Alt text](pictures/picture_25.jpg?raw=true "Title")
![Alt text](pictures/picture_26.jpg?raw=true "Title")
![Alt text](pictures/picture_27.jpg?raw=true "Title")
![Alt text](pictures/picture_28.jpg?raw=true "Title")
![Alt text](pictures/picture_29.jpg?raw=true "Title")
![Alt text](pictures/picture_30.jpg?raw=true "Title")
![Alt text](pictures/picture_31.jpg?raw=true "Title")
![Alt text](pictures/picture_32.jpg?raw=true "Title")
![Alt text](pictures/picture_33.jpg?raw=true "Title")
![Alt text](pictures/picture_34.jpg?raw=true "Title")
![Alt text](pictures/picture_35.jpg?raw=true "Title")
![Alt text](pictures/picture_36.jpg?raw=true "Title")
![Alt text](pictures/picture_37.jpg?raw=true "Title")
![Alt text](pictures/picture_38.jpg?raw=true "Title")
![Alt text](pictures/picture_39.jpg?raw=true "Title")
![Alt text](pictures/picture_40.jpg?raw=true "Title")
![Alt text](pictures/picture_41.jpg?raw=true "Title")
![Alt text](pictures/picture_42.jpg?raw=true "Title")
![Alt text](pictures/picture_43.jpg?raw=true "Title")
![Alt text](pictures/picture_44.jpg?raw=true "Title")
![Alt text](pictures/picture_45.jpg?raw=true "Title")
![Alt text](pictures/picture_46.jpg?raw=true "Title")
![Alt text](pictures/picture_47.jpg?raw=true "Title")
![Alt text](pictures/picture_48.jpg?raw=true "Title")

      Copyright (C)  2018-2023 Alexandre Borges <alexandreborges at blackstormsecurity dot com>

      This program is free software: you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published by
      the Free Software Foundation, either version 3 of the License, or
      (at your option) any later version.

      This program is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      GNU General Public License for more details.

      See GNU Public License on <http://www.gnu.org/licenses/>.


# Current Version: 5.3

     Important note:  Malwoverview does NOT submit samples to any endpoint by default, 
     so it respects possible Non-Disclosure Agreements (NDAs). There're specific options
     that explicitly submit samples, but these options are explained in the help.


# ABOUT

Malwoverview.py is a first response tool for threat hunting, which performs an initial and quick 
triage of malware samples, URLs, IP addresses, domains, malware families, IOCs and hashes. Additionally,
Malwoverview is able to get dynamic and static behavior reports, submit and download samples
from several endpoints. In few words, it works as a client to main existing sandboxes. 

This tool aims to : 

1. Determine similar executable malware samples (PE/PE+) according to the import table (imphash) and group 
   them by different colors (pay attention to the second column from output). Thus, colors matter!
2. Show hash information on Virus Total, Hybrid Analysis, Malshare, Polyswarm, URLhaus, Alien Vault, 
   Malpedia and ThreatCrowd engines. 
3. Determining whether the malware samples contain overlay and, if you want, extract it. 
4. Check suspect files on Virus Total, Hybrid Analysis and Polyswarm.
5. Check URLs on Virus Total, Malshare, Polyswarm, URLhaus engines and Alien Vault. 
6. Download malware samples from Hybrid Analysis, Malshare, URLHaus, Polyswarm and Malpedia engines.
7. Submit malware samples to VirusTotal, Hybrid Analysis and Polyswarm.
8. List last suspected URLs from URLHaus.
9. List last payloads from URLHaus. 
10. Search for specific payloads on the Malshare.
11. Search for similar payloads (PE32/PE32+) on Polyswarm engine.
12. Classify all files in a directory searching information on Virus Total and Hybrid Analysis. 
13. Make reports about a suspect domain using different engines such as VirusTotal, Malpedia and 
    ThreatCrowd. 
14. Check APK packages directly from Android devices against Hybrid Analysis and Virus Total. 
15. Submit APK packages directly from Android devices to Hybrid Analysis and Virus Total. 
16. Show URLs related to an user provided tag from URLHaus.
17. Show payloads related to a tag (signature) from URLHaus.
18. Show information about an IP address from Virus Total, Alien Vault, Malpedia and ThreatCrowd.
19. Show IP address, domain and URL information from Polyswarm. 
21. Perform meta-search on Polyswarm Network using several criteria: imphash, IPv4, domain, URL and
    malware family. 
22. Gather threat hunting information from AlienVault using different criteria. 
23. Gather threat hunting information from Malpedia using different criteria. 
24. Gather threat hunting information from Malware Bazaar using different criteria. 
25. Gather IOC information from ThreatFox using different criteria. 
26. Gather threat hunting information from Triage using different criteria. 
27. Get evaluation to hashes from a given file against Virus Total. 
28. Submit large files (>= 32 MB) to Virus Total. 
29. Malwoverview uses Virus Total API v.3, so there isn't longer any option using v.2.
30. Retrieve different information from InQuest Labs and download samples from there. 


# CONTRIBUTORS:

      Alexandre Borges (project owner)
      Corey Forman (https://github.com/digitalsleuth)
      Christian Clauss (https://github.com/cclauss)

# INSTALLATION 

This tool has been tested on REMnux, Ubuntu, Kali Linux, macOS and Windows. Malwoverview 
can be installed by executing the following command:

      * pip3.11 install git+https://github.com/alexandreborges/malwoverview (preferred method) 
      
      or...
      
      * python -m pip install -U malwoverview
      
      or...
      
      * git clone https://github.com/alexandreborges/malwoverview

If you are installing Malwoverview on  macOS, you must execute the following commands:

      * /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
      * brew install libmagic
      * pip install urllib3==1.26.6
      * pip3 install -U malwoverview
      * Add Python binary directory to the PATH variable by editing .bash_profile file in your home 
        directory. Example:

          export PATH=$PATH:/Users/alexandreborges/Library/Python/3.9/bin

      * Execute: . ./.bash_profile

If you are installing Malwoverview on Windows, you must execute the following commands AFTER 
installing Malwoverview:

      * python -m pip uninstall python-magic
      * python -m pip install python-magic-bin 

To use Malwoverview you should insert VirusTotal, Hybrid Analysis, URLHaus, Malshare, Polyswarm,
Alien Vault, Malpedia  and Triage into the .malwapi.conf configuration file 
(the default one at the home directory (/home/[username] or /root) -- if the file doesn't exist,
so you should create it) or you could create a custom configuration file and indicate it by 
using the -c option.

Nonetheless, starting on version 4.4.2, it isn't longer necessary to insert all APIs into .malwapi.conf
before using Malwoverview. Therefore, users can only insert few APIs and use the respective options 
to these APIs.

* A special note about the Alien Vault: it is necessary to subscribe to pulses on Alien Vault 
website before using -n 1 option.

The .malwapi.conf configuration file (from the the home directory -- /home/[username] or /root) 
has the following format:

      [VIRUSTOTAL]
      VTAPI = 

      [HYBRID-ANALYSIS]
      HAAPI = 

      [MALSHARE]
      MALSHAREAPI = 

      [HAUSSUBMIT]
      HAUSSUBMITAPI =

      [POLYSWARM]
      POLYAPI = 

      [ALIENVAULT]
      ALIENAPI = 

      [MALPEDIA]
      MALPEDIAAPI =

      [TRIAGE]
      TRIAGEAPI =

      [INQUEST]
      INQUESTAPI =


The APIs can be requested on the respective service websites:

01. Virus Total (community and paid API): https://www.virustotal.com/gui/join-us
02. Hybrid Analysis: https://www.hybrid-analysis.com/signup
03. Malshare: https://malshare.com/doc.php
04. URLHaus: https://urlhaus.abuse.ch/api/#account 
05. Polyswarm: https://docs.polyswarm.io/consumers
06. Alien Vault: https://otx.alienvault.com/api
07. Malpedia: It doesn't offer open registration, but you can request an user account 
    directly through Twitter (DM) or feedback e-email. The Malpedia Twitter 
    handle is @malpedia.
08. Malware Bazaar: It isn't necessary an API.
09. ThreatFox: It isn't necessary an API.
10. InQuest: https://labs.inquest.net/.
11. Triage: https://tria.ge/signup.
 
----------------------------------------------------
A special note about API requests to the MALPEDIA:
----------------------------------------------------

The service and acceptance is based on the community vetting. Thus, it's recommended 
you send a request for an API from your business e-mail address and NOT 
public/free one (Gmail, Outlook and so on). Additionally, it'd be great whether 
you provided further information about you (LinkedIn account, Twitter and so on) 
because it would make simpler to proof your identity, professional profile and 
legitimacy, so making quicker the approval of your request.  

-----------------------------------------------------

----------------------------------------------------
Additional explanation about Triage:
----------------------------------------------------

Every Triage operation is based on the Triage ID of each artifact, so you need to
use the "-x 1 -X \<attribute\>:\<value\>" to look for the correct ID of the artifact,
so use this ID information with the remaining Triage options (-x [2-7]) for getting 
further threat hunting information from Triage endpoint.

-----------------------------------------------------

----------------------------------------------------
Note about background color of the terminal:
----------------------------------------------------

Malwoverview has been written to produce outputs to 
dark background terminal. However, there's the -o 0 
option, which changes and adapts output's colors to 
light background.

-----------------------------------------------------

On Linux and MacOS systems, create the .malwapi.conf file within
/home/\[username\] directory (Linux home user directory -- /home/[username] or /root).

To check the installation, execute:

       malwoverview.py --help
       
Further information is available on: 

       (PYPI.org repository) https://pypi.org/project/malwoverview/
       (Github) https://github.com/alexandreborges/malwoverview

If you want to perform the manual steps (usually, it is not necessary), so few steps 
should be executed:

## REMnux / Ubuntu (manual steps)

1. Python version 3.8 or later (Only Python 3.x !!! It does NOT work using Python 2.7) 

       $ apt-get install python3.11  (for example)

2. Python-magic.  

      To install python-magic package you can execute the following command:

       $ pip3.11 install python-magic

      Or compiling it from the github repository:

       $ git clone https://github.com/ahupp/python-magic
       $ cd python-magic/
       $ python3.11 setup.py build
       $ python3.11 setup.py install

      As there are serious problems about existing two versions of python-magic package, my 
      recommendation is to install it from github (second procedure above) and copy the magic.py 
      file to the SAME directory of malwoverview tool. 
      
3. Install several Python packages: 

       $ pip3.11 install -r requirements.txt

       OR

       $ pip3.11 install -U pefile
       $ pip3.11 install -U colorama
       $ pip3.11 install -U simplejson
       $ pip3.11 install -U python-magic
       $ pip3.11 install -U requests
       $ pip3.11 install -U validators
       $ pip3.11 install -U geocoder
       $ pip3.11 install -U polyswarm-api
       $ pip3.11 install -U pathlib
       $ pip3.11 install -U configparser

4. To check an Android mobile you need to install the "adb" program by executing the following command:

       # apt get install adb

   PS: before trying Android's options, check:

       * If the adb program is listed in the PATH environment variable.
       * If the system has authorized access to the device by using "adb devices -l"


## Examples:

    malwoverview.py -d /home/remnux/malware/windows_2/
    malwoverview.py -v 1 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
    malwoverview.py -v 2 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
    malwoverview.py -v 3 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
    malwoverview.py -v 4 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe,
    malwoverview.py -v 5 -V http://jamogames.com/templates/JLHk/
    malwoverview.py -v 6 -V 185.220.100.243
    malwoverview.py -v 7 -V xurl.es
    malwoverview.py -v 8 -V ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585
    malwoverview.py -v 9 -V cc2d791b16063a302e1ebd35c0e84e6cf6519e90bb710c958ac4e4ddceca68f7.exe
    malwoverview.py -v 10 -V /home/remnux/malware/hash_list_3.txt
    malwoverview.py -v 11 -V /home/remnux/malware/hash_list_3.txt
    malwoverview.py -v 12 -V 9d26e19b8fc5819b634397d48183637bacc9e1c62d8b1856b8116141cb8b4000
    malwoverview.py -v 13 -V /largefiles/4b3b46558cffe1c0b651f09c719af2779af3e4e0e43da060468467d8df445e93
    malwoverview.py -a 1 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8
    malwoverview.py -a 1 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8.exe
    malwoverview.py -a 2 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8
    malwoverview.py -a 3 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8
    malwoverview.py -a 4 -A malware1.apk
    malwoverview.py -a 4 -A 82eb6039cdda6598dc23084768e18495d5ebf3bc3137990280bc0d9351a483eb
    malwoverview.py -a 5 -A 2b03806939d1171f063ba8d14c3b10622edb5732e4f78dc4fe3eac98b56e5d46
    malwoverview.py -a 5 -A 2b03806939d1171f063ba8d14c3b10622edb5732e4f78dc4fe3eac98b56e5d46.elf
    malwoverview.py -a 6 -A 47eccaaa672667a9cea23e24fd702f7b3a45cbf8585403586be474585fd80243.exe
    malwoverview.py -a 7 -A 47eccaaa672667a9cea23e24fd702f7b3a45cbf8585403586be474585fd80243.exe
    malwoverview.py -a 8 -A 47eccaaa672667a9cea23e24fd702f7b3a45cbf8585403586be474585fd80243.exe
    malwoverview.py -a 9 -A malware_7.apk
    malwoverview.py -a 10 -A 925f649617743f0640bdfff4b6b664b9e12761b0e24bbb99ca72740545087ad2.elf
    malwoverview.py -a 11 -A cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
    malwoverview.py -a 12 -A cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
    malwoverview.py -a 13 -A cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
    malwoverview.py -a 14 -A d90a5552fd4ef88a8b621dd3642e3be8e52115a67e6b17b13bdff461d81cf5a8
    malwoverview.py -a 15 -A 925f649617743f0640bdfff4b6b664b9e12761b0e24bbb99ca72740545087ad2
    malwoverview.py -l 1 -L d3dcc08c9b955cd3f68c198e11d5788869d1b159dc8014d6eaa39e6c258123b0
    malwoverview.py -l 2
    malwoverview.py -l 3
    malwoverview.py -l 4
    malwoverview.py -l 5
    malwoverview.py -l 6
    malwoverview.py -j 1 -J 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6
    malwoverview.py -j 2 -J 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6
    malwoverview.py -j 3 -J https://unada.us/acme-challenge/3NXwcYNCa/
    malwoverview.py -j 4 -J Qakbot
    malwoverview.py -j 5 -J Emotet
    malwoverview.py -j 5 -J Icedid
    malwoverview.py -j 6
    malwoverview.py -j 7
    malwoverview.py -p 1 -P 1999ba265cd51c94e8ae3a6038b3775bf9a49d6fe57d75dbf1726921af8a7ab2
    malwoverview.py -p 2 -P 301524c3f959d2d6db9dffdf267ab16a706d3286c0b912f7dda5eb42b6d89996.exe
    malwoverview.py -p 3 -P 68c11ef39769674123066bcd52e1d687502eb6c4c0788b4f682e8d31c15e5306
    malwoverview.py -p 4 -P 68c11ef39769674123066bcd52e1d687502eb6c4c0788b4f682e8d31c15e5306.exe
    malwoverview.py -p 5 -P 188.40.75.132
    malwoverview.py -p 6 -P covid19tracer.ca
    malwoverview.py -p 7 -P http://ksahosting.net/wp-includes/utf8.php
    malwoverview.py -p 8 -P Qakbot
    malwoverview.py -y 1
    malwoverview.py -y 2
    malwoverview.py -y 3
    malwoverview.py -y 4 -Y com.spaceship.netprotect
    malwoverview.py -y 5 -Y com.mwr.dz
    malwoverview.py -v 1 -V 368afeda7af69f329e896dc86e9e4187a59d2007e0e4b47af30a1c117da0d792.apk
    malwoverview.py -n 1 -N 10
    malwoverview.py -n 2 -N 176.57.215.100
    malwoverview.py -n 3 -N threesmallhills.com
    malwoverview.py -n 4 -N 6d1756aa6b45244764409398305c460368d64ff9 -o 0
    malwoverview.py -n 5 -N http://ksahosting.net/wp-includes/utf8.php
    malwoverview.py -m 1 | more
    malwoverview.py -m 2 | more
    malwoverview.py -m 3 | more 
    malwoverview.py -m 4 -M apt41 | more
    malwoverview.py -m 5 | more 
    malwoverview.py -m 6 -M win.qakbot
    malwoverview.py -m 7 -M 3d375d0ead2b63168de86ca2649360d9dcff75b3e0ffa2cf1e50816ec92b3b7d 
    malwoverview.py -m 8 -M win.qakbot
    malwoverview.py -b 1 -B c9d7b5d06cd8ab1a01bf0c5bf41ef2a388e41b4c66b1728494f86ed255a95d48
    malwoverview.py -b 2 -B Revil | more
    malwoverview.py -b 3 -B f34d5f2d4577ed6d9ceec516c1f5a744
    malwoverview.py -b 4 -B 100 
    malwoverview.py -b 4 -B time | more
    malwoverview.py -b 5 -B bda50ff249b947617d9551c717e78131ed32bf77db9dc5b7591d3e1af6cb2f1a
    malwoverview.py -b 6 -B 3 | more
    malwoverview.py -b 7 -B 193.150.103.37:21330
    malwoverview.py -b 8 -B Magecart | more
    malwoverview.py -b 9 -B "Cobalt Strike"
    malwoverview.py -b 10 | more
    malwoverview.py -x 1 -X score:10 | more
    malwoverview.py -x 1 -X 71382e72d8fb3728dc8941798ab1c180493fa978fd7eadc1ab6d21dae0d603e2
    malwoverview.py -x 2 -X 220315-qxzrfsadfl
    malwoverview.py -x 3 -X cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
    malwoverview.py -x 4 -X http://ztechinternational.com/Img/XSD.exe
    malwoverview.py -x 5 -X 220315-xmbp7sdbel
    malwoverview.py -x 6 -X 220315-xmbp7sdbel
    malwoverview.py -x 7 -X 220315-xmbp7sdbel
    malwoverview.py -i 1 -I 5119c804448dd877e1a32d5157dc2e5ff9344cb55e053b20117c9b3b4c974389 
    malwoverview.py -i 2 -I 5119c804448dd877e1a32d5157dc2e5ff9344cb55e053b20117c9b3b4c974389
    malwoverview.py -i 3 -I 0a1b0c7a21c8929b7742db195338af5c
    malwoverview.py -i 4 -I list
    malwoverview.py -i 5 -I rebrand.ly | more
    malwoverview.py -i 6 -I 10.247.111.124 
    malwoverview.py -i 7 -I diseno@distracom.com 
    malwoverview.py -i 8 -I 20firmas-02.jpg
    malwoverview.py -i 9 -I http://diagnostic.htb 
    malwoverview.py -i 10 -I http://jaao.net 
    malwoverview.py -i 11 -I list
    malwoverview.py -i 12 -I rebrand.ly
    malwoverview.py -i 13 -I list | more


# HISTORY

Version 5.3:

      This version:

            * Fixes issues related to Malshare (-l and -L options).
            * Adds a new Malshare option (-l 7) to list all samples 
              from last 24 hours.

Version 5.2:

      This version:

            * Multiple issues related to Hybrid Analysis have been fixed.

Version 5.1.1:

      This version:

            * A formatting issue related to -v 10 option has been fixed.

Version 5.1:

      This version:

            * Introduces thirteen options related to InQuest Labs.
            * Fix an issue related to -b 6 option from ThreatFox.

Version 5.0.3:

      This version:

            * Includes the possibility of getting information from 
              Hybrid-Analysis using a SHA256 hash or the malware file.
            * Removes all options related to ThreatCrowd.
            * Fix an issue related to downloading from Malshare.
            * Includes macOS as operating system supported to run Malwoverview.

Version 5.0.2:

      This version:

            * Includes a small fix for options -v 1 and -v 8. 

Version 5.0.0:

      This version:

            * Includes upgrades of all Virus Total options from API v.2 
              to API v.3.
            * Introduces a new option to check hashes within a given
              file using Virus Total.
            * Introduces a new option to submit large files (>= 32 MB) to
              Virus Total.
            * Changes all Virus Total options.
            * Inverts Malpedia options ("m" and "M") purposes.
            * Introduces a new purpose for -D option.
            * Removes Malshare option to check a binary.
            * Removes all Valhalla options completely.
            * Changes all Malshare options.
            * Removes -g option.
            * Changes all URLhaus options.
            * Changes all Polyswarm options.
            * Removes -S and -z options.
            * Upgrades, fixes and merges Android options.
            * Updates Android options to Android 11 version.
            * Removes -t and T options.
            * Fixes and changes Hybrid Analysis options.
            * Changes -d option to Virus Total APIi v.3 with a new content.
            * Swaps options -q and -Q from Threatcrowd.
            * Fixes tag option from Triage.
            * Fixes URL formatting issues from URLhaus.
            * Removes several support functions.
            * Fixes several color issues.
            * Fixes descriptions.
            * Changes configuration, setup and requirement files.
            * Removes many option's letters used in previous versions.

Version 4.4.2:

      This version:

            * It is NOT longer necessary to insert all APIs into .malwapi.conf file 
              before using Malwoverview. For example, if you have only Virus Total
              and Hybrid Analysis APIs, so you can use their respective options 
              without needing insert the remaining ones. The same rule is valid 
              for any API and option. 

            * Small fixes have been done on the code and this README file. 

Version 4.4.1:

      This version:

            * Improves and fixes a formatting issue with cmd field 
              from option -x 2.

Version 4.4.0.2:

      This version:

            * Improves and fixes a formatting issue with cmd field 
              from option -x 7.

Version 4.4:

      This version:

            * Introduces Triage endpoint and seven associated options. 
            * Changes the overlay extraction option (previously -x) 
              to -v 4. 

Version 4.3.5:

      This version:

            * Fixes formating issues related to option -M 6 from Malpedia. 
            * Fixes formating issues related to option -W from URLHaus. 
            * Fixes formating issues related to option -k from URLHaus. 
            * Fixes working issues related to option -L from Malshare. 
            * Corrects misspelled words.

Version 4.3.4:

      This version:

            * Removes two columns from option -y 1 (Android package checking on HA) 
              to offer better formatting. 

Version 4.3.3:

      This version:

            * Fixes output formatting of option -y (Android package checking on VT and HA) 
            * Fixes issue with option -y while using -o 0. 


Version 4.3.2:

      This version:

            * Fixes output formatting of option -n 2 (Alien Vault).
            * Fixes URL output formatting of long URL when using option -I (Virus Total). 
            * Fixes option -f when using a binary without IAT (Virus Total). 
            * Fixes option -B 10, which caused a endless loop (ThreatFox). 
            * Fixes option formatting issue related to -K 2 when fetched URLs were long
              (URLHaus). 
            * Introduces "FireEye" endpoint in -v 2 output (VirusTotal). This
              addition has been suggested by @vxsh4d0w.

Version 4.3.1:

      This version:

            * Introduces a fix in the "-b 8" ThreatFox option.
            * Corrects sentences in the help's section.

Version 4.3:

      This version:

            * Introduces Malware Bazaar and ThreatFox endpoints, with 5 options for each one.
              to get the APIs.
            * Changes background option from -b to -o.
            * Fixes problems on Malpedia and URLHaus options.

Version 4.2:

      This version:

            * Fixes -L option from Malware.
            * Introduces additional instruction on README.md (this file) to help professionals
              to get the APIs.

Version 4.1:

      This version:

            * Introduces the -E and -C options for Valhalla service 
              (https://www.nextron-systems.com/valhalla/) 
            * Introduces few changes in the setup.py file (contribution from Christian 
              Clauss). 
            * Introduces a new contributor: Christian Clauss (https://github.com/cclauss) 

Version 4.0.3:

      This version:

            * Fixes the fact of Virus Total evaluation wasn't showed when the user specified "-v 2" and 
              "-v 3" options.
            * The version of the Python request package is fixed to prevent issues with Polyswarm API 2.x.

Version 4.0.2:

      This version:

            * Two small bugs (typos) in the functions for Polyswarm downloading and Android package checking
              have been fixed. 
            * An unnecessary and dead code has been removed.
            * Several typos in the README.md and in the help have been corrected. 
            * All fixes for this version have been suggested by Christian Clauss (https://github.com/cclauss)


Version 4.0.1:

      This version:

            * Fixes small typos and the README. 


Version 4.0.0:

      This version:

            * Introduces new engines such as Alien Vault, Malpedia and ThreatCrowd. 
            * The -s option has been removed. Use -v 2 option for antivirus report.
            * The -n option is not longer associated to Malshare. Use -l option with 
              values between 1 and 14.
            * To specify the hash in Malshare use the L option instead of -m option. 
            * The -i option has been removed. Use the -v 3 option for IAT/EAT. 
            * The -a option has been changed to include the system environments in Hybrid 
              Analysis. However, the -e option has been kept to be used with other options. 
            * The -M option is not longer responsible for downloading samples in Malshare. Use
              -D option for this task. 
            * The -B option for list URLs from URLHaus has been replaced by -K 2 option. 
            * The -Z and -X options (related to Android) have been replaced for -y 2 and -y 3, 
              respectively. 
            * The -D option (download a malware sample) has been extended to Polyswarm. 
            * The malware sample's DLL list has been introduced. 
            * The -R and -G options from Polyswarm have been completely fixed. Additionally, both
              ones also include the polyscore in the output. 
            * The -N option is not longer associated to Polyswarm . 
            * The -G 4 option has been introduced and it makes possible to search samples by 
              families and types such as "*Trickbot*", "*Ransomware", "*Trojan*" and so on. 
            * Colors from -I option have been fixed. 
            * The -w option has been removed. 
            * Several issues in the help have been fixed. 


Version 3.1.2:

      This version:

            * Introduces the -c option that allows the user to specify a custom API configuration file. 
            * The API configuration file has been changed to .malwapi.conf file.
            * The project structure has been changed to make easier to install it in different operating 
              systems.
            * Updates for this version are a contribution from Corey Forman (https://github.com/digitalsleuth).

Version 3.0.0:

      This version:

            * Includes fixes in the URL reporting (-u option) from Virus Total.  
            * New players have have been included in the URL reporting (-u option) from Virus Total.
            * Fixes have been included in payload listing (-K option) from URLhaus.
            * Yara information has been include in the hash report (-m option) from Malshare.
            * Fixes have been included in the -l option. 
            * New file types have been included in the -n option: Java, Zip, data, RAR, PDF, Composite (OLE),
              MS_DOS and UTF-8.
            * New -W option, which is used to show URLs related to an user provided tags from URLHaus.
            * New -k option, which is used to show payloads related to a tag from URLHaus
            * New -I option, which is used to show information related to an IP address from Virus Total.
            * The -R option was refactored and now it supports searching for file, IPv4, domain or URL on 
              Polyswarm. 

Version 2.5.0:

      This version:

            * Introduces the following options:
                  * -y to check all third-party APKs from an Android device against 
                       the Hybrid Analysis. 
                  * -Y to send a third-party APKs from an Android device to the Hybrid
                       Analysis. 
                  * -Z to check all third-party APKs from an Android device against 
                       the Virus Total. 
                  * -X to check all third-party APKs from an Android device against the
                       Virus Total (it is necessary private API). 
                  * -T to send a third-party APK from an Android device to Virus Total. 
            * Fixes several issues related to color in command outputs.  
            * Adds the filename identification in the report while sending a sample to Virus Total.

Version 2.1.9.1:

      This version:

            * Fixes several issues about colors in outputs. 
            * Removes the -L option from Malshare (unfortunately, Malshare doesn't provide an 
              URL list anymore). 
            * Removes the -c option.
            * Introduces some verification lines in the URLHaus command. 

Version 2.1:

      This version:

            * Fixes formatting issues related to Hybrid Analysis output (-Q 1 -a 1). 
            * Fixes color issues. 
            * Fixes small issues related to Polyswarm. 

Version 2.0.8.1:

      This version:

            * Introduces installation using: pip3.8 install malwoverview (Linux) or 
              python -m pip install malwoverviewwin (Windows). 
            * Fixes small problems related to Polyswarm usage. 
            * Changes the help to verify whether the APIs were inserted into configmalw.py file. 

Version 2.0.1:

      This version:

            * Fixes a problem related to searching by hash on Malshare (-m option). 
            * Fixes a problem related to searching by hash on Polyswarm (-O option). 

Version 2.0.0:

      This version:

            * Introduces a completely ported version of Malwoverview to Python 3.x (it does not work in 
              Python 2.7.x anymore!)
            * Fixes several bugs related to IAT/EAT listing. 
            * Fixes several bugs related to colors. 
            * Introduces multi-threading to some options. 
            * Introduces several options related to Malshare. 
            * Introduces several options related to URLHaus.
            * Introduces several options related to Polyswarm engine. 
            * Changes the place of the API key configuration. Now you should edit the configmalw.py file. 
            * Changes the help libraries and functions, so making the Malwoverview's help more complete. 
            * Introduces geolocation feature by using the package named Geocoder written by Dennis Carrierre.
            * Fixes problems related to Hybrid Analysis engine. 
            * Fixes several mistaked related to a mix between spaces and Tab.
            * Extends the -d option to include Hybrid Analysis. 
            
Version 1.7.5:

      This version: 

            * It has been fixed a problem related to sample submission to Hybrid Analysis on Windows operating 
              system. Additionally, file name handling has been also fixed. 
            
Version 1.7.3:

      This version: 

            * Malwoverview has been adapted to API version 2.6.0 of Hybrid Analysis.
            * -A option has been fixed according to new version (2.6.0) of Hybrid Analysis.
            * -a option has been modified to work together with  -e option.
            * help information has been modified. 
            
Version 1.7.2:

      This version: 

            * A small fix related to -g option has been included. 
            
Version 1.7.1:

      This version: 

            * Relevant fix of a problem related to options -A and -H options.
            * Includes a new Hybrid Analysis environment to the -e option (Windows 7 32-bits with HWP support).
            * Updates the Malwoverview to support Hybrid Analysis API version 2.5.0.

Version 1.7.0:

      This version: 

            * Includes -A option for submitting a sample to Hybrid Analysis.
            * Includes -g option for checking the status a submission of a sample to Hybrid Analysis.
            * Includes -e option for specifying the testing environment on the Hybrid Analysis.
            * Includes -r option for getting a complete domain report from Virus Total.
            * Modifies the -H options for working together the -e option.
            * Modifies several functions of the tool to prepare it for version 1.8.0

Version 1.6.3:

      This version: 

            * Includes creation of new functions aiming 1.7.0 version.
            * Includes new exception handling blocks.

Version 1.6.2:

      This version: 

            * Includes small fixes.
            * For the Hybrid Analysis API version 2.40 is not longer necessary to include the API Secret.  

Version 1.6.1:

      This version: 

            * Includes small format fixes.

Version 1.6.0:

      This version: 

            * It is using the Hybrid Analysis API version 2.4.0.
            * Includes certificate information in the Hybrid Analysis report. 
            * Includes MITRE information in the Hybrid Analysis report. 
            * Includes an option to download samples from Hybrid Analysis. 

Version 1.5.1:

      This version: 

            * Small change to fix format issue in -d option. 

Version 1.5.0:

      This version: 

            * Includes the -u option to check URLs against Virus Total and associated engines. 
            * Includes the -H option to find existing reports on Virus Total and Hybrid Analysis through the 
              hash.
            * Includes the -V option to submit a file to Virus Total. Additionally, the report is shown after 
              few minutes.
            * Includes two small fixes. 

Version 1.4.5.2:

      This version:

            * Includes two small fixes.

Version 1.4.5.1:

      This version:

            * Includes one small fix. 

Version 1.4.5:

      This version:

            * Adds the -w option to use malwoverview in Windows systems.
            * Improves and fixes colors when using -b option with black window.  

Version 1.4: 

      This version:

            * Adds the -a option for getting the Hybrid Analysis summary report.
            * Adds the -i option for listing imported and exported functions. Therefore, imported/exported
              function report was decoupled for a separated option.  

Version 1.3: 

      This version:

            * Adds the -p option for public Virus Total API.

Version 1.2: 

      This version includes:

            * evaluates a single file (any filetype)
            * shows PE sessions.
            * shows imported functions.
            * shows exported function.
            * extracts overlay.
            * shows AV report from the main players. (any filetype)

Version 1.1: 

      This version:

            * Adds the VT checking feature.


Version 1.0:

      Malwoverview is a tool to perform a first triage of malware samples in a directory and group them 
      according to their import functions (imphash) using colors. This version:

            * Shows the imphash information classified by color. 
            * Checks whether malware samples are packed.  
            * Checks whether malware samples have overlay. 
            * Shows the entropy of the malware samples. 


