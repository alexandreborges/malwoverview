# Malwoverview

[<img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/alexandreborges/malwoverview?color=red&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases/tag/v8.0) [<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/alexandreborges/malwoverview?color=Yellow&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases) [<img alt="GitHub Release Date" src="https://img.shields.io/github/release-date/alexandreborges/malwoverview?label=Release%20Date&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases) [<img alt="GitHub" src="https://img.shields.io/github/license/alexandreborges/malwoverview?style=for-the-badge">](https://github.com/alexandreborges/malwoverview/blob/master/LICENSE) 
[<img alt="GitHub stars" src="https://img.shields.io/github/stars/alexandreborges/malwoverview?logoColor=Red&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/stargazers)
[<img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/ale_sp_brazil?style=for-the-badge&logo=X&color=blueviolet">](https://twitter.com/ale_sp_brazil)
[![Downloads](https://static.pepy.tech/personalized-badge/malwoverview?period=month&units=international_system&left_color=grey&right_color=orange&left_text=Last%2030%20days)](https://pepy.tech/project/malwoverview)
[<img alt="Downloads/Total" src="https://static.pepy.tech/personalized-badge/malwoverview?period=total&units=international_system&left_color=grey&right_color=red&left_text=Total%20Downloads">](https://pepy.tech/project/malwoverview)
[![CodeQL](https://github.com/alexandreborges/malwoverview/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/alexandreborges/malwoverview/actions/workflows/github-code-scanning/codeql)

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

      Copyright (C)  2018-2026 Alexandre Borges (https://exploitreversing.com) 

      This program is free software: you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published by
      the Free Software Foundation, either version 3 of the License, or
      (at your option) any later version.

      This program is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      GNU General Public License for more details.

      See GNU Public License on <http://www.gnu.org/licenses/>.


## Current Version: 8.0 (Codename: Revolutions)

     Important note:  Malwoverview does NOT submit samples to any endpoint by default, 
     so it respects possible Non-Disclosure Agreements (NDAs). There're specific options
     that explicitly submit samples, but these options are explained in the help.


## ABOUT

Malwoverview.py is a first response tool for threat hunting, which performs an initial and quick 
triage of malware samples, URLs, IP addresses, domains, malware families, IOCs and hashes. Additionally,
Malwoverview is able to get dynamic and static behavior reports, submit and download samples
from several endpoints. In few words, it works as a client to main existing sandboxes. 

This tool aims to : 

01. Determine similar executable malware samples (PE/PE+) according to the import table (imphash) and group 
    them by different colors (pay attention to the second column from output). Thus, colors matter!
02. Show hash information on Virus Total, Hybrid Analysis, Malshare, Polyswarm, URLhaus, Alien Vault, 
    Malpedia and ThreatCrowd engines. 
03. Determining whether the malware samples contain overlay and, if you want, extract it. 
04. Check suspect files on Virus Total, Hybrid Analysis and Polyswarm.
05. Check URLs on Virus Total, Malshare, Polyswarm, URLhaus engines and Alien Vault. 
06. Download malware samples from Hybrid Analysis, Malshare, URLHaus, Polyswarm and Malpedia engines.
07. Submit malware samples to VirusTotal, Hybrid Analysis and Polyswarm.
08. List last suspected URLs from URLHaus.
09. List last payloads from URLHaus. 
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
30. Retrieve information about a given IP address from IPInfo service.
31. Retrieve information about a given IP address from BGPView service.
32. Retrieve combined information about a given IP address from multiple services.
33. Offer extra option to save any downloaded file to a central location.
34. List and search vulnerabilities from NIST through different criterias.
35. Query VulnCheck database - Community/Free tier.
36. Gather threat hunting information from Shodan using different criteria.
37. Check IP reputation from AbuseIPDB.
38. Check IP classification from GreyNoise (community API).
39. Perform domain and IP Whois/RDAP lookups.
40. Cross-service hash correlation across VirusTotal, Hybrid Analysis, Triage, and AlienVault.
41. Batch hash check against Malware Bazaar from a file containing hashes.
42. Batch hash check against Hybrid Analysis from a file containing hashes.
43. Batch hash check against Triage from a file containing hashes.
44. Directory scan against Malware Bazaar, Hybrid Analysis, and Triage.
45. Extract IOCs (hashes, IPs, URLs, domains, CVEs) from text files.
46. Scan files or directories with YARA rules.
47. Interactive REPL mode for continuous threat hunting sessions.
48. JSON and CSV structured output formats.
49. Result caching with configurable TTL (SQLite-based).
50. HTTP/HTTPS/SOCKS5 proxy support for all API requests.
51. MITRE ATT&CK technique mapping for behavior reports.
52. TUI (Text User Interface) dashboard mode with panel-based navigation.
53. Gather threat hunting information from URLScan.io — submit URLs, retrieve scan results, and search scans.
54. LLM-powered threat enrichment — AI-generated risk assessment, MITRE ATT&CK mapping, and analyst recommendations appended to any query result. Supports Claude, Gemini, OpenAI, and Ollama (local).

## CONTRIBUTORS

      Alexandre Borges (https://github.com/alexandreborges) | project owner and main developer
      Artur Marzano (https://github.com/Macmod) | co-main developer
      Corey Forman (https://github.com/digitalsleuth) | responsible for REMnux integration
      Christian Clauss (https://github.com/cclauss)

## HOW TO CONTRIBUTE TO THIS PROJECT

Since version 6.0.0, there is a new branch named "dev". All contributions and proposals 
must be done into this "dev" branch.

Professionals who want to contribute must open an issue explaining your proposed improvement 
and how it would make the project better. Once it has been accepted, so she/he is 
authorized to submit the PR, which will be tested. 

Once all changes are tested, this new version of Malwoverview is replicated to the master 
branch and a new Python package is generated.

## INSTALLATION

This tool has been tested on REMnux, Ubuntu, Kali Linux, macOS and Windows. Malwoverview 
can be installed by executing the following command:

      * pip3.11 install git+https://github.com/alexandreborges/malwoverview
      
      or...
      
      * python -m pip install -U malwoverview
      
If you want to install the Malwoverview on macOS, you have to execute the following commands:

      * /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
      * brew install libmagic
      * pip3 install urllib3==1.26.6
      * pip3 install -U malwoverview
      * Add Python binary directory to the PATH variable by editing .bash_profile file in your home 
        directory. Example:

          export PATH=$PATH:/Users/alexandreborges/Library/Python/3.9/bin

      * Execute: . ./.bash_profile

If you are installing Malwoverview on Windows, make sure that the following conditions are true  
AFTER having installed Malwoverview:

      * python-magic is NOT installed. (pip show python-magic)
      * python-magic-bin IS installed. (pip show python-magic-bin)

#### Note: It is recommended to save the .malwapi.conf before any update!

#### Optional Features

Some features require optional dependencies. Install them as needed:

      * YARA scanning:       pip install malwoverview[yara]
      * PDF report export:   pip install malwoverview[pdf]
      * TUI dashboard:       pip install malwoverview[tui]
      * All optional:        pip install malwoverview[all]


## REQUIRED APIs

It is possible to start using Malwoverview does without inserting all APIs. However, 
to use all options of Malwoverview, you must insert the respective API of the following services:
VirusTotal, Hybrid Analysis, URLHaus, Malshare, Polyswarm, Alien Vault, Malpedia, Triage,
IPInfo, Malware Bazaar, ThreatFox, VulnCheck, Shodan, AbuseIPDB, GreyNoise and URLScan.io into the .malwapi.conf configuration file, which 
must be present (or created) in the home directory (/home/[username]
or /root on Linux, and C:\Users\[username] on Windows. Alternatively, users can create 
a custom configuration file and indicate it by using the -c option.

To highlight: if the .malwapi.conf file does not exist in your home directory, so you must 
create it!

* A special note about the Alien Vault: it is necessary to subscribe to pulses on Alien Vault 
website before using -n 1 option.

The .malwapi.conf configuration file has the following format:

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

      [IPINFO]
      IPINFOAPI =  
      
      [BAZAAR]
      BAZAARAPI = 

      [THREATFOX]
      THREATFOXAPI = 

      [VULNCHECK]
      VULNCHECKAPI =

      [URLHAUS]
      URLHAUSAPI =

      [SHODAN]
      SHODANAPI =

      [ABUSEIPDB]
      ABUSEIPDBAPI =

      [GREYNOISE]
      GREYNOISEAPI =

      [URLSCANIO]
      URLSCANIOAPI =

      [LLM]
      PROVIDER =
      CLAUDE_API_KEY =
      GEMINI_API_KEY =
      OPENAI_API_KEY =
      OPENAI_MODEL = gpt-4o-mini
      OLLAMA_URL = http://localhost:11434
      OLLAMA_MODEL = llama3.1

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
08. Malware Bazaar: https://bazaar.abuse.ch/api/#auth\_key
09. ThreatFox: https://threatfox.abuse.ch/api/#auth\_key
10. Triage: https://tria.ge/signup.
11. IPInfo: https://ipinfo.io/
12. VulnCheck: https://vulncheck.com/signin (Community/Free tier available)
13. BGPView: https://bgpview.docs.apiary.io/
14. Shodan: https://account.shodan.io/register
15. AbuseIPDB: https://www.abuseipdb.com/register
16. GreyNoise: https://viz.greynoise.io/signup
17. URLScan.io: https://urlscan.io/user/signup

#### LLM Enrichment Providers (optional)

Malwoverview supports LLM-powered threat enrichment via the --enrich flag.
After any query, an AI-generated threat assessment is appended with risk level,
malware family identification, MITRE ATT&CK mapping, and analyst recommendations.

Three providers are supported. Configure one in the [LLM] section of .malwapi.conf:

**18. Anthropic Claude (paid, best quality)**

      Best results for threat intelligence analysis. Accurately identifies malware
      families, maps precise MITRE ATT&CK techniques, and provides actionable
      recommendations based on real threat knowledge.

      Setup:
      a) Create an API account at https://console.anthropic.com/ (separate from
         claude.ai subscription)
      b) Go to Settings → Billing → Add credit ($5 minimum, pay-per-use)
      c) Go to Settings → API Keys → Create Key
      d) Copy the key (starts with sk-ant-api03-...)
      e) Configure .malwapi.conf:

            [LLM]
            PROVIDER = claude
            CLAUDE_API_KEY = sk-ant-api03-your-key-here

      Cost: ~$0.01-0.02 per enrichment call using Sonnet model. $5 credit provides
      approximately 250-500 enrichment calls.

**19. Google Gemini (requires billing)**

      Good quality results. Requires a Google Cloud billing account.

      Setup:
      a) Go to https://aistudio.google.com/apikeys
      b) Sign in with Google account
      c) Click Create API Key → copy the key
      d) Enable billing: click the project link next to your key → Google Cloud
         Console → Billing → Link a billing account
      e) Configure .malwapi.conf:

            [LLM]
            PROVIDER = gemini
            GEMINI_API_KEY = your-gemini-key-here
            GEMINI_MODEL = gemini-2.0-flash

      Note: The free tier has a low rate limit (2-5 requests per minute). For
      higher limits, enable pay-per-use billing.

**20. OpenAI (paid)**

      Good quality results using GPT models. Requires an OpenAI account with
      API credits.

      Setup:
      a) Create an account at https://platform.openai.com/signup
      b) Go to https://platform.openai.com/api-keys → Create new secret key
      c) Add billing at https://platform.openai.com/settings/organization/billing
      d) Configure .malwapi.conf:

            [LLM]
            PROVIDER = openai
            OPENAI_API_KEY = sk-your-key-here
            OPENAI_MODEL = gpt-4o-mini

      Available models:
      - gpt-4o-mini  — Cheapest (~$0.002 per enrichment), good quality (default)
      - gpt-4o       — Better quality (~$0.01 per enrichment)

**21. Ollama (free, local, private)**

      Runs entirely on your machine. No API key needed, no data leaves your
      system. Good for environments where sending threat data to cloud APIs
      is not permitted. Quality depends on the model chosen.

      Setup:
      a) Download and install Ollama from https://ollama.com/download
         (available for Windows, Linux, and macOS)
      b) Open a terminal and pull a model:

            ollama pull qwen2.5:14b

         Recommended models:
         - qwen2.5:14b  — Best quality at reasonable size (9 GB, needs 16 GB RAM)
         - llama3.1:8b  — Good quality, smaller (5 GB, needs 8 GB RAM)
         - llama3.1:70b — Excellent quality, large (40 GB, needs 48 GB RAM)

      c) Ollama starts automatically and serves on http://localhost:11434
      d) Configure .malwapi.conf:

            [LLM]
            PROVIDER = ollama
            OLLAMA_URL = http://localhost:11434
            OLLAMA_MODEL = qwen2.5:14b

      Performance: GPU with 12+ GB VRAM provides fast responses (5-10s).
      CPU-only is slower (30-60s) but functional. Larger models (14b, 70b)
      require more VRAM and may timeout on CPU if insufficient memory is
      available. The llama3.1:8b model is recommended for machines with
      limited GPU memory (6 GB or less).

Expected response times:

      - Claude API:  3-8 seconds
      - Gemini API:  3-8 seconds
      - Ollama (GPU with sufficient VRAM): 5-15 seconds
      - Ollama (CPU-only, 8b model): 30-60 seconds
      - Ollama (CPU-only, 14b+ model): 60-300 seconds

Usage examples:

      # CLI: append --enrich to any query
      malwoverview -v 8 -V <hash> --enrich
      malwoverview -ip 1 -IP 8.8.8.8 --enrich
      malwoverview --correlate-hash <hash> --enrich

      # Interactive REPL: toggle enrichment on/off or switch provider
      malwoverview --interactive
      malwoverview> set enrich on                    # use provider from config
      malwoverview> set enrich claude                # switch to Claude
      malwoverview> set enrich ollama                # switch to Ollama
      malwoverview> set enrich openai                # switch to OpenAI
      malwoverview> set enrich off                   # disable enrichment
      malwoverview> vt hash <hash>                   # malware analysis + enrichment
      malwoverview> nist cve CVE-2024-3400           # CVE lookup + enrichment
      malwoverview> vulncheck cve CVE-2024-3400      # VulnCheck + enrichment

      # TUI: click the Enrich button to cycle through providers
      #   Enrich (OFF) → claude → gemini → openai → ollama → OFF
      #   Green button  = provider active and configured
      #   Yellow button = provider selected but API key missing
      #   Default button = enrichment disabled
      malwoverview --tui


----------------------------------------------------
Note about API requests to the MALPEDIA:
----------------------------------------------------

The service and acceptance are based on the community vetting. Thus, it's 
recommended that you submit an API request from your business e-mail address
and NOT from a public/free one (Gmail, Outlook and so on). Additionally, it 
would be great if you provided more information about yourself (LinkedIn 
account, X/Twitter, Mastodon, BlueSky, etc.) as this would facilitate 
verification of your identity, professional profile, and legitimacy, 
speeding up the approval of your request.  


----------------------------------------------------
Note about Triage:
----------------------------------------------------

Every Triage operation is based on the Triage ID of each artifact, so you 
need touse the "-x 1 -X \<attribute\>:\<value\>" to search for the 
correct ID of the artifact then use this ID information with the 
remaining Triage options (-x [2-7]) to get more threat hunting information 
from Triage endpoint.


----------------------------------------------------
Note about URLHaus, Malware Bazaar and Threat Fox: 
----------------------------------------------------

Starting in the second half of 2025, an Auth-Key (API) will be required to 
use the URLHaus,Malware Bazaar and Threat Fox services.


----------------------------------------------------
Note about background color of the terminal:
----------------------------------------------------

Malwoverview was written to produce output for a dark 
terminal background. However, there is the -o 0 option 
that changes and adapts the output colors for a light background.

-----------------------------------------------------


To check the installation, execute:

       malwoverview --help
       
Further information is available on: 

       (PYPI.org repository) https://pypi.org/project/malwoverview/
       (Github) https://github.com/alexandreborges/malwoverview

If you want to perform the manual installation (it is not usually necessary), 
so few steps should be executed, as shown in the next sub-section. 


## MANUAL INSTALLATION (REMnux and Ubuntu)

1. Python version 3.11 or later (Only Python 3.x !!! It does NOT work using 
Python 2.7) 

       $ apt-get install python3.11  (for example)

2. Python-magic.  

      To install python-magic package you can execute the following command:

       $ pip3.11 install python-magic

      Or you can compile it from the github repository:

       $ git clone https://github.com/ahupp/python-magic
       $ cd python-magic/
       $ python3.11 setup.py build
       $ python3.11 setup.py install

      As there are serious issues related to existing two versions of 
      python-magic package, the recommendation is to install it from 
      Github (second procedure above) and copy the magic.py file to the 
      SAME directory of malwoverview tool. 
      
3. Install all needed Python packages: 

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

4. To check an Android mobile you need to install the "adb" tool:

       $ sudo apt get install adb

   PS: before trying Android's options, check:

       * If the adb tool is listed in the PATH environment variable.
       * If the system has authorized access to the device by using "adb devices -l"


## HELP

usage: python malwoverview.py -c <API configuration file> -d <directory> -o <0|1> -v <1-13>
-V <argument> -a <1-17> -A <filename> -l <1-7> -L <hash> -j <1-7>
-J <argument> -p <1-8> -P <argument> -y <1-5> -Y <file name> -n <1-5>
-N <argument> -m <1-8> -M <argument> -b <1-12> -B <argument> -x <1-9> -X <argument>
-ip <1-7> -IP <argument> -O <directory> --nist <1-5> --NIST <argument> -vc <1-8>
-VC <argument> -s <1-2> -S <argument> -ab <1> -AB <argument> -gn <1> -GN <argument>
-wh <1-2> -WH <argument> -u <1-5> -U <arg> --correlate-hash <hash> --extract-iocs <file|url> --yara <rules>
--yara-target <target> --output-format text|json|csv --proxy <url> --quiet --verbose
--no-cache --cache-ttl <seconds> --report html|pdf --interactive --attack-map

Malwoverview is a first response tool for threat hunting written by Alexandre Borges. 

MALWARE OPTIONS:
  Malware analysis and intelligence query options

	-h, --help
	
		+ show this help message and exit

	-c CONFIG FILE, --config CONFIG FILE
	
		+ Use a custom config file to specify API's.

	-d DIRECTORY, --directory DIRECTORY
	
		+ Specifies the directory containing malware samples to be checked against VIRUS TOTAL.
		+ Use the option -D to decide whether you are being using a public VT API or a Premium 
		VT API.

	-o BACKGROUND, --background BACKGROUND
	
		+ Adapts the output colors to a light background color terminal. 
		+ The default is dark background color terminal.

	-v VIRUSTOTAL, --virustotal_option VIRUSTOTAL

		+ -v 1: given a file using -V option, it queries the VIRUS TOTAL database (API v.3)
			  to get the report for the given file through -V option.
		+ v 2: it shows an antivirus report for a given file using -V option (API v.3);
		+ v 3: equal to -v2, but the binary's IAT and EAT are also shown (API v.3); 
		+ v 4: it extracts the overlay; 
		+ v 5: submits an URL to VT scanning; 
		+ v 6: submits an IP address to Virus Total; 
		+ v 7: this options gets a report on the provided domain from Virus Total; 
		+ v 8: verifies a given hash against Virus Total; 
		+ v 9: submits a sample to VT (up to 32 MB). Use forward slash to specify the 
			   target file on Windows systems. Demands passing sample file with -V option; 
		+ -v 10: verifies hashes from a provided file through option -V. This option uses 
				public VT API v.3;
		+ -v 11: verifies hashes from a provided file through option -V. This option uses 
				Premium API v.3; 
		+ -v 12: it shows behaviour information of a sample given a hash through option -V. 
				This option uses VT API v.3; -v 13: it submits LARGE files (above 32 MB)
				to VT using API v.3;

	-V VIRUSTOTAL_ARG, --virustotal_arg VIRUSTOTAL_ARG
	
		+ Provides argument for -v option. If "-v 1" to "-v 4" then -V must be
		a file path; If "-v 5" then -V must be a URL; If "-v 6" then -V must
		be an IP address; If "-v 7" then -V must be a domain; If "-v 8" then
		-V must be a hash (MD5/SHA1/SHA256); If "-v 9" or "-v 13" then -V must
		be a file path to submit; If "-v 10" or "-v 11" then -V must be a file
		containing hashes (one per line); If "-v 12" then -V must be a hash for
		behavior analysis.

	-a HYBRID_ANALYSIS, --hybrid_option HYBRID_ANALYSIS
	
		+ This parameter fetches reports from HYBRID ANALYSIS, download samples and submits
		samples to be analyzed. 
		+ The possible values are: 
			+ 1: gets a report for a given hash or sample from a Windows 7 32-bit environment; 
			+ 2: gets a report for a given hash or sample from a Windows 7 32-bit 
			environment (HWP Support); 
			+ 3: gets a report for given hash or sample from a Windows 64-bit environment; 
			+ 4: gets a report for a given hash or sample from an Android environment; 
			+ 5: gets a report for a given hash or sample from a Linux 64-bit environment; 
			+ 6: submits a sample to Windows 7 32-bit environment; 
			+ 7. submits a sample to Windows 7 32-bit environment with HWP support environment; 
			+ 8. submits a sample to Windows 7 64-bit environment;
			+ 9. submits a sample to an Android environment; 
			+ 10. submits a sample to a Linux 64-bit environment;
			+ 11. downloads a sample from a Windows 7 32-bit environment; 
			+ 12. downloads a sample from a Windows 7 32-bit HWP environment; 
			+ 13. downloads a sample from a Windows 7 64-bit environment; 
			+ 14. downloads a sample from an Android environment; 
			+ 15. downloads a sample from a Linux 64-bit environment.
			+ 16: batch hash check from a file (one hash per line) against
			Hybrid Analysis;
			+ 17: directory scan — computes SHA256 for each file in a directory
			and checks against Hybrid Analysis.

	-A SUBMIT_HA, --ha_arg SUBMIT_HA
	
		+ Provides argument for -a option from HYBRID ANALYSIS. If "-a 1" to
		"-a 5" then -A must be a hash or a file path (auto-detected); If "-a 6"
		to "-a 10" then -A must be a file path to submit; If "-a 11" to "-a 15"
		then -A must be a hash to download; If "-a 16" then -A must be a file
		containing hashes (one per line); If "-a 17" then -A must be a directory
		path to scan.

	-D VT_PUBLIC_PREMIUM, --vtpubpremium VT_PUBLIC_PREMIUM
	
		+ This option must be used with -d option. 
		+ Possible values: 
			+ <0> it uses the Premium VT API v3 (default); 
			+ <1> it uses the Public VT API v3.
			
	-l MALSHARE_HASHES, --malsharelist MALSHARE_HASHES
	
		+ This option performs download a sample and shows hashes of a specific type
		from the last 24 hours from MALSHARE repository. 
		+ Possible values are: 
			+ 1: Download a sample; 
			+ 2: PE32 (default) ; 
			+ 3: ELF ; 
			+ 4: Java; 
			+ 5: PDF ; 
			+ 6: Composite(OLE); 
			+ 7: List of hashes from past 24 hours.

	-L MALSHARE_HASH_SEARCH, --malshare_hash MALSHARE_HASH_SEARCH
	
		+ Provides a hash as argument for downloading a sample from MALSHARE repository.
		
	-j HAUS_OPTION, --haus_option HAUS_OPTION
	
		+ This option fetches information from URLHaus depending of the value passed as argument: 
			+ 1: performs download of the given sample; 
			+ 2: queries information about a 
			provided hash ; 
			+ 3: searches information about a given URL; 
			+ 4: searches a malicious URL by a given tag (case sensitive); 
			+ 5: searches for payloads given a tag; 
			+ 6: retrives a list of downloadable links to recent payloads; 
			+ 7: retrives a list of recent malicious URLs.

	-J HAUS_ARG, --haus_arg HAUS_ARG
	
		+ Provides argument for -j option from URLHaus. If "-j 1" then -J must
		be a SHA256 hash to download the sample; If "-j 2" then -J must be a
		hash (MD5/SHA1/SHA256) to search; If "-j 3" then -J must be a URL to
		check; If "-j 4" then -J must be a tag (case sensitive); If "-j 5" then
		-J must be a signature name.

	-p POLY_OPTION, --poly_option POLY_OPTION
	
		+ (Only for Linux) This option is related to POLYSWARM operations:
			+ 1. searches information related to a given hash provided using -P option; 
			+ 2. submits a sample provided by -P option to be analyzed by Polyswarm engine ; 
			+ 3. Downloads a sample from Polyswarm by providing the hash throught option -P.
			Attention: Polyswarm enforces a maximum of 20 samples per month; 
			+ 4. searches for similar samples given a sample file thought option -P;
			+ 5. searches for samples related to a provided IP address through option -P; 
			+ 6. searches for samples related to a given domain provided by option -P; 
			+ 7. searches for samples related to a provided URL throught option -P; 
			+ 8. searches for samples related to a provided malware family given by option -P.

	-P POLYSWARM_ARG, --poly_arg POLYSWARM_ARG
	
		+ (Only for Linux) Provides an argument for -p option from POLYSWARM.

	-y ANDROID_OPTION, --android_option ANDROID_OPTION
	
		+ This ANDROID option has multiple possible values: 
			+ <1>: Check all third-party APK packages from the USB-connected Android device 
			against Hybrid Analysis using multithreads. Notes: the Android device does not 
			need to be rooted and the system does need to have the adb tool in the PATH 
			environment variable; 
			+ <2>: Check all third-party APK packages from the USB-connected Android device
			against VirusTotal using Public API (slower because of 60 seconds delay for each 
			4 hashes). Notes: the Android device does not need to be rooted and the system 
			does need to have adb tool in the PATH environment variable; 
			+ <3>: Check all third-party APK packages from the USB-connected Android device 
			against VirusTotal using multithreads (only for Private Virus API). Notes: the 
			Android device does not need to be rooted and the system needs to have adb tool 
			in the PATH environment variable; 
			+ <4> Sends an third-party APK from your USB-connected Android device to 
			Hybrid Analysis; 
			+ 5. Sends an third-party APK from your USB-connected Android device to Virus-Total.

	-Y ANDROID_ARG, --android_arg ANDROID_ARG
	
		+ This option provides the argument for -y from ANDROID.

	-n ALIENVAULT, --alienvault ALIENVAULT
	
		+ Checks multiple information from ALIENVAULT. The possible values are: 
			+ 1: Get the subscribed pulses; 
			+ 2: Get information about an IP address; 
			+ 3: Get information about a domain; 
			+ 4: Get information about a hash; 
			+ 5: Get information about a URL.

	-N ALIENVAULT_ARGS, --alienvaultargs ALIENVAULT_ARGS
	
		+ Provides argument for -n option from ALIENVAULT. If "-n 1" then -N
		must be the number of subscribed pulses to retrieve; If "-n 2" then -N
		must be an IP address; If "-n 3" then -N must be a domain; If "-n 4"
		then -N must be a hash (MD5/SHA256); If "-n 5" then -N must be a URL.

	-m MALPEDIA, --malpedia MALPEDIA
	
		+ This option is related to MALPEDIA and presents different meanings depending on 
		the chosen value. Thus:
			+ 1: List meta information for all families; 
			+ 2: List all actors ID; 
			+ 3: List all available payloads organized by family from Malpedia; 
			+ 4: Get meta information from an specific actor, so it is necessary to use 
			the -M option. Additionally, try to confirm the correct actor ID by executing
			malwoverview with option -m 3; 
			+ 5: List all families IDs; 
			+ 6: Get meta-information from an specific family, so it is necessary to 
			use the -M option. Additionally, try to confirm the correct family ID by 
			executing malwoverview with option -m 5; 
			+ 7: Get a malware sample from malpedia (zip format -- password: infected). 
			It is necessary to specify the requested hash by using -M option;
			+ 8: Get a zip file containing Yara rules for a specific family 
			(get the possible families using -m 5), which must be specified by using -M option.

	-M MALPEDIAARG, --malpediarg MALPEDIAARG
	
		+ Provides argument for -m option from MALPEDIA. If "-m 4" then -M must
		be an actor name (confirm with -m 2); If "-m 6" then -M must be a
		family name (confirm with -m 5); If "-m 7" then -M must be a hash to
		download the sample; If "-m 8" then -M must be a family name to get
		YARA rules.

	-b BAZAAR, --bazaar BAZAAR
	
		+ Checks multiple information from MALWARE BAZAAR and THREATFOX. The possible 
		values are: 
			+ 1: (Bazaar) Query information about a malware hash sample; 
			+ 2: (Bazaar) Get information and a list of malware samples associated 
			and according to a specific tag; 
			+ 3: (Bazaar) Get a list of malware samples according to a given imphash; 
			+ 4: (Bazaar) Query latest malware samples; 
			+ 5: (Bazaar) Download a malware sample from Malware Bazaar by providing a 
			SHA256 hash. The downloaded sample is zipped using the following 
			password: infected; 
			+ 6: (ThreatFox) Get current IOC dataset from last x days given by 
			option -B (maximum of 7 days); 
			+ 7: (ThreatFox) Search for the specified IOC on ThreatFox given by option -B; 
			+ 8: (ThreatFox) Search IOCs according to the specified tag given by option -B; 
			+ 9: (ThreatFox) Search IOCs according to the specified malware family provided by 
			option -B; 
			+ 10. (ThreatFox) List all available malware families.
			+ 11: (Bazaar) Batch hash check from a file (one hash per line)
			against Malware Bazaar;
			+ 12: (Bazaar) Directory scan — computes SHA256 for each file in a
			directory and checks against Malware Bazaar.

	-B BAZAAR_ARG, --bazaararg BAZAAR_ARG
	
		+ Provides argument to -b MALWARE BAZAAR and THREAT FOX option:
			+ "-b 1" indicates that the -B's argument must be a hash and a report about 
			the sample will be retrieved; 
			+ "-b 2" indicates that -B's argument must be a malware tag and last samples 
			matching this tag will be shown; 
			+ "-b 3" means that the argument given by -M must be a imphash and last samples 
			matching this impshash will be shown; 
			+ "-b 4" means that the argument given by -M must be "100 or time", where "100" 
			lists last "100 samples" and "time" lists last samples added to Malware Bazaar 
			in the last 60 minutes; 
			+ "-b 5" means that the sample will be downloaded and -B's argument must be 
			a SHA256 hash of the sample that you want to download from Malware Bazaar; 
			+ "-b 6" indicates that a list of IOCs will be retrieved and the -B's value 
			is the number of DAYS to filter such IOCs. The maximum time is 7 (days); 
			+ "-b 7" indicates that the -B's argument is the IOC you want to search for; 
			+ "-b 8" indicates that the -B's argument is the IOC's TAG that you want 
			search for; 
			+ "-b 9" indicates that the -B argument is the malware family that you want 
			to search for IOCs;
			
	-x TRIAGE, --triage TRIAGE
	
		+ Provides information from TRIAGE according to the specified value: 
			+ 1: this option gets sample's general information by providing an 
			argument with -X option in the following possible formats: 
				- sha256:<value>
				- sha1:<value>
				- md5:<value>
				- family:<value>
				- score:<value>
				- tag:<value>
				- url:<value>
				- wallet:<value>
				- ip:<value>; 
				
			+ 2: Get a sumary report for a given Triage ID (got from option -x 1); 
			+ 3: Submit a sample for analysis; 
			+ 4: Submit a sample through a URL for analysis; 
			+ 5: Download sample specified by the Triage ID; 
			+ 6: Download pcapng file from sample associated to given Triage ID; 
			+ 7: Get a dynamic report for the given Triage ID (got from option -x 1);
			+ 8: Batch hash check from a file (one hash per line) against Triage;
			+ 9: Directory scan — computes SHA256 for each file in a directory
			and checks against Triage.

	-X TRIAGE_ARG, --triagearg TRIAGE_ARG
	
		+ Provides argument for -x option from TRIAGE. If "-x 1" then -X must
		be a search query (e.g., sha256:<hash>, family:<name>, tag:<tag>,
		ip:<ip>); If "-x 2" then -X must be a Triage sample ID (obtained from
		-x 1); If "-x 3" then -X must be a file path to submit; If "-x 4"
		then -X must be a URL to submit; If "-x 5" or "-x 6" then -X must be
		a Triage sample ID to download; If "-x 7" then -X must be a Triage
		sample ID for dynamic report; If "-x 8" then -X must be a file
		containing hashes (one per line); If "-x 9" then -X must be a directory
		path to scan.

      -O OUTPUTDIR, --output-dir OUTPUTDIR
            
            + Set output directory for all sample downloads.
      
      -ip IP, --ip IP

      + Get IP information from various sources. The possible values are:
            + 1: Get details for an IP address provided with -IP from IPInfo;
            + 2: Get details for an IP address provided with -IP from BGPView;
            + 3: Get details for an IP address provided with -IP from all
            available intel services (VirusTotal/Alienvault);
            + 4: Get details for an IP address from Shodan;
            + 5: Get details for an IP address from AbuseIPDB;
            + 6: Get details for an IP address from GreyNoise;
            + 7: Get details for an IP address from all services (comprehensive).

      -IP IPARG, --iparg IPARG

            + Provides an IP address (IPv4 or IPv6) for the -ip option. All -ip
            options (1 through 7) require a valid IP address.

	-s SHODAN, --shodan SHODAN

		+ SHODAN options:
			+ 1: IP lookup;
			+ 2: Search query.

	-S SHODAN_ARG, --shodanarg SHODAN_ARG

		+ Provides argument for -s option from SHODAN. If "-s 1" then -S must
		be an IP address; If "-s 2" then -S must be a search query (e.g.,
		"apache", "port:22 country:BR").

	-ab ABUSEIPDB, --abuseipdb ABUSEIPDB

		+ ABUSEIPDB options:
			+ 1: Check IP reputation.

	-AB ABUSEIPDB_ARG, --abuseipdbarg ABUSEIPDB_ARG

		+ Provides an IP address for -ab option from ABUSEIPDB.

	-gn GREYNOISE, --greynoise GREYNOISE

		+ GREYNOISE options:
			+ 1: Quick IP check (community API).

	-GN GREYNOISE_ARG, --greynoisearg GREYNOISE_ARG

		+ Provides an IP address for -gn option from GREYNOISE.

	-wh WHOIS, --whois WHOIS

		+ WHOIS options:
			+ 1: Domain whois lookup;
			+ 2: IP whois/RDAP lookup.

	-WH WHOIS_ARG, --whoisarg WHOIS_ARG

		+ Provides argument for -wh option from WHOIS. If "-wh 1" then -WH must
		be a domain name; If "-wh 2" then -WH must be an IP address.

	-u URLSCANIO, --urlscanio URLSCANIO

		+ URLSCAN.IO options:
			+ 1: Submit a URL for scanning;
			+ 2: Get scan result by UUID;
			+ 3: Search scans using Elasticsearch query syntax
			(e.g., "page.server:nginx", "task.tags:phishing");
			+ 4: Search scans by domain;
			+ 5: Search scans by IP.

	-U URLSCANIO_ARG, --urlscanioarg URLSCANIO_ARG

		+ Provides argument for -u option from URLSCAN.IO. If "-u 1" then -U
		must be a URL to submit for scanning; If "-u 2" then -U must be a UUID
		(obtained from -u 1); If "-u 3" then -U must be an Elasticsearch query
		(e.g., "page.server:nginx", "task.tags:phishing"); If "-u 4" then -U
		must be a domain; If "-u 5" then -U must be an IP address.

	--correlate-hash HASH

		+ Cross-service hash correlation: queries a hash across VirusTotal,
		Hybrid Analysis, Triage, and AlienVault producing a consolidated report.

	--extract-iocs SOURCE

		+ Extract IOCs (hashes, IPs, URLs, domains, emails, CVEs) from a file
		(.txt, .pdf, .eml) or URL (http/https).
		PDF extraction requires: pip install malwoverview[pdf]

	--yara RULES_FILE

		+ YARA rules file to use for scanning. Must be used with --yara-target.
		Requires: pip install malwoverview[yara]

	--yara-target TARGET

		+ File or directory to scan with YARA rules.

	--attack-map

		+ Enable MITRE ATT&CK technique mapping for behavior reports.

GENERAL OPTIONS:
  Output format, proxy, cache, and verbosity options

	--output-format text|json|csv

		+ Output format: text (default, colored terminal), json, or csv.

	--proxy URL

		+ HTTP/HTTPS/SOCKS5 proxy URL (e.g., socks5://127.0.0.1:9050).

	--quiet

		+ Suppress banner and cosmetic output.

	--verbose

		+ Show debug information (request URLs, timing, etc.).

	--no-cache

		+ Disable result caching.

	--cache-ttl SECONDS

		+ Cache time-to-live in seconds (default: 3600).

	--report html|pdf

		+ Generate a report in the specified format.
		PDF export requires: pip install malwoverview[pdf]

	--report-file PATH

		+ Output path for the generated report.

	--interactive

		+ Launch interactive REPL mode.

	--tui

		+ Launch TUI (Text User Interface) dashboard mode with service selector,
		query input, and scrollable results panel. Requires: pip install malwoverview[tui]

	--enrich

		+ Enable LLM enrichment of results. Appends an AI-generated threat assessment
		after each query result. Works with all query types including malware hash
		lookups, IP reputation checks, CVE searches (NIST and VulnCheck), and
		cross-service correlation. Uses the provider configured in .malwapi.conf
		[LLM] section, or overridden with --llm. Supported providers:
		  - claude:  Anthropic Claude API (best quality, paid)
		  - gemini:  Google Gemini API (requires billing)
		  - openai:  OpenAI API (paid, GPT models)
		  - ollama:  Local Ollama instance (free, private)

	--llm PROVIDER

		+ Override the LLM provider for enrichment (use with --enrich).
		  Examples:
		    malwoverview -v 8 -V <hash> --enrich --llm claude
		    malwoverview --nist 2 --NIST CVE-2024-3400 --enrich --llm claude
		    malwoverview -vc 3 -VC CVE-2024-3400 --enrich --llm ollama

VULNERABILITY OPTIONS:
  Vulnerability database query options

      NIST CVE Database Query:
      Query options for NIST CVE database (Query type and value are required; other options are optional)

      --nist NIST_OPTION,   Query type: 1=CPE/Product Search, 2=CVE ID Search, 
                            3=CVSS v3 Severity, 4=Keyword Search, 5=CWE ID Search
      --NIST NIST_ARG       Search value (format depends on query type)
      --time YEARS          Limit results to last N years
      --rpp NUM             Results per page (default: 100, max: 2000)
      --startindex NUM      Pagination start index (default: 0)
      --ncves NUM           Limit output to first N CVEs

      VulnCheck Database Query:
      Query options for VulnCheck vulnerability database (Community/Free tier)

      --vulncheck VULNCHECK_OPTION   Query type: 1=List available indexes, 
                                     2=Get KEV (Known Exploited Vulnerabilities), 
                                     3=Search CVE in KEV, 
                                     4=Get KEV backup link,
                                     5=List MITRE CVEs,
                                     6=List NIST NVD2 CVEs,
                                     7=Search CVE in MITRE,
                                     8=Search CVE in NIST NVD2
      --VULNCHECK VULNCHECK_ARG      Search value (CVE ID for options 3/7/8, 
                                     max results for options 2/5/6, e.g., 50)

## SUBCOMMANDS

Starting in version 8.0, Malwoverview supports an alternative subcommand syntax
alongside the traditional flag-based syntax. Both syntaxes are fully supported
and produce identical results.

Available subcommands:

      vt          VirusTotal operations (file, av, hash, url, ip, domain, submit, behavior, batch)
      ha          Hybrid Analysis operations (report, submit, download, batch, dir)
      bazaar      Malware Bazaar operations (hash, tag, download, batch, dir)
      triage      Triage operations (search, summary, submit, dynamic, batch, dir)
      urlhaus     URLHaus operations (hash, url, tag, download)
      ip          IP address lookups (info, bgp, shodan, abuse, greynoise, all)
      whois       Whois/RDAP lookups (domain, ip)
      shodan      Shodan operations (ip, search)
      urlscanio   URLScan.io operations (submit, result, search, domain, ip)
      correlate   Cross-service correlation (hash)
      extract     IOC extraction from files or URLs
      yara        YARA rule scanning
      nist        NIST CVE database queries
      vulncheck   VulnCheck database queries

Subcommand examples (equivalent to flag-based syntax):

      # These pairs are equivalent:
      malwoverview vt hash <sha256>                     # same as: malwoverview -v 8 -V <sha256>
      malwoverview vt behavior <sha256>                 # same as: malwoverview -v 12 -V <sha256>
      malwoverview ha report <hash> --env 3             # same as: malwoverview -a 3 -A <hash>
      malwoverview ha batch <hashfile>                  # same as: malwoverview -a 16 -A <hashfile>
      malwoverview bazaar hash <sha256>                 # same as: malwoverview -b 1 -B <sha256>
      malwoverview bazaar batch <hashfile>              # same as: malwoverview -b 11 -B <hashfile>
      malwoverview bazaar dir <directory>               # same as: malwoverview -b 12 -B <directory>
      malwoverview triage search sha256:<value>         # same as: malwoverview -x 1 -X sha256:<value>
      malwoverview triage batch <hashfile>              # same as: malwoverview -x 8 -X <hashfile>
      malwoverview ip all <ipaddr>                      # same as: malwoverview -ip 7 -IP <ipaddr>
      malwoverview ip shodan <ipaddr>                   # same as: malwoverview -ip 4 -IP <ipaddr>
      malwoverview whois domain <domain>                # same as: malwoverview -wh 1 -WH <domain>
      malwoverview correlate hash <sha256>              # same as: malwoverview --correlate-hash <sha256>
      malwoverview extract <file|url>                    # same as: malwoverview --extract-iocs <file|url>
      malwoverview yara <rules> <target>                # same as: malwoverview --yara <rules> --yara-target <target>
      malwoverview nist 2 CVE-2021-44228               # same as: malwoverview --nist 2 --NIST CVE-2021-44228

Use --help with any subcommand for details:

      malwoverview vt --help
      malwoverview ip --help
      malwoverview ha report --help


## EXAMPLES

### MALWARE OPTIONS:

      malwoverview -d /home/remnux/malware/windows_2/
      malwoverview -v 1 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
      malwoverview -v 2 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
      malwoverview -v 3 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
      malwoverview -v 4 -V 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe,
      malwoverview -v 5 -V http://jamogames.com/templates/JLHk/
      malwoverview -v 6 -V 185.220.100.243
      malwoverview -v 7 -V xurl.es
      malwoverview -v 8 -V ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585
      malwoverview -v 9 -V cc2d791b16063a302e1ebd35c0e84e6cf6519e90bb710c958ac4e4ddceca68f7.exe
      malwoverview -v 10 -V /home/remnux/malware/hash_list_3.txt
      malwoverview -v 11 -V /home/remnux/malware/hash_list_3.txt
      malwoverview -v 12 -V 9d26e19b8fc5819b634397d48183637bacc9e1c62d8b1856b8116141cb8b4000
      malwoverview -v 13 -V /largefiles/4b3b46558cffe1c0b651f09c719af2779af3e4e0e43da060468467d8df445e93
      malwoverview -a 1 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8
      malwoverview -a 1 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8.exe
      malwoverview -a 2 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8
      malwoverview -a 3 -A 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8
      malwoverview -a 4 -A malware1.apk
      malwoverview -a 4 -A 82eb6039cdda6598dc23084768e18495d5ebf3bc3137990280bc0d9351a483eb
      malwoverview -a 5 -A 2b03806939d1171f063ba8d14c3b10622edb5732e4f78dc4fe3eac98b56e5d46
      malwoverview -a 5 -A 2b03806939d1171f063ba8d14c3b10622edb5732e4f78dc4fe3eac98b56e5d46.elf
      malwoverview -a 6 -A 47eccaaa672667a9cea23e24fd702f7b3a45cbf8585403586be474585fd80243.exe
      malwoverview -a 7 -A 47eccaaa672667a9cea23e24fd702f7b3a45cbf8585403586be474585fd80243.exe
      malwoverview -a 8 -A 47eccaaa672667a9cea23e24fd702f7b3a45cbf8585403586be474585fd80243.exe
      malwoverview -a 9 -A malware_7.apk
      malwoverview -a 10 -A 925f649617743f0640bdfff4b6b664b9e12761b0e24bbb99ca72740545087ad2.elf
      malwoverview -a 11 -A cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
      malwoverview -a 12 -A cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
      malwoverview -a 13 -A cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
      malwoverview -a 14 -A d90a5552fd4ef88a8b621dd3642e3be8e52115a67e6b17b13bdff461d81cf5a8
      malwoverview -a 15 -A 925f649617743f0640bdfff4b6b664b9e12761b0e24bbb99ca72740545087ad2
      malwoverview -l 1 -L d3dcc08c9b955cd3f68c198e11d5788869d1b159dc8014d6eaa39e6c258123b0
      malwoverview -l 2
      malwoverview -l 3
      malwoverview -l 4
      malwoverview -l 5
      malwoverview -l 6
      malwoverview -j 1 -J 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6
      malwoverview -j 2 -J 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6
      malwoverview -j 3 -J https://unada.us/acme-challenge/3NXwcYNCa/
      malwoverview -j 4 -J Qakbot
      malwoverview -j 5 -J Emotet
      malwoverview -j 5 -J Icedid
      malwoverview -j 6
      malwoverview -j 7
      malwoverview -p 1 -P 1999ba265cd51c94e8ae3a6038b3775bf9a49d6fe57d75dbf1726921af8a7ab2
      malwoverview -p 2 -P 301524c3f959d2d6db9dffdf267ab16a706d3286c0b912f7dda5eb42b6d89996.exe
      malwoverview -p 3 -P 68c11ef39769674123066bcd52e1d687502eb6c4c0788b4f682e8d31c15e5306
      malwoverview -p 4 -P 68c11ef39769674123066bcd52e1d687502eb6c4c0788b4f682e8d31c15e5306.exe
      malwoverview -p 5 -P 188.40.75.132
      malwoverview -p 6 -P covid19tracer.ca
      malwoverview -p 7 -P http://ksahosting.net/wp-includes/utf8.php
      malwoverview -p 8 -P Qakbot
      malwoverview -y 1
      malwoverview -y 2
      malwoverview -y 3
      malwoverview -y 4 -Y com.spaceship.netprotect
      malwoverview -y 5 -Y com.mwr.dz
      malwoverview -v 1 -V 368afeda7af69f329e896dc86e9e4187a59d2007e0e4b47af30a1c117da0d792.apk
      malwoverview -n 1 -N 10
      malwoverview -n 2 -N 176.57.215.100
      malwoverview -n 3 -N threesmallhills.com
      malwoverview -n 4 -N 6d1756aa6b45244764409398305c460368d64ff9 -o 0
      malwoverview -n 5 -N http://ksahosting.net/wp-includes/utf8.php
      malwoverview -m 1 | more
      malwoverview -m 2 | more
      malwoverview -m 3 | more 
      malwoverview -m 4 -M apt41 | more
      malwoverview -m 5 | more 
      malwoverview -m 6 -M win.qakbot
      malwoverview -m 7 -M 3d375d0ead2b63168de86ca2649360d9dcff75b3e0ffa2cf1e50816ec92b3b7d 
      malwoverview -m 8 -M win.qakbot
      malwoverview -b 1 -B c9d7b5d06cd8ab1a01bf0c5bf41ef2a388e41b4c66b1728494f86ed255a95d48
      malwoverview -b 2 -B Revil | more
      malwoverview -b 3 -B f34d5f2d4577ed6d9ceec516c1f5a744
      malwoverview -b 4 -B 100 
      malwoverview -b 4 -B time | more
      malwoverview -b 5 -B bda50ff249b947617d9551c717e78131ed32bf77db9dc5b7591d3e1af6cb2f1a
      malwoverview -b 6 -B 3 | more
      malwoverview -b 7 -B 193.150.103.37:21330
      malwoverview -b 8 -B Magecart | more
      malwoverview -b 9 -B "Cobalt Strike"
      malwoverview -b 10 | more
      malwoverview -x 1 -X score:10 | more
      malwoverview -x 1 -X 71382e72d8fb3728dc8941798ab1c180493fa978fd7eadc1ab6d21dae0d603e2
      malwoverview -x 2 -X 220315-qxzrfsadfl
      malwoverview -x 3 -X cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
      malwoverview -x 4 -X http://ztechinternational.com/Img/XSD.exe
      malwoverview -x 5 -X 220315-xmbp7sdbel
      malwoverview -x 6 -X 220315-xmbp7sdbel
      malwoverview -x 7 -X 220315-xmbp7sdbel
      malwoverview -ip 1 -IP 8.8.8.8
      malwoverview -ip 2 -IP 8.8.8.8
      malwoverview -ip 3 -IP 8.8.8.8
      malwoverview -b 5 -B <hash> -O <directory>
      malwoverview -b 11 -B /home/remnux/malware/hash_list.txt
      malwoverview -b 12 -B /home/remnux/malware/samples/
      malwoverview -a 16 -A /home/remnux/malware/hash_list.txt
      malwoverview -a 17 -A /home/remnux/malware/samples/
      malwoverview -x 8 -X /home/remnux/malware/hash_list.txt
      malwoverview -x 9 -X /home/remnux/malware/samples/
      malwoverview -ip 4 -IP 8.8.8.8
      malwoverview -ip 5 -IP 8.8.8.8
      malwoverview -ip 6 -IP 8.8.8.8
      malwoverview -ip 7 -IP 8.8.8.8
      malwoverview -s 1 -S 8.8.8.8
      malwoverview -s 2 -S "apache"
      malwoverview -ab 1 -AB 185.220.100.243
      malwoverview -gn 1 -GN 185.220.100.243
      malwoverview -wh 1 -WH example.com
      malwoverview -wh 2 -WH 8.8.8.8
      malwoverview -u 1 -U https://example.com
      malwoverview -u 2 -U 019ce889-ab8d-768b-894e-3e5bf5401f8d
      malwoverview -u 3 -U task.tags:phishing
      malwoverview -u 4 -U example.com
      malwoverview -u 5 -U 8.8.8.8
      malwoverview --correlate-hash ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585
      malwoverview --extract-iocs /home/remnux/malware/report.txt
      malwoverview --extract-iocs /home/remnux/malware/report.pdf
      malwoverview --extract-iocs https://example.com/threat-report.html
      malwoverview --yara /home/remnux/rules/malware.yar --yara-target /home/remnux/malware/samples/
      malwoverview --interactive
      malwoverview --tui
      malwoverview -v 8 -V <hash> --output-format json
      malwoverview -ip 3 -IP 8.8.8.8 --proxy socks5://127.0.0.1:9050
      malwoverview -v 12 -V <hash> --attack-map

      # LLM enrichment (append AI threat assessment to any query)
      malwoverview -v 8 -V <hash> --enrich                    # uses provider from config
      malwoverview -v 8 -V <hash> --enrich --llm claude       # override: use Claude
      malwoverview -v 8 -V <hash> --enrich --llm ollama       # override: use Ollama
      malwoverview -v 8 -V <hash> --enrich --llm openai       # override: use OpenAI
      malwoverview -ip 1 -IP 8.8.8.8 --enrich
      malwoverview --correlate-hash <hash> --enrich
      malwoverview --nist 2 --NIST CVE-2024-3400 --enrich     # CVE enrichment (NIST)
      malwoverview -vc 3 -VC CVE-2024-3400 --enrich           # CVE enrichment (VulnCheck)
      malwoverview --nist 4 --NIST palo alto --enrich          # keyword search + enrichment

### SUBCOMMAND SYNTAX (alternative to flags):

      # VirusTotal
      malwoverview vt hash ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585
      malwoverview vt file 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
      malwoverview vt av 95a8370c36d81ea596d83892115ce6b90717396c8f657b17696c7eeb2dba1d2e.exe
      malwoverview vt url http://jamogames.com/templates/JLHk/
      malwoverview vt ip 185.220.100.243
      malwoverview vt domain xurl.es
      malwoverview vt submit cc2d791b16063a302e1ebd35c0e84e6cf6519e90bb710c958ac4e4ddceca68f7.exe
      malwoverview vt behavior 9d26e19b8fc5819b634397d48183637bacc9e1c62d8b1856b8116141cb8b4000
      malwoverview vt batch /home/remnux/malware/hash_list_3.txt
      malwoverview vt batch /home/remnux/malware/hash_list_3.txt --public

      # Hybrid Analysis
      malwoverview ha report 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8
      malwoverview ha report 2e1fcadbac81296946930fe3ba580fd0b1aca11bc8ffd7cefa19dea131274ae8 --env 3
      malwoverview ha submit 47eccaaa672667a9cea23e24fd702f7b3a45cbf8585403586be474585fd80243.exe
      malwoverview ha download cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
      malwoverview ha batch /home/remnux/malware/hash_list.txt
      malwoverview ha dir /home/remnux/malware/samples/

      # Malware Bazaar
      malwoverview bazaar hash c9d7b5d06cd8ab1a01bf0c5bf41ef2a388e41b4c66b1728494f86ed255a95d48
      malwoverview bazaar tag Revil | more
      malwoverview bazaar download bda50ff249b947617d9551c717e78131ed32bf77db9dc5b7591d3e1af6cb2f1a
      malwoverview bazaar batch /home/remnux/malware/hash_list.txt
      malwoverview bazaar dir /home/remnux/malware/samples/

      # Triage
      malwoverview triage search score:10 | more
      malwoverview triage search sha256:71382e72d8fb3728dc8941798ab1c180493fa978fd7eadc1ab6d21dae0d603e2
      malwoverview triage summary 220315-qxzrfsadfl
      malwoverview triage submit cd856b20a5e67a105b220be56c361b21aff65cac00ed666862b6f96dd190775e
      malwoverview triage dynamic 220315-xmbp7sdbel
      malwoverview triage batch /home/remnux/malware/hash_list.txt
      malwoverview triage dir /home/remnux/malware/samples/

      # URLHaus
      malwoverview urlhaus hash 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6
      malwoverview urlhaus url https://unada.us/acme-challenge/3NXwcYNCa/
      malwoverview urlhaus tag Qakbot
      malwoverview urlhaus download 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6

      # IP lookups
      malwoverview ip info 8.8.8.8
      malwoverview ip bgp 8.8.8.8
      malwoverview ip shodan 8.8.8.8
      malwoverview ip abuse 185.220.100.243
      malwoverview ip greynoise 185.220.100.243
      malwoverview ip all 8.8.8.8

      # Shodan (standalone)
      malwoverview shodan ip 8.8.8.8
      malwoverview shodan search "apache"

      # Whois
      malwoverview whois domain example.com
      malwoverview whois ip 8.8.8.8

      # Cross-service correlation
      malwoverview correlate hash ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585

      # IOC extraction (text, PDF, email, or URL)
      malwoverview extract /home/remnux/malware/report.txt
      malwoverview extract /home/remnux/malware/report.pdf
      malwoverview extract https://example.com/threat-report.html

      # YARA scanning
      malwoverview yara /home/remnux/rules/malware.yar /home/remnux/malware/samples/

      # NIST CVE queries
      malwoverview nist 1 "windows" --ncves 50
      malwoverview nist 2 CVE-2021-44228
      malwoverview nist 3 CRITICAL --ncves 50
      malwoverview nist 4 "remote code execution" --ncves 50

      # VulnCheck queries
      malwoverview vulncheck 2 30
      malwoverview vulncheck 3 CVE-2021-44228

      # Subcommands combined with global options
      malwoverview vt hash <sha256> --output-format json
      malwoverview ip all 8.8.8.8 --proxy socks5://127.0.0.1:9050
      malwoverview vt behavior <sha256> --attack-map

### VULNERABILITIES OPTIONS:

      # Search for Windows vulnerabilities
      malwoverview --nist 1 --NIST "windows" --ncves 50

      # Search for Apache vulnerabilities
      malwoverview --nist 1 --NIST "apache" --ncves 30

      # Search for Chrome vulnerabilities
      malwoverview --nist 1 --NIST "chrome" --ncves 25

      # Search for Chromium vulnerabilities
      malwoverview --nist 1 --NIST "chromium" --ncves 25

      # Search for Linux vulnerabilities
      malwoverview --nist 1 --NIST "linux" --ncves 25

      # Search for MacOS vulnerabilities
      malwoverview --nist 1 --NIST "MacOS" --ncves 25

      # Search for Log4Shell vulnerability
      malwoverview --nist 2 --NIST "CVE-2021-44228" 

      # Search for ProxyShell vulnerability
      malwoverview --nist 2 --NIST "CVE-2021-34473" 

      # Search for Spring4Shell vulnerability
      malwoverview --nist 2 --NIST "CVE-2022-22965" 

      # Search for CRITICAL severity vulnerabilities
      malwoverview --nist 3 --NIST "CRITICAL" --ncves 50

      # Search for HIGH severity vulnerabilities
      malwoverview --nist 3 --NIST "HIGH" --ncves 40

      # Search for MEDIUM severity vulnerabilities
      malwoverview --nist 3 --NIST "MEDIUM" --ncves 30

      # Search for Authentication Bypass vulnerabilities
      malwoverview --nist 4 --NIST "authentication bypass" --ncves 30

      # Search for Remote Code Execution (RCE) vulnerabilities
      malwoverview --nist 4 --NIST "remote code execution" --ncves 50

      # Search for SQL injection vulnerabilities
      malwoverview --nist 4 --NIST "sql injection" --ncves 25

      # Search for Path Traversal vulnerabilities (CWE-22)
      malwoverview --nist 5 --NIST "CWE-22" --ncves 30

      # Search for SQL Injection vulnerabilities (CWE-89)
      malwoverview --nist 5 --NIST "CWE-89" ---ncves 40

      # Search for Cross-Site Scripting vulnerabilities (CWE-79)
      malwoverview --nist 5 --NIST "CWE-79" --ncves 35

      # List available VulnCheck indexes (Community/Free tier)
      malwoverview -vc 1

      # Get Known Exploited Vulnerabilities (KEV) - 30 results
      malwoverview -vc 2 -VC 30

      # Get Known Exploited Vulnerabilities (KEV) - 100 results
      malwoverview -vc 2 -VC 100

      # Search for a specific CVE in KEV database
      malwoverview -vc 3 -VC CVE-2021-44228

      # Search for a specific CVE in KEV database 
      malwoverview -vc 3 -VC CVE-2022-22965

      # Get backup download link for VulnCheck KEV dataset
      malwoverview -vc 4

      # List recent CVEs from MITRE database
      malwoverview -vc 5

      # List recent CVEs from MITRE database - 20 results
      malwoverview -vc 5 -VC 20

      # List recent CVEs from NIST NVD2 database
      malwoverview -vc 6

      # List recent CVEs from NIST NVD2 database - 50 results
      malwoverview -vc 6 -VC 50

      # Search for specific CVE in MITRE database (official CVE records)
      malwoverview -vc 7 -VC CVE-2024-21412

      # Search for specific CVE in NIST NVD2 (CVSS scores, CWE, CISA KEV status)
      malwoverview -vc 8 -VC CVE-2024-21412

## HISTORY

Version 8.0:

      This version:

            * Introduces LLM-powered threat enrichment (--enrich) with support
              for Anthropic Claude, Google Gemini, OpenAI, and local Ollama. Provides
              AI-generated risk assessment, MITRE ATT&CK mapping, and
              analyst recommendations for any query result.
            * Introduces URLScan.io integration for URL scanning, result
              retrieval, and search queries (-u option).
            * Introduces Shodan integration for IP lookups and search queries
              (-s option and -ip 4).
            * Introduces AbuseIPDB integration for IP reputation checks
              (-ab option and -ip 5).
            * Introduces GreyNoise integration for IP classification
              (-gn option and -ip 6).
            * Introduces Whois/RDAP lookups for domains and IPs (-wh option).
            * Introduces cross-service hash correlation across VirusTotal,
              Hybrid Analysis, Triage, and AlienVault (--correlate-hash).
            * Introduces batch hash check for Malware Bazaar (-b 11),
              Hybrid Analysis (-a 16), and Triage (-x 8).
            * Introduces directory scan for Malware Bazaar (-b 12),
              Hybrid Analysis (-a 17), and Triage (-x 9).
            * Introduces comprehensive IP lookup across all services (-ip 7).
            * Introduces IOC extraction from text files, PDFs, emails, and
              URLs (--extract-iocs).
            * Introduces YARA rule scanning with error-tolerant compilation
              and tabular directory output (--yara / --yara-target).
            * Introduces interactive REPL mode (--interactive).
            * Introduces JSON and CSV structured output (--output-format).
            * Introduces result caching with configurable TTL (--no-cache,
              --cache-ttl).
            * Introduces HTTP/HTTPS/SOCKS5 proxy support (--proxy).
            * Introduces MITRE ATT&CK technique mapping (--attack-map).
            * Introduces quiet and verbose modes (--quiet, --verbose).
            * Introduces HTML/PDF report generation (--report).
            * Adds centralized session factory with automatic retry logic
              and rate-limit handling for all API requests.
            * Adds progress bars (tqdm) for batch operations.
            * Adds startup config validation for required API keys.
            * Adds auto-detection of hash type (MD5/SHA1/SHA256).
            * Introduces TUI dashboard mode (--tui) with panel-based
              navigation using the Textual library (optional dependency).
            * Security hardening: SSRF protection, URL parameter encoding,
              HTTPS enforcement, rate-limit caps, secure temp files.

Version 7.1.2:

      This version:

            * Fixes resource leak - file handles (5 locations) - files opened 
              without context managers in hash.py (sha256hash, md5hash), 
              hybrid.py (file upload), virustotal.py (2 locations), and 
              triage.py (file upload).
            * Fixes URL injection/SSRF in alienvault.py (3 locations) - user input 
              for domain, file, and URL indicators not URL-encoded.
            * Fixes URL injection/SSRF in malpedia.py (4 locations) - user input 
              for actor, family, sample, and yara endpoints not URL-encoded.
            * Improves IP validation in bgpview.py - adds ipaddress.ip_address() 
              validation to prevent injection attacks.
            * Fixes bare except clauses (3 locations) - bgpview.py, vulncheck.py, 
              nist.py now use except Exception: to avoid catching KeyboardInterrupt 
              and SystemExit.

Version 7.1.1:

      This version:

            * Fixes path traversal vulnerability (9 locations) - user-controlled 
              filenames not sanitized in malpedia.py.
            * Fixes URL injection/SSRF in triage.py - user input inserted directly 
              into URLs without encoding.
            * Fixes incomplete URL encoding in triage.py - applies quote() to all 
              4 endpoints (overview, sample, pcap, report), not just search.
            * Fixes URL injection/SSRF in ipinfo.py - IP address parameter not 
              validated, API token moved to Authorization header.
            * Improves IP validation in ipinfo.py - replaces permissive regex with 
              stdlib ipaddress.ip_address() for proper validation.
            * Fixes subprocess injection in android.py - unsanitized paths passed 
              to ADB shell commands.
            * Strengthens Android path validation - replaces incomplete metacharacter 
              blocklist with secure allowlist (permits only /a-zA-Z0-9._-).
            * Fixes resource leak - file handles (9 locations) - files opened 
              without context managers in malpedia.py.
            * Fixes unsafe HTTP redirects (4 locations) - allow_redirects=True 
              allowed redirect to attacker-controlled URLs.
            * Fixes unbounded response size (4 locations) - no size limits on 
              downloaded files, added 500MB limit.
            * Optimizes download performance (4 locations) - uses bytearray instead 
              of bytes concatenation to avoid O(n²) complexity.
            * Fixes missing timeout in ipinfo.py - no timeout on HTTP request.
            * Fixes CLI validation bug - accepted argument-only invocations.
            * Fixes Polyswarm crash - NameError when score lookup failed.
            * Fixes IPInfo error handling - wrong error structure returned.

Version 7.1:

      This version:

            * Introduces options to list and search for vulnerabilites
              on Vulncheck. 

Version 7.0:

      This version:

            * Introduces options to search for vulnerabilites on NIST.
            * Fixes multiples URLHaus options.
            * Removes InQuest and Virus Exchange options.
            * Fixes and modificates multiple minor issues.
            * Fixes Python requirements file.
            * Fixes setup.py file.  

Version 6.2:

      This version:

            * Modifies Malware Bazaar option to use Auth-Key.
            * Modifies Threat Fox option to use Auth-Key.

Version 6.1.1:

      This version:

            * Modifies the code to not require to registers all APIs at 
              the first usage.
            * Add a new section in the README (this file) about required APIs.

Version 6.1.0:

      This version:

            * Introduces -vx option for Virus Exchange.
            * Introduces -ip option for IPInfo and BGPView.
            * Introduces -O option to save samples in a central directory. 
            * Fixes multiple other issues.

Version 6.0.1:

      This version:

            * Issue in Malshare's download option has been fixed.

Version 6.0.0:

      This version:

            * It has been completely refactored.
	    * README.md has been also changed.
            * Special thanks to Artur Marzano, who has contributed
              and dedicated his time to conduct and write this new version.

Version 5.4.5:

      This version:

	    * Includes a fix related to the installation path. 

Version 5.4.4:

      This version:

	    * Includes only small changes and updates in the README.md.

Version 5.4.3:

      This version:

	    * Fixes a recent issue on -v 10 and 11 options (VT) due to 
	      a change in one of the used libraries. 
	    * Fixes other minor issues on several options.

Version 5.4.2:

      This version:

            * Fixes two small issues.

Version 5.4.1:

      This version:

            * Fixes issues related to URLHaus.
            * Fixes issues related to Polyswarm.
            * Fixes issues related to Malware Bazaar.
            * Fixes issues related to InQuest.
            * Introduces changes to the help description. 
            * Introduces changes to installation process. 

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


