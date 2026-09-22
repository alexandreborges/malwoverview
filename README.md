# Malwoverview

[<img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/alexandreborges/malwoverview?color=red&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases/tag/v8.2.0) [<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/alexandreborges/malwoverview?color=Yellow&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases) [<img alt="GitHub Release Date" src="https://img.shields.io/github/release-date/alexandreborges/malwoverview?label=Release%20Date&style=for-the-badge">](https://github.com/alexandreborges/malwoverview/releases) [<img alt="GitHub" src="https://img.shields.io/github/license/alexandreborges/malwoverview?style=for-the-badge">](https://github.com/alexandreborges/malwoverview/blob/master/LICENSE) 
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


## Current Version: 8.2.0 (Codename: Revolutions)

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
31. Retrieve combined information about a given IP address from multiple services.
32. Offer extra option to save any downloaded file to a central location.
33. List and search vulnerabilities from NIST through different criterias.
34. Query VulnCheck database - Community/Free tier.
35. Gather threat hunting information from Shodan using different criteria.
36. Check IP reputation from AbuseIPDB.
37. Check IP classification from GreyNoise (community API).
38. Perform domain and IP Whois/RDAP lookups.
39. Cross-service hash correlation across VirusTotal, Hybrid Analysis, Triage, and AlienVault.
40. Batch hash check against Malware Bazaar from a file containing hashes.
41. Batch hash check against Hybrid Analysis from a file containing hashes.
42. Batch hash check against Triage from a file containing hashes.
43. Directory scan against Malware Bazaar, Hybrid Analysis, and Triage.
44. Extract IOCs (hashes, IPs, URLs, domains, CVEs) from text files.
45. Scan files or directories with YARA rules.
46. Interactive REPL mode for continuous threat hunting sessions.
47. JSON and CSV structured output formats.
48. Result caching with configurable TTL (SQLite-based).
49. HTTP/HTTPS/SOCKS5 proxy support for all API requests.
50. MITRE ATT&CK technique mapping for behavior reports.
51. TUI (Text User Interface) dashboard mode with panel-based navigation.
52. Gather threat hunting information from URLScan.io — submit URLs, retrieve scan results, and search scans.
53. LLM-powered threat enrichment — AI-generated risk assessment, MITRE ATT&CK mapping, and analyst recommendations appended to any query result. Supports Claude, Gemini, OpenAI, and Ollama (local).
54. Batch IP check against VirusTotal from a file containing IP addresses, showing a summary table (IP Address, Country, AS Owner, Detection).
55. Hunt on VirusTotal with YARA rules: submit and follow Retrohunt jobs, list the matched files, and create and list Livehunt rulesets and notifications.
56. Scan with a whole directory of YARA rules, each file compiled in its own namespace.
57. Search Malware Bazaar samples by YARA rule name, and download and extract the YARAify rule set from abuse.ch.
58. Download the complete Malpedia YARA ruleset for a given TLP level.
59. List the MalShare file types seen in the last 24 hours, and list the hashes of any of those types.
60. Batch hash check against URLHaus from a file containing hashes.
61. Certificate Transparency pivots through crt.sh, with no API key: enumerate the subdomains seen in issued certificates and list the certificates themselves.
62. Inspect, prune and empty the local result cache.
63. Interactive mode and TUI reach every service the command line reaches, and the TUI exports its results to json and csv.
64. Local PE triage of a file or directory with no API key, listing file type, size, overlay, overlay size and entropy, and highlighting the files above an entropy threshold.
65. Android scans hash every APK of a package, including the split APKs, instead of the base APK alone.
66. Authenticode signature checking with no API key, reporting whether a binary is signed and whether the signature is still valid, and naming the signer of a tampered file.
67. Every embedded signature of a multi-signed binary is reported, each with its own digest algorithm, certificate, thumbprint and serial number, so a second signer is never hidden behind the first.
68. The VirusTotal file check (-v 1) and hash report (-v 8) show the signature block: whether the certificate verified, the signer and counter signer chains, the signing date and every certificate with its status, algorithm, validity dates, serial number and thumbprint.
69. List the CVEs associated with a component, given either its name or the path to a local binary, whose VERSIONINFO supplies the component description that modern NVD entries are written against.

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
      * Signature checking:  pip install malwoverview[signature]
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

* A special note about Malshare and Shodan: both services require their API key to be sent in the
URL itself, and neither documents a header or a request body alternative (the Malshare hashlookup
endpoint is a POST, but the key still travels in the query string). Malwoverview replaces these two
keys with [REDACTED] in every error message it prints, so they do not end up in the output you paste
into a bug report, but the key is still recorded in the access logs of those services and in any
proxy that terminates TLS between you and them. Treat both keys as exposed to the service operator
and rotate them as you would any other credential.

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
      PROVIDER = claude
      CLAUDE_API_KEY =
      CLAUDE_MODEL = claude-opus-4-8
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
13. Shodan: https://account.shodan.io/register
14. AbuseIPDB: https://www.abuseipdb.com/register
15. GreyNoise: https://viz.greynoise.io/signup
16. URLScan.io: https://urlscan.io/user/signup

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
            CLAUDE_MODEL = claude-opus-4-8

      CLAUDE_MODEL is optional and defaults to claude-opus-4-8. Common choices:
      - claude-opus-4-8    — Best quality (default)
      - claude-sonnet-4-6  — Strong balance of quality and cost
      - claude-haiku-4-5   — Fastest and cheapest

      Cost: ~$0.02-0.04 per enrichment call using the default Opus model (less with
      Sonnet or Haiku). $5 credit provides roughly 125-250 Opus enrichment calls.

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

usage: python malwoverview.py -c <API configuration file> -d <directory> -o <0|1> -v <1-20>
-V <virustotal arg> -a <1-13> -A <filename> -l <1-8> -L <hash|file type> -j <1-8>
-J <URLhaus argument> -p <1-8> -P <polyswarm argument> -y <1-5> -Y <file name> -n <1-5>
-N <argument> -m <1-9> -M <argument> -b <1-15> -B <arg> -x <1-9> -X <arg>
-ip <1-8> -IP <IP address> -O <output directory> --nist <1-6> --NIST <argument> -vc <1-8>
-VC <argument> -s <1-2> -S <arg> -ab <1> -AB <arg> -gn <1> -GN <arg>
-wh <1-2> -WH <arg> -ct <1-2> -CT <domain> -u <1-5> -U <arg> --correlate-hash <hash>
--extract-iocs <file|url> --yara <rules> --yara-target <target>
--peinfo <file|directory> --entropy-threshold <value>
--sigcheck <file|directory> --no-signature --sig-verify-mode <any|first|all|best>
--output-format text|json|csv --proxy <url> --quiet --verbose --no-cache
--cache-ttl <seconds> --cache-stats --prune-cache --clear-cache --no-resolve --defang
--no-ioc-filter --report html|pdf --interactive --tui --attack-map

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
		+ -v 14: submits a Retrohunt job using the YARA rules file or rules directory 
				given with -V (VT scans the samples it received over the past months 
				against the rules);
		+ -v 15: lists your Retrohunt jobs, optionally filtered by a status passed 
				through -V (starting, running, aborting, aborted or finished);
		+ -v 16: shows the status and progress of the Retrohunt job whose id is 
				given with -V;
		+ -v 17: lists the files matched by the Retrohunt job whose id is given with -V;
		+ -v 18: creates a Livehunt ruleset from the YARA rules file or rules directory 
				given with -V (VT then matches every new submission against it);
		+ -v 19: lists your Livehunt rulesets;
		+ -v 20: lists your Livehunt notifications. Options 14 to 20 need a VT key with 
				premium (enterprise) privileges;

	-V VIRUSTOTAL_ARG, --virustotal_arg VIRUSTOTAL_ARG
	
		+ Provides argument for -v option. If "-v 1" to "-v 4" then -V must be
		a file path; If "-v 5" then -V must be a URL; If "-v 6" then -V must
		be an IP address; If "-v 7" then -V must be a domain; If "-v 8" then
		-V must be a hash (MD5/SHA1/SHA256); If "-v 9" or "-v 13" then -V must
		be a file path to submit; If "-v 10" or "-v 11" then -V must be a file
		containing hashes (one per line); If "-v 12" then -V must be a hash for
		behavior analysis; If "-v 14" or "-v 18" then -V must be a YARA rules
		file or a directory of rules; If "-v 15" then -V may be a job status;
		If "-v 16" or "-v 17" then -V must be a Retrohunt job id.

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
			+ 11. downloads the sample for a given hash (the stored sample is the 
			same regardless of the sandbox environment, so a single option 
			replaces the former options 11 to 15); 
			+ 12. batch hash check from a file (one hash per line); 
			+ 13. directory scan - computes SHA256 for each file and checks 
			against Hybrid Analysis.

	-A SUBMIT_HA, --ha_arg SUBMIT_HA
	
		+ Provides argument for -a option from HYBRID ANALYSIS. If "-a 1" to
		"-a 5" then -A must be a hash or a file path (auto-detected); If "-a 6"
		to "-a 10" then -A must be a file path to submit; If "-a 11" then -A
		must be a hash to download; If "-a 12" then -A must be a file
		containing hashes (one per line); If "-a 13" then -A must be a directory
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
			+ 6: List the file types available in the last 24 hours (and how many 
			samples of each); 
			+ 7: List of hashes from past 24 hours; 
			+ 8: List hashes of the file type given with -L (use -l 6 to discover 
			the valid file types).

	-L MALSHARE_HASH_SEARCH, --malshare_hash MALSHARE_HASH_SEARCH
	
		+ Provides a hash as argument for downloading a sample from MALSHARE 
		repository (-l 1) or, when used with -l 8, the file type whose hashes 
		must be listed.
		
	-j HAUS_OPTION, --haus_option HAUS_OPTION
	
		+ This option fetches information from URLHaus depending of the value passed as argument: 
			+ 1: performs download of the given sample; 
			+ 2: queries information about a 
			provided hash ; 
			+ 3: searches information about a given URL; 
			+ 4: searches a malicious URL by a given tag (case sensitive); 
			+ 5: searches for payloads given a tag; 
			+ 6: retrives a list of downloadable links to recent payloads; 
			+ 7: retrives a list of recent malicious URLs; 
			+ 8: batch hash check from a file (one hash per line).

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
			(get the possible families using -m 5), which must be specified by using -M option; 
			+ 9: Get a zip file containing the complete Malpedia Yara ruleset for a 
			TLP level, which must be given with -M as one of tlp_white, tlp_green, 
			tlp_amber or auto (the short forms white, green and amber are also 
			accepted). Combine it with --yara to scan with the downloaded rules.

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
			directory and checks against Malware Bazaar;
			+ 13: (Bazaar) Search samples matching the YARA rule name given by 
			option -B. Rule names are listed at the end of a hash report 
			(-b 1), and are also the rule names inside the YARAify set 
			downloaded with -b 14 and extracted with -b 15;
			+ 14: (YARAify) Download the YARAify rule set (abuse.ch), which is the 
			rule set behind Malware Bazaar;
			+ 15: (YARAify) Extract the downloaded YARAify rule set into a rules 
			directory that can be given to --yara.

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
            + 2: Removed in 8.1.0 (BGPView shut down);
            + 3: Get details for an IP address provided with -IP from all
            available intel services (VirusTotal/Alienvault);
            + 4: Get details for an IP address from Shodan;
            + 5: Get details for an IP address from AbuseIPDB;
            + 6: Get details for an IP address from GreyNoise;
            + 7: Get details for an IP address from all services (comprehensive);
            + 8: Batch check IP addresses from a file (one per line) against
            VirusTotal and show a summary table (IP Address, Country, AS Owner,
            Detection). Use -D to choose between Public (-D 1) and Premium
            (-D 0, default) VT API.

      -IP IPARG, --iparg IPARG

            + Provides an argument for the -ip option. For -ip 1 through 7 it
            must be a valid IP address (IPv4 or IPv6); for -ip 8 it must be a
            file containing IP addresses (one per line).

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

	-ct CRTSH, --crtsh CRTSH

		+ Queries the Certificate Transparency logs through crt.sh, which needs
		no API key. Possible values:
			+ 1: lists the distinct DNS names seen in the certificates issued for
			the domain given with -CT, which is a cheap way of enumerating
			subdomains. Names belonging to other domains, which appear because a
			certificate can cover several tenants, are counted and reported
			separately;
			+ 2: lists the certificates themselves (identifier, issuer, common
			name and validity dates, newest first).

	-CT CRTSH_ARG, --crtsharg CRTSH_ARG

		+ Provides the domain name queried by the -ct option.

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

	--peinfo TARGET

		+ Local PE triage of a file or directory (no API key): file type, size,
		overlay, overlay size and entropy. Directories are scanned recursively.
		Entropy is the highest PE section entropy, or the whole-file Shannon
		entropy for non-PE files.

	--entropy-threshold VALUE

		+ Entropy value at which --peinfo highlights a file as packed or
		encrypted. Default: 7.0

	--sigcheck TARGET

		+ Check the Authenticode signature of a file or directory (no API key):
		status, signer, issuer, certificate dates, digest algorithm, certificate
		thumbprint and serial number. The status is one of VALID, TAMPERED,
		UNTRUSTED, EXPIRED, MALFORMED, INVALID, NONE (no embedded signature),
		PRESENT (a signature is there but was not verified) or N/A (not a PE
		file). Only embedded signatures are read: a file reported as NONE can
		still be signed through a Windows catalog.
		Full verification requires: pip install malwoverview[signature]

		VALID means the file still matches the certificate it was signed with.
		It is not a verdict on the file: signing certificates are stolen,
		abused and issued by mistake, and malware has carried valid Microsoft
		signatures. An embedded signature is stored in the overlay, so a signed
		file always reports one and that overlay is not an appended payload.

		Certificate revocation is not checked. No network request is made, so a
		file signed with a certificate that was revoked afterwards still
		reports VALID.

		A signature stays VALID after its certificate expires when it carries a
		countersignature, because the countersignature proves the file was
		signed while the certificate was still valid. This is how Authenticode
		is meant to work, and the report says so when it happens: an expiry
		date in the past next to VALID is not a contradiction.

		A file can carry more than one embedded signature, usually SHA-1 for
		compatibility plus SHA-256, and the signers frequently differ. The
		Signer column shows one of them and marks the rest as (+N); running
		--sigcheck on a single file lists every signature with its own digest
		algorithm, certificate, thumbprint and serial number.

	--no-signature

		+ Skip signature verification in --peinfo and --sigcheck, reporting
		only whether a signature is present. Useful on large directories.

	--sig-verify-mode MODE

		+ Which embedded signature decides the status of a multi-signed file:
		any, first, all or best. Default: best

		best follows the signature made with the strongest digest algorithm,
		which is the one Windows honours. first follows file order, matching
		sigcheck.exe. all requires every signature to verify, and any accepts
		the file when a single one does. The choice matters: across 517
		multi-signed drivers, 37 change status depending on this setting, and
		any reports VALID on 21 files that first rejects.

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

	--cache-stats

		+ Show the local result cache location, how many entries it holds, how many
		of them are expired under the current --cache-ttl, and its size on disk.
		Then exit.

	--prune-cache

		+ Delete only the expired entries from the local result cache (according to
		--cache-ttl) and exit.

	--clear-cache

		+ Delete every entry from the local result cache and exit.

	--no-resolve

		+ Do not resolve or geolocate the host names found in the results. Listing a
		feed (for example the URLHaus payloads and tag listings) normally makes your
		host look up every URL it shows, which tells the operator of that
		infrastructure that it is being investigated. With this option the location
		column shows "Not Resolved" instead.

	--defang

		+ Print the IOCs listed by --extract-iocs in defanged form
		(hxxp://example[.]com), so they can be copied into a report or a ticket
		without becoming clickable. It applies to that listing only, and changes
		only the output: the queries are still made with the real values.

	--no-ioc-filter

		+ Turn off the noise filtering that --extract-iocs applies by default.
		Normally an HTML page has its <script>, <style> and <svg> blocks skipped,
		a domain is only reported when its last label is a real top-level domain,
		and links back to the source site or to known page furniture (analytics,
		fonts, social buttons) are dropped. With this option every regex match in
		the raw source is reported instead.

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
                            3=CVSS v3 Severity, 4=Keyword Search, 5=CWE ID Search, 
                            6=Component Search (name or path to a local binary)
      --NIST NIST_ARG       Search value (format depends on query type)
      --time YEARS          Limit results to last N years
      --rpp NUM             NVD page size used while paginating (default: 2000, max: 2000)
      --startindex NUM      Pagination start index (default: 0)
      --ncves NUM           Limit output to first N CVEs (--nist 6 lists the 25 most 
                            recent by default; 0 lists all)
      --sort-by KEY         Order --nist results by cve (the CVE ID year, default) or 
                            published (the NVD publication date). --time bounds results 
                            by the same reference

      VulnCheck Database Query:
      Query options for VulnCheck vulnerability database (Community/Free tier)

	-vc VULNCHECK_OPTION, --vulncheck VULNCHECK_OPTION

		+ Query type: 
    
    1: List available indexes; 
		2: Get KEV (Known Exploited Vulnerabilities); 
		3: Search CVE in KEV; 
		4: Get KEV backup link; 
		5: List MITRE CVEs; 
		6: List NIST NVD2 CVEs; 
		7: Search CVE in MITRE; 
		8: Search CVE in NIST NVD2.

	-VC VULNCHECK_ARG, --VULNCHECK VULNCHECK_ARG

		+ Search value (CVE ID for options 3/7/8, max results for options
		2/5/6, e.g., 50).

## SUBCOMMANDS

Starting in version 8.0, Malwoverview supports an alternative subcommand syntax
alongside the traditional flag-based syntax. Both syntaxes are fully supported
and produce identical results.

Available subcommands:

      vt          VirusTotal operations (file, av, hash, url, ip, domain, submit, behavior, batch)
      ha          Hybrid Analysis operations (report, submit, download, batch, dir)
      bazaar      Malware Bazaar operations (hash, tag, download, batch, dir)
      triage      Triage operations (search, summary, submit, dynamic, batch, dir)
      urlhaus     URLHaus operations (hash, url, tag, download, batch)
      ip          IP address lookups (info, shodan, abuse, greynoise, all, batch)
      whois       Whois/RDAP lookups (domain, ip)
      shodan      Shodan operations (ip, search)
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
      malwoverview ha batch <hashfile>                  # same as: malwoverview -a 12 -A <hashfile>
      malwoverview bazaar hash <sha256>                 # same as: malwoverview -b 1 -B <sha256>
      malwoverview bazaar batch <hashfile>              # same as: malwoverview -b 11 -B <hashfile>
      malwoverview bazaar dir <directory>               # same as: malwoverview -b 12 -B <directory>
      malwoverview triage search sha256:<value>         # same as: malwoverview -x 1 -X sha256:<value>
      malwoverview triage batch <hashfile>              # same as: malwoverview -x 8 -X <hashfile>
      malwoverview ip all <ipaddr>                      # same as: malwoverview -ip 7 -IP <ipaddr>
      malwoverview ip shodan <ipaddr>                   # same as: malwoverview -ip 4 -IP <ipaddr>
      malwoverview ip batch <ipfile>                    # same as: malwoverview -ip 8 -IP <ipfile>
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
      malwoverview -v 14 -V /home/remnux/rules/apt_rules.yar
      malwoverview -v 14 -V /home/remnux/rules/
      malwoverview -v 15
      malwoverview -v 16 -V 1712345678-abcdef0123456789
      malwoverview -v 17 -V 1712345678-abcdef0123456789
      malwoverview -v 18 -V /home/remnux/rules/livehunt.yar
      malwoverview -v 19
      malwoverview -v 20
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
      malwoverview -a 12 -A /home/remnux/malware/hash_list.txt
      malwoverview -a 13 -A /home/remnux/malware/samples/
      malwoverview -l 1 -L d3dcc08c9b955cd3f68c198e11d5788869d1b159dc8014d6eaa39e6c258123b0
      malwoverview -l 2
      malwoverview -l 3
      malwoverview -l 4
      malwoverview -l 5
      malwoverview -l 6
      malwoverview -l 8 -L PE32
      malwoverview -j 1 -J 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6
      malwoverview -j 2 -J 7c99d644cf39c14208df6d139313eaf95123d569a9206939df996cfded6924a6
      malwoverview -j 3 -J https://unada.us/acme-challenge/3NXwcYNCa/
      malwoverview -j 4 -J Qakbot
      malwoverview -j 5 -J Emotet
      malwoverview -j 5 -J Icedid
      malwoverview -j 6
      malwoverview -j 7
      malwoverview -j 8 -J /home/remnux/malware/hash_list.txt
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
      malwoverview -m 9 -M tlp_white
      malwoverview -m 9 -M tlp_green
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
      malwoverview -ip 3 -IP 8.8.8.8
      malwoverview -b 5 -B <hash> -O <directory>
      malwoverview -b 11 -B /home/remnux/malware/hash_list.txt
      malwoverview -b 12 -B /home/remnux/malware/samples/
      malwoverview -b 13 -B Windows_Trojan_Emotet
      malwoverview -b 14
      malwoverview -b 15
      malwoverview -x 8 -X /home/remnux/malware/hash_list.txt
      malwoverview -x 9 -X /home/remnux/malware/samples/
      malwoverview -ip 4 -IP 8.8.8.8
      malwoverview -ip 5 -IP 8.8.8.8
      malwoverview -ip 6 -IP 8.8.8.8
      malwoverview -ip 7 -IP 8.8.8.8
      malwoverview -ip 8 -IP /home/remnux/malware/ip_list.txt
      malwoverview -ip 8 -IP /home/remnux/malware/ip_list.txt -D 1
      malwoverview -s 1 -S 8.8.8.8
      malwoverview -s 2 -S "apache"
      malwoverview -ab 1 -AB 185.220.100.243
      malwoverview -gn 1 -GN 185.220.100.243
      malwoverview -wh 1 -WH example.com
      malwoverview -wh 2 -WH 8.8.8.8
      malwoverview -ct 1 -CT iana.org
      malwoverview -ct 2 -CT iana.org
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
      malwoverview --yara /home/remnux/rules/ --yara-target /home/remnux/malware/samples/
      malwoverview --peinfo /home/remnux/malware/samples/
      malwoverview --peinfo /home/remnux/malware/dropper.exe
      malwoverview --peinfo /home/remnux/malware/samples/ --entropy-threshold 7.5
      malwoverview --peinfo /home/remnux/malware/samples/ --output-format csv
      malwoverview --peinfo /home/remnux/malware/samples/ --no-signature
      malwoverview --sigcheck /home/remnux/malware/suspicious.exe
      malwoverview --sigcheck /home/remnux/malware/samples/
      malwoverview --sigcheck /home/remnux/malware/samples/ --output-format json
      malwoverview --sigcheck /home/remnux/malware/samples/ --sig-verify-mode all
      malwoverview --interactive
      malwoverview --tui
      malwoverview -v 8 -V <hash> --output-format json
      malwoverview -ip 3 -IP 8.8.8.8 --proxy socks5://127.0.0.1:9050
      malwoverview -v 12 -V <hash> --attack-map
      malwoverview -a 1 -A <hash> --attack-map
      malwoverview --correlate-hash <hash> --attack-map

      # Local result cache
      malwoverview --cache-stats
      malwoverview --prune-cache
      malwoverview --clear-cache

      # Download the YARAify rule set and scan with it (-b 15 extracts into
      # <output directory>/yaraify-rules, so use the same -O for both steps)
      malwoverview -b 14 -O /home/remnux/rules
      malwoverview -b 15 -O /home/remnux/rules
      malwoverview --yara /home/remnux/rules/yaraify-rules --yara-target /home/remnux/malware/samples/

      # Malpedia rule set (-m 9 saves malpedia_yara_<level>.zip; extract it first)
      malwoverview -m 9 -M tlp_white -O /home/remnux/rules
      unzip /home/remnux/rules/malpedia_yara_tlp_white.zip -d /home/remnux/rules/malpedia
      malwoverview --yara /home/remnux/rules/malpedia --yara-target /home/remnux/malware/samples/

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
      malwoverview nist 6 "Ancillary Function Driver for WinSock"
      malwoverview nist 6 ksmbd
      malwoverview nist 6 iCloud --sort-by published

      # VulnCheck queries
      malwoverview vulncheck 2 30
      malwoverview vulncheck 3 CVE-2021-44228

      # Subcommands combined with global options
      malwoverview vt hash <sha256> --output-format json
      malwoverview ip all 8.8.8.8 --proxy socks5://127.0.0.1:9050
      malwoverview vt behavior <sha256> --attack-map

### INTERACTIVE MODE (--interactive):

      malwoverview --interactive

      # Inside the prompt (type "help" for the full list):
      vt hash ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585
      vt file /home/remnux/malware/sample.exe
      vt behavior 9d26e19b8fc5819b634397d48183637bacc9e1c62d8b1856b8116141cb8b4000
      vt batch /home/remnux/malware/hash_list.txt
      vt retrohunt submit /home/remnux/rules/
      vt retrohunt list
      vt retrohunt status 1712345678-abcdef0123456789
      vt livehunt notifications
      bazaar yara Windows_Trojan_Emotet
      bazaar yaradownload
      bazaar yaraextract
      bazaar dir /home/remnux/malware/samples/
      urlhaus batch /home/remnux/malware/hash_list.txt
      urlhaus payloads
      triage submit /home/remnux/malware/sample.exe
      triage pcap 220315-xmbp7sdbel
      malpedia ruleset tlp_white
      malpedia meta emotet
      malshare types
      malshare type PE32
      hybrid file /home/remnux/malware/sample.exe
      hybrid dir /home/remnux/malware/samples/
      threatfox malwarelist
      ip batch /home/remnux/malware/ip_list.txt
      ip multi 8.8.8.8
      ip all 8.8.8.8
      crtsh subdomains iana.org
      crtsh certs iana.org
      android ha
      android sendvt com.example.app
      yara /home/remnux/rules/ /home/remnux/malware/samples/
      iocs /home/remnux/malware/report.pdf
      peinfo /home/remnux/malware/samples/
      peinfo /home/remnux/malware/samples/ 7.5
      sigcheck /home/remnux/malware/suspicious.exe
      cache stats
      cache prune
      set attack on
      set enrich claude
      export json
      export csv results.csv          # the export path must be inside the current directory

### TUI MODE (--tui):

      malwoverview --tui

      # Pick a service on the left panel, type the query, press Enter.
      # F3 copies the result, F4 picks an ID out of it, F5 exports the
      # collected results to json, F6 exports them to csv, Ctrl+L clears.
      # Ctrl+V (or Shift+Insert) pastes the clipboard into the query box from
      # anywhere in the dashboard, so a hash can be pasted without clicking
      # into the box first.
      # The key list is printed above the results and is written again every
      # time the pane is cleared, which includes the start of every search.
      # While the query box has the focus, quitting is Ctrl+Q, because Q itself
      # has to remain typeable.

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

      # List the CVEs of a component by reading a local binary, whose VERSIONINFO
      # supplies both the file name and the component description to search on
      malwoverview --nist 6 --NIST "C:\Windows\System32\drivers\afd.sys"

      # The same search from the component name alone, when the binary is not at hand
      malwoverview --nist 6 --NIST "Ancillary Function Driver for WinSock"
      malwoverview --nist 6 --NIST "Common Log File System Driver" --ncves 40

      # The Linux and Apple equivalents, named the same way
      malwoverview --nist 6 --NIST ksmbd
      malwoverview --nist 6 --NIST iCloud

      # Ordered by the NVD publication date instead of the CVE ID year
      malwoverview --nist 6 --NIST iCloud --sort-by published

      # All CVEs of a product from a partial CPE, with no version
      malwoverview --nist 1 --NIST "cpe:2.3:a:openbsd:openssh"

      # All CVEs of one exact product version
      malwoverview --nist 1 --NIST "cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*"

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

## WHAT IS NEW IN 8.2.0, BY EXAMPLE

Everything this version adds or changes, as commands you can run. The narrative
version of the same list is the 8.2.0 block under HISTORY, below.

### 1. List the CVEs of a component, on any platform

The argument is the component itself. Name it and the search runs anywhere:

      malwoverview --nist 6 --NIST openssl
      malwoverview --nist 6 --NIST systemd
      malwoverview --nist 6 --NIST WebKit
      malwoverview --nist 6 --NIST Safari
      malwoverview --nist 6 --NIST "Ancillary Function Driver for WinSock"

A Linux kernel module is named the same way, and ksmbd, the in-kernel SMB
server, matches 236 CVEs where its Windows counterpart srv2.sys matches 1:

      malwoverview --nist 6 --NIST ksmbd
      malwoverview --nist 6 --NIST nf_tables

On iOS and macOS, name the component Apple ships rather than a framework file:

      malwoverview --nist 6 --NIST iCloud
      malwoverview --nist 6 --NIST FaceTime

Name the project or the framework rather than the file it ships as. On Linux the
library file libssl.so.3 matches 9 CVEs while the project name openssl matches
658, and the same holds for macOS and iOS frameworks.

### 2. Pointing at a Windows binary instead

A Windows PE records its own component name, so pointing at one searches three
keys and merges the results: the file name on disk, the internal name and the
component description:

      malwoverview --nist 6 --NIST "C:\Windows\System32\drivers\afd.sys"

That matters because afd.sys by name matches 7 CVEs, while the driver itself
matches 74 - modern NVD entries name the component, not the file:

      malwoverview --nist 6 --NIST afd.sys

A file that is not a Windows PE has no such metadata, so only its name is
searched and the report says so rather than failing.

### 3. Choosing how many CVEs to list

The 25 most recent are listed by default:

      malwoverview --nist 6 --NIST "C:\Windows\System32\win32k.sys"

      # The whole history instead
      malwoverview --nist 6 --NIST "C:\Windows\System32\win32k.sys" --ncves 0

      # A different number of rows
      malwoverview --nist 6 --NIST openssl --ncves 50

      # Bounded by year rather than by row count
      malwoverview --nist 6 --NIST "C:\Windows\System32\drivers\clfs.sys" --time 3

### 4. Choosing how the CVEs are ordered

Rows are listed most recent first, by the year in the CVE ID:

      malwoverview --nist 6 --NIST iCloud

NVD often publishes a record years after the ID was assigned, so the two
readings of "recent" disagree. Ordering by the publication date instead moves
those backfilled rows to the top:

      malwoverview --nist 6 --NIST iCloud --sort-by published

The flag applies to every --nist option, and --time bounds the results by the
same reference, so the order and the filter can no longer disagree:

      malwoverview --nist 6 --NIST iCloud --time 5
      malwoverview --nist 6 --NIST iCloud --time 5 --sort-by published

### 5. Reading the vendor column

NIST matches the words of a keyword separately, so a component named with common
words also matches other vendors' products. Only one of these eight rows is
really vmx86.sys, and the Vendor column says which:

      malwoverview --nist 6 --NIST "C:\Windows\System32\drivers\vmx86.sys"

The same column separates the vendors of a widely reused name:

      malwoverview --nist 6 --NIST Bluetooth

### 6. Searches that used to return almost nothing

A keyword search reported 1 CVE of the 74 that matched:

      malwoverview --nist 4 --NIST "Ancillary Function Driver"

A CPE without a version was silently a keyword search, and now reports the 137
CVEs of the product:

      malwoverview --nist 1 --NIST "cpe:2.3:a:openbsd:openssh"

A CPE with a concrete version still matches that exact version:

      malwoverview --nist 1 --NIST "cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*"

### 7. The component search in the other surfaces

      # Machine-readable: the records keep the full description and the vendors
      malwoverview --nist 6 --NIST openssl --output-format json

      # Light background
      malwoverview -o 0 --nist 6 --NIST "C:\Windows\System32\drivers\http.sys"

      # Interactive mode
      malwoverview --interactive
      #   malwoverview> nist component WebKit

      # TUI: pick NIST Component from the service list
      malwoverview --tui

## WHAT IS NEW IN 8.1.0, BY EXAMPLE

Everything this version adds or changes, as commands you can run. The narrative
version of the same list is the 8.1.0 block under HISTORY, below.

### 1. Options that changed number (read this first)

The only breaking change. The five Hybrid Analysis download options did the same
thing, so they collapsed into one and the two options after them moved down:

      # Download a sample from Hybrid Analysis  (was -a 11, -a 12, -a 13, -a 14 or -a 15)
      malwoverview -a 11 -A 495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979

      # Batch hash check from a file            (was -a 16)
      malwoverview -a 12 -A /home/remnux/malware/hashes.txt

      # Scan every file in a directory          (was -a 17)
      malwoverview -a 13 -A /home/remnux/malware/samples/

Every other option kept its number. All new numbers are additive.

### 2. Local analysis with no API key and no network request

      # Triage a directory: type, size, overlay, overlay size, entropy, signature
      malwoverview --peinfo /home/remnux/malware/samples/

      # Lower the bar for what counts as packed or encrypted (default 7.0)
      malwoverview --peinfo /home/remnux/malware/samples/ --entropy-threshold 6.5

      # Skip signature verification on a large sweep
      malwoverview --peinfo /home/remnux/malware/samples/ --no-signature

      # YARA now accepts a whole rules directory, scanned recursively
      malwoverview --yara /home/remnux/rules/ --yara-target /home/remnux/malware/samples/

### 3. Authenticode: is it signed, and is the signature valid?

      # One file: status, signer, issuer, certificate dates, thumbprint, serial
      malwoverview --sigcheck /home/remnux/malware/suspicious.exe

      # A whole directory, one row per file
      malwoverview --sigcheck /home/remnux/malware/samples/

A file can carry several embedded signatures — commonly SHA-1 for compatibility
plus SHA-256 — and the signers are often different. The table marks the extra
ones as (+N); run the single-file form to list them all. Which signature decides
the status is selectable:

      # Strongest digest decides (default, and what Windows honours)
      malwoverview --sigcheck /home/remnux/malware/driver.sys --sig-verify-mode best

      # First in file order decides (what sigcheck.exe reports)
      malwoverview --sigcheck /home/remnux/malware/driver.sys --sig-verify-mode first

      # Every signature must verify (strictest)
      malwoverview --sigcheck /home/remnux/malware/driver.sys --sig-verify-mode all

      # Any one signature verifying is enough (most permissive)
      malwoverview --sigcheck /home/remnux/malware/driver.sys --sig-verify-mode any

VirusTotal's own signature data is now shown as well, so a hash lookup reports
the signer chain, the signing date and every certificate thumbprint:

      # Signature block from VirusTotal, by hash
      malwoverview -v 8 -V 495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979

      # Same block when checking a local file
      malwoverview -v 1 -V /home/remnux/malware/suspicious.exe

### 4. Certificate Transparency through crt.sh (no API key)

      # Distinct DNS names seen in certificates issued for a domain
      malwoverview -ct 1 -CT example.com

      # The certificates themselves: identifier, issuer, common name, validity
      malwoverview -ct 2 -CT example.com

### 5. VirusTotal Retrohunt and Livehunt (needs an enterprise key)

      # Submit a Retrohunt job from a rules file or a rules directory
      malwoverview -v 14 -V /home/remnux/rules/hunting.yar

      # List your Retrohunt jobs, optionally filtered by status
      malwoverview -v 15
      malwoverview -v 15 -V finished

      # Status and progress of one job, then the files it matched
      malwoverview -v 16 -V 1234abcd-5678-90ef-1234-567890abcdef
      malwoverview -v 17 -V 1234abcd-5678-90ef-1234-567890abcdef

      # Create a Livehunt ruleset, list your rulesets, list notifications
      malwoverview -v 18 -V /home/remnux/rules/livehunt.yar
      malwoverview -v 19
      malwoverview -v 20

### 6. More places to get YARA rules, and how to pivot on them

A hash lookup now lists the YARA rules that matched the sample, which is where
the rule name for the next command comes from:

      # 1. look a sample up: the report ends with the rules that matched it
      malwoverview -b 1 -B 3b89db05cd1e6283a5d23e32eb6a6c17d92953c80c93befa194a0c93a633c1b5

              tags:         elf Mirai upx-dec
              yara rules:
                            ELF_Mirai
                            linux_generic_ipv6_catcher
                            unixredflags3

      # 2. take one of those names and pull every other sample it matched
      malwoverview -b 13 -B ELF_Mirai

The rule names also live in the rule sets themselves, which can be downloaded
and read locally:

      # Download the YARAify rule set from abuse.ch, then extract it.
      # Both use -O for the working directory; -b 15 finds the archive there.
      malwoverview -b 14 -O /home/remnux/rules/
      malwoverview -b 15 -O /home/remnux/rules/

The archive lands as /home/remnux/rules/yaraify-rules.zip and is extracted into
/home/remnux/rules/yaraify-rules/, one .yar file per rule. That directory is the
--yara target, and its file names are the rule names:

      malwoverview --yara /home/remnux/rules/yaraify-rules/ --yara-target /home/remnux/malware/samples/

A rule set collected from many authors will not compile cleanly against every
YARA version. Files with syntax errors are listed and skipped, and the scan runs
with the rest: a run of the set above compiled 548 of 557 files.

      # The complete Malpedia YARA ruleset for a TLP level
      malwoverview -m 9 -M white

### 7. Options that were broken and now work

      # -m 1 returned the family list; it now returns family meta information
      malwoverview -m 1

      # -l 6 lists the file types seen in the last 24 hours, -l 8 lists one of them
      malwoverview -l 6
      malwoverview -l 8 -L PE32

      # -ip 3 and -ip 7 used to be identical; -ip 3 is VirusTotal + OTX,
      # -ip 7 queries every configured service (IPInfo was never reached)
      malwoverview -ip 3 -IP 8.8.8.8
      malwoverview -ip 7 -IP 8.8.8.8

      # -j 8 (URLhaus batch hash check) was unreachable
      malwoverview -j 8 -J /home/remnux/malware/hashes.txt

### 8. Machine-readable output for every option

json and csv now work across the whole tool rather than a third of it:

      malwoverview -v 8 -V 495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979 --output-format json
      malwoverview --sigcheck /home/remnux/malware/samples/ --output-format csv
      malwoverview -b 6 -B 3 --output-format json

      # LLM enrichment reaches json and csv too, as a typed record
      malwoverview -v 8 -V 495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979 --enrich --output-format json

### 9. Keeping a lookup quiet, and keeping output safe to paste

      # Do not resolve attacker-controlled hostnames to IP addresses
      malwoverview -j 2 -J http://malicious.example.com/payload.bin --no-resolve

      # Defang the extracted IOCs so the list can be pasted into a ticket
      malwoverview --extract-iocs /home/remnux/malware/report.txt --defang

      # The source can equally be a URL, so a published report can be read and
      # its IOCs defanged in one step
      malwoverview --extract-iocs https://example.com/threat-report.html --defang

      # A vendor blog is mostly navigation, analytics and minified JavaScript, so
      # the extractor skips <script>, <style> and <svg>, drops links back to the
      # source site and to known page furniture, and only reports a domain whose
      # last label is a real top-level domain
      malwoverview --extract-iocs https://www.fortinet.com/blog/threat-research/dprk-related-campaigns-with-lnk-and-github-c2

      # Turn all of that off and report every regex match in the raw source
      malwoverview --extract-iocs https://example.com/threat-report.html --no-ioc-filter

### 10. Cache control

      malwoverview --cache-stats
      malwoverview --prune-cache
      malwoverview --clear-cache

### 11. Both interactive surfaces reach every service

      # Command-line REPL
      malwoverview --interactive

      # Full-screen dashboard: 111 services, Ctrl+V pastes, F5 exports json,
      # F6 exports csv
      malwoverview --tui

## WHAT IS NEW IN 8.0.0 TO 8.0.5, BY EXAMPLE

8.0.0 added a lot at once, so the commands are grouped here by what they are
for rather than by option number. 8.0.1 to 8.0.5 were mostly fixes and are at
the end. Where 8.1.0 later changed an option number, the command below uses the
current number and says what it used to be.

### 1. Five new services

      # URLScan.io (-u): submit a URL, fetch a result by id, search,
      # then look up a domain or an IP
      malwoverview -u 1 -U https://example.com
      malwoverview -u 2 -U 019ce889-ab8d-768b-894e-3e5bf5401f8d
      malwoverview -u 3 -U task.tags:phishing
      malwoverview -u 4 -U example.com
      malwoverview -u 5 -U 8.8.8.8

      # Shodan (-s): a single IP, or a search query
      malwoverview -s 1 -S 8.8.8.8
      malwoverview -s 2 -S "apache"

      # AbuseIPDB (-ab): IP reputation
      malwoverview -ab 1 -AB 185.220.100.243

      # GreyNoise (-gn): background internet noise, or aimed at you?
      malwoverview -gn 1 -GN 185.220.100.243

      # Whois / RDAP (-wh): a domain, then an IP
      malwoverview -wh 1 -WH example.com
      malwoverview -wh 2 -WH 8.8.8.8

The new IP services are also reachable from -ip, so one address can be taken
service by service, or through all of them at once:

      malwoverview -ip 4 -IP 8.8.8.8
      malwoverview -ip 5 -IP 8.8.8.8
      malwoverview -ip 6 -IP 8.8.8.8
      malwoverview -ip 7 -IP 8.8.8.8

### 2. One hash across several services in a single command

      malwoverview --correlate-hash ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585

### 3. Batch hash checks and directory scans

      # Malware Bazaar: a file of hashes, then a directory of samples
      malwoverview -b 11 -B /home/remnux/malware/hash_list.txt
      malwoverview -b 12 -B /home/remnux/malware/samples/

      # Hybrid Analysis (8.0.0 numbered these -a 16 and -a 17)
      malwoverview -a 12 -A /home/remnux/malware/hash_list.txt
      malwoverview -a 13 -A /home/remnux/malware/samples/

      # Triage
      malwoverview -x 8 -X /home/remnux/malware/hash_list.txt
      malwoverview -x 9 -X /home/remnux/malware/samples/

### 4. IOC extraction and YARA scanning

      # Pull hashes, IPs, URLs, domains, emails and CVEs out of a report
      malwoverview --extract-iocs /home/remnux/malware/report.txt
      malwoverview --extract-iocs /home/remnux/malware/report.pdf
      malwoverview --extract-iocs https://example.com/threat-report.html

      # Scan samples with YARA rules
      malwoverview --yara /home/remnux/rules/malware.yar --yara-target /home/remnux/malware/samples/

### 5. LLM enrichment of any result

      # Provider taken from the [LLM] section of .malwapi.conf
      malwoverview -v 8 -V <hash> --enrich

      # Override it per run: claude, gemini, openai or ollama
      malwoverview -v 8 -V <hash> --enrich --llm claude
      malwoverview --nist 2 --NIST CVE-2024-3400 --enrich --llm gemini

### 6. Structured output, reports and ATT&CK mapping

      malwoverview -v 8 -V <hash> --output-format json
      malwoverview -ip 1 -IP 8.8.8.8 --output-format csv

      malwoverview -v 12 -V <hash> --attack-map

      malwoverview -v 8 -V <hash> --report html --report-file /home/remnux/report.html
      malwoverview -v 8 -V <hash> --report pdf --report-file /home/remnux/report.pdf

### 7. Caching, proxying and verbosity

      malwoverview -v 8 -V <hash> --no-cache
      malwoverview -v 8 -V <hash> --cache-ttl 86400
      malwoverview -ip 3 -IP 8.8.8.8 --proxy socks5://127.0.0.1:9050
      malwoverview -v 8 -V <hash> --quiet
      malwoverview -v 8 -V <hash> --verbose

### 8. Two interactive surfaces

      malwoverview --interactive
      malwoverview --tui

### 9. What 8.0.1 to 8.0.5 fixed, as commands

      # 8.0.1: these take a file path again, not only a hash
      malwoverview -v 1 -V /home/remnux/malware/suspicious.exe
      malwoverview -a 1 -A /home/remnux/malware/suspicious.exe
      malwoverview -l 1 -L ab4d6a82cafc92825a0b88183325855f0c44920da970b42c949d5d5ffdcc0585

      # 8.0.2: batch IP check against VirusTotal, Premium then Public API
      malwoverview -ip 8 -IP /home/remnux/malware/ip_list.txt
      malwoverview -ip 8 -IP /home/remnux/malware/ip_list.txt -D 1

      # 8.0.2: Android scans work on current devices again, hashing with SHA256
      malwoverview -y 1
      malwoverview -y 2

      # 8.0.3 and 8.0.4: Claude enrichment works again and is rendered with colour
      malwoverview -v 8 -V <hash> --enrich --llm claude

      # 8.0.5: overlay and entropy in the directory check and the hash report
      malwoverview -d /home/remnux/malware/samples/
      malwoverview -v 8 -V <hash>

## HISTORY

Version 8.2.0:

      This version adds a component vulnerability search, gives every NIST
      query a chosen ordering reference, and repairs the queries themselves,
      which returned only a fraction of the CVEs that matched.

      NEW OPTIONS

      1. --nist 6 lists the CVEs associated with a component, given either its
         name or the path to a local binary. Naming it works on any platform:
         --nist 6 --NIST openssl, WebKit or Safari. Pointing at a Windows PE
         searches three keys and merges the results: the file name on disk, the
         internal name in its VERSIONINFO and its component description, so
         --nist 6 --NIST afd.sys matches 7 CVEs while passing the driver itself
         matches 74, because modern NVD entries name the component ("Ancillary
         Function Driver for WinSock") and not the file. A file that is not a
         Windows PE carries no such metadata, so only its name is searched and
         the report says so. Off Windows, name the project rather than the file
         it ships as: libssl.so.3 matches 9 CVEs where openssl matches 658.
         Results are a table, most recent first.

      REPAIRED OPTIONS

      2. --nist 1, 3, 4 and 5 returned only the last one percent of the CVEs
         that matched and discarded everything older than the previous year, so
         a keyword search for "Ancillary Function Driver" reported 1 CVE of the
         74 that matched and --time did not recover them. The queries now
         paginate through the whole result set, and a year filter is applied
         only when --time asks for one.

      3. --nist 1 sent a CPE to NIST only when the value carried a concrete
         version; every other value, including a CPE without a version, became
         a keyword search over the CVE text. A partial CPE is now matched as a
         CPE, so --nist 1 --NIST "cpe:2.3:a:openbsd:openssh" reports the 137
         CVEs of the product instead of the descriptions that mention it.

      NEW BEHAVIOUR

      4. All NIST results are ordered most recent first, by the year in the CVE
         ID. NVD often publishes a record years after its ID was assigned, so
         --sort-by published orders by the NVD publication date instead. The
         choice governs --time as well, which used to bound results by the CVE
         ID year while the table was ordered by publication date: --time 5 on
         a component listed 17 CVEs when 28 had been published inside that
         window. Both surfaces now use one reference, and the closing line of
         the table names which one produced the order.

      5. --nist 6 lists the 25 most recent CVEs, since the whole history of a
         component is rarely what is wanted. --ncves <number> lists more,
         --ncves 0 lists all and --time <years> bounds them by year.

      6. NIST matches the words of a keyword separately rather than as a
         phrase, so a component named with common words also matches other
         vendors' products: "HTTP Protocol Stack" matches Apache, Envoy and
         Novell CVEs. A Vendor column and a closing line name the vendors of
         the affected products, taken from the CPE data of each CVE, and the
         exported records carry them.

      7. --rpp is the page size used while paginating and defaults to 2000, the
         NIST maximum. A query that cannot be retrieved completely now says so
         instead of silently returning its oldest part.

      INTERACTIVE AND GRAPHICAL MODES

      8. The component search is reachable as "nist component <name|file>" in
         interactive mode and as NIST Component in the TUI.

      REPORTS

      9. Advisory lines are wrapped by terminal cells instead of by characters,
         so a value holding East Asian characters no longer runs past the rule
         of its own table. Every report that prints an advisory is affected.

      The changes below are security fixes.

      10. LOW: every value that becomes part of an NIST query is now length
          capped and stripped of terminal control characters, whether it was
          typed, taken from a file name or read out of a binary, and the file
          handle is released when a binary cannot be parsed.

      11. LOW: a negative --ncves printed an empty table instead of the CVEs
          that matched, and a negative --time discarded all of them. Both now
          list everything rather than reporting a component as clean.

Version 8.1.0:

      This version adds YARA hunting and local PE triage, repairs options
      that did not do what they announced, and includes a set of security
      fixes.

      ATTENTION: two options changed number. The five Hybrid Analysis download
      options (-a 11 to -a 15) are now a single option, -a 11. The batch hash
      check moved to -a 12 (it was -a 16) and the directory scan to -a 13 (it
      was -a 17). Nothing else changed number.

      NEW OPTIONS

            * --sigcheck: Authenticode signature checking of a file or a
              directory, with no API key and no network request. Reports VALID,
              TAMPERED, UNTRUSTED, EXPIRED, MALFORMED, INVALID, NONE or N/A with
              the signer, issuer and certificate dates. Every embedded signature
              is listed, each with its own digest algorithm, thumbprint and
              serial number. Verification needs
              pip install malwoverview[signature]; without it the status is
              PRESENT or NONE.

            * --sig-verify-mode any|first|all|best: which signature decides the
              status of a multi-signed file. Default best.

            * --no-signature: skips signature verification on large directories.

            * --peinfo and --entropy-threshold: local PE triage of a file or
              directory, listing file type, size, overlay, overlay size, entropy
              and signature status, highlighting files at or above the threshold
              (default 7.0). Recursive, no API key.

            * -ct 1|2 and -CT: Certificate Transparency through crt.sh, no API
              key. -ct 1 lists the DNS names seen in certificates issued for a
              domain, -ct 2 lists the certificates.

            * -v 14 to -v 20: VirusTotal Retrohunt and Livehunt. Submit a job,
              list jobs, follow a job, list matched files, create a ruleset, list
              rulesets and list notifications. Requires a premium key.

            * -b 13, -b 14 and -b 15: Malware Bazaar search by YARA rule name,
              and download and extraction of the YARAify rule set.

            * -m 9: download of the Malpedia YARA ruleset for a TLP level.

            * -l 8: lists the hashes of a MalShare file type given with -L.

            * -j 8: URLHaus batch hash check, which no option reached before.

            * --cache-stats, --prune-cache and --clear-cache.

            * --no-resolve: does not resolve or geolocate the host names shown by
              -j 2 and -j 3.

            * --defang: prints the IOCs listed by --extract-iocs as
              hxxp://example[.]com. Output only.

            * --no-ioc-filter: turns off the --extract-iocs noise filtering and
              reports every regex match in the raw source.

            * --yara now accepts a directory of rules, each file compiled in its
              own namespace. A file that fails to compile is reported and
              skipped.

      REPAIRED OPTIONS

            * -m 1 called the same endpoint as -m 5. It now retrieves the family
              meta information and accepts an optional filter with -M.

            * -l 6 was labelled "Composite(OLE)" and listed PDF samples. It now
              lists the file types seen in the last 24 hours with a count.

            * -ip 3 and -ip 7 produced identical output. -ip 3 now queries
              VirusTotal and AlienVault only; -ip 7 queries every remaining
              service, including IPInfo.

            * -l 1 wrote a zero byte file for every sample and reported success.
              Redirects are followed and an empty body is refused.

            * -a 6 to -a 10 and -y 4 always failed with "Requested URI - Not
              Found". Hybrid Analysis requests no longer go through the www host,
              whose redirect dropped the upload.

            * -b 14 answered HTTP 301. The rule set is fetched from the working
              address with the abuse.ch Auth-Key.

            * -v 20 reads the Livehunt notifications from the
              hunting_notification_files endpoint, which carries the sha256.

            * -b 6, -m 4 and the other options that consume an argument now
              require it. Eight of them stopped with a raw TypeError when it was
              omitted.

            * -A now accepts a native Windows path (-a 1 to -a 5), which was
              rejected as "Input contains invalid characters".

            * --report html, --report pdf and --enrich now work for
              --correlate-hash, --extract-iocs and --yara, which produced no
              report.

            * The Malpedia sample and rule downloads no longer end the program
              before the report and the json/csv export.

            * The validated form of every argument is now the one used. A URL
              written as hxxp://example[.]com was sent to the service still
              defanged, and paths such as ~/samples were not expanded.

            * -ip 2 (BGPView) is removed: its domain no longer resolves. The
              number is kept and reports the removal, pointing at -ip 1 and
              -ip 7. No other -ip number changed.

            * --defang is documented as applying to --extract-iocs only, which is
              the only option that reads it.

      NEW BEHAVIOUR

            * -y 1, -y 2 and -y 3 hash every APK of a package instead of the base
              APK alone. On the test device a scan went from 35 to 79 APKs.
              -y 4 and -y 5 report when the selected package is a split APK.

            * -b 1 lists the YARA rules that matched the sample, so a name can be
              passed to -b 13.

            * -v 1 and -v 8 show the signature block VirusTotal already returned:
              whether it verified, the signer and counter signer chains, the
              signing date and every certificate with its status, algorithm,
              dates, serial number and thumbprint.

            * --sigcheck and --peinfo report the certificate thumbprint, serial
              number and digest algorithm, in the report and in json and csv.

            * --extract-iocs no longer reports a web page's own code. On a vendor
              blog it returned 855 IOCs, 743 of them "domains" produced by
              minified JavaScript. Script, style, svg and noscript blocks are
              skipped, a domain is reported only when its last label is a real
              top-level domain, and links back to the source site and to page
              furniture are dropped: 855 IOCs became 16, keeping every sample
              hash and the command-and-control URLs. Suppression is counted and
              reported. Code-hosting, paste and messaging services are never
              suppressed.

            * --extract-iocs names the host and the kind of failure when a fetch
              fails, instead of printing the raw urllib3 exception.

            * A GreyNoise Community 404 is reported as the result it is, that the
              address is not an internet scanner, instead of an error.

            * A network failure no longer reaches the user as a Python traceback.
              43 try blocks caught only ValueError, so a connection error escaped
              uncaught. The host reported is taken from the parsed URL, never
              from the exception text.

            * A TLS failure is explained: a handshake that completes and then
              closes, a certificate that fails verification, a port that answers
              without TLS and a refused handshake each get their own line. The
              exception text is read but never printed.

            * crt.sh uses a patient retry policy (5 retries, 2 second backoff)
              because it answers the same URL with 200, 404 or 502 seconds apart.
              Every other service keeps the previous policy.

            * HTTP 429 is now retried, at most three times, honouring both forms
              of Retry-After and never waiting more than 300 seconds. Sample
              uploads are not retried.

            * The entropy calculation reads the file in blocks instead of loading
              it whole. The reported value does not change.

            * The YARA scanner no longer changes the working directory of the
              process while compiling rules.

            * --attack-map matching is exact instead of a substring search, which
              had attributed unrelated techniques (an empty tag matched all 691).
              It is extended to the Hybrid Analysis reports and --correlate-hash.

            * --enrich is sent the collected records instead of the text scraped
              from the terminal, and now works with --output-format json and csv,
              where it was silently ignored.

            * Every option now produces records for --output-format json and csv.
              Only a third of them did.

            * MalShare results are included in json and csv.

            * The [INQUEST] and [VIRUSEXCHANGE] sections are removed from
              .malwapi.conf and the code behind them.

            * The minimum Python version is 3.10, and the classifiers announce
              3.10 to 3.13.

      INTERACTIVE AND GRAPHICAL MODES

            * --interactive gains every command that only the command line had:
              the VirusTotal reports, uploads, behaviour report, batch check,
              Retrohunt and Livehunt; the Malware Bazaar imphash, download,
              batch, directory, YARA rule search and YARAify rule set; the
              URLHaus payload download, signature search, payload list, batch
              check and feed; the Triage submissions, downloads, dynamic report,
              batch and directory checks; the Malpedia family meta, payload list
              and rule set; the MalShare file type listings; the Hybrid Analysis
              submission, batch and directory checks; the ThreatFox family list;
              the IP batch and multi-service queries; and crtsh, android, yara,
              iocs and cache. ATT&CK is switched with "set attack on|off".

            * --tui is rebuilt on the module code used by the command line
              instead of its own copy of every service call: 3013 lines became
              818, and the service list went from 37 to 111 entries. Results
              export with F5 (json) and F6 (csv), which it did not support at
              all.

            * --tui pasting is fixed. A hash pasted before clicking into the
              query box was discarded without a message, because only the focused
              widget receives a paste and the dashboard starts on the service
              list. The paste is now caught for the whole window.

            * --tui gains Ctrl+V and Shift+Insert, which read the clipboard
              directly for terminals that never send a paste. No third-party
              package is needed.

            * The --tui key list is written again every time the results pane is
              cleared, and is built from the key bindings themselves. The key bar
              keeps Quit (as Ctrl+Q) and Paste while the query box has the focus,
              and its labels no longer repeat the key.

      REPORTS

            * --peinfo and --sigcheck size their columns from the files being
              scanned and never shorten the file name, which is commonly the
              SHA256. Type and Signer stay capped; a shortened value is shortened
              on screen only.

            * Every table column is measured in terminal cells rather than
              characters, so a CJK certificate subject or file name no longer
              pushes the columns out of line. Truncation stops on a character
              boundary.

            * The rules of a table now equal the sum of its columns, the column
              headers and rules are neutral, an empty cell reads n/a and the
              closing counts open with "[+] ". Applied to -j 8, -a 12, -a 13,
              -b 11, -b 12, -b 13, -x 8, -x 9, -l 6, -s 2, -u 3, --yara,
              --peinfo and --sigcheck, whose rules disagreed with their columns
              by as much as 51 characters.

            * The same treatment was completed across every remaining report.
              No rule is written as a fixed number any more: each is drawn from
              a named width or from the header it sits under, so the title, the
              rule and the columns can no longer disagree. 88 rules in 19 files,
              reaching every service the tool queries.

            * 38 report titles were padded with 28 trailing spaces, putting the
              title line past the rule below it. Invisible on screen and visible
              as soon as the output is piped, redirected or copied.

            * -b 6 to -b 10: long values are wrapped to the report width. A
              reference URL or a comma-joined alias list ran up to 137 columns
              under a 100 column rule; over one -b 6 run, 52 of 5936 lines did.

            * -j 2 to -j 7: each report is drawn to one width taken from the
              columns it actually prints, replacing the six different numbers
              (100, 104, 126, 130, 136 and 146) used before. -j 2 also sizes its
              URL column from the response and no longer prints its header twice.

            * -l 1 and -l 8 are tables. The header announced three columns
              centred at 75, 38 and 8 under a rule of 126, while the rows below
              printed "sha256: ... md5: ... type: ...", so the headers lined up
              with nothing. A MalShare error is no longer printed underneath a
              header promising results that never arrive.

            * -ct 1 and -ct 2: the report header is drawn to the width of the
              table it introduces, and the status, error and count lines are
              wrapped to it as bulleted advisories instead of running past it.

            * -a 12 and -a 13: a hash Hybrid Analysis has never seen produced a
              blank row and now reads not found, which is distinct from the
              verdict "unknown". An HTTP failure is reported as such. -a 13 no
              longer cuts every file name to 40 characters.

            * -j 8: the Status column showed the raw answer, so a hit read "ok".
              It now reads found, not found, invalid hash or bad request. The
              hash column follows the hashes in the file.

            * -x 8 and -x 9: the file name and the tags were cut with a plain
              slice and are now ellipsised, and the score is coloured by value.

            * -b 11 and -b 12: the Signature column is 17 columns and an unknown
              sample reads n/a instead of leaving a gap.

            * -s 2 is a table instead of four labelled lines per host, a hundred
              blocks for one query. The columns are IP, Port, Country, Product,
              Vulns and Organization. The raw banner is replaced by Product,
              which is what Shodan parsed from the banner or the Server header;
              the whole banner still reaches json and csv. Vulns is the number of
              CVEs Shodan lists against the host.

            * -u 3: the Score column was always zero, because the search endpoint
              returns no verdicts at all and the code defaulted the value; the
              json and csv records carried "malicious": "False" for every result
              of a phishing query. Both fields are gone, replaced by Age(d), the
              age of the domain in days, coloured by value. Cells are ellipsised
              instead of sliced, and the IP column no longer cuts an IPv6 address
              in half.

            * -u 2: the verdict, score, categories, tags and brands are
              highlighted instead of being drawn like the MIME type, values wrap
              instead of running off the screen, and the certificate dates are
              shown as UTC instead of raw epoch seconds. The page title is no
              longer cut at 80 characters.

            * -u 1: the closing note is prefixed with "[+] ", drawn as advice
              rather than as one more field, and carries the UUID of the scan
              just submitted so the retrieval command can be copied.

            * --correlate-hash, -wh 1 and -wh 2 wrap their values, with
              continuations aligned under the first line. A WHOIS status reached
              187 columns over a rule of 100, and the ATT&CK IDs of a pulse set
              reached 200. The SHA512 is broken across lines; the records keep
              every value on one line.

            * --yara no longer prints the per-file compiler errors, which are a
              property of the rule set rather than of the samples and pushed the
              report off the screen. The count stays in the summary and the
              detail is available with --verbose. The File and Rule columns are
              sized from their content, because cutting either breaks the link
              back to the sample or the rule.

            * The certificate block of -v 1 and -v 8 wraps at 120 columns. A
              status is one sentence per problem joined with commas and reached
              233 characters on one line.

            * --enrich output wraps to the width of the rule above it, with
              continuations indented under a list marker. The json and csv
              records keep the unwrapped answer.

            * -y 1 reports its APK inventory at the end of the table rather than
              above it, prefixed with "[+] " in the neutral colour. The rows are
              printed by one thread per package and those threads were never
              joined outside Windows, so the line is now printed after they are.
              -y 2 and -y 3 are treated the same way.

            * -ip 3 and -ip 7: the two cross-reference notes are prefixed with
              "[+] ", where they read as part of the data above them.

            * A YARA rule file that is skipped now reports why. The path took the
              whole line and the reason was cut off.

            * The json and csv output of --correlate-hash, --extract-iocs and
              --yara no longer starts with a blank line.

            * The reports are no longer printed to the standard output together
              with the json or the csv, which made the result impossible to
              parse, and twenty-nine functions no longer end the program before
              the export. The text goes to the standard error when a command
              produces no record, so a failure can be told apart from an empty
              result.

            * The csv written to the standard output on Windows no longer follows
              every row with a blank one, and both the json and the csv are
              written in UTF-8 rather than the encoding of the console.

            * The csv written by "export csv" in the interactive mode no longer
              ends every line with two carriage returns on Windows.

            * A certificate holding characters the console cannot represent no
              longer ends the run with UnicodeEncodeError.

            * An invalid escape sequence in the PolySwarm family search no longer
              emits a SyntaxWarning.

            * A truncated or corrupt ATT&CK cache no longer crashes with "Error
              while connecting to Virus Total!". It is detected, downloaded again
              and written atomically.

            * A refused Hybrid Analysis submission no longer stops with a
              KeyError; the reason given by the service is printed.

            * 43 handlers around a request caught only ValueError, so a network
              failure could still reach the user as a Python traceback. They now
              catch the request errors too and name the service and the host.
              The message never contains the exception text, because MalShare
              and Shodan carry the API key in the URL.

            * Seven of those handlers in URLHaus were unreachable: a broader
              handler above them caught the failure first, printed nothing and
              exited. -j 7 against an unreachable service printed a header, a
              rule and nothing else, which reads exactly like a search that
              found nothing.

            * --defang now also defangs the Source line of the IOC extraction
              report, so the whole report can be pasted somewhere safely. A
              local file path is left alone, and the exported record keeps the
              real value in both cases.

            * The SUBCOMMANDS list in this file advertised "ip bgp", removed in
              this release, omitted "ip batch" and "urlhaus batch", and listed a
              urlscanio subcommand that has never existed. URLScan.io is
              reachable through -u.

      COLOURS

            * On a light background neither cyan nor light blue is used any more,
              only blue. On a dark background both remain in use. This changed
              298 places across 16 files, including the shared info() colour.

            * An audit of the whole package found 26 further places that broke
              the rule, some inside a background test and some coloured once for
              both backgrounds. Green on dark is now light green.

            * The neutral colour was never applied on Windows with a dark
              background: it was written as an extended 256 colour escape, which
              the converter colorama uses understands only the basic codes, so it
              was dropped and the previous colour stayed in force. Every table
              rule, column header and bulleted advisory was affected.

            * -x 8 and -x 9: the Tags column is light blue on dark and blue on
              light. It used the same tone as the Hash column beside it.

            * -b 1: the field labels are light cyan on dark and blue on light,
              matching every other report; the light background used green.

            * -j 8: the hash column is light purple on dark and blue on light.
              The status column is grey until there is something to report.

            * -ab 1: the field labels are light blue on dark and blue on light.

            * -y 1: the Package column is light blue on dark.

            * -y 2 and -y 3: the Hash column is pink on dark and purple on light.

            * -s 2: the Product column is light blue on dark and cyan on light.

      The changes below are security fixes. None of them changes any command
      syntax.

            * Fixes terminal escape sequence injection coming from service
              responses (HIGH). Attacker-controlled fields printed to the
              terminal (the VirusTotal behavior data and sample names, the
              Malware Bazaar and URLHaus file names, signatures and tags, the
              AlienVault OTX pulse names and descriptions, the ThreatFox and
              Hybrid Analysis fields) were able to move the cursor and overwrite
              a verdict already printed, set the window title, write to the
              clipboard or clear the screen. Every JSON response is now sanitized
              as soon as it is parsed.

            * Fixes the same escape sequence injection in the graphical mode
              (HIGH). --tui parsed the service responses itself in sixteen
              places, none of them sanitized. It no longer parses any response.

            * Fixes terminal escape sequence injection coming from the command
              line and from input files (MEDIUM). -B, -X, -TR, -S, -M, -L, -NIST
              and the other free text arguments accepted ESC, the 8-bit CSI and
              backspace, and the validators echoed a rejected value back to the
              terminal without cleaning it first. This affected Linux and macOS
              only.

            * Fixes terminal escape sequence injection from three further sources
              (MEDIUM): the values extracted by --extract-iocs, whose URL pattern
              excluded whitespace but not the other control characters; the WHOIS
              fields, which arrive as plain text written by the registrar and the
              registrant; and the sha256 read from a USB-connected Android
              device, which is now checked against an allowlist of 64 hexadecimal
              characters.

            * Fixes a denial of service in --extract-iocs (MEDIUM). The HTML
              handling removed script, style, svg and comment blocks with a lazy
              regular expression, which is quadratic when the opening tag is
              never closed: 50,000 unterminated script tags in 400 KB took 158
              seconds, and the option reads up to 10 MB from a URL. The blocks
              are now removed by a single forward scan.

            * Fixes a possible denial of service in the IOC extraction
              (LOW/MEDIUM): the domain and e-mail regular expressions could take
              a very long time on a crafted document. The text is now split into
              bounded tokens before the matching, and the extracted IOCs are
              unchanged.

            * Fixes CSV formula injection in the exported reports (MEDIUM).
              Values starting with "=", "+", "-", "@" or a tab were run as
              formulas by Excel and LibreOffice. They are now prefixed with a
              single quote, and embedded line breaks are removed.

            * Fixes CSV formula injection in the header row of the exported
              reports (LOW). The column names are taken from the service
              response and were written without the protection above.

            * Fixes escape sequences reaching the terminal through an error
              message in the interactive and graphical modes (LOW). Both printed
              the text of an unhandled exception without cleaning it.

            * Fixes DNS rebinding in --extract-iocs (MEDIUM). The address that
              was validated is now the address connected to, while the host name
              is kept in the Host header and in the TLS SNI. Host names that
              cannot be resolved are refused. Requests made through a proxy are
              not pinned.

            * Fixes a bypass of the private address protection using IPv4-mapped
              IPv6 addresses such as ::ffff:127.0.0.1 (MEDIUM). The multicast and
              unspecified addresses are also refused now.

            * Fixes the exposure of API keys in error messages (MEDIUM). The
              Malshare and Shodan keys are replaced by [REDACTED], and the
              Malshare connection errors are handled instead of raising an
              exception.

            * Adds a default timeout of 15 seconds to connect and 180 seconds to
              read on every HTTP request that does not set its own (MEDIUM).

            * Stops sending the full local path of the sample to VirusTotal
              (LOW/MEDIUM). Only the file name is sent on -v 9.

            * Refuses APK paths containing ".." during the Android scans (LOW).

            * Sanitizes the file name used in the Triage submission (LOW).

            * Removes every escape sequence from the LLM enrichment output, and
              no longer only the color ones (LOW).

            * Warns when .malwapi.conf is readable by other users and suggests
              "chmod 600" (Linux and macOS).

Version 8.0.5:

      This version:

            * Adds overlay and entropy reporting to the VirusTotal options: the
              directory check (-d) gains an "Overlay" column (YES/NO, or N/A for
              non-PE files) and an "Ent" column (0.00 to 8.00), the file report
              (-v 1/2/3) gains the overlay, its size in KB/MB and the entropy,
              and the hash report (-v 8) gains the overlay and size taken from
              VirusTotal's pe_info data without downloading the sample. Entropy
              is the highest per-section entropy of the PE, the best signal for
              packed or encrypted sections, falling back to the whole-file
              Shannon entropy for non-PE files. "AV Detection" is renamed to
              "AV" and the -d table is realigned.

Version 8.0.4:

      This version:

            * Renders the LLM enrichment report with color instead of raw
              Markdown: headings and **bold** key terms are highlighted and the
              markup symbols removed. On a dark background the body text uses a
              near-white tone while headings keep their blue/purple/cyan
              accents. The CLI, the REPL and the TUI share the renderer, and the
              prompts ask the model for that structure so it stays consistent.

Version 8.0.3:

      This version:

            * Fixes Claude (Anthropic) LLM enrichment, which failed on every
              call because the model name was hard-coded to a retired model. It
              is now set by CLAUDE_MODEL in the [LLM] section of .malwapi.conf,
              alongside GEMINI_MODEL / OPENAI_MODEL / OLLAMA_MODEL, and defaults
              to claude-opus-4-8. Claude is also the default provider now, and
              the fix covers the CLI, the REPL and the TUI.

Version 8.0.2:

      This version:

            * Introduces a batch IP check against VirusTotal (-ip 8 / "ip
              batch"), which reads one IP address per line from a file and
              prints the IP Address, Country, AS Owner and detection ratio.
              Use -D 1 for the Public API, which sleeps 61s every 4 IPs to
              honour the rate limit, or -D 0 for Premium (default).

            * Fixes the Android device-scan options (-y 1, -y 2 and -y 3), which
              had stopped working on current Android versions. The package
              listing now understands the modern /data/app layout (the '~~'
              prefix and '==' segments introduced in Android 10+) and adb's CRLF
              output, so the options also work on Windows. On-device hashing uses
              sha256sum instead of md5sum, and clear messages are printed when
              adb is not in the PATH or no third-party packages are found.

            * Fixes two SSRF bypasses in --extract-iocs <url>. The first (issue
              #96) validated with urlparse() while requests normalized the URL
              differently, so http://127.0.0.1:6666\@1.1.1.1 passed the
              public-hostname check and still reached an internal address; the
              validator now rejects backslashes, whitespace and control
              characters and validates the effective URL taken from
              requests.PreparedRequest. The second followed redirects
              automatically after the check had already passed, letting a public
              URL reach an internal or cloud-metadata address such as
              169.254.169.254; every hop is now re-validated against the
              private/reserved-address allowlist, with a redirect limit.

            * Hardens the Android send options (-y 4 and -y 5) against a path
              traversal from a malicious or compromised device: the package name
              reported by adb is restricted to valid Android package characters
              and the output file name is reduced to its base name, so a crafted
              package listing cannot write outside the output directory.

Version 8.0.1:

      This version:

            * Fixes a regression where -v 1, -v 2, -v 3, -v 4 (VirusTotal
              file submission options) and -v 10, -v 11 (VirusTotal batch
              hash check) were incorrectly validated as hashes instead of
              file paths. Now these options accept filenames as they did
              in 7.1.2.
            * Fixes a regression where -a 1 through -a 5 (Hybrid Analysis
              hash/file auto-detect options) were incorrectly validated as
              hashes only. Adds sanitize_hash_or_path to accept either.
            * Fixes a regression where -a 6 through -a 10 (Hybrid Analysis
              file upload options) and -a 16, -a 17 (batch/dir check) were
              being double-validated as both hash and path, causing failures.
            * Adds missing CLI input validation for Polyswarm (-p 1 through
              -p 8) and Malshare (-l 1 with -L <hash>).

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


