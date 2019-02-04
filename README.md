# Malwoverview.py

![Alt text](malwoverview1_1.jpg?raw=true "Title")


(Gaps in the VT output at image above are because public VT API key, which allows only 4 searches per minute).  



![Alt text](malwoverview1_2a2.jpg?raw=true "Title")
![Alt text](malwoverview1_2b1.jpg?raw=true "Title")
![Alt text](malwoverview1_3a.jpg?raw=true "Title")
![Alt text](malwoverview1_4d.jpg?raw=true "Title")
![Alt text](malwoverview_145a.jpg?raw=true "Title")
![Alt text](malwoverview_145b.jpg?raw=true "Title")
![Alt text](malwoverview_145c.jpg?raw=true "Title")
![Alt text](malwoverview1_5.jpg?raw=true "Title")
![Alt text](malwoverview1_5_a.jpg?raw=true "Title")
![Alt text](malwoverview1_5_b.jpg?raw=true "Title")
![Alt text](malwoverview1_5_c.jpg?raw=true "Title")


      Copyright (C)  2018-2019 Alexandre Borges <ab at blackstormsecurity dot com>

      This program is free software: you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published by
      the Free Software Foundation, either version 3 of the License, or
      (at your option) any later version.

      This program is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      GNU General Public License for more details.

      See GNU Public License on <http://www.gnu.org/licenses/>.


# Current Version: 1.5.0

## Important aspect:  Malwoverview does NOT submit samples to VT by default. It submits only hashes, so respecting Non-Disclosure Agreements (NDAs). Nonetheless, if you use the "-V" (upcase), so Malwoverview SUBMIT your sample to Virus Total. 

# ABOUT

Malwoverview.py is a simple tool to perform an initial and quick triage on a directory containing malware samples (not zipped).  

This tool aims to : 

1. Determining similar executable malware samples (PE/PE+) according to the import table (imphash) and group them by different colors (pay attention to the second column from output). Thus, colors matter!
2. Determining whether executable malware samples are packed or not packed according to the following rules:
      
      
            2a. Two or more sections with Entropy > 7.0 or < 1.0 ==> Packed.

            2b. One one section with Entropy > 7.0 or two sections with SizeOfRawData ==> Likely packed.

            2c. None section with Entropy > 7.0 or SizeOfRawData ==> not packed.
      
      
3. Determining whether the malware samples contain overlay.
4. Determining the .text section entropy. 


            Malwoverview.py only examines PE/PE+ files, skipping everything else.  

5. Checking each malware sample against Virus Total. 


# REQUERIMENTS

This tool was tested on a Kali Linux 2018 system and Windows 10. Therefore, it will be necessary to install:

## Kali Linux

1. Python version 2.7.x. 

       $ apt-get install python
            
2. Python-magic.  

      To install python-magic package you can execute the following command:
      
       $ pip install python-magic
      
      Or compiling it from the github repository:
      
       $ git clone https://github.com/ahupp/python-magic
       $ cd python-magic/
       $ python setup.py build
       $ python setup.py install
      
      As there are serious problems about existing two versions of python-magic package, my recommendation is to install it
      from github (second procedure above) and copy the magic.py file to the SAME directory of malwoverview tool. 
      
3. Pefile and colorama packages: 

       $ pip install pefile
       $ pip install colorama
       $ pip install simple-json
       $ pip install requests
       $ pip install validators

## Windows

1. Install the Python version 2.7.x. from https://www.python.org/downloads/windows/ 

2. Python-magic.  

      To install python-magic package you can execute the following command:
      
       C:\> pip install python-magic
      
      Or compiling it from the github repository:
      
       C:\> git clone https://github.com/ahupp/python-magic
       C:\> cd python-magic/
       C:\> python setup.py build
       C:\> python setup.py install
      
3. Pefile and colorama packages: 

       C:\> pip install pefile
       C:\> pip install colorama
       C:\> pip install simple-json
       C:\> pip install requests
       C:\> pip install validators
       
4. (IMPORTANT) Remove the magic.py file from malwoverview directory.

5. Install the python-magic DLLs by executing the following command:

       C:\> pip install python-magic-bin==0.4.14 

## Virus Total and Hybrid-Analysis.

You must edit the malwoverview.py and insert your APIs and secret to enable Virus Total and Hybrid-Analysis checking:

VT: 

      VTAPI = '<----ENTER YOUR API HERE and UNCOMMENT THE LINE---->'

Hybrid-Analysis: 

      HAAPI = '<----ENTER YOUR API HERE and UNCOMMENT THE LINE---->'    
      HASECRET = '<----ENTER YOUR SECRET HERE and UNCOMMENT THE LINE---->'
       
# USAGE

To use the malwoverview, execute the command as shown below:

      $ malwoverview -d <directory> -f <fullpath> -i <0|1> -b <0|1> -v <0|1> -a <0|1> -p <0|1> -s <0|1> -x <0|1>
        -w <|1> -u <url> -H <hash file> -V <filename>

  where: 
  
        <directory> -d is the folder containing malware samples. 
        <fullpath>  -f specifies the full path to a file. Shows general information about the file (any filetype).
        (optional)  -b 1 (optional) adapts the output colors to black window.
        (optional)  -i 1 show imports and exports (it is used with -f option).
        (optional)  -x 1 extracts overlay (it is used with -f option).
        (optional)  -v 1 queries Virus Total database for positives and totals (any filetype).
        (optional)  -a 1 (optional) query Hybrid Analysis database for general report.Thus, you need to edit the 
                          malwoverview.py and insert your HA API and respective secret.
        (optional)  -s 1 shows antivirus reports from the main players. This option is used with 
                         -f option (any filetype). 
        (optional)  -p 1 use this option if you have a public Virus Total API. It forces a one minute wait 
                         every 4 malware samples, but allows obtaining a complete evaluation of the malware repository.
        (optional)  -w 1 used when the OS is Microsoft Windows.
                    -u <url> SUBMIT a URL to the Virus Total scanning.
                    -H <filehash> hash to be checked on Virus Total and Hybrid Analysis.
                    -V <file name> SUBMIT a FILE(up to 32MB) to Virus Total scanning and read the report. 
                        Attention: use forward slash to specify the target file even on Windows systems. Furthermore, 
                        the minimum waiting time is set up in 90 seconds because the Virus Total queue. If an error 
                        occurs, so wait few minutes and try to access the report by using -f option.

        If you use Virus Total option, so it is necessary to edit the malwoverview.py and insert your VT API. 
        
        Remember that public VT API only allows 4 searches per second (as shown at the image above). Therefore, if you 
        are willing to wait some minutes, so you can use the -p option, which forces a one minute wait every 4 malware 
        samples, but allows obtaining a complete evaluation of the repository.
        
  
        *ATENTION: if the directory contains many malware samples while using -d option, so malwoverview.py could 
         take some time. :)
  
# HISTORY

Version 1.5.0:

      This version: 
      
            * Includes the -u option to check URLs against Virus Total and associated engines. 
            * Includes the -H option to find existing reports on Virus Total and Hybrid Analysis through the hash.
            * Includes the -V option to submit a file to Virus Total. Additionally, the report is shown afer few minutes.
            * Includes two small fixes. 

Version 1.4.5.1:

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
            * Adds the -i option for listing imported and exported functions. Therefore, imported/exported function 
              report was decoupled for a separated option.  
                  
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

      Malwoverview is a tool to perform a first triage of malware samples in a directory and group them according 
      to their import functions (imphash) using colors. This version:

            * Shows the imphash information classified by color. 
            * Checks whether malware samples are packed.  
            * Checks whether malware samples have overlay. 
            * Shows the entropy of the malware samples. 


