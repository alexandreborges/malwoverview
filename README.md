# Malwoverview.py

![Alt text](malwoverview.jpg?raw=true "Title")

version 1.1 


      Copyright (C)  2018 Alexandre Borges <ab at blackstormsecurity dot com>

      This program is free software: you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published by
      the Free Software Foundation, either version 3 of the License, or
      (at your option) any later version.

      This program is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      GNU General Public License for more details.

      See GNU Public License on <http://www.gnu.org/licenses/>.



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


# REQUERIMENTS

This tool was tested on a Kali Linux 2018 system. Therefore, it will be necessary to install:

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
       
      
      
# USAGE

To use the malwoverview, execute the command as shown below:

      $ python malwoverview.py -d <directory> -b 0|1 -v 0|1
      
  where: 
  
        <directory> is the folder containing malware samples. 
        (optional) -b 1 forces light gray backgound (for black terminals).
        (optional) -v 1 queries Virus Total database for positives and totals.
        
        If you use Virus Total option, so it is necessary to edit the malwoverview.py and insert your VT API.
        
  
        *ATENTION: if the directory contains many malware samples, so malwoverview.py could take some time. :)
  
# NEXT VERSIONS

Next version will include detection of the packing's type. :)
