# Malwoverview

version 1.0 

# ABOUT

Malwoverview is a simple tool to make an initial triage on a directory containing malware samples.  

This tool aims to : 

1. Determining similar executable malware samples (PE/PE+) through the import table (imphash) and group them by different color. 
2. Determining whether executable malware samples are packed or not packed according to the following rules:
      
      a. More than one section with Entropy > 7.0 or SizeOfRawData ==> Packed.
      b. One one section with Entropy > 7.0 or SizeOfRawData ==> Likely packed.
      c. None section with Entropy > 7.0 or SizeOfRawData ==> not packed.
      
3. Determining whether the malware samples contain overlay.
4. Determining the .text section entropy. 

Malwoverview is a tool that should be used against only PE/PE+ files.  



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
      
      
# Usage

To use the malwoverview, execute the command as shown below:

      $ python malwoverview <directory>
      
  where <directory> is the folder containing malwares. 
      
      

