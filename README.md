# Malwoverview


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
