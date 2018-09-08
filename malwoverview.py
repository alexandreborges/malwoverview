#!/usr/bin/python

# Copyright (C)  2018 Alexandre Borges <ab@blackstormsecurity.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See GNU Public License on <http://www.gnu.org/licenses/>.

import os
import sys
import re
import pefile
import peutils
import magic
import optparse

from colorama import Fore, Back, Style

F = []
H = []

def ftype(filename):
    type = magic.from_file(filename)
    return type

def packed(pe):
    try:
       
        n = 0
        
        for sect in pe.sections:
            if sect.SizeOfRawData == 0:
                n = n + 1
            if (sect.get_entropy() < 1 and sect.get_entropy() > 0) or sect.get_entropy() > 7:
                n = n + 2
        if n > 2:
            return True
        if (n > 0 and n < 3):
            return "probably packed"
        else:
            return False

    except:
        return None

if __name__ == "__main__":
        
    backg=0

    parser = optparse.OptionParser("malwoverview "+"-d <directory> -b <0|1>")
    parser.add_option('-d', dest='direct',type='string',help='directory containing malware samples.')
    parser.add_option('-b', dest='backg', type='int',default = 0, help='(optional) forces light gray background (for black terminals).')
    (options, args) = parser.parse_args()
    
    optval = [0,1]
    repo = options.direct
    bkg = options.backg

    if (options.direct == None):
        print parser.usage
        exit(0)
    if (options.backg) not in optval:
        print parser.usage
        exit(0)

    directory = repo
    if os.path.isabs(directory) == False:
        directory = os.path.abspath('.') + "/" + directory
    os.chdir(directory)

    for file in os.listdir(directory):


        filename = str(file)
        if os.path.isdir(filename) == True:
            continue
        targetfile = ftype(filename)
        if re.match(r'^PE[0-9]{2}|^MS-DOS', targetfile):
            mype = pefile.PE(filename)
            imph = mype.get_imphash()
            F.append(filename)
            H.append(imph)
        else:
            continue

    d = dict(zip(F,H))
    n = 30
    prev1 = 0
    prev2 = 0
    result = ""

    if (bkg == 1):
        print (Back.WHITE + "\n")
    else:
        print "\n"

    print "FileName".center(32) +  "ImpHash".center(37) + "Packed?".center(9) + "Overlay?".center(10)+ ".text_entropy".center(13)
    print (32*'-').center(32) +  (36*'-').center(35) + (11*'-').center(10) + (10*'-').ljust(10) + (13*'-').center(13)


    for key,value in sorted(d.iteritems(), key=lambda (k,v):(v,k)):

        prev1 = value

        mype2 = pefile.PE(key)
        over = mype2.get_overlay_data_start_offset()
        if over == None:
            ovr =  ""
        else:
            ovr =  "OVERLAY"
        rf = mype2.write()
        entr = mype2.sections[0].entropy_H(rf)
        pack = packed(mype2)
        if pack == False:
            result = "no"
        elif pack == True:
            result = "PACKED"
        else:
            result = "Likely"

        if ((prev2 == prev1) and (n < 36)):
            print("\033[%dm" % n + "%-32s" % key), 
            print("\033[%dm" % n + "  %-32s" % value), 
            print("\033[%dm" % n + "  %-6s" % result), 
            print("\033[%dm" % n + "  %7s" % ovr), 
            print("\033[%dm" % n + "      %4.2f" % entr)
        else:
            if ((n > 35) and (prev1 != prev2)):
                n = 29
            elif (n > 35):
                n = 35
            n = n + 1
            print("\033[%dm" % n + "%-32s" % key), 
            print("\033[%dm" % n + "  %-32s" % value), 
            print("\033[%dm" % n + "  %-6s" % result), 
            print("\033[%dm" % n + "  %7s" % ovr), 
            print("\033[%dm" % n + "      %4.2f" % entr)
            prev2 = value

