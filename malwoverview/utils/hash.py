import hashlib
import os
from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv


def sha256hash(fname):
    BSIZE = 65536
    hnd = open(fname, 'rb')
    hash256 = hashlib.sha256()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hash256.update(info)
    return hash256.hexdigest()


def md5hash(fname):
    BSIZE = 65536
    hnd = open(fname, 'rb')
    hashmd5 = hashlib.md5()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    return hashmd5.hexdigest()


def calchash(ffpname2):
    targetfile = ffpname2
    mysha256hash = ''
    dname = str(os.path.dirname(targetfile))
    if not os.path.abspath(dname):
        dname = os.path.abspath('.') + "/" + dname

    print(mycolors.reset, end=' ')

    try:
        mysha256hash = sha256hash(targetfile)
        return mysha256hash
    except Exception:
        if (cv.bkg == 1):
            print((mycolors.foreground.lightred + "Error while calculing the hash!\n"))
        else:
            print((mycolors.foreground.red + "Error while calculating the hash\n"))
        printr()
