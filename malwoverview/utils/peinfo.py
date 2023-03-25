import pefile
from utils.colors import mycolors, printr
import modules.configvars as cv
import magic


def ftype(filename):
    type = magic.from_file(filename)
    return type


def isoverlay(file_item):
    mype2 = pefile.PE(file_item)
    over = mype2.get_overlay_data_start_offset()
    if over is None:
        ovr = "NO"
    else:
        ovr = "YES"
    return ovr


def overextract(fname):
    with open(fname, "rb") as o:
        r = o.read()
    pe = pefile.PE(fname)
    offset = pe.get_overlay_data_start_offset()
    if offset is None:
        exit(0)
    with open(fname + ".overlay", "wb") as t:
        t.write(r[offset:])
    if (cv.bkg == 1):
        print((mycolors.foreground.yellow + "\n\nOverlay extracted:   " + mycolors.reset + "%s.overlay" % fname))
    else:
        print((mycolors.foreground.green + "\n\nOverlay extracted:   " + mycolors.reset + "%s.overlay" % fname))
    printr()


def listexports(fname):
    exps = []

    mype2 = pefile.PE(fname, fast_load=True)
    if mype2.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress != 0:
        mype2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        for exptab in mype2.DIRECTORY_ENTRY_EXPORT.symbols:
            x = hex(mype2.OPTIONAL_HEADER.ImageBase + exptab.address), exptab.name
            exps.append(x)

    return exps


def listimports(fname):
    imps = []

    mype2 = pefile.PE(fname, fast_load=True)
    if mype2.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
        mype2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if mype2.DIRECTORY_ENTRY_IMPORT is not None:
            for entry in mype2.DIRECTORY_ENTRY_IMPORT:
                for imptab in entry.imports:
                    if imptab.name is None:
                        imptab.name = "None"
                    if imptab.address is None:
                        imptab.address = int(0)
                    x = hex(int(imptab.address)), imptab.name
                    imps.append(x)
    return imps


def list_imports_exports(targetfile):
    printr()

    print(("\nImported Functions".ljust(40)))
    print((110 * '-').ljust(110))
    IR = []
    IR = sorted(listimports(targetfile))
    dic = {}
    dic = dict(IR)
    d = iter(list(dic.items()))
    IX = []
    for key, value in sorted(d):
        IX.append(str(value))
    Y = iter(IX)

    for i in Y:
        if i is None:
            break

        while (i == 'None'):
            i = next(Y, None)

        if i is None:
            break
        if (cv.bkg == 1):
            print((mycolors.foreground.pink + "%-40s" % (i)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.cyan + "%-40s" % (i)[2:-1]), end=' ')
        w = next(Y, None)
        if w is None:
            break
        if (w == 'None'):
            w = next(Y, None)
        if w is None:
            break
        if (cv.bkg == 1):
            print((mycolors.foreground.lightcyan + "%-40s" % (w)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.green + "%-40s" % (w)[2:-1]), end=' ')
        t = next(Y, None)
        if t is None:
            break
        if (t == 'None'):
            t = next(Y, None)
        if t is None:
            break
        if (cv.bkg == 1):
            print((mycolors.foreground.yellow + "%-40s" % (t)[2:-1]))
        else:
            print((mycolors.foreground.purple + "%-40s" % (t)[2:-1]))

    printr()

    print(("\n\nExported Functions".ljust(40)))
    print((110 * '-').ljust(110))
    ER = []
    ER = sorted(listexports(targetfile))
    dic2 = {}
    dic2 = dict(ER)
    d2 = iter(list(dic2.items()))
    EX = []
    for key, value in sorted(d2):
        EX.append(str(value))
    Y2 = iter(EX)
    for i in Y2:
        if i is None:
            break
        while (i == 'None'):
            i = next(Y2, None)
        if i is None:
            break
        if (cv.bkg == 1):
            print((mycolors.foreground.yellow + "%-40s" % (i)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.purple + "%-40s" % (i)[2:-1]), end=' ')
        w = next(Y2, None)
        if w is None:
            break
        if (w == 'None'):
            w = next(Y2, None)
        if w is None:
            break
        if (cv.bkg == 1):
            print((mycolors.foreground.lightcyan + "%-40s" % (w)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.green + "%-40s" % (w)[2:-1]), end=' ')

        t = next(Y2, None)
        if t is None:
            break
        if (t == 'None'):
            t = next(Y2, None)
        if t is None:
            break
        if (cv.bkg == 1):
            print((mycolors.foreground.lightcyan + "%-40s" % (t)[2:-1]))
        else:
            print((mycolors.foreground.cyan + "%-40s" % (t)[2:-1]))

    printr()
