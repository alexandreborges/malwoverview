import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors


def debug(msg):
    if cv.verbosity >= 1:
        print(mycolors.foreground.darkgrey + "[DEBUG] " + str(msg) + mycolors.reset)


def info(msg):
    if cv.verbosity >= 0:
        print(str(msg))


def warn(msg):
    print(mycolors.foreground.yellow + "[WARN] " + str(msg) + mycolors.reset)
