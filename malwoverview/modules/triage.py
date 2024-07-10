import malwoverview.modules.configvars as cv
from requests import Request
from malwoverview.utils.colors import mycolors, printr
import binascii
import textwrap
from io import BytesIO
import requests
import json
import os


class TriageExtractor():
    triageurl = 'https://api.tria.ge/v0/'

    def __init__(self, TRIAGEAPI):
        self.TRIAGEAPI = TRIAGEAPI

    def requestTRIAGEAPI(self):
        if (self.TRIAGEAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Triage, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Triage API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def triage_search(self, triagex):
        triage = TriageExtractor.triageurl + "search?query="
        triagetext = ''
        triageresponse = ''

        self.requestTRIAGEAPI()

        try:
            print("\n")
            print((mycolors.reset + "TRIAGE OVERVIEW REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json', 'Authorization': 'Bearer ' + self.TRIAGEAPI})
            triageresponse = requestsession.get(triage + triagex)
            triagetext = json.loads(triageresponse.text)

            if 'error' in triagetext:
                if triagetext['error'] == "NOT_FOUND":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided argument was not found!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided argument was not found!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided argument is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided argument is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "UNAUTHORIZED":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID_QUERY":
                    if (cv.bkg == 1):
                        print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                    else:
                        print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                    exit(1)

            if (cv.bkg == 1):
                for i in triagetext.keys():
                    if (i == "data"):
                        if (triagetext['data'] is not None):
                            for d in triagetext['data']:
                                y = d.keys()
                                if ("id" in y):
                                    if d['id']:
                                        print(mycolors.foreground.lightcyan + "\nid: ".ljust(12) + mycolors.reset + d['id'], end=' ')

                                if ("status" in y):
                                    if d['status']:
                                        print(mycolors.foreground.lightcyan + "\nstatus: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                                if ("kind" in y):
                                    if d['kind']:
                                        print(mycolors.foreground.lightcyan + "\nkind: ".ljust(12) + mycolors.reset + d['kind'], end=' ')

                                if ("filename" in y):
                                    if d['filename']:
                                        print(mycolors.foreground.lightcyan + "\nfilename: ".ljust(12) + mycolors.reset + d['filename'], end=' ')

                                if ("submitted" in y):
                                    if d['submitted']:
                                        print(mycolors.foreground.lightcyan + "\nsubmitted: ".ljust(12) + mycolors.reset + d['submitted'], end=' ')

                                if ("completed" in y):
                                    if d['completed']:
                                        print(mycolors.foreground.lightcyan + "\ncompleted: ".ljust(12) + mycolors.reset + d['completed'], end=' ')

                                if ("private" in y):
                                    if d['private']:
                                        print(mycolors.foreground.lightcyan + "\nprivate: ".ljust(12) + mycolors.reset + d['private'], end=' ')

                                for x in triagetext['data'][0].keys():
                                    if (x == "tasks"):
                                        if (triagetext['data'][0]['tasks'] is not None):
                                            for d in triagetext['data'][0]['tasks']:
                                                print(mycolors.foreground.lightcyan + "\ntasks: " + mycolors.reset, end=' ')
                                                z = d.keys()
                                                if ("id" in z):
                                                    if d['id']:
                                                        print(mycolors.foreground.lightcyan + "\n\t   id: ".ljust(13) + mycolors.reset + d['id'], end=' ')

                                                if ("status" in z):
                                                    if d['status']:
                                                        print(mycolors.foreground.lightcyan + "\n\t   status: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                                                if ("target" in z):
                                                    if d['target']:
                                                        print(mycolors.foreground.lightcyan + "\n\t   target: ".ljust(12) + mycolors.reset + d['target'], end=' ')

                                                if ("pick" in z):
                                                    if d['pick']:
                                                        print(mycolors.foreground.lightcyan + "\n\t   pick: ".ljust(13) + mycolors.reset + d['pick'], end=' ')

                                print("\n" + (90 * '-').center(45), end='')

                    if (i == "next"):
                        if (triagetext['next'] is not None):
                            print(mycolors.foreground.lightcyan + "\nnext: ".ljust(12) + mycolors.reset + triagetext['next'], end=' ')

            if (cv.bkg == 0):
                for i in triagetext.keys():
                    if (i == "data"):
                        if (triagetext['data'] is not None):
                            for d in triagetext['data']:
                                y = d.keys()
                                if ("id" in y):
                                    if d['id']:
                                        print(mycolors.foreground.cyan + "\nid: ".ljust(12) + mycolors.reset + d['id'], end=' ')

                                if ("status" in y):
                                    if d['status']:
                                        print(mycolors.foreground.cyan + "\nstatus: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                                if ("kind" in y):
                                    if d['kind']:
                                        print(mycolors.foreground.cyan + "\nkind: ".ljust(12) + mycolors.reset + d['kind'], end=' ')

                                if ("filename" in y):
                                    if d['filename']:
                                        print(mycolors.foreground.cyan + "\nfilename: ".ljust(12) + mycolors.reset + d['filename'], end=' ')

                                if ("submitted" in y):
                                    if d['submitted']:
                                        print(mycolors.foreground.cyan + "\nsubmitted: ".ljust(12) + mycolors.reset + d['submitted'], end=' ')

                                if ("completed" in y):
                                    if d['completed']:
                                        print(mycolors.foreground.cyan + "\ncompleted: ".ljust(12) + mycolors.reset + d['completed'], end=' ')

                                if ("private" in y):
                                    if d['private']:
                                        print(mycolors.foreground.cyan + "\nprivate: ".ljust(12) + mycolors.reset + d['private'], end=' ')

                                for x in triagetext['data'][0].keys():
                                    if (x == "tasks"):
                                        if (triagetext['data'][0]['tasks'] is not None):
                                            for d in triagetext['data'][0]['tasks']:
                                                print(mycolors.foreground.purple + "\ntasks: " + mycolors.reset, end=' ')
                                                z = d.keys()
                                                if ("id" in z):
                                                    if d['id']:
                                                        print(mycolors.foreground.purple + "\n\t   id: ".ljust(13) + mycolors.reset + d['id'], end=' ')

                                                if ("status" in z):
                                                    if d['status']:
                                                        print(mycolors.foreground.purple + "\n\t   status: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                                                if ("target" in z):
                                                    if d['target']:
                                                        print(mycolors.foreground.purple + "\n\t   target: ".ljust(12) + mycolors.reset + d['target'], end=' ')

                                                if ("pick" in z):
                                                    if d['pick']:
                                                        print(mycolors.foreground.purple + "\n\t   pick: ".ljust(13) + mycolors.reset + d['pick'], end=' ')

                                print("\n" + (90 * '-').center(45), end='')

                    if (i == "next"):
                        if (triagetext['next'] is not None):
                            print(mycolors.foreground.purple + "\nnext: ".ljust(12) + mycolors.reset + triagetext['next'], end=' ')

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            printr()

    def triage_summary(self, triagex):
        triage = TriageExtractor.triageurl

        triagetext = ''
        triageresponse = ''

        self.requestTRIAGEAPI()

        try:
            print("\n")
            print((mycolors.reset + "TRIAGE SEARCH REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json', 'Authorization': 'Bearer ' + self.TRIAGEAPI})
            triageresponse = requestsession.get(triage + 'samples/' + triagex + '/overview.json')
            triagetext = json.loads(triageresponse.text)

            if 'error' in triagetext:
                if triagetext['error'] == "NOT_FOUND":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided ID was not found!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided ID was not found!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "UNAUTHORIZED":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID_QUERY":
                    if (cv.bkg == 1):
                        print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                    else:
                        print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                    exit(1)

            if (cv.bkg == 1):
                for i in triagetext.keys():
                    if (i == "sample"):
                        if (triagetext['sample'] is not None):
                            y = triagetext['sample'].keys()
                            if ("id" in y):
                                print(mycolors.foreground.lightcyan + "\n\nid: ".ljust(13) + mycolors.reset + triagetext['sample']['id'], end=' ')

                            if ("target" in y):
                                print(mycolors.foreground.lightcyan + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                            if ("size" in y):
                                print((mycolors.foreground.lightcyan + "\nsize: ".ljust(12) + mycolors.reset + "%d") % int(triagetext['sample']['size']), end=' ')

                            if ("md5" in y):
                                print(mycolors.foreground.lightcyan + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                            if ("sha1" in y):
                                print(mycolors.foreground.lightcyan + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                            if ("sha256" in y):
                                print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                            if ("completed" in y):
                                print(mycolors.foreground.lightcyan + "\ncompleted: ".ljust(12) + mycolors.reset + triagetext['sample']['completed'], end=' ')

                    if (i == "analysis"):
                        if (triagetext['analysis'] is not None):
                            if ("score" in triagetext['analysis']):
                                print(mycolors.foreground.lightcyan + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['analysis']['score']), end=' ')

                    if (i == "tasks"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.lightcyan + "\n\ntasks: ".ljust(11) + mycolors.reset, end=' ')
                            for d in (triagetext[i].keys()):
                                print("\n".ljust(12) + mycolors.foreground.lightcyan + "* " + d + ": \n" + mycolors.reset, end=' ')
                                if ("kind" in triagetext[i][d]):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "kind: ".ljust(10) + mycolors.reset + triagetext[i][d]['kind'], end=' ')
                                if ("status" in triagetext[i][d]):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "status: ".ljust(10) + mycolors.reset + triagetext[i][d]['status'], end=' ')
                                if ("score" in triagetext[i][d]):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext[i][d]['score']), end=' ')
                                if ("target" in triagetext[i][d]):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + triagetext[i][d]['target'], end=' ')
                                if ("resource" in triagetext[i][d]):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "resource: ".ljust(8) + mycolors.reset + triagetext[i][d]['resource'], end=' ')
                                if ("platform" in triagetext[i][d]):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "platform: ".ljust(8) + mycolors.reset + triagetext[i][d]['platform'], end=' ')

                                print(mycolors.foreground.yellow + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                                if ("tags" in triagetext[i][d]):
                                    for j in triagetext[i][d]['tags']:
                                        print("\n".ljust(22) + mycolors.reset + j, end=' ')

                                print(mycolors.reset + "")

                    if (i == "targets"):
                        if (triagetext['targets'] is not None):
                            print(mycolors.foreground.lightcyan + "\ntargets: ".ljust(12) + mycolors.reset, end=' ')
                            for k in range(len(triagetext['targets'])):
                                for m in (triagetext['targets'][k]):
                                    if ("tasks" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset, end=' ')
                                        for i in range(len(triagetext['targets'][k][m])):
                                            print(str(triagetext['targets'][k][m][i]), end=' ')
                                    if ("score" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("target" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("size" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "size: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]) + "bytes", end=' ')
                                    if ("md5" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "md5: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("sha1" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "sha1: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("sha256" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "sha256: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("tags" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                                        for j in (triagetext['targets'][k][m]):
                                            print("\n".ljust(22) + mycolors.reset + j, end=' ')
                                    if ("family" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "family: ".ljust(9) + mycolors.reset, end=' ')
                                        for n in range(len(triagetext['targets'][k][m])):
                                            print(mycolors.reset + str(triagetext['targets'][k][m][n]), end=' ')
                                    if ("iocs" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "iocs: ", end=' ')
                                        for j in (triagetext['targets'][k][m]):
                                            if ('ips' == j):
                                                for i in range(len(triagetext['targets'][k][m][j])):
                                                    print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]), end=' ')
                                            if ('domains' == j):
                                                for i in range(len(triagetext['targets'][k][m][j])):
                                                    print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]), end=' ')
                                            if ('urls' == j):
                                                for i in range(len(triagetext['targets'][k][m][j])):
                                                    print(mycolors.reset + ("\n".ljust(22) + ("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['targets'][k][m][j][i]), width=80))), end=' ')

                    if (i == "signatures"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.lightcyan + "\nsignatures: ".ljust(12) + mycolors.reset, end=' ')
                            for y in range(len(triagetext[i])):
                                for d in (triagetext[i][y]).keys():
                                    if (d == 'name'):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]), end=' ')

                            print(mycolors.reset + "")

                    if (i == "extracted"):
                        if (triagetext['extracted'] is not None):
                            print(mycolors.foreground.lightcyan + "\nextracted: ".ljust(12) + mycolors.reset, end=' ')
                            for k in range(len(triagetext['extracted'])):
                                for m in (triagetext['extracted'][k]):
                                    if ("tasks" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset, end=' ')
                                        for i in range(len(triagetext['extracted'][k][m])):
                                            print(str(triagetext['extracted'][k][m][i]), end=' ')
                                    if ("resource" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]), end=' ')
                                    if ("dumped_file" == m):
                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "dumped: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]), end=' ')
                                    if ("config" == m):
                                        for x in ((triagetext['extracted'][k][m]).keys()):
                                            if ('family' == x):
                                                print(mycolors.foreground.yellow + "\n".ljust(12) + "family: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]), end=' ')
                                            if ('rule' == x):
                                                print(mycolors.foreground.yellow + "\n".ljust(12) + "rule: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]), end=' ')
                                            if ("extracted_pe" == x):
                                                print(mycolors.foreground.yellow + "\n".ljust(12) + "extracted_pe: ".ljust(9) + mycolors.reset, end=' ')
                                                for i in range(len(triagetext['extracted'][k][m][x])):
                                                    print("\n".ljust(22) + str(triagetext['extracted'][k][m][x][i]), end=' ')
                                            if ('c2' == x):
                                                print(mycolors.foreground.yellow + "\n".ljust(12) + "c2: ".ljust(9) + mycolors.reset, end=' ')
                                                for z in range(len(triagetext['extracted'][k][m][x])):
                                                    print("\n".ljust(22) + mycolors.reset + str(triagetext['extracted'][k][m][x][z]), end=' ')
                                            if ("botnet" == x):
                                                print(mycolors.foreground.yellow + "\n".ljust(12) + "botnet: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]), end=' ')
                                            if ("keys" == x):
                                                for p in range(len(triagetext['extracted'][k][m][x])):
                                                    for q in (triagetext['extracted'][k][m][x][p]).keys():
                                                        if ('key' == q):
                                                            print(mycolors.foreground.yellow + "\n".ljust(12) + "key: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x][p][q]), end=' ')
                                                        if ('value' == q):
                                                            print(mycolors.foreground.yellow + "\n".ljust(12) + "value:".ljust(10) + mycolors.reset, end='')
                                                            print(mycolors.reset + (("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['extracted'][k][m][x][p][q]), width=80))), end=' ')

            if (cv.bkg == 0):
                for i in triagetext.keys():
                    if (i == "sample"):
                        if (triagetext['sample'] is not None):
                            y = triagetext['sample'].keys()
                            if ("id" in y):
                                print(mycolors.foreground.green + "\n\nid: ".ljust(13) + mycolors.reset + triagetext['sample']['id'], end=' ')

                            if ("target" in y):
                                print(mycolors.foreground.green + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                            if ("size" in y):
                                print((mycolors.foreground.green + "\nsize: ".ljust(12) + mycolors.reset + "%d") % int(triagetext['sample']['size']), end=' ')

                            if ("md5" in y):
                                print(mycolors.foreground.green + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                            if ("sha1" in y):
                                print(mycolors.foreground.green + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                            if ("sha256" in y):
                                print(mycolors.foreground.green + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                            if ("completed" in y):
                                print(mycolors.foreground.green + "\ncompleted: ".ljust(12) + mycolors.reset + triagetext['sample']['completed'], end=' ')

                    if (i == "analysis"):
                        if (triagetext['analysis'] is not None):
                            if ("score" in triagetext['analysis']):
                                print(mycolors.foreground.green + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['analysis']['score']), end=' ')

                    if (i == "tasks"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.green + "\n\ntasks: ".ljust(11) + mycolors.reset, end=' ')
                            for d in (triagetext[i].keys()):
                                print("\n".ljust(12) + mycolors.foreground.blue + "* " + d + ": \n" + mycolors.reset, end=' ')
                                if ("kind" in triagetext[i][d]):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "kind: ".ljust(10) + mycolors.reset + triagetext[i][d]['kind'], end=' ')
                                if ("status" in triagetext[i][d]):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "status: ".ljust(10) + mycolors.reset + triagetext[i][d]['status'], end=' ')
                                if ("score" in triagetext[i][d]):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext[i][d]['score']), end=' ')
                                if ("target" in triagetext[i][d]):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + triagetext[i][d]['target'], end=' ')
                                if ("resource" in triagetext[i][d]):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "resource: ".ljust(8) + mycolors.reset + triagetext[i][d]['resource'], end=' ')
                                if ("platform" in triagetext[i][d]):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "platform: ".ljust(8) + mycolors.reset + triagetext[i][d]['platform'], end=' ')

                                print(mycolors.foreground.red + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                                if ("tags" in triagetext[i][d]):
                                    for j in triagetext[i][d]['tags']:
                                        print("\n".ljust(22) + mycolors.reset + j, end=' ')

                                print(mycolors.reset + "")

                    if (i == "targets"):
                        if (triagetext['targets'] is not None):
                            print(mycolors.foreground.green + "\ntargets: ".ljust(12) + mycolors.reset, end=' ')
                            for k in range(len(triagetext['targets'])):
                                for m in (triagetext['targets'][k]):
                                    if ("tasks" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset, end=' ')
                                        for i in range(len(triagetext['targets'][k][m])):
                                            print(str(triagetext['targets'][k][m][i]), end=' ')
                                    if ("score" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("target" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("size" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "size: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]) + "bytes", end=' ')
                                    if ("md5" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "md5: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("sha1" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "sha1: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("sha256" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "sha256: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]), end=' ')
                                    if ("tags" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                                        for j in (triagetext['targets'][k][m]):
                                            print("\n".ljust(22) + mycolors.reset + j, end=' ')
                                    if ("family" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "family: ".ljust(9) + mycolors.reset, end=' ')
                                        for n in range(len(triagetext['targets'][k][m])):
                                            print(mycolors.reset + str(triagetext['targets'][k][m][n]), end=' ')
                                    if ("iocs" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "iocs: ", end=' ')
                                        for j in (triagetext['targets'][k][m]):
                                            if ('ips' == j):
                                                for i in range(len(triagetext['targets'][k][m][j])):
                                                    print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]), end=' ')
                                            if ('domains' == j):
                                                for i in range(len(triagetext['targets'][k][m][j])):
                                                    print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]), end=' ')
                                            if ('urls' == j):
                                                for i in range(len(triagetext['targets'][k][m][j])):
                                                    print(mycolors.reset + ("\n".ljust(22) + ("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['targets'][k][m][j][i]), width=80))), end=' ')

                    if (i == "signatures"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.green + "\nsignatures: ".ljust(12) + mycolors.reset, end=' ')
                            for y in range(len(triagetext[i])):
                                for d in (triagetext[i][y]).keys():
                                    if (d == 'name'):
                                        print(mycolors.foreground.red + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]), end=' ')

                            print(mycolors.reset + "")

                    if (i == "extracted"):
                        if (triagetext['extracted'] is not None):
                            print(mycolors.foreground.green + "\nextracted: ".ljust(12) + mycolors.reset, end=' ')
                            for k in range(len(triagetext['extracted'])):
                                for m in (triagetext['extracted'][k]):
                                    if ("tasks" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset, end=' ')
                                        for i in range(len(triagetext['extracted'][k][m])):
                                            print(str(triagetext['extracted'][k][m][i]), end=' ')
                                    if ("resource" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]), end=' ')
                                    if ("dumped_file" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "dumped: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]), end=' ')
                                    if ("config" == m):
                                        for x in ((triagetext['extracted'][k][m]).keys()):
                                            if ('family' == x):
                                                print(mycolors.foreground.red + "\n".ljust(12) + "family: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]), end=' ')
                                            if ('rule' == x):
                                                print(mycolors.foreground.red + "\n".ljust(12) + "rule: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]), end=' ')
                                            if ("extracted_pe" == x):
                                                print(mycolors.foreground.red + "\n".ljust(12) + "extracted_pe: ".ljust(9) + mycolors.reset, end=' ')
                                                for i in range(len(triagetext['extracted'][k][m][x])):
                                                    print("\n".ljust(22) + str(triagetext['extracted'][k][m][x][i]), end=' ')
                                            if ('c2' == x):
                                                print(mycolors.foreground.red + "\n".ljust(12) + "c2: ".ljust(9) + mycolors.reset, end=' ')
                                                for z in range(len(triagetext['extracted'][k][m][x])):
                                                    print("\n".ljust(22) + mycolors.reset + str(triagetext['extracted'][k][m][x][z]), end=' ')
                                            if ("botnet" == x):
                                                print(mycolors.foreground.red + "\n".ljust(12) + "botnet: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]), end=' ')
                                            if ("keys" == x):
                                                for p in range(len(triagetext['extracted'][k][m][x])):
                                                    for q in (triagetext['extracted'][k][m][x][p]).keys():
                                                        if ('key' == q):
                                                            print(mycolors.foreground.red + "\n".ljust(12) + "key: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x][p][q]), end=' ')
                                                        if ('value' == q):
                                                            print(mycolors.foreground.red + "\n".ljust(12) + "value:".ljust(10) + mycolors.reset, end='')
                                                            print(mycolors.reset + (("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['extracted'][k][m][x][p][q]), width=80))), end=' ')

            print(mycolors.reset + "\n")
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            printr()

    def triage_sample_submit(self, triagex):
        triage = TriageExtractor.triageurl

        triagetext = ''

        self.requestTRIAGEAPI()

        def encode_multipart_formdata(infodata):
            boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

            body = BytesIO()
            for field, value in infodata.items():
                if isinstance(value, tuple):
                    filename, file = value
                    body.write('--{boundary}\r\nContent-Disposition: form-data; filename="{filename}"; name=\"{field}\"\r\n\r\n'.format(boundary=boundary, field=field, filename=filename).encode('utf-8'))
                    b = file.read()
                    if isinstance(b, str):
                        b = b.encode('ascii')
                    body.write(b)
                    body.write(b'\r\n')
                else:
                    body.write('--{boundary}\r\nContent-Disposition: form-data; name="{field}"\r\n\r\n{value}\r\n'.format(boundary=boundary, field=field, value=value).encode('utf-8'))
            body.write('--{0}--\r\n'.format(boundary).encode('utf-8'))
            body.seek(0)

            return body, "multipart/form-data; boundary=" + boundary

        try:

            print("\n")
            print((mycolors.reset + "TRIAGE SAMPLE SUBMIT REPORT".center(80)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (80 * '-').center(40))

            myfile = open(triagex, 'rb')
            mydata = {
                'kind': 'file',
                'interactive': False,
            }

            filename = os.path.basename(triagex)
            mybody, content_type = encode_multipart_formdata({
                '_json': json.dumps(mydata),
                'file': (filename, myfile),
            })

            req = Request('POST', triage + 'samples', data=mybody, headers={"Content-Type": content_type, "Authorization": "Bearer " + self.TRIAGEAPI})
            requestsession = requests.Session()
            triageres = requestsession.send(req.prepare())
            triagetext = triageres.json()

            if 'error' in triagetext:

                if triagetext['error'] == "UNAUTHORIZED":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID_QUERY":
                    if (cv.bkg == 1):
                        print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                    else:
                        print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                    exit(1)

            if 'id' in triagetext:
                if (cv.bkg == 1):
                    print("\n" + mycolors.foreground.yellow + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ')
                    print("\n" + mycolors.foreground.yellow + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ')
                    print("\n" + mycolors.foreground.yellow + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ')
                    print("\n" + mycolors.foreground.yellow + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ')
                if (cv.bkg == 0):
                    print("\n" + mycolors.foreground.blue + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ')
                    print("\n" + mycolors.foreground.blue + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ')
                    print("\n" + mycolors.foreground.blue + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ')
                    print("\n" + mycolors.foreground.blue + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ')

            print(mycolors.reset + "\n")
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            printr()

    def triage_url_sample_submit(self, triagex):
        triage = TriageExtractor.triageurl

        triagetext = ''
        triageresponse = ''

        self.requestTRIAGEAPI()

        try:
            print("\n")
            print((mycolors.reset + "TRIAGE URL SAMPLE SUBMIT REPORT".center(80)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (80 * '-').center(40))

            mydata = {
                'kind': 'fetch',
                'url': triagex,
                'interactive': False,
            }

            requestsession = requests.Session()
            requestsession.headers.update({
                'accept': 'application/json',
                'Authorization': 'Bearer ' + self.TRIAGEAPI,
                'Content-Type': 'application/json'
            })
            triageresponse = requestsession.post(triage + 'samples', data=json.dumps(mydata))
            triagetext = json.loads(triageresponse.text)

            if 'error' in triagetext:
                if triagetext['error'] == "UNAUTHORIZED":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID_QUERY":
                    if (cv.bkg == 1):
                        print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                    else:
                        print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                    exit(1)

            if 'id' in triagetext:
                if (cv.bkg == 1):
                    print("\n" + mycolors.foreground.yellow + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ')
                    print("\n" + mycolors.foreground.yellow + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ')
                    print("\n" + mycolors.foreground.yellow + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ')
                    print("\n" + mycolors.foreground.yellow + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ')
                if (cv.bkg == 0):
                    print("\n" + mycolors.foreground.blue + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ')
                    print("\n" + mycolors.foreground.blue + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ')
                    print("\n" + mycolors.foreground.blue + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ')
                    print("\n" + mycolors.foreground.blue + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ')

            print(mycolors.reset + "\n")
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            printr()

    def triage_download(self, triagex):
        triage = TriageExtractor.triageurl

        triagetext = ''
        triageresponse = ''

        self.requestTRIAGEAPI()

        try:

            print("\n")
            print((mycolors.reset + "TRIAGE DOWNLOAD REPORT".center(80)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (80 * '-').center(40))

            requestsession = requests.Session()
            requestsession.headers.update({'Authorization': 'Bearer ' + self.TRIAGEAPI})
            triageresponse = requestsession.get(triage + 'samples/' + triagex + '/sample')
            if (triageresponse.status_code == 404):
                triagetext = json.loads(triageresponse.text)

            if 'error' in triagetext:
                if triagetext['error'] == "NOT_FOUND":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided ID was not found!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided ID was not found!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "UNAUTHORIZED":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID_QUERY":
                    if (cv.bkg == 1):
                        print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                    else:
                        print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                    exit(1)

            open(triagex + '.bin', 'wb').write(triageresponse.content)
            if (cv.bkg == 1):
                print("\n" + mycolors.foreground.yellow + "SAMPLE SAVED as: " + triagex + ".bin" + mycolors.reset, end=' ')
            if (cv.bkg == 0):
                print("\n" + mycolors.foreground.blue + "SAMPLE SAVED as: " + triagex + ".bin" + mycolors.reset, end=' ')

            print(mycolors.reset + "\n")
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            printr()

    def triage_download_pcap(self, triagex):
        triage = TriageExtractor.triageurl

        triagetext = ''
        triageresponse = ''

        self.requestTRIAGEAPI()

        try:
            print("\n")
            print((mycolors.reset + "TRIAGE PCAPNG DOWNLOAD REPORT".center(80)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (80 * '-').center(40))

            requestsession = requests.Session()
            requestsession.headers.update({'Authorization': 'Bearer ' + self.TRIAGEAPI})
            triageresponse = requestsession.get(triage + 'samples/' + triagex + '/behavioral1/dump.pcapng')
            if (triageresponse.status_code == 404):
                triagetext = json.loads(triageresponse.text)

            if 'error' in triagetext:
                if triagetext['error'] == "NOT_FOUND":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe pcap file was not found!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe pcap file was not found!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "UNAUTHORIZED":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID_QUERY":
                    if (cv.bkg == 1):
                        print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                    else:
                        print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                    exit(1)

            open(triagex + '.pcapng', 'wb').write(triageresponse.content)
            if (cv.bkg == 1):
                print("\n" + mycolors.foreground.yellow + "PCAP SAVED as: " + triagex + ".pcapng" + mycolors.reset, end=' ')
            if (cv.bkg == 0):
                print("\n" + mycolors.foreground.blue + "PCAP SAVED as: " + triagex + ".pcapng" + mycolors.reset, end=' ')

            print(mycolors.reset + "\n")
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            printr()

    def triage_dynamic(self, triagex):
        triage = TriageExtractor.triageurl

        triagetext = ''
        triageresponse = ''

        self.requestTRIAGEAPI()

        try:
            print("\n")
            print((mycolors.reset + "TRIAGE DYNAMIC REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json', 'Authorization': 'Bearer ' + self.TRIAGEAPI})
            triageresponse = requestsession.get(triage + 'samples/' + triagex + '/behavioral1/report_triage.json')
            triagetext = json.loads(triageresponse.text)

            if 'error' in triagetext:
                if triagetext['error'] == "NOT_FOUND":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided ID was not found!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided ID was not found!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "UNAUTHORIZED":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                    exit(1)

                if triagetext['error'] == "INVALID_QUERY":
                    if (cv.bkg == 1):
                        print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                    else:
                        print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                    exit(1)

            if (cv.bkg == 1):
                for i in triagetext.keys():
                    if (i == "sample"):
                        if (triagetext['sample'] is not None):
                            y = triagetext['sample'].keys()
                            if ("id" in y):
                                print(mycolors.foreground.lightcyan + "\nid: ".ljust(12) + mycolors.reset + triagetext['sample']['id'], end=' ')

                            if ("target" in y):
                                print(mycolors.foreground.lightcyan + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                            if ("score" in y):
                                print(mycolors.foreground.lightcyan + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['sample']['score']), end=' ')

                            if ("submitted" in y):
                                print(mycolors.foreground.lightcyan + "\nsubmitted: ".ljust(12) + mycolors.reset + triagetext['sample']['submitted'], end=' ')

                            if ("size" in y):
                                print(mycolors.foreground.lightcyan + "\nsize: ".ljust(12) + mycolors.reset + str(triagetext['sample']['size']), end=' ')

                            if ("md5" in y):
                                print(mycolors.foreground.lightcyan + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                            if ("sha1" in y):
                                print(mycolors.foreground.lightcyan + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                            if ("sha256" in y):
                                print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                            print(mycolors.foreground.lightcyan + "\nstatic_tags: ".ljust(12) + mycolors.reset, end=' ')
                            if ("static_tags" in triagetext[i]):
                                for j in triagetext[i]['static_tags']:
                                    print("\n".ljust(12) + mycolors.reset + j, end=' ')

                    if (i == "analysis"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.lightcyan + "\n\nanalysis: ".ljust(11) + mycolors.reset, end=' ')
                            if ("score" in triagetext[i]):
                                print(mycolors.foreground.lightred + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext[i]['score']), end=' ')
                            if ("reported" in triagetext[i]):
                                print(mycolors.foreground.lightred + "\n".ljust(12) + "reported: ".ljust(10) + mycolors.reset + triagetext[i]['reported'], end=' ')
                            if ("platform" in triagetext[i]):
                                print(mycolors.foreground.lightred + "\n".ljust(12) + "platform: ".ljust(10) + mycolors.reset + str(triagetext[i]['platform']), end=' ')
                            if ("resource" in triagetext[i]):
                                print(mycolors.foreground.lightred + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + triagetext[i]['resource'], end=' ')
                            if ("max_time_network" in triagetext[i]):
                                print(mycolors.foreground.lightred + "\n".ljust(12) + "time_net: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_network']), end=' ')
                            if ("max_time_kernel" in triagetext[i]):
                                print(mycolors.foreground.lightred + "\n".ljust(12) + "time_krn: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_kernel']), end=' ')

                            print(mycolors.foreground.lightred + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                            if ("tags" in triagetext[i]):
                                for j in triagetext[i]['tags']:
                                    print("\n".ljust(22) + mycolors.reset + j, end=' ')

                            print(mycolors.foreground.lightred + "\n".ljust(12) + "ttps: ".ljust(10) + mycolors.reset, end=' ')
                            if ("ttp" in triagetext[i]):
                                for j in triagetext[i]['ttp']:
                                    print("\n".ljust(22) + mycolors.reset + j, end=' ')

                            print(mycolors.foreground.lightred + "\n".ljust(12) + "features: ".ljust(10) + mycolors.reset, end=' ')
                            if ("features" in triagetext[i]):
                                for j in triagetext[i]['features']:
                                    print("\n".ljust(22) + mycolors.reset + j, end=' ')

                            print(mycolors.reset + "")

                    if (i == "processes"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.lightcyan + "\nprocesses: ".ljust(12) + mycolors.reset, end=' ')
                            for k in range(len(triagetext[i])):
                                for m in (triagetext[i][k]):
                                    if ("pid" == m):
                                        print(mycolors.foreground.lightred + "\n".ljust(12) + "pid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("ppid" == m):
                                        print(mycolors.foreground.lightred + "\n".ljust(12) + "ppid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("procid" == m):
                                        print(mycolors.foreground.lightred + "\n".ljust(12) + "procid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("procid_parent" == m):
                                        print(mycolors.foreground.lightred + "\n".ljust(12) + "procid_p: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("cmd" == m):
                                        print(mycolors.foreground.lightred + "\n".ljust(12) + "cmd: ".ljust(10) + mycolors.reset + (("\n".ljust(22)).join(textwrap.wrap(str(triagetext[i][k][m]), width=90))), end=' ')
                                    if ("image" == m):
                                        print(mycolors.foreground.lightred + "\n".ljust(12) + "image: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                print(mycolors.reset + "")

                    if (i == "signatures"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.lightcyan + "\nsignatures: ".ljust(12) + mycolors.reset, end=' ')
                            for y in range(len(triagetext[i])):
                                for d in (triagetext[i][y]).keys():
                                    if (d == 'name'):
                                        print(mycolors.foreground.lightred + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]), end=' ')
                            print(mycolors.reset + "")

                        if (triagetext[i] is not None):
                            list_1 = []
                            set_1 = ()
                            print(mycolors.foreground.lightcyan + "\n".ljust(12) + "iocs: ".ljust(10) + mycolors.reset, end='')
                            for y in range(len(triagetext[i])):
                                for d in (triagetext[i][y]).keys():
                                    if (d == 'indicators'):
                                        for z in range(len(triagetext[i][y][d])):
                                            for t in (triagetext[i][y][d][z]).keys():
                                                if (t == 'ioc'):
                                                    list_1.append(triagetext[i][y][d][z][t])
                            set_1 = set(list_1)
                            final_list = (list(set_1))
                            for w in final_list:
                                print("\n".ljust(17) + mycolors.reset + (("\n".ljust(19)).join(textwrap.wrap("* " + w, width=90))), end=' ')

                    if (i == "network"):
                        list_1 = []
                        set_1 = ()
                        print(mycolors.foreground.lightcyan + "\nnetwork: ".ljust(12) + mycolors.reset, end='')
                        for d in (triagetext[i]).keys():
                            if (d == 'flows'):
                                for z in range(len(triagetext[i][d])):
                                    for t in (triagetext[i][d][z]).keys():
                                        if (t == 'domain'):
                                            list_1.append(triagetext[i][d][z][t])
                        set_1 = set(list_1)
                        final_list = (list(set_1))
                        for w in final_list:
                            print("\n".ljust(12) + mycolors.reset + (("\n".ljust(12)).join(textwrap.wrap(w, width=90))), end=' ')

                        print(mycolors.reset + "")

            if (cv.bkg == 0):
                for i in triagetext.keys():
                    if (i == "sample"):
                        if (triagetext['sample'] is not None):
                            y = triagetext['sample'].keys()
                            if ("id" in y):
                                print(mycolors.foreground.purple + "\nid: ".ljust(12) + mycolors.reset + triagetext['sample']['id'], end=' ')

                            if ("target" in y):
                                print(mycolors.foreground.purple + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                            if ("score" in y):
                                print(mycolors.foreground.purple + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['sample']['score']), end=' ')

                            if ("submitted" in y):
                                print(mycolors.foreground.purple + "\nsubmitted: ".ljust(12) + mycolors.reset + triagetext['sample']['submitted'], end=' ')

                            if ("size" in y):
                                print(mycolors.foreground.purple + "\nsize: ".ljust(12) + mycolors.reset + str(triagetext['sample']['size']), end=' ')

                            if ("md5" in y):
                                print(mycolors.foreground.purple + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                            if ("sha1" in y):
                                print(mycolors.foreground.purple + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                            if ("sha256" in y):
                                print(mycolors.foreground.purple + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                            print(mycolors.foreground.purple + "\nstatic_tags: ".ljust(12) + mycolors.reset, end=' ')
                            if ("static_tags" in triagetext[i]):
                                for j in triagetext[i]['static_tags']:
                                    print("\n".ljust(12) + mycolors.reset + j, end=' ')

                    if (i == "analysis"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.purple + "\n\nanalysis: ".ljust(11) + mycolors.reset, end=' ')
                            if ("score" in triagetext[i]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext[i]['score']), end=' ')
                            if ("reported" in triagetext[i]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "reported: ".ljust(10) + mycolors.reset + triagetext[i]['reported'], end=' ')
                            if ("platform" in triagetext[i]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "platform: ".ljust(10) + mycolors.reset + str(triagetext[i]['platform']), end=' ')
                            if ("resource" in triagetext[i]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + triagetext[i]['resource'], end=' ')
                            if ("max_time_network" in triagetext[i]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "time_net: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_network']), end=' ')
                            if ("max_time_kernel" in triagetext[i]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "time_krn: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_kernel']), end=' ')

                            print(mycolors.foreground.red + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                            if ("tags" in triagetext[i]):
                                for j in triagetext[i]['tags']:
                                    print("\n".ljust(22) + mycolors.reset + j, end=' ')

                            print(mycolors.foreground.red + "\n".ljust(12) + "ttps: ".ljust(10) + mycolors.reset, end=' ')
                            if ("ttp" in triagetext[i]):
                                for j in triagetext[i]['ttp']:
                                    print("\n".ljust(22) + mycolors.reset + j, end=' ')

                            print(mycolors.foreground.red + "\n".ljust(12) + "features: ".ljust(10) + mycolors.reset, end=' ')
                            if ("features" in triagetext[i]):
                                for j in triagetext[i]['features']:
                                    print("\n".ljust(22) + mycolors.reset + j, end=' ')

                            print(mycolors.reset + "")

                    if (i == "processes"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.purple + "\nprocesses: ".ljust(12) + mycolors.reset, end=' ')
                            for k in range(len(triagetext[i])):
                                for m in (triagetext[i][k]):
                                    if ("pid" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "pid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("ppid" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "ppid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("procid" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "procid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("procid_parent" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "procid_p: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                    if ("cmd" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "cmd: ".ljust(10) + mycolors.reset + (("\n".ljust(22)).join(textwrap.wrap(str(triagetext[i][k][m]), width=90))), end=' ')
                                    if ("image" == m):
                                        print(mycolors.foreground.red + "\n".ljust(12) + "image: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]), end=' ')
                                print(mycolors.reset + "")

                    if (i == "signatures"):
                        if (triagetext[i] is not None):
                            print(mycolors.foreground.purple + "\nsignatures: ".ljust(12) + mycolors.reset, end=' ')
                            for y in range(len(triagetext[i])):
                                for d in (triagetext[i][y]).keys():
                                    if (d == 'name'):
                                        print(mycolors.foreground.red + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]), end=' ')
                            print(mycolors.reset + "")

                        if (triagetext[i] is not None):
                            list_1 = []
                            set_1 = ()
                            print(mycolors.foreground.purple + "\n".ljust(12) + "iocs: ".ljust(10) + mycolors.reset, end='')
                            for y in range(len(triagetext[i])):
                                for d in (triagetext[i][y]).keys():
                                    if (d == 'indicators'):
                                        for z in range(len(triagetext[i][y][d])):
                                            for t in (triagetext[i][y][d][z]).keys():
                                                if (t == 'ioc'):
                                                    list_1.append(triagetext[i][y][d][z][t])
                            set_1 = set(list_1)
                            final_list = (list(set_1))
                            for w in final_list:
                                print("\n".ljust(17) + mycolors.reset + (("\n".ljust(19)).join(textwrap.wrap("* " + w, width=90))), end=' ')

                    if (i == "network"):
                        list_1 = []
                        set_1 = ()
                        print(mycolors.foreground.purple + "\nnetwork: ".ljust(12) + mycolors.reset, end='')
                        for d in (triagetext[i]).keys():
                            if (d == 'flows'):
                                for z in range(len(triagetext[i][d])):
                                    for t in (triagetext[i][d][z]).keys():
                                        if (t == 'domain'):
                                            list_1.append(triagetext[i][d][z][t])
                        set_1 = set(list_1)
                        final_list = (list(set_1))
                        for w in final_list:
                            print("\n".ljust(12) + mycolors.reset + (("\n".ljust(12)).join(textwrap.wrap(w, width=90))), end=' ')

                        print(mycolors.reset + "")

            print(mycolors.reset + "\n")
            exit(0)
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
            printr()
