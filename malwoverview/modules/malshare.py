import modules.configvars as cv
from utils.colors import mycolors, printr
import json
import requests
import sys


class MalshareExtractor():
    urlmalshare = 'https://malshare.com/api.php?api_key='

    def __init__(self, MALSHAREAPI):
        self.MALSHAREAPI = MALSHAREAPI

    def requestMALSHAREAPI(self):
        if (self.MALSHAREAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Malshare, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malshare API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def malsharedown(self, filehash):
        if len(filehash) not in [32, 40, 64]:
            return False

        urlmalshare = MalshareExtractor.urlmalshare
        malresponse3 = ''
        resource = ''

        self.requestMALSHAREAPI()

        try:
            resource = filehash
            requestsession3 = requests.Session()
            finalurl3 = ''.join([
                urlmalshare, self.MALSHAREAPI,
                '&action=getfile&hash=', resource
            ])

            malresponse3 = requestsession3.get(
                url=finalurl3,
                allow_redirects=True
            )

            if (b'Sample not found by hash' in malresponse3.content):
                if (cv.bkg == 1):
                    print((mycolors.foreground.lightred + "\nSample not found by the given hash.\n"))
                else:
                    print((mycolors.foreground.red + "\nSample not found by the given hash.\n"))
                    exit(1)

            open(resource, 'wb').write(malresponse3.content)

            print("\n")
            print((mycolors.reset + "MALWARE SAMPLE SAVED! "))
            printr()
        except (BrokenPipeError, IOError):
            print(mycolors.reset, file=sys.stderr)
            exit(2)
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malshare.com!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malshare.com!\n"))
            printr()

    def malsharelastlist(self, typex):
        urlmalshare = MalshareExtractor.urlmalshare
        maltext = ''
        malresponse = ''
        filetype = ''
        maltype = typex

        self.requestMALSHAREAPI()

        if (maltype == 2):
            filetype = 'PE32'
        elif (maltype == 3):
            filetype = 'ELF'
        elif (maltype == 4):
            filetype = 'Java'
        elif (maltype == 5):
            filetype = 'PDF'
        else:
            filetype = 'Composite'

        try:
            print("\n")
            print((mycolors.reset + "SHA256 hash".center(75)), end='')
            print((mycolors.reset + "MD5 hash".center(38)), end='')
            print((mycolors.reset + "File type".center(8)), end='')
            print("\n" + (126 * '-').center(59))
            print((mycolors.reset))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            finalurl = ''.join([
                urlmalshare, self.MALSHAREAPI,
                '&action=type&type=', filetype
            ])
            malresponse = requestsession.get(url=finalurl)
            maltext = json.loads(malresponse.text)

            if maltext:
                try:
                    for i in range(0, len(maltext)):
                        if (maltext[i].get('sha256')):
                            if (cv.bkg == 1):
                                print((mycolors.reset + "sha256: " + mycolors.foreground.yellow + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.lightcyan + "%s" % maltext[i]['md5'] + mycolors.reset + "  type: " + mycolors.foreground.lightred + "%s" % filetype))
                            else:
                                print((mycolors.reset + "sha256: " + mycolors.foreground.red + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.blue + "%s" % maltext[i]['md5'] + mycolors.reset + "   type: " + mycolors.foreground.purple + "%s" % filetype))
                except KeyError:
                    pass
                except (BrokenPipeError, IOError):
                    print(mycolors.reset, file=sys.stderr)
                    return False
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malshare.com!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malshare.com!\n"))
            printr()
            return False

        return True