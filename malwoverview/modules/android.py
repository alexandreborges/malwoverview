import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.hash import sha256hash
from malwoverview.modules.hybrid import HybridAnalysisExtractor
import requests
import subprocess
import threading
import json
import time
import os

# threadLimiter = threading.BoundedSemaphore(10)


class androidVTThread(threading.Thread):
    def __init__(self, key, package, extractor):
        threading.Thread.__init__(self)
        self.key = key
        self.package = package
        self.extractor = extractor

    def run(self):
#        threadLimiter.acquire()
#        try:
        key1 = self.key
        package1 = self.package

        myhash = key1
        vtfinal = self.extractor.virustotal.vtcheck(myhash, 0)

        if (cv.bkg == 1):
            print((mycolors.foreground.yellow + "%-70s" % package1), end=' ')
            print((mycolors.foreground.lightcyan + "%-32s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.lightcyan + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.green + "%-70s" % package1), end=' ')
            print((mycolors.foreground.cyan + "%-32s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))
#        finally:
#            threadLimiter.release()


class quickHAAndroidThread(threading.Thread):
    def __init__(self, key, package, extractor):
        threading.Thread.__init__(self)
        self.key = key
        self.package = package
        self.extractor = extractor

    def run(self):
#        threadLimiter.acquire()
#        try:
        key1 = self.key
        package1 = self.package

        myhash = key1
        result = self.extractor.quickhashowAndroid(myhash)

        (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections) = result

        if (cv.bkg == 1):
            print((mycolors.foreground.lightcyan + "%-70s" % package1), end=' ')
            print((mycolors.foreground.yellow + "%-34s" % key1), end=' ')
            print((mycolors.foreground.lightcyan + "%9s" % final), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.lightcyan + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.lightcyan + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.yellow + "%7s" % totalsignatures), end='')
            if (threatscore == 'None'):
                print((mycolors.foreground.lightred + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.lightred + "%8s/100" % threatscore), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.lightred + "%20s" % verdict), end='\n')
            elif (verdict == "suspicious"):
                print((mycolors.foreground.yellow + "%20s" % verdict), end='\n')
            elif (verdict == "no specific threat"):
                print((mycolors.foreground.lightcyan + "%20s" % verdict), end='\n')
            else:
                verdict = 'not analyzed yet'
                print((mycolors.reset + "%20s" % verdict), end='\n')
        else:
            print((mycolors.foreground.cyan + "%-70s" % package1), end=' ')
            print((mycolors.foreground.green + "%-34s" % key1), end=' ')
            print((mycolors.foreground.cyan + "%9s" % final), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.purple + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.purple + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.green + "%7s" % totalsignatures), end='')
            if (threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.red + "%20s" % verdict), end='\n')
            elif (verdict == "suspicious"):
                print((mycolors.foreground.cyan + "%20s" % verdict), end='\n')
            elif (verdict == "no specific threat"):
                print((mycolors.foreground.green + "%20s" % verdict), end='\n')
            else:
                verdict = 'not analyzed yet'
                print((mycolors.reset + "%20s" % verdict), end='\n')
#        finally:
#            threadLimiter.release()


class AndroidExtractor():
    def __init__(self, hybrid, virustotal):
        self.hybrid = hybrid
        self.virustotal = virustotal

    def quickhashowAndroid(self, filehash, user_agent='Falcon Sandbox'):
        haurl = HybridAnalysisExtractor.haurl

        hatext = ''
        haresponse = ''
        final = 'Yes'
        verdict = '-'
        avdetect = '0'
        totalsignatures = '-'
        threatscore = '-'
        totalprocesses = '-'
        networkconnections = '-'

        self.hybrid.requestHAAPI()

        try:
            resource = filehash
            requestsession = requests.Session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.hybrid.HAAPI})
            requestsession.headers.update({'content-type': 'application/x-www-form-urlencoded'})
            finalurl = '/'.join([haurl, 'report', 'summary'])
            resource1 = resource + ":200"
            datahash = {
                'hashes[0]': resource1
            }

            haresponse = requestsession.post(url=finalurl, data=datahash)
            hatext = json.loads(haresponse.text)

            rc = str(hatext)

            if 'message' in rc:
                final = 'Not Found'
                return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

            if 'verdict' in hatext[0]:
                verdict = str(hatext[0]['verdict'])
            else:
                verdict = ''

            if 'threat_score' in hatext[0]:
                threatscore = str(hatext[0]['threat_score'])
            else:
                threatscore = ''

            if 'av_detect' in hatext[0]:
                avdetect = str(hatext[0]['av_detect'])
            else:
                avdetect = ''

            if 'total_signatures' in hatext[0]:
                totalsignatures = str(hatext[0]['total_signatures'])
            else:
                totalsignatures = ''

            if 'total_processes' in hatext[0]:
                totalprocesses = str(hatext[0]['total_processes'])
            else:
                totalprocesses = ''

            if 'total_network_connections' in hatext[0]:
                networkconnections = str(hatext[0]['total_network_connections'])
            else:
                networkconnections = ''

            return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
            printr()

    def checkandroidha(self, key, package):
        if len(key) == 0 or len(package) == 0:
            return

        if cv.windows:
            thread = quickHAAndroidThread(key, package, self)
            thread.start()
            thread.join()
        else:
            thread = quickHAAndroidThread(key, package, self)
            thread.start()

    def checkandroidvt(self, key, package):
        if len(key) == 0 or len(package) == 0:
            return

        key1 = key
        vtfinal = self.virustotal.vtcheck(key1, 0)
        if (cv.bkg == 1):
            print((mycolors.foreground.yellow + "%-70s" % package), end=' ')
            print((mycolors.foreground.lightcyan + "%-32s" % key1), end=' ')
            print((mycolors.foreground.lightred + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.green + "%-70s" % package), end=' ')
            print((mycolors.foreground.cyan + "%-32s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))

    def checkandroidvtx(self, key, package):
        if len(key) == 0 or len(package) == 0:
            return

        if (cv.windows == 1):
            thread = androidVTThread(key, package, self)
            thread.start()
            thread.join()
        else:
            thread = androidVTThread(key, package, self)
            thread.start()

    def checkandroid(self, engine):
        adb_comm = "adb"
        results = list()
        results2 = list()
        final1 = list()
        final2 = list()

        tm1 = 0

        myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
        myconn2 = myconn.stdout.decode()

        try:
            for i in myconn2.split('\n'):
                for j in i.split("base.apk"):
                    if 'package' in j:
                        key, value = j.split('package:')
                        _, value2 = value.split('/data/app/')
                        results.append(value2[:-3])
                        valuetmp = value + "base.apk"
                        results2.append(valuetmp)
        except AttributeError:
            pass

        try:
            for h in results2:
                myconn3 = subprocess.run([adb_comm, "shell", "md5sum", h], text=True, capture_output=True)
                x = myconn3.stdout.split(" ")[0]
                final1.append(x)

        except AttributeError:
            pass

        try:
            for n in results:
                final2.append(n)
        except AttributeError:
            pass

        zipAndroid = zip(final2, final1)
        dictAndroid = dict(zipAndroid)

        if (engine == 1):
            print(mycolors.reset + "\n")
            print("Package".center(70) + "Hash".center(34) + "Found?".center(12) + "AVdet".center(10) + "Sigs".center(5) + "Score".center(14) + "Verdict".center(14))
            print((162 * '-').center(81))
            for key, value in dictAndroid.items():
                try:
                    key1a = (key.split("==/", 1)[1])
                except IndexError:
                    key1a = key
                try:
                    key1b = (key1a.split("-", 1)[0])
                except IndexError:
                    key1b = key1a

                self.checkandroidha(value, key1b)

        if (engine == 2):
            print(mycolors.reset + "\n")
            print("Package".center(70) + "Hash".center(36) + "Virus Total".center(12))
            print((118 * '-').center(59))
            for key, value in dictAndroid.items():
                try:
                    key1a = (key.split("==/", 1)[1])
                except IndexError:
                    key1a = key
                try:
                    key1b = (key1a.split("-", 1)[0])
                except IndexError:
                    key1b = key1a
                tm1 = tm1 + 1
                if tm1 % 4 == 0:
                    time.sleep(61)
                self.checkandroidvt(value, key1b)

        if (engine == 3):
            print(mycolors.reset + "\n")
            print("Package".center(70) + "Hash".center(36) + "Virus Total".center(12))
            print((118 * '-').center(59))
            for key, value in dictAndroid.items():
                try:
                    key1a = (key.split("==/", 1)[1])
                except IndexError:
                    key1a = key
                try:
                    key1b = (key1a.split("-", 1)[0])
                except IndexError:
                    key1b = key1a
                self.checkandroidvtx(value, key1b)

    def sendandroidha(self, package, xx=3):
        adb_comm = "adb"
        results = list()
        results2 = list()
        newname = ''

        myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
        myconn2 = myconn.stdout.decode()

        try:
            for i in myconn2.split('\n'):
                for j in i.split('base.apk'):
                    if 'package' in j:
                        _, value = j.split('package:')
                        _, value2 = value.split('/data/app/')
                        results.append(value2)
                        valuetmp = value + "base.apk"
                        results2.append(valuetmp)

        except AttributeError:
            pass

        try:
            for j in results2:
                if (package in j):
                    subprocess.run([adb_comm, "pull", j], capture_output=True)
                    newname = j[10:]

        except AttributeError:
            pass

        try:
            targetfile1 = newname.split('==/', 1)[1]
            targetfile = targetfile1.split('-', 1)[0]
            os.rename('base.apk', targetfile)
            self.hybrid.hafilecheck(targetfile, xx=xx)
        except FileNotFoundError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
            else:
                print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
            exit(1)
        finally:
            if (targetfile != ".apk"):
                os.remove(targetfile)

    def sendandroidvt(self, package):
        adb_comm = "adb"
        results = list()
        results2 = list()
        newname = ''

        myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
        myconn2 = myconn.stdout.decode()

        try:
            for i in myconn2.split('\n'):
                for j in i.split('base.apk='):
                    if 'package' in j:
                        _, value = j.split('package:')
                        _, value2 = value.split('/data/app/')
                        results.append(value2)
                        valuetmp = value + "base.apk"
                        results2.append(valuetmp)

        except AttributeError:
            pass

        try:
            for j in results2:
                if (package in j):
                    subprocess.run([adb_comm, "pull", j], capture_output=True)
                    newname = j[10:]

        except AttributeError:
            pass

        try:
            targetfile1 = newname.split('==/', 1)[1]
            targetfile = targetfile1.split('-', 1)[0]
            os.rename(r'base.apk', targetfile)
            myhash = sha256hash(targetfile)
            self.virustotal.vtuploadfile(targetfile)
            if (cv.bkg == 1):
                print(mycolors.foreground.yellow + "\tWaiting for 120 seconds...\n")
            if (cv.bkg == 0):
                print(mycolors.foreground.purple + "\tWaiting for 120 seconds...\n")
            time.sleep(120)
            self.virustotal.vthashwork(myhash, 1)

        except FileNotFoundError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
            else:
                print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
            printr()
            exit(1)

        finally:
            if (targetfile != ".apk"):
                os.remove(targetfile)
