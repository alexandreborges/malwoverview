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
from malwoverview.utils.session import create_session


PKG_COL_WIDTH = 50
PKG_COL_WIDTH_HA = 40


def truncate_pkg(text, width=PKG_COL_WIDTH):
    text = str(text)
    if len(text) > width:
        return text[:width - 3] + '...'
    return text


class androidVTThread(threading.Thread):
    def __init__(self, key, package, extractor):
        threading.Thread.__init__(self)
        self.key = key
        self.package = package
        self.extractor = extractor

    def run(self):
        key1 = self.key
        package1 = self.package

        myhash = key1
        vtfinal = self.extractor.virustotal.vtcheck(myhash, 0)

        if (cv.bkg == 1):
            print((mycolors.foreground.yellow + "%-50s" % truncate_pkg(package1)), end=' ')
            print((mycolors.foreground.lightcyan + "%-65s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.lightcyan + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.blue + "%-50s" % truncate_pkg(package1)), end=' ')
            print((mycolors.foreground.cyan + "%-65s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))


class quickHAAndroidThread(threading.Thread):
    def __init__(self, key, package, extractor):
        threading.Thread.__init__(self)
        self.key = key
        self.package = package
        self.extractor = extractor

    def run(self):
        key1 = self.key
        package1 = self.package

        myhash = key1
        result = self.extractor.quickhashowAndroid(myhash)

        (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections) = result

        if (cv.bkg == 1):
            print((mycolors.foreground.lightcyan + "%-40s" % truncate_pkg(package1, PKG_COL_WIDTH_HA)), end=' ')
            print((mycolors.foreground.yellow + "%-64s" % key1), end=' ')
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
            print((mycolors.foreground.cyan + "%-40s" % truncate_pkg(package1, PKG_COL_WIDTH_HA)), end=' ')
            print((mycolors.foreground.blue + "%-64s" % key1), end=' ')
            print((mycolors.foreground.cyan + "%9s" % final), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.purple + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.purple + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.blue + "%7s" % totalsignatures), end='')
            if (threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.red + "%20s" % verdict), end='\n')
            elif (verdict == "suspicious"):
                print((mycolors.foreground.cyan + "%20s" % verdict), end='\n')
            elif (verdict == "no specific threat"):
                print((mycolors.foreground.blue + "%20s" % verdict), end='\n')
            else:
                verdict = 'not analyzed yet'
                print((mycolors.reset + "%20s" % verdict), end='\n')


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
            requestsession = create_session()
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
            print((mycolors.foreground.yellow + "%-50s" % truncate_pkg(package)), end=' ')
            print((mycolors.foreground.lightcyan + "%-65s" % key1), end=' ')
            print((mycolors.foreground.lightred + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.blue + "%-50s" % truncate_pkg(package)), end=' ')
            print((mycolors.foreground.cyan + "%-65s" % key1), end=' ')
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

    APK_PATH_ALLOWED = set('/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-~=')
    PKG_NAME_ALLOWED = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._')

    @staticmethod
    def _parse_packages(output):
        packages = {}
        if not output:
            return packages

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith('package:'):
                continue

            body = line[len('package:'):]
            apk_path, sep, pkg_name = body.rpartition('=')
            if not sep or not pkg_name or not apk_path:
                continue
            if not apk_path.startswith('/data/app/') or not apk_path.endswith('.apk'):
                continue
            if not all(c in AndroidExtractor.APK_PATH_ALLOWED for c in apk_path):
                continue
            if not all(c in AndroidExtractor.PKG_NAME_ALLOWED for c in pkg_name):
                continue

            packages[pkg_name] = apk_path

        return packages

    def _adb_not_found_msg(self):
        if (cv.bkg == 1):
            print(mycolors.foreground.lightred + "\nThe 'adb' tool was not found in your PATH. Install Android platform-tools and make sure 'adb' is reachable.\n")
        else:
            print(mycolors.foreground.red + "\nThe 'adb' tool was not found in your PATH. Install Android platform-tools and make sure 'adb' is reachable.\n")
        printr()

    def _no_packages_msg(self):
        if (cv.bkg == 1):
            print(mycolors.foreground.lightred + "\nNo third-party packages were found. Is a device connected and authorized? Check with 'adb devices'.\n")
        else:
            print(mycolors.foreground.red + "\nNo third-party packages were found. Is a device connected and authorized? Check with 'adb devices'.\n")
        printr()

    def _list_device_packages(self, adb_comm="adb"):
        try:
            myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
        except FileNotFoundError:
            self._adb_not_found_msg()
            return None

        output = myconn.stdout.decode(errors='ignore')
        return self._parse_packages(output)

    def checkandroid(self, engine):
        adb_comm = "adb"

        packages = self._list_device_packages(adb_comm)
        if packages is None:
            return

        dictAndroid = {}
        for pkg_name, apk_path in packages.items():
            myconn3 = subprocess.run([adb_comm, "shell", "sha256sum", apk_path], text=True, capture_output=True)
            hashout = (myconn3.stdout or '').strip()
            if not hashout:
                continue
            sha256 = hashout.split(" ")[0].strip()
            if sha256:
                dictAndroid[pkg_name] = sha256

        if not dictAndroid:
            self._no_packages_msg()
            return

        if (engine == 1):
            print(mycolors.reset + "\n")
            print("Package".center(40) + "Hash".center(66) + "Found?".center(12) + "AVdet".center(10) + "Sigs".center(5) + "Score".center(14) + "Verdict".center(14))
            print(161 * '-')
            for key, value in dictAndroid.items():
                self.checkandroidha(value, key)

        if (engine == 2):
            tm1 = 0
            print(mycolors.reset + "\n")
            print("Package".center(50) + "Hash".center(66) + "Virus Total".center(12))
            print(128 * '-')
            for key, value in dictAndroid.items():
                tm1 = tm1 + 1
                if tm1 % 4 == 0:
                    time.sleep(61)
                self.checkandroidvt(value, key)

        if (engine == 3):
            print(mycolors.reset + "\n")
            print("Package".center(50) + "Hash".center(66) + "Virus Total".center(12))
            print(128 * '-')
            for key, value in dictAndroid.items():
                self.checkandroidvtx(value, key)

    def _pull_apk(self, package, adb_comm="adb"):
        packages = self._list_device_packages(adb_comm)
        if packages is None:
            return None

        apk_path = None
        chosen = None
        for pkg_name, path in packages.items():
            if package == pkg_name or package in pkg_name or package in path:
                apk_path = path
                chosen = pkg_name
                break

        if not apk_path:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
            else:
                print((mycolors.foreground.red + "\nFile not found on device!\n"))
            printr()
            return None

        subprocess.run([adb_comm, "pull", apk_path], capture_output=True)

        localname = os.path.basename(apk_path)
        targetfile = os.path.basename(chosen) + ".apk"

        if not os.path.isfile(localname):
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nFailed to pull the APK from the device!\n"))
            else:
                print((mycolors.foreground.red + "\nFailed to pull the APK from the device!\n"))
            printr()
            return None

        os.replace(localname, targetfile)
        return targetfile

    def sendandroidha(self, package, xx=3):
        targetfile = self._pull_apk(package)
        if not targetfile:
            return

        try:
            self.hybrid.hafilecheck(targetfile, xx=xx)
        finally:
            if os.path.isfile(targetfile):
                os.remove(targetfile)

    def sendandroidvt(self, package):
        targetfile = self._pull_apk(package)
        if not targetfile:
            return

        try:
            myhash = sha256hash(targetfile)
            self.virustotal.vtuploadfile(targetfile)
            if (cv.bkg == 1):
                print(mycolors.foreground.yellow + "\tWaiting for 120 seconds...\n")
            if (cv.bkg == 0):
                print(mycolors.foreground.purple + "\tWaiting for 120 seconds...\n")
            time.sleep(120)
            self.virustotal.vthashwork(myhash, 1)
        finally:
            if os.path.isfile(targetfile):
                os.remove(targetfile)
