import modules.configvars as cv
import requests
import textwrap
from utils.colors import mycolors, printr
import json


class AlienVaultExtractor():
    urlalien = 'http://otx.alienvault.com/api/v1'

    def __init__(self, ALIENAPI):
        self.ALIENAPI = ALIENAPI

    def requestALIENAPI(self):
        if self.ALIENAPI == '':
            print(mycolors.foreground.red + "\nTo be able to get information from AlienVault, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Alien Vault API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def alien_subscribed(self, arg1):
        url = AlienVaultExtractor.urlalien

        self.requestALIENAPI()

        hatext = ''
        haresponse = ''
        history = arg1
        headers = {'X-OTX-API-KEY': self.ALIENAPI}
        search_params = {'limit': history}

        try:
            resource = url
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            finalurl = '/'.join([resource, 'pulses', 'subscribed'])
            haresponse = requestsession.post(url=finalurl, headers=headers, params=search_params)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if 'results' in hatext:
                    x = 0
                    c = 1
                    for d in hatext['results']:
                        printr()
                        print(mycolors.foreground.lightcyan + "INFORMATION: %d" % c)
                        print(mycolors.reset + '-' * 15 + "\n")
                        if d['name']:
                            print(mycolors.foreground.yellow + "Headline:".ljust(13) + mycolors.reset + hatext['results'][x]['name'], end='\n')
                        if d['description']:
                            print(mycolors.foreground.yellow + "Description:" + "\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap((hatext['results'][x]['description']).ljust(14), width=90)), end='\n')
                        if hatext['results'][x]['references']:
                            for r in hatext['results'][x]['references']:
                                print(mycolors.foreground.yellow + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='')
                        if hatext['results'][x]['tags']:
                            if (hatext['results'][x]['tags']):
                                print(mycolors.foreground.yellow + "\nTags:".ljust(13) + mycolors.reset, end=' ')
                                b = 0
                                for z in hatext['results'][x]['tags']:
                                    b = b + 1
                                    if ((b % 5) == 0):
                                        print(mycolors.reset + z, end='\n'.ljust(14))
                                    else:
                                        print(mycolors.reset + z, end=' ')
                                    if (b == (len(hatext['results'][x]['tags']))):
                                        print(mycolors.reset + z, end='\n')

                        if hatext['results'][x]['industries']:
                            print(mycolors.foreground.yellow + "\nIndustries: ".ljust(14), end='')
                            for r in hatext['results'][x]['industries']:
                                print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='\n'.ljust(14))
                        if hatext['results'][x]['created']:
                            print(mycolors.foreground.yellow + "\nCreated: ".ljust(14) + mycolors.reset + hatext['results'][x]['created'], end='')
                        if hatext['results'][x]['modified']:
                            print(mycolors.foreground.yellow + "\nModified: ".ljust(14) + mycolors.reset + hatext['results'][x]['modified'], end='')
                        if hatext['results'][x]['malware_families']:
                            print(mycolors.foreground.yellow + "\nFamily: ".ljust(14), end='')
                            for r in hatext['results'][x]['malware_families']:
                                print(mycolors.reset + r, end=' ')
                        if hatext['results'][x]['adversary']:
                            print(mycolors.foreground.yellow + "\nAdversary: ".ljust(14) + mycolors.reset + hatext['results'][x]['adversary'], end='')
                        if hatext['results'][x]['targeted_countries']:
                            print(mycolors.foreground.yellow + "\nTargets: ".ljust(14), end='')
                            for r in hatext['results'][x]['targeted_countries']:
                                print(mycolors.reset + r, end=' ')
                        if hatext['results'][x]['indicators']:
                            limit = 0
                            print("\n")
                            for r in hatext['results'][x]['indicators']:
                                if r['indicator']:
                                    print(mycolors.foreground.yellow + "Indicator: ".ljust(13) + mycolors.reset + r['indicator'].ljust(64), end='\t')
                                    print(mycolors.foreground.yellow + "Title: " + mycolors.reset + r['title'], end='\n')
                                    limit = limit + 1
                                if (limit > 9):
                                    break
                        x = x + 1
                        c = c + 1
            else:
                if 'results' in hatext:
                    x = 0
                    c = 1
                    for d in hatext['results']:
                        printr()
                        print(mycolors.foreground.purple + "INFORMATION: %d" % c)
                        print(mycolors.reset + '-' * 15 + "\n")
                        if d['name']:
                            print(mycolors.foreground.blue + "Headline:".ljust(13) + mycolors.reset + hatext['results'][x]['name'], end='\n')
                        if d['description']:
                            print(mycolors.foreground.blue + "Description:" + "\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap((hatext['results'][x]['description']).ljust(14), width=90)), end='\n')
                        if hatext['results'][x]['references']:
                            for r in hatext['results'][x]['references']:
                                print(mycolors.foreground.blue + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='')
                        if hatext['results'][x]['tags']:
                            print(mycolors.foreground.blue + "\nTags:".ljust(13) + mycolors.reset, end=' ')
                            b = 0
                            for z in hatext['results'][x]['tags']:
                                b = b + 1
                                if ((b % 5) == 0):
                                    print(mycolors.reset + z, end='\n'.ljust(14))
                                else:
                                    print(mycolors.reset + z, end=' ')
                                if (b == (len(hatext['results'][x]['tags']))):
                                    print(mycolors.reset + z, end='\n')

                        if hatext['results'][x]['industries']:
                            print(mycolors.foreground.blue + "\nIndustries: ".ljust(14), end='')
                            for r in hatext['results'][x]['industries']:
                                print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='\n'.ljust(14))
                        if hatext['results'][x]['created']:
                            print(mycolors.foreground.blue + "\nCreated: ".ljust(14) + mycolors.reset + hatext['results'][x]['created'], end='')
                        if hatext['results'][x]['modified']:
                            print(mycolors.foreground.blue + "\nModified: ".ljust(14) + mycolors.reset + hatext['results'][x]['modified'], end='')
                        if hatext['results'][x]['malware_families']:
                            print(mycolors.foreground.blue + "\nFamily: ".ljust(14), end='')
                            for r in hatext['results'][x]['malware_families']:
                                print(mycolors.reset + r, end=' ')
                        if hatext['results'][x]['adversary']:
                            print(mycolors.foreground.blue + "\nAdversary: ".ljust(14) + mycolors.reset + hatext['results'][x]['adversary'], end='')
                        if hatext['results'][x]['targeted_countries']:
                            print(mycolors.foreground.blue + "\nTargets: ".ljust(14), end='')
                            for r in hatext['results'][x]['targeted_countries']:
                                print(mycolors.reset + r, end=' ')
                        if hatext['results'][x]['indicators']:
                            limit = 0
                            print("\n")
                            for r in hatext['results'][x]['indicators']:
                                if r['indicator']:
                                    print(mycolors.foreground.blue + "Indicator: ".ljust(13) + mycolors.reset + r['indicator'].ljust(64), end='\t')
                                    print(mycolors.foreground.blue + "Title: " + mycolors.reset + r['title'], end='\n')
                                    limit = limit + 1
                                if (limit > 9):
                                    break
                        x = x + 1
                        c = c + 1

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
            printr()

    def alien_ipv4(self, arg1):
        url = AlienVaultExtractor.urlalien

        self.requestALIENAPI()
        hatext = ''
        haresponse = ''
        history = '10'
        headers = {'X-OTX-API-KEY': self.ALIENAPI}
        search_params = {'limit': history}
        myargs = arg1

        try:

            resource = url
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            finalurl = '/'.join([resource, 'indicators', 'IPv4', myargs])
            haresponse = requestsession.post(url=finalurl, headers=headers, params=search_params)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if 'sections' in hatext:
                    printr()
                    if hatext['asn']:
                        print(mycolors.foreground.lightcyan + "ASN:".ljust(13) + mycolors.reset + hatext['asn'], end='\n')
                    if hatext['city']:
                        print(mycolors.foreground.lightcyan + "City:".ljust(13) + mycolors.reset + hatext['city'], end='\n')
                    if hatext['country_name']:
                        print(mycolors.foreground.lightcyan + "Country:".ljust(13) + mycolors.reset + hatext['country_name'], end='\n')
                    if hatext['pulse_info']:
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.red + "\nNo further information about the provided IP address!\n" + mycolors.reset)
                                exit(0)
                        z = 0
                        i = 0
                        for key in hatext['pulse_info']:
                            if (isinstance(hatext['pulse_info'][key], list)):
                                while i < len(hatext['pulse_info'][key]):
                                    if (isinstance(hatext['pulse_info'][key][i], dict)):
                                        if 'malware_families' in hatext['pulse_info'][key][i]:
                                            print(mycolors.foreground.lightcyan + "\nMalware:".ljust(13) + mycolors.reset)
                                            for z in hatext['pulse_info'][key][i]['malware_families']:
                                                print("".ljust(13) + z['display_name'])
                                        if 'tags' in hatext['pulse_info'][key][i]:
                                            print(mycolors.foreground.lightcyan + "Tags:".ljust(12) + mycolors.reset, end=' ')
                                            if (hatext['pulse_info'][key][i]['tags']):
                                                b = 0
                                                for z in hatext['pulse_info'][key][i]['tags']:
                                                    b = b + 1
                                                    if ((b % 5) == 0):
                                                        print(mycolors.reset + z, end='\n'.ljust(14))
                                                    else:
                                                        print(mycolors.reset + z, end=' ')
                                                    if (b == (len(hatext['pulse_info'][key][i]['tags']))):
                                                        print(mycolors.reset + z, end='\n')
                                    i = i + 1
                    if hatext['pulse_info']:
                        if hatext['pulse_info']['pulses']:
                            i = 0
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "modified" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.lightcyan + "\nModified:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['modified']), end='')
                                if "name" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.lightcyan + "\nNews:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['name']), end='')
                                if "created" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.lightcyan + "\nCreated:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['created']), end='')
                                    break
                                else:
                                    i = i + i

                            k = 0
                            print(mycolors.foreground.lightcyan + "\n\nDescription:" + mycolors.reset, end='')
                            while (k < len(hatext['pulse_info']['pulses'])):
                                for key in hatext['pulse_info']['pulses'][k]:
                                    if (key == 'description'):
                                        if (hatext['pulse_info']['pulses'][k]['description']):
                                            print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['pulse_info']['pulses'][k]['description'], width=100)), end='\n')
                                            break
                                k = k + 1

                    if hatext['pulse_info']:
                        if hatext['pulse_info']['references']:
                            print(mycolors.foreground.lightcyan + "\nReferences: ".ljust(14) + mycolors.reset, end=' ')
                            for r in hatext['pulse_info']['references']:
                                print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='\n')
            else:
                if 'sections' in hatext:
                    print(mycolors.reset + "\n\n" + "ALIEN VAULT IPv4 REPORT".center(120))
                    printr()
                    print(mycolors.reset + '-' * 120 + "\n")
                    if hatext['asn']:
                        print(mycolors.foreground.green + "ASN:".ljust(13) + mycolors.reset + hatext['asn'], end='\n')
                    if hatext['city']:
                        print(mycolors.foreground.green + "City:".ljust(13) + mycolors.reset + hatext['city'], end='\n')
                    if hatext['country_name']:
                        print(mycolors.foreground.green + "Country:".ljust(13) + mycolors.reset + hatext['country_name'], end='\n')
                    if hatext['pulse_info']:
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.red + "\nNo further information about the provided IP address!\n" + mycolors.reset)
                                exit(0)
                        z = 0
                        i = 0
                        for key in hatext['pulse_info']:
                            if (isinstance(hatext['pulse_info'][key], list)):
                                while i < len(hatext['pulse_info'][key]):
                                    if (isinstance(hatext['pulse_info'][key][i], dict)):
                                        print(mycolors.foreground.green + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                        if 'malware_families' in hatext['pulse_info'][key][i]:
                                            for z in hatext['pulse_info'][key][i]['malware_families']:
                                                print("\n".ljust(14) + z['display_name'], end='')
                                        print(mycolors.foreground.green + "\nTags:".ljust(13) + mycolors.reset, end=' ')
                                        if 'tags' in hatext['pulse_info'][key][i]:
                                            b = 0
                                            for z in hatext['pulse_info'][key][i]['tags']:
                                                b = b + 1
                                                if ((b % 5) == 0):
                                                    print(mycolors.reset + z, end='\n'.ljust(14))
                                                else:
                                                    print(mycolors.reset + z, end=' ')
                                                if (b == (len(hatext['pulse_info'][key][i]['tags']))):
                                                    print(mycolors.reset + z, end='\n')
                                    i = i + 1
                    if hatext['pulse_info']:
                        if hatext['pulse_info']['pulses']:
                            i = 0
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "modified" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.green + "\nModified:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['modified']), end='')
                                if "name" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.green + "\nNews:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['name']), end='')
                                if "created" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.green + "\nCreated:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['created']), end='')
                                    break
                                else:
                                    i = i + i

                            k = 0
                            print(mycolors.foreground.green + "\n\nDescription:" + "\n".ljust(14) + mycolors.reset, end='')
                            while (k < len(hatext['pulse_info']['pulses'])):
                                for key in hatext['pulse_info']['pulses'][k]:
                                    if (key == 'description'):
                                        if (hatext['pulse_info']['pulses'][k]['description']):
                                            print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['pulse_info']['pulses'][k]['description'], width=100)), end='\n')
                                            break
                                k = k + 1

                    if hatext['pulse_info']:
                        if hatext['pulse_info']['references']:
                            print(mycolors.foreground.green + "\n\nReferences: ".ljust(14) + mycolors.reset, end='')
                            for r in hatext['pulse_info']['references']:
                                print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='\n')

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
            printr()

    def alien_domain(self, arg1):
        url = AlienVaultExtractor.urlalien

        self.requestALIENAPI()

        hatext = ''
        haresponse = ''
        history = '10'
        headers = {'X-OTX-API-KEY': self.ALIENAPI}
        search_params = {'limit': history}
        myargs = arg1

        try:

            resource = url
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            finalurl = '/'.join([resource, 'indicators', 'domain', myargs])
            haresponse = requestsession.post(url=finalurl, headers=headers, params=search_params)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if 'indicator' in hatext:
                    printr()
                    if hatext['alexa']:
                        print(mycolors.foreground.yellow + "Alexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='\n')
                    if hatext['pulse_info']:
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.red + "\nNot further information about the provided DOMAIN!\n" + mycolors.reset)
                                exit(0)
                        if hatext['pulse_info']['pulses']:
                            i = 0
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.yellow + "Tags:".ljust(13), end='')
                                    for j in hatext['pulse_info']['pulses'][i]['tags']:
                                        print(mycolors.reset + j, end=' ')
                                if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                    print(mycolors.foreground.yellow + "\nMalware:".ljust(14) + mycolors.reset, end='')
                                    for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.reset + z['display_name'], end=' ')
                                if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                    print(mycolors.foreground.yellow + "\nCountries:".ljust(14), end='')
                                    for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.reset + z, end=' ')
                                if 'name' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['name']:
                                        print(mycolors.foreground.yellow + "\nNews:".ljust(14) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                                if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                            print(mycolors.foreground.yellow + "\nAttack IDs:".ljust(14) + mycolors.reset + str(k['display_name']), end='')
                                    break
                                i = i + i

                        print(mycolors.foreground.yellow + "\nDescription:", end=' ')
                        for x in hatext['pulse_info']['pulses']:
                            if (isinstance(x, dict)):
                                for y in x:
                                    if 'description' in y:
                                        if (x['description']):
                                            print("\n".ljust(13), end=' ')
                                            print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(x['description'], width=100)), end='\n')
                    if hatext['pulse_info']:
                        if hatext['pulse_info']['references']:
                            print("\n")
                            for r in hatext['pulse_info']['references']:
                                print(mycolors.foreground.yellow + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='')

            else:
                if 'indicator' in hatext:
                    printr()
                    if hatext['alexa']:
                        print(mycolors.foreground.purple + "Alexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='\n')
                    if hatext['pulse_info']:
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.red + "\nNo further information about the provided DOMAIN!\n" + mycolors.reset)
                                exit(0)
                        if hatext['pulse_info']['pulses']:
                            i = 0
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    print(mycolors.foreground.purple + "Tags:".ljust(13), end='')
                                    for j in hatext['pulse_info']['pulses'][i]['tags']:
                                        print(mycolors.reset + j, end=' ')
                                if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                    print(mycolors.foreground.purple + "\nMalware:".ljust(14) + mycolors.reset, end='')
                                    for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.reset + z['display_name'], end=' ')
                                if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                    print(mycolors.foreground.purple + "\nCountries:".ljust(14), end='')
                                    for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.reset + z, end=' ')
                                if 'name' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['name']:
                                        print(mycolors.foreground.purple + "\nNews:".ljust(14) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                                if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                            print(mycolors.foreground.purple + "\nAttack IDs:".ljust(14) + mycolors.reset + str(k['display_name']), end='')
                                    break
                                i = i + i

                        print(mycolors.foreground.purple + "\nDescription:", end=' ')
                        for x in hatext['pulse_info']['pulses']:
                            if (isinstance(x, dict)):
                                for y in x:
                                    if 'description' in y:
                                        if (x['description']):
                                            print("\n".ljust(13), end=' ')
                                            print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(x['description'], width=100)), end='\n')
                    if hatext['pulse_info']:
                        if hatext['pulse_info']['references']:
                            print("\n")
                            for r in hatext['pulse_info']['references']:
                                print(mycolors.foreground.purple + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r, width=100)), end='')

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
            printr()

    def alien_hash(self, arg1):
        url = AlienVaultExtractor.urlalien

        self.requestALIENAPI()

        hatext = ''
        haresponse = ''
        history = '10'
        headers = {'X-OTX-API-KEY': self.ALIENAPI}
        search_params = {'limit': history}
        myargs = arg1

        try:

            resource = url
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            finalurl = '/'.join([resource, 'indicators', 'file', myargs])
            haresponse = requestsession.post(url=finalurl, headers=headers, params=search_params)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if 'indicator' in hatext:
                    printr()
                    if hatext['pulse_info']:
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.red + "\nNo further information about the provided HASH!\n" + mycolors.reset)
                                exit(0)
                        i = 0
                        if 'pulses' in (hatext['pulse_info']):
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    if (hatext['pulse_info']['pulses'][i]['tags']):
                                        print(mycolors.foreground.lightcyan + "\nTags:".ljust(13), end='')
                                        b = 0
                                        for j in hatext['pulse_info']['pulses'][i]['tags']:
                                            b = b + 1
                                            if ((b % 5) == 0):
                                                print(mycolors.reset + j, end='\n'.ljust(13))
                                            else:
                                                print(mycolors.reset + j, end=' ')
                                            if (b == (len(hatext['pulse_info']['pulses'][i]['tags']))):
                                                print(mycolors.reset + j, end='\n')

                                if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.foreground.lightcyan + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                        for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                            print(mycolors.reset + z['display_name'], end=' ')
                                if 'created' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['created']:
                                        print(mycolors.foreground.lightcyan + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                                if 'modified' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['modified']:
                                        print(mycolors.foreground.lightcyan + "\nModified:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                                if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.foreground.lightcyan + "\nCountries:".ljust(13), end='')
                                        for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                            print(mycolors.reset + z, end=' ')
                                if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                            print(mycolors.foreground.lightcyan + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                                if 'name' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['name']:
                                        print(mycolors.foreground.lightcyan + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                                    break
                                i = i + 1

                        print(mycolors.foreground.lightcyan + "\nDescription:", end='')
                        for x in hatext['pulse_info']['pulses']:
                            if (isinstance(x, dict)):
                                for y in x:
                                    if 'description' in y:
                                        if (x['description']):
                                            print("\n".ljust(13), end='')
                                            print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'], width=100)), end='\n')

                        if "references" in (hatext['pulse_info']):
                            for j in hatext['pulse_info']['references']:
                                print(mycolors.foreground.lightcyan + "\nReferences: ".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j, width=100)), end='')
                        print("\n")
            else:
                if 'indicator' in hatext:
                    printr()
                    if hatext['pulse_info']:
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.red + "\nNo further information about the provided HASH!\n" + mycolors.reset)
                                exit(0)
                        i = 0
                        if 'pulses' in (hatext['pulse_info']):
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    if (hatext['pulse_info']['pulses'][i]['tags']):
                                        print(mycolors.foreground.cyan + "\nTags:".ljust(13), end='')
                                        b = 0
                                        for j in hatext['pulse_info']['pulses'][i]['tags']:
                                            b = b + 1
                                            if ((b % 5) == 0):
                                                print(mycolors.reset + j, end='\n'.ljust(13))
                                            else:
                                                print(mycolors.reset + j, end=' ')
                                            if (b == (len(hatext['pulse_info']['pulses'][i]['tags']))):
                                                print(mycolors.reset + j, end='\n')
                                if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.foreground.cyan + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                        for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                            print(mycolors.reset + z['display_name'], end=' ')
                                if 'created' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['created']:
                                        print(mycolors.foreground.cyan + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                                if 'modified' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['modified']:
                                        print(mycolors.foreground.cyan + "\nModified:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                                if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.foreground.cyan + "\nCountries:".ljust(13), end='')
                                        for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                            print(mycolors.reset + z, end=' ')
                                if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                            print(mycolors.foreground.cyan + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                                if 'name' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['name']:
                                        print(mycolors.foreground.cyan + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                                    break
                                i = i + 1

                        print(mycolors.foreground.cyan + "\nDescription:", end='')
                        for x in hatext['pulse_info']['pulses']:
                            if (isinstance(x, dict)):
                                for y in x:
                                    if 'description' in y:
                                        if (x['description']):
                                            print("\n".ljust(13), end='')
                                            print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'], width=100)), end='\n')

                        if "references" in (hatext['pulse_info']):
                            for j in hatext['pulse_info']['references']:
                                print(mycolors.foreground.cyan + "\nReferences: ".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j, width=100)), end='')
                        print("\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
            printr()

    def alien_url(self, arg1):
        urlx = AlienVaultExtractor.urlalien

        self.requestALIENAPI()

        hatext = ''
        haresponse = ''
        history = '10'
        headers = {'X-OTX-API-KEY': self.ALIENAPI}
        search_params = {'limit': history}
        myargs = arg1

        try:

            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            finalurl = '/'.join([resource, 'indicators', 'url', myargs, 'general'])
            haresponse = requestsession.post(url=finalurl, headers=headers, params=search_params)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if 'indicator' in hatext:
                    printr()
                    if hatext['pulse_info']:
                        i = 0
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.lightred + "\nURL not found!\n" + mycolors.reset)
                                exit(0)
                        if 'pulses' in (hatext['pulse_info']):
                            if 'name' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['name']:
                                    print(mycolors.foreground.lightred + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                            print(mycolors.foreground.lightred + "\nDescription:", end='')
                            for x in hatext['pulse_info']['pulses']:
                                if (isinstance(x, dict)):
                                    for y in x:
                                        if 'description' in y:
                                            if (x['description']):
                                                print("\n".ljust(13), end='')
                                                print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'], width=100)), end='\n')
                            if "references" in (hatext['pulse_info']):
                                for j in hatext['pulse_info']['references']:
                                    print(mycolors.foreground.lightred + "\nReferences:".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j, width=100)), end='')
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    if hatext['pulse_info']['pulses'][i]['tags']:
                                        print(mycolors.foreground.lightred + "\nTags:".ljust(13), end='')
                                        for j in hatext['pulse_info']['pulses'][i]['tags']:
                                            print(mycolors.reset + j, end=' ')
                                if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.foreground.lightred + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                        for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                            print(mycolors.reset + z['display_name'], end=' ')
                                if 'created' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['created']:
                                        print(mycolors.foreground.lightred + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                                if 'modified' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['modified']:
                                        print(mycolors.foreground.lightred + "\nModified:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                                if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.foreground.lightred + "\nCountries:".ljust(13), end='')
                                        for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                            print(mycolors.reset + z, end=' ')
                                if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                            print(mycolors.foreground.lightred + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                                    break
                                i = i + 1

                            j = 0
                            while (j < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    if hatext['pulse_info']['pulses'][j]['tags']:
                                        print(mycolors.foreground.lightred + "\nTags:".ljust(13), end='')
                                        for z in hatext['pulse_info']['pulses'][j]['tags']:
                                            print(mycolors.reset + z, end=' ')
                                j = j + 1

                            t = 0
                            while (t < len(hatext['pulse_info']['pulses'])):
                                if 'malware_families' in hatext['pulse_info']['pulses'][t]:
                                    if hatext['pulse_info']['pulses'][t]['malware_families']:
                                        print(mycolors.foreground.lightred + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                        for w in hatext['pulse_info']['pulses'][t]['malware_families']:
                                            print(mycolors.reset + w['display_name'], end=' ')
                                t = t + 1
                    if hatext['alexa']:
                        print(mycolors.foreground.lightred + "\nAlexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='')

            else:
                if 'indicator' in hatext:
                    printr()
                    if hatext['pulse_info']:
                        i = 0
                        if 'count' in (hatext['pulse_info']):
                            if ((hatext['pulse_info']['count']) == 0):
                                print(mycolors.foreground.red + "\nURL not found!\n" + mycolors.reset)
                                exit(0)
                        if 'pulses' in (hatext['pulse_info']):
                            if 'name' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['name']:
                                    print(mycolors.foreground.red + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                            print(mycolors.foreground.red + "\nDescription:", end='')
                            for x in hatext['pulse_info']['pulses']:
                                if (isinstance(x, dict)):
                                    for y in x:
                                        if 'description' in y:
                                            if (x['description']):
                                                print("\n".ljust(13), end='')
                                                print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'], width=100)), end='\n')
                            if "references" in (hatext['pulse_info']):
                                for j in hatext['pulse_info']['references']:
                                    print(mycolors.foreground.red + "\nReferences:".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j, width=100)), end='')
                            while (i < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    if hatext['pulse_info']['pulses'][i]['tags']:
                                        print(mycolors.foreground.red + "\nTags:".ljust(13), end='')
                                        for j in hatext['pulse_info']['pulses'][i]['tags']:
                                            print(mycolors.reset + j, end=' ')
                                if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.foreground.red + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                        for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                            print(mycolors.reset + z['display_name'], end=' ')
                                if 'created' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['created']:
                                        print(mycolors.foreground.red + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                                if 'modified' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['modified']:
                                        print(mycolors.foreground.red + "\nModified:".ljust(13) + mycolors.reset, end='')
                                        print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                                if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.foreground.red + "\nCountries:".ljust(13), end='')
                                        for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                            print(mycolors.reset + z, end=' ')
                                if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                    if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                            print(mycolors.foreground.red + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                                    break
                                i = i + 1

                            j = 0
                            while (j < len(hatext['pulse_info']['pulses'])):
                                if "tags" in (hatext['pulse_info']['pulses'][i]):
                                    if hatext['pulse_info']['pulses'][j]['tags']:
                                        print(mycolors.foreground.red + "\nTags:".ljust(13), end='')
                                        for z in hatext['pulse_info']['pulses'][j]['tags']:
                                            print(mycolors.reset + z, end=' ')
                                j = j + 1

                            t = 0
                            while (t < len(hatext['pulse_info']['pulses'])):
                                if 'malware_families' in hatext['pulse_info']['pulses'][t]:
                                    if hatext['pulse_info']['pulses'][t]['malware_families']:
                                        print(mycolors.foreground.red + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                        for w in hatext['pulse_info']['pulses'][t]['malware_families']:
                                            print(mycolors.reset + w['display_name'], end=' ')
                                t = t + 1
                    if hatext['alexa']:
                        print(mycolors.foreground.red + "\nAlexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='')

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
            printr()
