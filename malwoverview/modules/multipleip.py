from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv

class MultipleIPExtractor:
    def __init__(self, extractors):
        self.extractors = extractors

    def get_multiple_ip_details(self, ip_address):
        for extractor in self.extractors:
            extractor_obj = self.extractors[extractor]
            if extractor == "IPInfo":
                extractor_obj.get_ip_details(ip_address)
            elif extractor == "BGPView":
                extractor_obj.get_ip_details(ip_address)
            elif extractor == "VirusTotal":
                data = extractor_obj._raw_ip_info(ip_address)
                self._get_info_virustotal(data.json())
            elif extractor == "AlienVault":
                data = extractor_obj._raw_ip_info(ip_address)
                self._get_info_alienvault(data.json())
            #elif extractor == "InQuest":
            #    data = extractor_obj._raw_ip_info(ip_address)
            #    self._get_info_inquest(data.json())
            # elif extractor == "PolySwarm":
            #     data = extractor_obj._raw_ip_info(ip_address)
            #     self._get_info_polyswarm(data)

    def _get_info_virustotal(self, data):
        try:
            attributes = data.get('data', {}).get('attributes', {})
    
            print()
            print((mycolors.reset + "VIRUSTOTAL IP REPORT".center(100)), end='')
            #print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))
    
            fields = {
                'Reputation': attributes.get('reputation'),
                'RIR': attributes.get('regional_internet_registry'),
                'Network': attributes.get('network'),
                'ASN': attributes.get('asn'),
                'AS Owner': attributes.get('as_owner'),
                'Country Code': attributes.get('country'),
                'Continent': attributes.get('continent')
            }

            COLSIZE = max(len(field) for field in fields.keys()) + 3
    
            for field, value in fields.items():
                print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + str(value))
    
            print("\nAnalysis Stats:")
            stats = attributes.get('last_analysis_stats', {})
            for stat, count in stats.items():
                print(mycolors.foreground.error(cv.bkg) + f"{stat.title()}:".ljust(COLSIZE) + "\t" + mycolors.reset + str(count))
            
            print("\nCommunity Votes:")
            votes = attributes.get('total_votes', {})
            for vote, count in votes.items():
                print(mycolors.foreground.error(cv.bkg) + f"{vote.title()}:".ljust(COLSIZE) + "\t" + mycolors.reset + str(count))
            
        except Exception as e:
            print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

        print()
        print("(For the full VirusTotal report use the -v and -V options)")

    def _get_info_alienvault(self, data):
        try:
            print()
            print((mycolors.reset + "ALIENVAULT IP REPORT".center(100)), end='')
            # print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))
        
            COLSIZE = 13
        
            infocolor = mycolors.foreground.info(cv.bkg)
            print(infocolor + f"ASN:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('asn')))
            print(infocolor + f"Country:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('country_name')))
            print(infocolor + f"Region:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('region')))
            print(infocolor + f"City:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('city')))
            print(infocolor + f"Continent:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('continent_code')))
            print(infocolor + f"Latitude:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('latitude')))
            print(infocolor + f"Longitude:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('longitude')))
            print(infocolor + f"Sections:".ljust(COLSIZE) + "\t" + mycolors.reset + ', '.join(data.get('sections', [])))
            print(mycolors.foreground.error(cv.bkg) + f"Pulses Found:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('pulse_info', {}).get('count')))
                
        except Exception as e:
            printc(f"\nError: {str(e)}\n", mycolors.foreground.error(cv.bkg))

        print()
        print("(For the full AlienVault report use the -n and -N options)")

"""
    def _get_info_inquest(self, data):
        try:
            print("\n")
            print((mycolors.reset + "INQUEST IP REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            print(data)

        except Exception as e:
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + f"\nError: {str(e)}\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + f"\nError: {str(e)}\n" + mycolors.reset)

        print()
        print("(For the full InQuest report use the -i and -I options)")

    def _get_info_polyswarm(self, data):
        print("\n")
        print((mycolors.reset + "POLYSWARM IP REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100 * '-').center(50))

        print(data)

        print()
        print("(For the full PolySwarm report use the -p and -P options)")
"""