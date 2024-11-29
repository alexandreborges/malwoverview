from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv

class MultipleIPExtractor:
    def __init__(self, extractors):
        self.extractors = extractors

    def get_multiple_ip_details(self, ip_address):
        # print("\n")
        # print((mycolors.reset + "MULTIPLE IP REPORTS".center(100)), end='')
        # print((mycolors.reset + "".center(28)), end='')
        # print("\n" + (100 * '-').center(50))

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
            # elif extractor == "PolySwarm":
            #     data = extractor_obj._raw_ip_info(ip_address)
            #     self._get_info_polyswarm(data)

    def _get_info_virustotal(self, data):
        try:
            attributes = data.get('data', {}).get('attributes', {})
    
            print("\n")
            print((mycolors.reset + "VIRUSTOTAL IP REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
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
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + f"{field}: ".ljust(COLSIZE) + mycolors.reset + str(value))
                else:
                    print(mycolors.foreground.cyan + f"{field}: ".ljust(COLSIZE) + mycolors.reset + str(value))
    
            print("\nAnalysis Stats:")
            stats = attributes.get('last_analysis_stats', {})
            for stat, count in stats.items():
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + f"{stat.title()}: ".ljust(COLSIZE) + mycolors.reset + str(count))
                else:
                    print(mycolors.foreground.red + f"{stat.title()}: ".ljust(COLSIZE) + mycolors.reset + str(count))
            
            print("\nCommunity Votes:")
            votes = attributes.get('total_votes', {})
            for vote, count in votes.items():
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + f"{vote.title()}: ".ljust(COLSIZE) + mycolors.reset + str(count))
                else:
                    print(mycolors.foreground.red + f"{vote.title()}: ".ljust(COLSIZE) + mycolors.reset + str(count))
            
        except Exception as e:
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + f"\nError: {str(e)}\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + f"\nError: {str(e)}\n" + mycolors.reset)

        print()
        print("(For the full VirusTotal report use the -v and -V options)")

    def _get_info_polyswarm(self, data):
        print("\n")
        print((mycolors.reset + "POLYSWARM IP REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100 * '-').center(50))

        print(data)

        print()
        print("(For the full PolySwarm report use the -p and -P options)")

    def _get_info_alienvault(self, data):
        try:
            print("\n")
            print((mycolors.reset + "ALIENVAULT IP REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))
        
            COLSIZE = 21
        
            if (cv.bkg == 1):
                print(mycolors.foreground.lightcyan + "ASN: ".ljust(COLSIZE) + mycolors.reset + str(data.get('asn')))
                print(mycolors.foreground.lightcyan + "City: ".ljust(COLSIZE) + mycolors.reset + str(data.get('city')))
                print(mycolors.foreground.lightcyan + "Region: ".ljust(COLSIZE) + mycolors.reset + str(data.get('region')))
                print(mycolors.foreground.lightcyan + "Country: ".ljust(COLSIZE) + mycolors.reset + str(data.get('country_name')))
                print(mycolors.foreground.lightcyan + "Continent: ".ljust(COLSIZE) + mycolors.reset + str(data.get('continent_code')))
                print(mycolors.foreground.lightcyan + "Latitude: ".ljust(COLSIZE) + mycolors.reset + str(data.get('latitude')))
                print(mycolors.foreground.lightcyan + "Longitude: ".ljust(COLSIZE) + mycolors.reset + str(data.get('longitude')))
                print(mycolors.foreground.lightcyan + "Sections Available: ".ljust(COLSIZE) + mycolors.reset + ', '.join(data.get('sections', [])))
                print(mycolors.foreground.lightred + "Pulses Found: ".ljust(COLSIZE) + mycolors.reset + str(data.get('pulse_info', {}).get('count')))
            else:
                print(mycolors.foreground.cyan + "ASN: ".ljust(COLSIZE) + mycolors.reset + str(data.get('asn')))
                print(mycolors.foreground.cyan + "City: ".ljust(COLSIZE) + mycolors.reset + str(data.get('city')))
                print(mycolors.foreground.cyan + "Region: ".ljust(COLSIZE) + mycolors.reset + str(data.get('region')))
                print(mycolors.foreground.cyan + "Country: ".ljust(COLSIZE) + mycolors.reset + str(data.get('country_name')))
                print(mycolors.foreground.cyan + "Continent: ".ljust(COLSIZE) + mycolors.reset + str(data.get('continent_code')))
                print(mycolors.foreground.cyan + "Latitude: ".ljust(COLSIZE) + mycolors.reset + str(data.get('latitude')))
                print(mycolors.foreground.cyan + "Longitude: ".ljust(COLSIZE) + mycolors.reset + str(data.get('longitude')))
                print(mycolors.foreground.cyan + "Sections Available: ".ljust(COLSIZE) + mycolors.reset + ', '.join(data.get('sections', [])))
                print(mycolors.foreground.red + "Pulses Found: ".ljust(COLSIZE) + mycolors.reset + str(data.get('pulse_info', {}).get('count')))
                
        except Exception as e:
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + f"\nError: {str(e)}\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + f"\nError: {str(e)}\n" + mycolors.reset)

        print()
        print("(For the full AlienVault report use the -n and -N options)")