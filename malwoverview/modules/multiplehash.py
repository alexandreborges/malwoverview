from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv
from malwoverview.utils.session import create_session
from malwoverview.utils.output import collector, is_text_output
import json


class MultipleHashExtractor:
    def __init__(self, extractors):
        self.extractors = extractors

    def get_multiple_hash_details(self, hash_value):
        if hash_value is None:
            from malwoverview.utils.colors import printc
            printc("A valid hash value is required.", mycolors.foreground.error(cv.bkg))
            return

        if is_text_output():
            print()
            print((mycolors.reset + "CONSOLIDATED HASH CORRELATION REPORT".center(100)), end='')
            print("\n" + (100 * '=').center(50))

        for extractor in self.extractors:
            extractor_obj = self.extractors[extractor]
            try:
                if extractor == "VirusTotal":
                    data = extractor_obj._raw_hash_info(hash_value)
                    self._display_vt(data)
                elif extractor == "HybridAnalysis":
                    data = extractor_obj._raw_hash_info(hash_value)
                    self._display_ha(data)
                elif extractor == "Triage":
                    data = extractor_obj._raw_hash_info(hash_value)
                    self._display_triage(data)
                elif extractor == "AlienVault":
                    data = extractor_obj._raw_hash_info(hash_value)
                    self._display_alien(data)
            except Exception as e:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\nError querying {extractor}: {str(e)}\n" + mycolors.reset)
                continue

        if is_text_output():
            print("\n" + (100 * '=').center(50))
            printr()

    def _display_vt(self, data):
        if data is None or data == {}:
            return

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "VIRUSTOTAL".center(100)), end='')
                print("\n" + (100 * '-').center(50))

            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            classification = attributes.get('popular_threat_classification', {})

            COLSIZE = 28
            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            fields = {
                'Meaningful Name': attributes.get('meaningful_name', 'N/A'),
                'Type Description': attributes.get('type_description', 'N/A'),
                'Size': attributes.get('size', 'N/A'),
                'Times Submitted': attributes.get('times_submitted', 'N/A'),
                'Malicious': stats.get('malicious', 'N/A'),
                'Undetected': stats.get('undetected', 'N/A'),
                'Suspicious': stats.get('suspicious', 'N/A'),
                'SHA256': attributes.get('sha256', 'N/A'),
                'MD5': attributes.get('md5', 'N/A'),
                'SHA1': attributes.get('sha1', 'N/A'),
            }

            if classification:
                suggested = classification.get('suggested_threat_label', 'N/A')
                fields['Threat Classification'] = suggested

            if is_text_output():
                for field_name, field_value in fields.items():
                    display_value = str(field_value) if field_value is not None else 'N/A'
                    if field_name in ('Malicious', 'Suspicious', 'Threat Classification'):
                        print(errorcolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)
                    else:
                        print(infocolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)

            collector.add({'source': 'VirusTotal', **{k: v for k, v in fields.items()}})

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def _display_ha(self, data):
        if data is None or data == {}:
            return

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "HYBRID ANALYSIS".center(100)), end='')
                print("\n" + (100 * '-').center(50))

            if isinstance(data, list) and len(data) > 0:
                sample = data[0]
            elif isinstance(data, dict):
                sample = data
            else:
                return

            COLSIZE = 28
            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            fields = {
                'SHA256': sample.get('sha256', 'N/A'),
                'MD5': sample.get('md5', 'N/A'),
                'SHA1': sample.get('sha1', 'N/A'),
                'Type': sample.get('type_short', sample.get('type', 'N/A')),
                'Size': sample.get('size', 'N/A'),
                'Verdict': sample.get('verdict', 'N/A'),
                'VX Family': sample.get('vx_family', 'N/A'),
                'Threat Score': sample.get('threat_score', 'N/A'),
                'AV Detect': sample.get('av_detect', 'N/A'),
                'Environment': sample.get('environment_description', 'N/A'),
            }

            if is_text_output():
                for field_name, field_value in fields.items():
                    display_value = str(field_value) if field_value is not None else 'N/A'
                    if field_name in ('Verdict', 'VX Family', 'Threat Score'):
                        print(errorcolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)
                    else:
                        print(infocolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)

            collector.add({'source': 'HybridAnalysis', **{k: v for k, v in fields.items()}})

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def _display_triage(self, data):
        if data is None or data == {}:
            return

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "TRIAGE".center(100)), end='')
                print("\n" + (100 * '-').center(50))

            sample = data.get('sample', {})
            analysis = data.get('analysis', {})
            targets = data.get('targets', [])

            COLSIZE = 28
            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            fields = {
                'Sample ID': sample.get('id', 'N/A'),
                'Target': sample.get('target', 'N/A'),
                'Size': sample.get('size', 'N/A'),
                'MD5': sample.get('md5', 'N/A'),
                'SHA1': sample.get('sha1', 'N/A'),
                'SHA256': sample.get('sha256', 'N/A'),
                'SHA512': sample.get('sha512', 'N/A'),
                'Score': sample.get('score', 'N/A'),
                'Status': sample.get('status', 'N/A'),
            }

            signatures = []
            for target in targets:
                sigs = target.get('signatures', [])
                for sig in sigs:
                    sig_name = sig.get('name', '')
                    if sig_name and sig_name not in signatures:
                        signatures.append(sig_name)

            if is_text_output():
                for field_name, field_value in fields.items():
                    display_value = str(field_value) if field_value is not None else 'N/A'
                    if field_name == 'Score':
                        print(errorcolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)
                    else:
                        print(infocolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)

                if signatures:
                    print(errorcolor + "Signatures:".ljust(COLSIZE) + "\t" + mycolors.reset + signatures[0])
                    for sig in signatures[1:15]:
                        print(infocolor + "".ljust(COLSIZE) + "\t" + mycolors.reset + sig)

            record = {'source': 'Triage', **{k: v for k, v in fields.items()}}
            if signatures:
                record['signatures'] = ', '.join(signatures[:15])
            collector.add(record)

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def _display_alien(self, data):
        if data is None or data == {}:
            return

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "ALIENVAULT OTX".center(100)), end='')
                print("\n" + (100 * '-').center(50))

            COLSIZE = 28
            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            pulse_info = data.get('pulse_info', {})
            pulse_count = pulse_info.get('count', 0)

            fields = {
                'Indicator': data.get('indicator', 'N/A'),
                'Pulse Count': str(pulse_count),
            }

            tags = []
            malware_families = []
            attack_ids = []
            countries = []
            pulse_names = []

            for pulse in pulse_info.get('pulses', [])[:5]:
                for tag in pulse.get('tags', []):
                    if tag not in tags:
                        tags.append(tag)
                for family in pulse.get('malware_families', []):
                    name = family.get('display_name', '')
                    if name and name not in malware_families:
                        malware_families.append(name)
                for attack in pulse.get('attack_ids', []):
                    aid = attack.get('display_name', '')
                    if aid and aid not in attack_ids:
                        attack_ids.append(aid)
                for country in pulse.get('targeted_countries', []):
                    if country not in countries:
                        countries.append(country)
                pname = pulse.get('name', '')
                if pname:
                    pulse_names.append(pname)

            if tags:
                fields['Tags'] = ', '.join(tags[:20])
            if malware_families:
                fields['Malware Families'] = ', '.join(malware_families)
            if attack_ids:
                fields['ATT&CK IDs'] = ', '.join(attack_ids)
            if countries:
                fields['Targeted Countries'] = ', '.join(countries)

            if is_text_output():
                for field_name, field_value in fields.items():
                    display_value = str(field_value) if field_value is not None else 'N/A'
                    if field_name in ('Malware Families', 'ATT&CK IDs'):
                        print(errorcolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)
                    else:
                        print(infocolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)

                if pulse_names:
                    print(infocolor + "Related Pulses:".ljust(COLSIZE) + mycolors.reset)
                    for pname in pulse_names[:5]:
                        print(infocolor + "  ".ljust(COLSIZE) + mycolors.reset + pname)

            record = {'source': 'AlienVault', **{k: v for k, v in fields.items()}}
            if pulse_names:
                record['related_pulses'] = ', '.join(pulse_names[:5])
            collector.add(record)

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)
