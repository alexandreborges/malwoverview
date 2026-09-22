import cmd
from malwoverview.utils.colors import mycolors, printr, strip_terminal_escapes
import malwoverview.modules.configvars as cv
from malwoverview.utils.capture import run_captured
from malwoverview.utils.output import collector
from malwoverview.utils.sanitize import (
    sanitize_hash, sanitize_ip, sanitize_domain, sanitize_url,
    sanitize_cve, sanitize_path, sanitize_tag, sanitize_general,
    sanitize_selector, sanitize_triage_id, sanitize_uuid,
    sanitize_export_path, sanitize_integer, sanitize_hash_or_path,
    sanitize_component,
)
from malwoverview.modules.nist import MAX_PAGE_SIZE as NIST_PAGE_SIZE


class InteractiveSession(cmd.Cmd):
    def __init__(self, args):
        super().__init__()
        self.intro = (
            mycolors.foreground.info(cv.bkg) +
            "\n  Malwoverview Interactive Mode\n" +
            "  Type 'help' for available commands, 'quit' to exit.\n" +
            mycolors.reset
        )
        self.prompt = mycolors.foreground.accent(cv.bkg) + "malwoverview> " + mycolors.reset
        self.args = args
        self._modules = {}
        self._init_modules()

    def _init_modules(self):
        import configparser
        from pathlib import Path

        config_file = configparser.ConfigParser()
        config_file.read(self.args.config)

        def getoption(section, name):
            if config_file.has_option(section, name):
                return config_file.get(section, name)
            return ''

        from malwoverview.modules.virustotal import VirusTotalExtractor
        from malwoverview.modules.bazaar import BazaarExtractor
        from malwoverview.modules.urlhaus import URLHausExtractor
        from malwoverview.modules.hybrid import HybridAnalysisExtractor
        from malwoverview.modules.triage import TriageExtractor
        from malwoverview.modules.alienvault import AlienVaultExtractor
        from malwoverview.modules.malpedia import MalpediaExtractor
        from malwoverview.modules.malshare import MalshareExtractor
        from malwoverview.modules.ipinfo import IPInfoExtractor
        from malwoverview.modules.nist import NISTExtractor
        from malwoverview.modules.vulncheck import VulnCheckExtractor
        from malwoverview.modules.shodan_mod import ShodanExtractor
        from malwoverview.modules.abuseipdb import AbuseIPDBExtractor
        from malwoverview.modules.greynoise import GreyNoiseExtractor
        from malwoverview.modules.whois_mod import WhoisExtractor
        from malwoverview.modules.polyswarm import PolyswarmExtractor
        from malwoverview.modules.urlscanio import URLScanIOExtractor
        from malwoverview.modules.threatfox import ThreatFoxExtractor
        from malwoverview.modules.multiplehash import MultipleHashExtractor
        from malwoverview.modules.multipleip import MultipleIPExtractor
        from malwoverview.modules.android import AndroidExtractor
        from malwoverview.modules.crtsh import CrtShExtractor

        self._modules = {
            'vt': VirusTotalExtractor(getoption('VIRUSTOTAL', 'VTAPI')),
            'bazaar': BazaarExtractor(getoption('BAZAAR', 'BAZAARAPI')),
            'urlhaus': URLHausExtractor(getoption('URLHAUS', 'URLHAUSAPI')),
            'ha': HybridAnalysisExtractor(getoption('HYBRID-ANALYSIS', 'HAAPI')),
            'triage': TriageExtractor(getoption('TRIAGE', 'TRIAGEAPI')),
            'alien': AlienVaultExtractor(getoption('ALIENVAULT', 'ALIENAPI')),
            'malpedia': MalpediaExtractor(getoption('MALPEDIA', 'MALPEDIAAPI')),
            'malshare': MalshareExtractor(getoption('MALSHARE', 'MALSHAREAPI')),
            'ipinfo': IPInfoExtractor(getoption('IPINFO', 'IPINFOAPI')),
            'nist': NISTExtractor(),
            'vulncheck': VulnCheckExtractor(getoption('VULNCHECK', 'VULNCHECKAPI')),
            'shodan': ShodanExtractor(getoption('SHODAN', 'SHODANAPI')),
            'abuseipdb': AbuseIPDBExtractor(getoption('ABUSEIPDB', 'ABUSEIPDBAPI')),
            'greynoise': GreyNoiseExtractor(getoption('GREYNOISE', 'GREYNOISEAPI')),
            'whois': WhoisExtractor(),
            'polyswarm': PolyswarmExtractor(getoption('POLYSWARM', 'POLYAPI')),
            'urlscanio': URLScanIOExtractor(getoption('URLSCANIO', 'URLSCANIOAPI')),
            'threatfox': ThreatFoxExtractor(getoption('THREATFOX', 'THREATFOXAPI')),
            'crtsh': CrtShExtractor(),
        }

        self._modules['correlate'] = MultipleHashExtractor({
            "VirusTotal": self._modules['vt'],
            "HybridAnalysis": self._modules['ha'],
            "Triage": self._modules['triage'],
            "AlienVault": self._modules['alien'],
        })

        self._modules['android'] = AndroidExtractor(
            self._modules['ha'], self._modules['vt'])

        self._modules['multipleip'] = MultipleIPExtractor({
            "VirusTotal": self._modules['vt'],
            "AlienVault": self._modules['alien'],
        })

        self._modules['multipleipall'] = MultipleIPExtractor({
            "IPInfo": self._modules['ipinfo'],
            "VirusTotal": self._modules['vt'],
            "AlienVault": self._modules['alien'],
            "Shodan": self._modules['shodan'],
            "AbuseIPDB": self._modules['abuseipdb'],
            "GreyNoise": self._modules['greynoise'],
        })

        from malwoverview.utils.llm import LLMEnricher
        provider = getoption('LLM', 'PROVIDER')
        self._llm = LLMEnricher(
            provider,
            getoption('LLM', 'CLAUDE_API_KEY'),
            getoption('LLM', 'GEMINI_API_KEY'),
            getoption('LLM', 'OLLAMA_URL'),
            getoption('LLM', 'OLLAMA_MODEL'),
            getoption('LLM', 'GEMINI_MODEL'),
            getoption('LLM', 'OPENAI_API_KEY'),
            getoption('LLM', 'OPENAI_MODEL'),
            getoption('LLM', 'CLAUDE_MODEL'),
        )
        self._enrich = False

    def _safe_run(self, func, *args, _prompt_type='threat', **kwargs):
        ok, captured, error = run_captured(func, *args, _tee=True, **kwargs)
        if not ok:
            print(mycolors.foreground.red + f"\nError: {strip_terminal_escapes(str(error))}" + mycolors.reset)
        printr()

        if self._enrich and self._llm.is_configured():
            from malwoverview.utils.llm import records_to_prompt_text
            payload = records_to_prompt_text(collector.records) or captured.strip()
            if payload:
                self._llm.print_enrichment(payload, _prompt_type)

    def _check(self, sanitizer, value):
        """Run a sanitizer and print error on failure. Returns cleaned value or None."""
        clean, err = sanitizer(value)
        if err:
            print(mycolors.foreground.red + f"Input error: {err}" + mycolors.reset)
        return clean

    _VT_USAGE = ("Usage: vt hash|ip|domain|url|behavior <value> | "
                 "vt file|report|threat|overall|upload|largefile <path> | "
                 "vt batch|batchpublic <file> | "
                 "vt retrohunt submit|list|status|matches [value] | "
                 "vt livehunt create|list|notifications [value]")

    def do_vt(self, line):
        """VirusTotal: vt hash|ip|domain|url|behavior <value> | vt file|report|threat|overall|upload|largefile <path> | vt batch|batchpublic <file> | vt retrohunt submit|list|status|matches [value] | vt livehunt create|list|notifications [value]"""
        parts = line.split(None, 1)
        if not parts:
            print(self._VT_USAGE)
            return
        sub = parts[0]
        arg = parts[1] if len(parts) > 1 else ''
        vt = self._modules['vt']

        if sub == 'retrohunt':
            self._vt_retrohunt(vt, arg)
            return
        if sub == 'livehunt':
            self._vt_livehunt(vt, arg)
            return

        if sub in ('list', 'notifications'):
            print("Did you mean 'vt retrohunt list' or 'vt livehunt notifications'?")
            return

        if not arg:
            print(self._VT_USAGE)
            return

        if sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(vt.vthashwork, val, 1)
        elif sub == 'behavior':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(vt.vtbehavior, val)
        elif sub == 'ip':
            val = self._check(sanitize_ip, arg)
            if val:
                self._safe_run(vt.vtipwork, val)
        elif sub == 'domain':
            val = self._check(sanitize_domain, arg)
            if val:
                self._safe_run(vt.vtdomainwork, val)
        elif sub == 'url':
            val = self._check(sanitize_url, arg)
            if val:
                self._safe_run(vt.vturlwork, val)
        elif sub in ('file', 'report', 'threat', 'overall'):
            val = self._check(sanitize_path, arg)
            if val:
                flags = {
                    'file': (0, 0, 0),
                    'report': (1, 0, 0),
                    'threat': (1, 1, 0),
                    'overall': (1, 0, 1),
                }[sub]
                self._safe_run(vt.filechecking_v3, val, *flags)
        elif sub == 'upload':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(vt.vtuploadfile, val)
        elif sub == 'largefile':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(vt.vtlargefile, val)
        elif sub in ('batch', 'batchpublic'):
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(vt.vtbatchcheck, val, 1 if sub == 'batch' else 0)
        else:
            print(self._VT_USAGE)

    def _vt_retrohunt(self, vt, arg):
        parts = arg.split(None, 1)
        sub = parts[0] if parts else ''
        value = parts[1] if len(parts) > 1 else ''
        if sub == 'submit':
            val = self._check(sanitize_path, value)
            if val:
                self._safe_run(vt.vtretrohuntsubmit, val)
        elif sub == 'list':
            self._safe_run(vt.vtretrohuntlist, value.strip() or None)
        elif sub == 'status':
            val = self._check(sanitize_general, value)
            if val:
                self._safe_run(vt.vtretrohuntstatus, val)
        elif sub == 'matches':
            val = self._check(sanitize_general, value)
            if val:
                self._safe_run(vt.vtretrohuntmatches, val)
        else:
            print("Usage: vt retrohunt submit <rules> | list [status] | status <id> | matches <id>")

    def _vt_livehunt(self, vt, arg):
        parts = arg.split(None, 1)
        sub = parts[0] if parts else ''
        value = parts[1] if len(parts) > 1 else ''
        if sub == 'create':
            val = self._check(sanitize_path, value)
            if val:
                self._safe_run(vt.vtlivehuntcreate, val)
        elif sub == 'list':
            self._safe_run(vt.vtlivehuntlist)
        elif sub == 'notifications':
            self._safe_run(vt.vtlivehuntnotifications)
        else:
            print("Usage: vt livehunt create <rules> | list | notifications")

    _BAZAAR_USAGE = ("Usage: bazaar hash|download <hash> | tag <tag> | imphash <imphash> | "
                     "latest <100|time> | yara <rule name> | batch <file> | dir <directory> | "
                     "yaradownload | yaraextract")

    def do_bazaar(self, line):
        """Malware Bazaar: bazaar hash|download <hash> | bazaar tag <tag> | bazaar imphash <imphash> | bazaar latest <100|time> | bazaar yara <rule name> | bazaar batch <file> | bazaar dir <directory> | bazaar yaradownload | bazaar yaraextract"""
        parts = line.split(None, 1)
        if not parts:
            print(self._BAZAAR_USAGE)
            return
        sub = parts[0]
        arg = parts[1] if len(parts) > 1 else ''
        bz = self._modules['bazaar']

        if sub == 'yaradownload':
            self._safe_run(bz.bazaar_yaradownload)
            return
        if sub == 'yaraextract':
            self._safe_run(bz.bazaar_yaraextract)
            return

        if not arg:
            print(self._BAZAAR_USAGE)
            return

        if sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(bz.bazaar_hash, val)
        elif sub == 'download':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(bz.bazaar_download, val)
        elif sub == 'tag':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(bz.bazaar_tag, val)
        elif sub == 'imphash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(bz.bazaar_imphash, val)
        elif sub == 'latest':
            val = self._check(sanitize_selector, arg)
            if val:
                self._safe_run(bz.bazaar_lastsamples, val)
        elif sub == 'yara':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(bz.bazaar_yara, val)
        elif sub == 'batch':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(bz.bazaar_batchcheck, val)
        elif sub == 'dir':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(bz.bazaar_dircheck, val)
        else:
            print(self._BAZAAR_USAGE)

    _URLHAUS_USAGE = ("Usage: urlhaus hash|sample <hash> | url <url> | tag <tag> | "
                      "signature <signature> | batch <file> | payloads | getbatch")

    def do_urlhaus(self, line):
        """URLHaus: urlhaus hash <hash> | urlhaus sample <hash> | urlhaus url <url> | urlhaus tag <tag> | urlhaus signature <signature> | urlhaus batch <file> | urlhaus payloads | urlhaus getbatch"""
        parts = line.split(None, 1)
        if not parts:
            print(self._URLHAUS_USAGE)
            return
        sub = parts[0]
        arg = parts[1] if len(parts) > 1 else ''
        uh = self._modules['urlhaus']

        if sub == 'payloads':
            self._safe_run(uh.hauspayloadslist)
            return
        if sub == 'getbatch':
            self._safe_run(uh.hausgetbatch)
            return

        if not arg:
            print(self._URLHAUS_USAGE)
            return

        if sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(uh.haushashsearch, val)
        elif sub == 'sample':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(uh.haussample, val)
        elif sub == 'url':
            val = self._check(sanitize_url, arg)
            if val:
                self._safe_run(uh.urlhauscheck, val)
        elif sub == 'tag':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(uh.haustagsearchroutine, val)
        elif sub == 'signature':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(uh.haussigsearchroutine, val)
        elif sub == 'batch':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(uh.hausbatchcheck, val)
        else:
            print(self._URLHAUS_USAGE)

    _TRIAGE_USAGE = ("Usage: triage search <query> | summary|download|pcap|dynamic <id> | "
                     "submit <file> | urlsubmit <url> | batch <file> | dir <directory>")

    def do_triage(self, line):
        """Triage: triage search <query> | triage summary <id> | triage download <id> | triage pcap <id> | triage dynamic <id> | triage submit <file> | triage urlsubmit <url> | triage batch <file> | triage dir <directory>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print(self._TRIAGE_USAGE)
            return
        sub, arg = parts
        tr = self._modules['triage']
        if sub == 'search':
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(tr.triage_search, val)
        elif sub in ('summary', 'download', 'pcap', 'dynamic'):
            val = self._check(sanitize_triage_id, arg)
            if val:
                method = {
                    'summary': tr.triage_summary,
                    'download': tr.triage_download,
                    'pcap': tr.triage_download_pcap,
                    'dynamic': tr.triage_dynamic,
                }[sub]
                self._safe_run(method, val)
        elif sub == 'submit':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(tr.triage_sample_submit, val)
        elif sub == 'urlsubmit':
            val = self._check(sanitize_url, arg)
            if val:
                self._safe_run(tr.triage_url_sample_submit, val)
        elif sub == 'batch':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(tr.triage_batchcheck, val)
        elif sub == 'dir':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(tr.triage_dircheck, val)
        else:
            print(self._TRIAGE_USAGE)

    def do_ip(self, line):
        """IP Lookup: ip <address> | ip shodan|abuseipdb|greynoise|multi|all <address> | ip batch <file> | ip batchpublic <file>"""
        parts = line.split(None, 1)
        if not parts:
            print("Usage: ip [shodan|abuseipdb|greynoise|multi|all] <address> | "
                  "ip batch|batchpublic <file>")
            return
        if len(parts) == 1:
            val = self._check(sanitize_ip, parts[0])
            if val:
                self._safe_run(self._modules['ipinfo'].get_ip_details, val)
            return
        sub, arg = parts
        if sub in ('batch', 'batchpublic'):
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(self._modules['vt'].vtipbatchcheck, val,
                               0 if sub == 'batch' else 1)
        elif sub in ('shodan', 'abuseipdb', 'greynoise', 'multi', 'all'):
            val = self._check(sanitize_ip, arg)
            if not val:
                return
            if sub == 'shodan':
                self._safe_run(self._modules['shodan'].shodan_ip, val)
            elif sub == 'abuseipdb':
                self._safe_run(self._modules['abuseipdb'].check_ip, val)
            elif sub == 'greynoise':
                self._safe_run(self._modules['greynoise'].quick_check, val)
            elif sub == 'multi':
                self._safe_run(self._modules['multipleip'].get_multiple_ip_details, val)
            elif sub == 'all':
                self._safe_run(self._modules['multipleipall'].get_multiple_ip_details, val)
        else:
            val = self._check(sanitize_ip, sub)
            if val:
                self._safe_run(self._modules['ipinfo'].get_ip_details, val)

    def do_correlate(self, line):
        """Cross-service hash correlation: correlate <hash>"""
        if not line.strip():
            print("Usage: correlate <hash>")
            return
        val = self._check(sanitize_hash, line.strip())
        if val:
            self._safe_run(self._modules['correlate'].get_multiple_hash_details, val)

    def do_whois(self, line):
        """Whois: whois domain <domain> | whois ip <ip>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: whois domain|ip <value>")
            return
        sub, arg = parts
        wh = self._modules['whois']
        if sub == 'domain':
            val = self._check(sanitize_domain, arg)
            if val:
                self._safe_run(wh.domain_whois, val)
        elif sub == 'ip':
            val = self._check(sanitize_ip, arg)
            if val:
                self._safe_run(wh.ip_whois, val)
        else:
            print("Unknown subcommand. Use: domain, ip")

    def do_nist(self, line):
        """NIST CVE: nist cve <CVE-ID> | nist keyword <term> | nist component <name|file>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: nist cve|keyword|component <value>")
            return
        sub, arg = parts
        n = self._modules['nist']
        if sub == 'cve':
            val = self._check(sanitize_cve, arg)
            if val:
                def _nist_cve():
                    result = n.query_cve(2, val, NIST_PAGE_SIZE, 0, None)
                    if result:
                        n.print_results(result, verbose=False, color_scheme=cv.bkg, max_cves=None)
                self._safe_run(_nist_cve, _prompt_type='cve')
        elif sub == 'keyword':
            val = self._check(sanitize_general, arg)
            if val:
                def _nist_keyword():
                    result = n.query_cve(4, val, NIST_PAGE_SIZE, 0, None)
                    if result:
                        n.print_results(result, verbose=False, color_scheme=cv.bkg, max_cves=None)
                self._safe_run(_nist_keyword, _prompt_type='cve')
        elif sub == 'component':
            val = self._check(sanitize_component, arg)
            if val:
                def _nist_component():
                    n.component_cve(val, None, None, NIST_PAGE_SIZE)
                self._safe_run(_nist_component, _prompt_type='cve')
        else:
            print("Unknown subcommand. Use: cve, keyword, component")

    _HYBRID_USAGE = ("Usage: hybrid hash <hash> [env 1-5] | quick|download <hash> | "
                     "file <path> [env 1-5] | batch <file> | dir <directory>")

    def _split_env(self, arg):
        parts = arg.rsplit(None, 1)
        if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= 5:
            return parts[0], int(parts[1]) - 1
        return arg, 0

    def do_hybrid(self, line):
        """Hybrid Analysis: hybrid hash <hash> [env 1-5] | hybrid quick <hash> | hybrid download <hash> | hybrid file <path> [env 1-5] | hybrid batch <file> | hybrid dir <directory>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print(self._HYBRID_USAGE)
            return
        sub, arg = parts
        ha = self._modules['ha']
        if sub == 'hash':
            value, env = self._split_env(arg)
            val = self._check(sanitize_hash, value)
            if val:
                self._safe_run(ha.hashow, val, env)
        elif sub in ('quick', 'download'):
            val = self._check(sanitize_hash, arg)
            if not val:
                return
            if sub == 'quick':
                self._safe_run(ha.quickhashow, val)
            else:
                self._safe_run(ha.downhash, val)
        elif sub == 'file':
            value, env = self._split_env(arg)
            val = self._check(sanitize_path, value)
            if val:
                self._safe_run(ha.hafilecheck, val, env)
        elif sub == 'batch':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(ha.habatchcheck, val)
        elif sub == 'dir':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(ha.habatchdircheck, val)
        else:
            print(self._HYBRID_USAGE)

    def do_threatfox(self, line):
        """ThreatFox: threatfox search <term> | threatfox tag <tag> | threatfox malware <name> | threatfox recent <days> | threatfox malwarelist"""
        parts = line.split(None, 1)
        if parts and parts[0] == 'malwarelist':
            self._safe_run(self._modules['threatfox'].threatfox_listmalware)
            return
        if len(parts) < 2:
            print("Usage: threatfox search|tag|malware|recent <value> | threatfox malwarelist")
            return
        sub, arg = parts
        tf = self._modules['threatfox']
        if sub == 'search':
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(tf.threatfox_searchiocs, val)
        elif sub == 'tag':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(tf.threatfox_searchtags, val)
        elif sub == 'malware':
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(tf.threatfox_searchmalware, val)
        elif sub == 'recent':
            val = self._check(lambda v: sanitize_integer(v, 1, 30), arg)
            if val:
                self._safe_run(tf.threatfox_listiocs, val)
        else:
            print("Unknown subcommand. Use: search, tag, malware, recent")

    def do_alienvault(self, line):
        """AlienVault OTX: alienvault ip <ip> | alienvault domain <domain> | alienvault hash <hash> | alienvault url <url>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: alienvault ip|domain|hash|url <value>")
            return
        sub, arg = parts
        av = self._modules['alien']
        if sub == 'ip':
            val = self._check(sanitize_ip, arg)
            if val:
                self._safe_run(av.alien_ipv4, val)
        elif sub == 'domain':
            val = self._check(sanitize_domain, arg)
            if val:
                self._safe_run(av.alien_domain, val)
        elif sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(av.alien_hash, val)
        elif sub == 'url':
            val = self._check(sanitize_url, arg)
            if val:
                self._safe_run(av.alien_url, val)
        else:
            print("Unknown subcommand. Use: ip, domain, hash, url")

    _MALPEDIA_USAGE = ("Usage: malpedia actors|families|payloads | meta [filter] | "
                       "actor|family <name> | sample <hash> | yara <family> | "
                       "ruleset <tlp_white|tlp_green|tlp_amber|auto>")

    def do_malpedia(self, line):
        """Malpedia: malpedia actors | malpedia families | malpedia payloads | malpedia meta [filter] | malpedia actor <name> | malpedia family <name> | malpedia sample <hash> | malpedia yara <family> | malpedia ruleset <tlp level>"""
        parts = line.split(None, 1)
        if not parts:
            print(self._MALPEDIA_USAGE)
            return
        sub = parts[0]
        arg = parts[1] if len(parts) > 1 else ''
        mp = self._modules['malpedia']
        if sub == 'actors':
            self._safe_run(mp.malpedia_actors)
        elif sub == 'families':
            self._safe_run(mp.malpedia_families)
        elif sub == 'payloads':
            self._safe_run(mp.malpedia_payloads)
        elif sub == 'meta':
            if arg:
                val = self._check(sanitize_general, arg)
                if val:
                    self._safe_run(mp.malpedia_families_meta, val)
            else:
                self._safe_run(mp.malpedia_families_meta)
        elif sub == 'ruleset' and arg:
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(mp.malpedia_get_yara_ruleset, val)
        elif sub == 'actor' and arg:
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(mp.malpedia_get_actor, val)
        elif sub == 'family' and arg:
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(mp.malpedia_get_family, val)
        elif sub == 'sample' and arg:
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(mp.malpedia_get_sample, val)
        elif sub == 'yara' and arg:
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(mp.malpedia_get_yara, val)
        else:
            print(self._MALPEDIA_USAGE)

    def do_malshare(self, line):
        """MalShare: malshare download <hash> | malshare list <type> | malshare types | malshare type <file type>"""
        parts = line.split(None, 1)
        if parts and parts[0] == 'types':
            self._safe_run(self._modules['malshare'].malsharetypes)
            return
        if len(parts) < 2:
            print("Usage: malshare download <hash> | list <type> | types | type <file type>")
            return
        sub, arg = parts
        ms = self._modules['malshare']
        if sub == 'download':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(ms.malsharedown, val)
        elif sub == 'list':
            val = self._check(lambda v: sanitize_integer(v, 1), arg)
            if val:
                self._safe_run(ms.malsharelastlist, int(val))
        elif sub == 'type':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(ms.malsharetypelist, val)
        else:
            print("Unknown subcommand. Use: download, list, types, type")

    def do_polyswarm(self, line):
        """PolySwarm: polyswarm hash <hash> | polyswarm ip <ip> | polyswarm domain <domain> | polyswarm url <url> | polyswarm file <path>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: polyswarm hash|ip|domain|url|file <value>")
            return
        sub, arg = parts
        ps = self._modules['polyswarm']
        if sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(ps.polyhashsearch, val, 0)
        elif sub == 'ip':
            val = self._check(sanitize_ip, arg)
            if val:
                self._safe_run(ps.polymetasearch, val, 5)
        elif sub == 'domain':
            val = self._check(sanitize_domain, arg)
            if val:
                self._safe_run(ps.polymetasearch, val, 6)
        elif sub == 'url':
            val = self._check(sanitize_url, arg)
            if val:
                self._safe_run(ps.polymetasearch, val, 7)
        elif sub == 'file':
            val = self._check(sanitize_path, arg)
            if val:
                self._safe_run(ps.polyfile, val)
        else:
            print("Unknown subcommand. Use: hash, ip, domain, url, file")

    def do_shodan(self, line):
        """Shodan: shodan ip <address> | shodan search <query>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: shodan ip|search <value>")
            return
        sub, arg = parts
        sh = self._modules['shodan']
        if sub == 'ip':
            val = self._check(sanitize_ip, arg)
            if val:
                self._safe_run(sh.shodan_ip, val)
        elif sub == 'search':
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(sh.shodan_search, val)
        else:
            print("Unknown subcommand. Use: ip, search")

    def do_abuseipdb(self, line):
        """AbuseIPDB: abuseipdb <ip>"""
        arg = line.strip()
        if not arg:
            print("Usage: abuseipdb <ip>")
            return
        val = self._check(sanitize_ip, arg)
        if val:
            self._safe_run(self._modules['abuseipdb'].check_ip, val)

    def do_greynoise(self, line):
        """GreyNoise: greynoise <ip>"""
        arg = line.strip()
        if not arg:
            print("Usage: greynoise <ip>")
            return
        val = self._check(sanitize_ip, arg)
        if val:
            self._safe_run(self._modules['greynoise'].quick_check, val)

    def do_vulncheck(self, line):
        """VulnCheck: vulncheck cve <CVE-ID> | vulncheck kev | vulncheck mitre <CVE-ID> | vulncheck nist <CVE-ID>"""
        parts = line.split(None, 1)
        if not parts:
            print("Usage: vulncheck cve|kev|mitre|nist [value]")
            return
        sub = parts[0]
        arg = parts[1] if len(parts) > 1 else ''
        vc = self._modules['vulncheck']
        if sub == 'cve' and arg:
            val = self._check(sanitize_cve, arg)
            if val:
                self._safe_run(vc.vulncheck_cve_search, val, _prompt_type='cve')
        elif sub == 'kev':
            self._safe_run(vc.vulncheck_kev, _prompt_type='cve')
        elif sub == 'mitre' and arg:
            val = self._check(sanitize_cve, arg)
            if val:
                self._safe_run(vc.vulncheck_mitre_search, val, _prompt_type='cve')
        elif sub == 'nist' and arg:
            val = self._check(sanitize_cve, arg)
            if val:
                self._safe_run(vc.vulncheck_nist_search, val, _prompt_type='cve')
        else:
            print("Usage: vulncheck cve|kev|mitre|nist [value]")

    def do_urlscanio(self, line):
        """URLScan.io: urlscanio submit <url> | urlscanio result <uuid> | urlscanio search <query> | urlscanio domain <domain> | urlscanio ip <ip>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: urlscanio submit|result|search|domain|ip <value>")
            return
        sub, arg = parts
        us = self._modules['urlscanio']
        if sub == 'submit':
            val = self._check(sanitize_url, arg)
            if val:
                self._safe_run(us.urlscanio_submit, val)
        elif sub == 'result':
            val = self._check(sanitize_uuid, arg)
            if val:
                self._safe_run(us.urlscanio_result, val)
        elif sub == 'search':
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(us.urlscanio_search, val)
        elif sub == 'domain':
            val = self._check(sanitize_domain, arg)
            if val:
                self._safe_run(us.urlscanio_domain, val)
        elif sub == 'ip':
            val = self._check(sanitize_ip, arg)
            if val:
                self._safe_run(us.urlscanio_ip, val)
        else:
            print("Unknown subcommand. Use: submit, result, search, domain, ip")

    def do_crtsh(self, line):
        """Certificate Transparency (crt.sh): crtsh subdomains <domain> | crtsh certs <domain>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: crtsh subdomains|certs <domain>")
            return
        sub, arg = parts
        ct = self._modules['crtsh']
        if sub == 'subdomains':
            val = self._check(sanitize_domain, arg)
            if val:
                self._safe_run(ct.crtsh_subdomains, val)
        elif sub == 'certs':
            val = self._check(sanitize_domain, arg)
            if val:
                self._safe_run(ct.crtsh_certificates, val)
        else:
            print("Unknown subcommand. Use: subdomains, certs")

    def do_android(self, line):
        """Android device (needs adb in PATH): android ha | android vt | android vtpublic | android sendha <package> | android sendvt <package>"""
        parts = line.split(None, 1)
        if not parts:
            print("Usage: android ha|vt|vtpublic | android sendha|sendvt <package>")
            return
        sub = parts[0]
        arg = parts[1] if len(parts) > 1 else ''
        ad = self._modules['android']
        if sub in ('ha', 'vtpublic', 'vt'):
            engine = {'ha': 1, 'vtpublic': 2, 'vt': 3}[sub]
            self._safe_run(ad.checkandroid, engine)
        elif sub in ('sendha', 'sendvt'):
            if not arg:
                print(f"Usage: android {sub} <package>")
                return
            val = self._check(sanitize_tag, arg)
            if val:
                if sub == 'sendha':
                    self._safe_run(ad.sendandroidha, val)
                else:
                    self._safe_run(ad.sendandroidvt, val)
        else:
            print("Unknown subcommand. Use: ha, vt, vtpublic, sendha, sendvt")

    def do_yara(self, line):
        """YARA scan: yara <rules file or directory> <file or directory to scan>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: yara <rules file or directory> <target file or directory>")
            return
        rules = self._check(sanitize_path, parts[0])
        if not rules:
            return
        target = self._check(sanitize_path, parts[1])
        if not target:
            return

        def _scan():
            from malwoverview.modules.yara_scan import YaraScanner
            YaraScanner(rules).scan_and_display(target)
        self._safe_run(_scan)

    def do_peinfo(self, line):
        """Local PE triage (no API key): peinfo <file or directory> [entropy threshold]"""
        parts = line.split()
        if not parts:
            print("Usage: peinfo <file or directory> [entropy threshold]")
            return
        target = self._check(sanitize_path, parts[0])
        if not target:
            return
        threshold = 7.0
        if len(parts) > 1:
            try:
                threshold = float(parts[1])
            except ValueError:
                print("The entropy threshold must be a number, for example 7.0")
                return

        def _scan():
            from malwoverview.modules.pe_scan import PEScanner
            PEScanner(threshold).scan_and_display(target)
        self._safe_run(_scan)

    def do_sigcheck(self, line):
        """Check the Authenticode signature of a file or directory: sigcheck <file or directory> [any|first|all|best]"""
        from malwoverview.utils.authenticode import VERIFY_MODES, DEFAULT_VERIFY_MODE

        parts = line.strip().rsplit(None, 1)
        arg = line.strip()
        mode = DEFAULT_VERIFY_MODE
        if len(parts) > 1 and parts[1].lower() in VERIFY_MODES:
            arg, mode = parts[0], parts[1].lower()

        if not arg:
            print("Usage: sigcheck <file or directory> [%s]" % '|'.join(VERIFY_MODES))
            return
        target = self._check(sanitize_path, arg)
        if not target:
            return

        def _scan():
            from malwoverview.modules.pe_scan import PEScanner
            PEScanner(verify_mode=mode).signature_and_display(target)
        self._safe_run(_scan)

    def do_iocs(self, line):
        """Extract IOCs from a file (.txt, .pdf, .eml) or URL: iocs <file or URL>"""
        arg = line.strip()
        if not arg:
            print("Usage: iocs <file or URL>")
            return
        if arg.startswith(('http://', 'https://')):
            source = self._check(sanitize_url, arg)
        else:
            source = self._check(sanitize_path, arg)
        if not source:
            return

        def _extract():
            from malwoverview.utils.ioc_extract import IOCExtractor
            IOCExtractor().extract_and_display(source)
        self._safe_run(_extract)

    def do_cache(self, line):
        """Local result cache: cache stats | cache prune | cache clear"""
        import sqlite3
        from malwoverview.utils.cache import cache_stats, prune_cache, clear_cache
        from malwoverview.utils.peinfo import humansize
        sub = line.strip() or 'stats'
        if sub not in ('stats', 'prune', 'clear'):
            print("Usage: cache stats|prune|clear")
            return
        try:
            if sub == 'stats':
                info = cache_stats()
                COLSIZE = 16
                infocolor = mycolors.foreground.info(cv.bkg)
                print()
                print(infocolor + "Cache file:".ljust(COLSIZE) + mycolors.reset + str(info['db_path']))
                print(infocolor + "Entries:".ljust(COLSIZE) + mycolors.reset + str(info['entries']))
                print(infocolor + "Expired:".ljust(COLSIZE) + mycolors.reset + str(info['expired']))
                print(infocolor + "TTL:".ljust(COLSIZE) + mycolors.reset + str(info['ttl']) + " seconds")
                print(infocolor + "Size on disk:".ljust(COLSIZE) + mycolors.reset + humansize(info['size_bytes']))
            elif sub == 'prune':
                print(mycolors.foreground.success(cv.bkg) + "\nExpired cache entries removed: " + str(prune_cache()) + mycolors.reset)
            else:
                print(mycolors.foreground.success(cv.bkg) + "\nCache entries removed: " + str(clear_cache()) + mycolors.reset)
        except sqlite3.Error as e:
            print(mycolors.foreground.error(cv.bkg) + "\nCould not access the result cache: " + str(e) + mycolors.reset)
        printr()

    def do_set(self, line):
        """Change settings: set background 0|1 | set format text|json|csv | set verbose|quiet | set enrich on|off | set attack on|off"""
        parts = line.split()
        if not parts:
            print(f"  background: {cv.bkg}")
            print(f"  format:     {cv.output_format}")
            print(f"  verbosity:  {cv.verbosity}")
            print(f"  enrich:     {'on' if self._enrich else 'off'} ({self._llm.provider or 'not configured'})")
            print(f"  attack-map: {'on' if cv.attack_map else 'off'}")
            return
        if parts[0] == 'background' and len(parts) > 1:
            if parts[1] in ('0', '1'):
                cv.bkg = int(parts[1])
            else:
                print("Usage: set background 0|1")
        elif parts[0] == 'format' and len(parts) > 1:
            if parts[1] in ('text', 'json', 'csv'):
                cv.output_format = parts[1]
            else:
                print("Usage: set format text|json|csv")
        elif parts[0] == 'verbose':
            cv.verbosity = 1
        elif parts[0] == 'quiet':
            cv.verbosity = -1
        elif parts[0] == 'attack':
            if len(parts) > 1 and parts[1] in ('on', 'off'):
                cv.attack_map = (parts[1] == 'on')
                print(f"  MITRE ATT&CK mapping {'enabled' if cv.attack_map else 'disabled'}.")
            else:
                print("Usage: set attack on|off")
        elif parts[0] == 'enrich':
            if len(parts) > 1 and parts[1] in ('on', 'off', 'claude', 'gemini', 'openai', 'ollama'):
                if parts[1] == 'off':
                    self._enrich = False
                    print("  LLM enrichment disabled.")
                elif parts[1] in ('claude', 'gemini', 'openai', 'ollama'):
                    from malwoverview.utils.llm import LLMEnricher
                    import configparser
                    config_file = configparser.ConfigParser()
                    config_file.read(self.args.config)
                    def _getoption(s, n):
                        return config_file.get(s, n) if config_file.has_option(s, n) else ''
                    self._llm = LLMEnricher(
                        parts[1],
                        _getoption('LLM', 'CLAUDE_API_KEY'),
                        _getoption('LLM', 'GEMINI_API_KEY'),
                        _getoption('LLM', 'OLLAMA_URL'),
                        _getoption('LLM', 'OLLAMA_MODEL'),
                        _getoption('LLM', 'GEMINI_MODEL'),
                        _getoption('LLM', 'OPENAI_API_KEY'),
                        _getoption('LLM', 'OPENAI_MODEL'),
                        _getoption('LLM', 'CLAUDE_MODEL'),
                    )
                    if self._llm.is_configured():
                        self._enrich = True
                        print(f"  LLM enrichment enabled (provider: {self._llm.provider})")
                    else:
                        print(f"  Provider '{parts[1]}' not configured. Check API key in .malwapi.conf [LLM] section.")
                elif parts[1] == 'on':
                    if self._llm.is_configured():
                        self._enrich = True
                        print(f"  LLM enrichment enabled (provider: {self._llm.provider})")
                    else:
                        print(f"  LLM provider not configured. Use: set enrich claude|gemini|openai|ollama")
            else:
                print("Usage: set enrich on|off|claude|gemini|ollama")
        else:
            print("Usage: set background|format|verbose|quiet|enrich|attack [value]")

    def do_export(self, line):
        """Export last results: export json|csv [filename]"""
        parts = line.split()
        if not parts:
            print("Usage: export json|csv [filename]")
            return
        fmt = parts[0]
        if fmt not in ('json', 'csv'):
            print("Usage: export json|csv [filename]")
            return
        if len(parts) > 1:
            val = self._check(sanitize_export_path, parts[1])
            if not val:
                return
            with open(val, 'w', newline='') as f:
                old_fmt = cv.output_format
                cv.output_format = fmt
                collector.finalize(f)
                cv.output_format = old_fmt
            print(f"Exported to {val}")
        else:
            old_fmt = cv.output_format
            cv.output_format = fmt
            collector.finalize()
            cv.output_format = old_fmt

    def do_quit(self, line):
        """Exit interactive mode"""
        print(mycolors.foreground.info(cv.bkg) + "\nGoodbye!" + mycolors.reset)
        return True

    def do_exit(self, line):
        """Exit interactive mode"""
        return self.do_quit(line)

    do_EOF = do_quit

    def emptyline(self):
        pass
