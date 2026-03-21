import cmd
import sys
import builtins
from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv
from malwoverview.utils.output import collector
from malwoverview.utils.sanitize import (
    sanitize_hash, sanitize_ip, sanitize_domain, sanitize_url,
    sanitize_cve, sanitize_path, sanitize_tag, sanitize_general,
    sanitize_selector, sanitize_triage_id, sanitize_uuid,
    sanitize_export_path, sanitize_integer,
)


class _InteractiveExit(Exception):
    """Raised instead of SystemExit inside interactive mode."""
    pass


class InteractiveSession(cmd.Cmd):
    intro = (
        mycolors.foreground.cyan +
        "\n  Malwoverview Interactive Mode\n" +
        "  Type 'help' for available commands, 'quit' to exit.\n" +
        mycolors.reset
    )
    prompt = mycolors.foreground.green + "malwoverview> " + mycolors.reset

    def __init__(self, args):
        super().__init__()
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
        from malwoverview.modules.bgpview import BGPViewExtractor
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
            'bgpview': BGPViewExtractor(),
            'nist': NISTExtractor(),
            'vulncheck': VulnCheckExtractor(getoption('VULNCHECK', 'VULNCHECKAPI')),
            'shodan': ShodanExtractor(getoption('SHODAN', 'SHODANAPI')),
            'abuseipdb': AbuseIPDBExtractor(getoption('ABUSEIPDB', 'ABUSEIPDBAPI')),
            'greynoise': GreyNoiseExtractor(getoption('GREYNOISE', 'GREYNOISEAPI')),
            'whois': WhoisExtractor(),
            'polyswarm': PolyswarmExtractor(getoption('POLYSWARM', 'POLYAPI')),
            'urlscanio': URLScanIOExtractor(getoption('URLSCANIO', 'URLSCANIOAPI')),
            'threatfox': ThreatFoxExtractor(getoption('THREATFOX', 'THREATFOXAPI')),
        }

        self._modules['correlate'] = MultipleHashExtractor({
            "VirusTotal": self._modules['vt'],
            "HybridAnalysis": self._modules['ha'],
            "Triage": self._modules['triage'],
            "AlienVault": self._modules['alien'],
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
        )
        self._enrich = False

    def _safe_run(self, func, *args, _prompt_type='threat', **kwargs):
        _orig_exit = builtins.exit
        _orig_sys_exit = sys.exit
        _orig_quit = builtins.quit

        def _fake_exit(code=0):
            raise _InteractiveExit()

        builtins.exit = _fake_exit
        builtins.quit = _fake_exit
        sys.exit = _fake_exit

        capture_buf = None
        orig_stdout = sys.stdout
        if self._enrich and self._llm.is_configured():
            from io import StringIO
            capture_buf = StringIO()

            class _Tee:
                def __init__(self, a, b):
                    self.a, self.b = a, b
                def write(self, data):
                    self.a.write(data)
                    self.b.write(data)
                def flush(self):
                    self.a.flush()
                    self.b.flush()
                @property
                def encoding(self):
                    return getattr(self.a, 'encoding', 'utf-8')

            sys.stdout = _Tee(orig_stdout, capture_buf)

        try:
            result = func(*args, **kwargs)
            printr()
            return result
        except (_InteractiveExit, SystemExit):
            printr()
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {e}" + mycolors.reset)
            printr()
        finally:
            if capture_buf:
                sys.stdout = orig_stdout
            builtins.exit = _orig_exit
            builtins.quit = _orig_quit
            sys.exit = _orig_sys_exit

        if capture_buf:
            captured = capture_buf.getvalue().strip()
            if captured:
                self._llm.print_enrichment(captured, _prompt_type)

    def _check(self, sanitizer, value):
        """Run a sanitizer and print error on failure. Returns cleaned value or None."""
        clean, err = sanitizer(value)
        if err:
            print(mycolors.foreground.red + f"Input error: {err}" + mycolors.reset)
        return clean

    def do_vt(self, line):
        """VirusTotal: vt hash <hash> | vt ip <ip> | vt domain <domain> | vt url <url>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: vt hash|ip|domain|url <value>")
            return
        sub, arg = parts
        vt = self._modules['vt']
        if sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(vt.vthashwork, val, 1)
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
        else:
            print("Unknown subcommand. Use: hash, ip, domain, url")

    def do_bazaar(self, line):
        """Malware Bazaar: bazaar hash <hash> | bazaar tag <tag> | bazaar latest <100|time>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: bazaar hash|tag|latest <value>")
            return
        sub, arg = parts
        bz = self._modules['bazaar']
        if sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(bz.bazaar_hash, val)
        elif sub == 'tag':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(bz.bazaar_tag, val)
        elif sub == 'latest':
            val = self._check(sanitize_selector, arg)
            if val:
                self._safe_run(bz.bazaar_lastsamples, val)
        else:
            print("Unknown subcommand. Use: hash, tag, latest")

    def do_urlhaus(self, line):
        """URLHaus: urlhaus hash <hash> | urlhaus url <url> | urlhaus tag <tag>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: urlhaus hash|url|tag <value>")
            return
        sub, arg = parts
        uh = self._modules['urlhaus']
        if sub == 'hash':
            val = self._check(sanitize_hash, arg)
            if val:
                self._safe_run(uh.haushashsearch, val)
        elif sub == 'url':
            val = self._check(sanitize_url, arg)
            if val:
                self._safe_run(uh.urlhauscheck, val)
        elif sub == 'tag':
            val = self._check(sanitize_tag, arg)
            if val:
                self._safe_run(uh.haustagsearchroutine, val)
        else:
            print("Unknown subcommand. Use: hash, url, tag")

    def do_triage(self, line):
        """Triage: triage search <query> | triage summary <id>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: triage search|summary <value>")
            return
        sub, arg = parts
        tr = self._modules['triage']
        if sub == 'search':
            val = self._check(sanitize_general, arg)
            if val:
                self._safe_run(tr.triage_search, val)
        elif sub == 'summary':
            val = self._check(sanitize_triage_id, arg)
            if val:
                self._safe_run(tr.triage_summary, val)
        else:
            print("Unknown subcommand. Use: search, summary")

    def do_ip(self, line):
        """IP Lookup: ip <address> | ip shodan <address> | ip abuseipdb <address> | ip greynoise <address>"""
        parts = line.split(None, 1)
        if not parts:
            print("Usage: ip [shodan|abuseipdb|greynoise|bgpview] <address>")
            return
        if len(parts) == 1:
            val = self._check(sanitize_ip, parts[0])
            if val:
                self._safe_run(self._modules['ipinfo'].get_ip_details, val)
            return
        sub, arg = parts
        if sub in ('shodan', 'abuseipdb', 'greynoise', 'bgpview'):
            val = self._check(sanitize_ip, arg)
            if not val:
                return
            if sub == 'shodan':
                self._safe_run(self._modules['shodan'].shodan_ip, val)
            elif sub == 'abuseipdb':
                self._safe_run(self._modules['abuseipdb'].check_ip, val)
            elif sub == 'greynoise':
                self._safe_run(self._modules['greynoise'].quick_check, val)
            elif sub == 'bgpview':
                self._safe_run(self._modules['bgpview'].get_ip_details, val)
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
        """NIST CVE: nist cve <CVE-ID> | nist keyword <term>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: nist cve|keyword <value>")
            return
        sub, arg = parts
        n = self._modules['nist']
        if sub == 'cve':
            val = self._check(sanitize_cve, arg)
            if val:
                def _nist_cve():
                    result = n.query_cve(2, val, 100, 0, None)
                    if result:
                        n.print_results(result, verbose=False, color_scheme=cv.bkg, max_cves=None)
                self._safe_run(_nist_cve, _prompt_type='cve')
        elif sub == 'keyword':
            val = self._check(sanitize_general, arg)
            if val:
                def _nist_keyword():
                    result = n.query_cve(4, val, 100, 0, None)
                    if result:
                        n.print_results(result, verbose=False, color_scheme=cv.bkg, max_cves=None)
                self._safe_run(_nist_keyword, _prompt_type='cve')
        else:
            print("Unknown subcommand. Use: cve, keyword")

    def do_hybrid(self, line):
        """Hybrid Analysis: hybrid hash <hash> | hybrid quick <hash> | hybrid download <hash>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: hybrid hash|quick|download <value>")
            return
        sub, arg = parts
        ha = self._modules['ha']
        if sub in ('hash', 'quick', 'download'):
            val = self._check(sanitize_hash, arg)
            if not val:
                return
            if sub == 'hash':
                self._safe_run(ha.hashow, val)
            elif sub == 'quick':
                self._safe_run(ha.quickhashow, val)
            elif sub == 'download':
                self._safe_run(ha.downhash, val)
        else:
            print("Unknown subcommand. Use: hash, quick, download")

    def do_threatfox(self, line):
        """ThreatFox: threatfox search <term> | threatfox tag <tag> | threatfox malware <name> | threatfox recent <days>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: threatfox search|tag|malware|recent <value>")
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

    def do_malpedia(self, line):
        """Malpedia: malpedia actors | malpedia families | malpedia actor <name> | malpedia family <name> | malpedia sample <hash> | malpedia yara <family>"""
        parts = line.split(None, 1)
        if not parts:
            print("Usage: malpedia actors|families|actor|family|sample|yara [value]")
            return
        sub = parts[0]
        arg = parts[1] if len(parts) > 1 else ''
        mp = self._modules['malpedia']
        if sub == 'actors':
            self._safe_run(mp.malpedia_actors)
        elif sub == 'families':
            self._safe_run(mp.malpedia_families)
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
            print("Usage: malpedia actors|families|actor|family|sample|yara [value]")

    def do_malshare(self, line):
        """MalShare: malshare download <hash> | malshare list <type>"""
        parts = line.split(None, 1)
        if len(parts) < 2:
            print("Usage: malshare download|list <value>")
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
        else:
            print("Unknown subcommand. Use: download, list")

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

    def do_set(self, line):
        """Change settings: set background 0|1 | set format text|json|csv | set verbose|quiet | set enrich on|off"""
        parts = line.split()
        if not parts:
            print(f"  background: {cv.bkg}")
            print(f"  format:     {cv.output_format}")
            print(f"  verbosity:  {cv.verbosity}")
            print(f"  enrich:     {'on' if self._enrich else 'off'} ({self._llm.provider or 'not configured'})")
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
            print("Usage: set background|format|verbose|quiet|enrich [value]")

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
            with open(val, 'w') as f:
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
        print(mycolors.foreground.cyan + "\nGoodbye!" + mycolors.reset)
        return True

    def do_exit(self, line):
        """Exit interactive mode"""
        return self.do_quit(line)

    do_EOF = do_quit

    def emptyline(self):
        pass
