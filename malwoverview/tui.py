import os
import re
import configparser
from threading import Event

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Input, Button, RichLog, ListView, ListItem, Label, Static,
)
from textual import events, work
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

try:
    import pyperclip
    _HAS_PYPERCLIP = True
except ImportError:
    _HAS_PYPERCLIP = False

import malwoverview.modules.configvars as cv
from malwoverview.utils.capture import run_captured
from malwoverview.utils.clipboard import read_clipboard
from malwoverview.utils.colors import strip_terminal_escapes
from malwoverview.utils.output import collector
from malwoverview.utils.sanitize import (
    sanitize_hash, sanitize_ip, sanitize_domain, sanitize_url,
    sanitize_cve, sanitize_path, sanitize_tag, sanitize_general,
    sanitize_selector, sanitize_triage_id, sanitize_uuid, sanitize_integer,
    sanitize_component,
)
from malwoverview.modules.nist import MAX_PAGE_SIZE as NIST_PAGE_SIZE


SELF = '@self'


def _sanitize_days(value):
    return sanitize_integer(value, 1, 7)


def _sanitize_ioc_source(value):
    value = value.strip()
    if value.startswith(('http://', 'https://')):
        return sanitize_url(value)
    return sanitize_path(value)


def _sanitize_yara_args(value):
    parts = value.split(None, 1)
    if len(parts) < 2:
        return None, "Give the rules path and the target path separated by a space."
    rules, err = sanitize_path(parts[0])
    if err:
        return None, f"rules: {err}"
    target, err = sanitize_path(parts[1])
    if err:
        return None, f"target: {err}"
    return rules + '\n' + target, None


SERVICE_TABLE = [
    ('vt_hash', 'VT Hash', 'sha256, sha1, md5', 'vt', 'vthashwork', (1,), sanitize_hash),
    ('vt_file', 'VT File Report', 'file path', 'vt', 'filechecking_v3', (0, 0, 0), sanitize_path),
    ('vt_file_full', 'VT File Full Report', 'file path', 'vt', 'filechecking_v3', (1, 0, 0), sanitize_path),
    ('vt_behavior', 'VT Behavior', 'sha256, sha1, md5', 'vt', 'vtbehavior', (), sanitize_hash),
    ('vt_ip', 'VT IP', 'ip address', 'vt', 'vtipwork', (), sanitize_ip),
    ('vt_domain', 'VT Domain', 'domain name', 'vt', 'vtdomainwork', (), sanitize_domain),
    ('vt_url', 'VT URL', 'full URL (https://...)', 'vt', 'vturlwork', (), sanitize_url),
    ('vt_batch', 'VT Batch Hash', 'file with hashes', 'vt', 'vtbatchcheck', (1,), sanitize_path),
    ('vt_dir', 'VT Directory Scan', 'folder path', 'vt', 'vtdirchecking', (0,), sanitize_path),
    ('vt_ip_batch', 'VT IP Batch', 'file with IP addresses', 'vt', 'vtipbatchcheck', (0,), sanitize_path),
    ('vt_upload', 'VT Upload Sample', 'file path', 'vt', 'vtuploadfile', (), sanitize_path),
    ('vt_largefile', 'VT Upload Large File', 'file path', 'vt', 'vtlargefile', (), sanitize_path),
    ('vt_retro_submit', 'VT Retrohunt Submit', 'rules file or directory', 'vt', 'vtretrohuntsubmit', (), sanitize_path),
    ('vt_retro_list', 'VT Retrohunt Jobs', 'no argument', 'vt', 'vtretrohuntlist', (), None),
    ('vt_retro_status', 'VT Retrohunt Status', 'job id', 'vt', 'vtretrohuntstatus', (), sanitize_general),
    ('vt_retro_matches', 'VT Retrohunt Matches', 'job id', 'vt', 'vtretrohuntmatches', (), sanitize_general),
    ('vt_livehunt_create', 'VT Livehunt Create', 'rules file', 'vt', 'vtlivehuntcreate', (), sanitize_path),
    ('vt_livehunt_list', 'VT Livehunt Rulesets', 'no argument', 'vt', 'vtlivehuntlist', (), None),
    ('vt_livehunt_notif', 'VT Livehunt Notifications', 'no argument', 'vt', 'vtlivehuntnotifications', (), None),

    ('bazaar_hash', 'Bazaar Hash', 'sha256, sha1, md5', 'bazaar', 'bazaar_hash', (), sanitize_hash),
    ('bazaar_tag', 'Bazaar Tag', 'tag (e.g. Emotet)', 'bazaar', 'bazaar_tag', (), sanitize_tag),
    ('bazaar_imphash', 'Bazaar Imphash', 'import hash', 'bazaar', 'bazaar_imphash', (), sanitize_hash),
    ('bazaar_latest', 'Bazaar Latest', '100 or time', 'bazaar', 'bazaar_lastsamples', (), sanitize_selector),
    ('bazaar_download', 'Bazaar Download', 'sha256', 'bazaar', 'bazaar_download', (), sanitize_hash),
    ('bazaar_batch', 'Bazaar Batch', 'file with hashes', 'bazaar', 'bazaar_batchcheck', (), sanitize_path),
    ('bazaar_dir', 'Bazaar Dir Scan', 'folder path', 'bazaar', 'bazaar_dircheck', (), sanitize_path),
    ('bazaar_yara', 'Bazaar YARA Search', 'YARA rule name', 'bazaar', 'bazaar_yara', (), sanitize_tag),
    ('bazaar_yaradownload', 'YARAify Download Rules', 'no argument', 'bazaar', 'bazaar_yaradownload', (), None),
    ('bazaar_yaraextract', 'YARAify Extract Rules', 'no argument', 'bazaar', 'bazaar_yaraextract', (), None),

    ('threatfox_ioc', 'ThreatFox IOC', 'ioc value', 'threatfox', 'threatfox_searchiocs', (), sanitize_general),
    ('threatfox_tag', 'ThreatFox Tag', 'tag', 'threatfox', 'threatfox_searchtags', (), sanitize_tag),
    ('threatfox_malware', 'ThreatFox Malware', 'malware family', 'threatfox', 'threatfox_searchmalware', (), sanitize_general),
    ('threatfox_recent', 'ThreatFox Recent', 'days (1-7)', 'threatfox', 'threatfox_listiocs', (), _sanitize_days),
    ('threatfox_malwarelist', 'ThreatFox Families', 'no argument', 'threatfox', 'threatfox_listmalware', (), None),

    ('urlhaus_hash', 'URLHaus Hash', 'sha256, md5', 'urlhaus', 'haushashsearch', (), sanitize_hash),
    ('urlhaus_sample', 'URLHaus Download', 'sha256, md5', 'urlhaus', 'haussample', (), sanitize_hash),
    ('urlhaus_url', 'URLHaus URL', 'full URL', 'urlhaus', 'urlhauscheck', (), sanitize_url),
    ('urlhaus_tag', 'URLHaus Tag', 'tag (e.g. Emotet)', 'urlhaus', 'haustagsearchroutine', (), sanitize_tag),
    ('urlhaus_signature', 'URLHaus Signature', 'signature', 'urlhaus', 'haussigsearchroutine', (), sanitize_tag),
    ('urlhaus_batch', 'URLHaus Batch', 'file with hashes', 'urlhaus', 'hausbatchcheck', (), sanitize_path),
    ('urlhaus_payloads', 'URLHaus Payloads', 'no argument', 'urlhaus', 'hauspayloadslist', (), None),
    ('urlhaus_getbatch', 'URLHaus Feed', 'no argument', 'urlhaus', 'hausgetbatch', (), None),

    ('triage_search', 'Triage Search', 'hash, family:, tag:', 'triage', 'triage_search', (), sanitize_general),
    ('triage_summary', 'Triage Summary', 'triage sample ID', 'triage', 'triage_summary', (), sanitize_triage_id),
    ('triage_dynamic', 'Triage Dynamic', 'triage sample ID', 'triage', 'triage_dynamic', (), sanitize_triage_id),
    ('triage_download', 'Triage Download', 'triage sample ID', 'triage', 'triage_download', (), sanitize_triage_id),
    ('triage_pcap', 'Triage PCAP', 'triage sample ID', 'triage', 'triage_download_pcap', (), sanitize_triage_id),
    ('triage_submit', 'Triage Submit File', 'file path', 'triage', 'triage_sample_submit', (), sanitize_path),
    ('triage_urlsubmit', 'Triage Submit URL', 'full URL', 'triage', 'triage_url_sample_submit', (), sanitize_url),
    ('triage_batch', 'Triage Batch', 'file with hashes', 'triage', 'triage_batchcheck', (), sanitize_path),
    ('triage_dir', 'Triage Dir Scan', 'folder path', 'triage', 'triage_dircheck', (), sanitize_path),

    ('ha_hash', 'HA Hash Report', 'sha256, sha1, md5', 'ha', 'hashow', (0,), sanitize_hash),
    ('ha_quick', 'HA Quick Check', 'sha256, sha1, md5', 'ha', 'quickhashow', (), sanitize_hash),
    ('ha_download', 'HA Download', 'sha256', 'ha', 'downhash', (), sanitize_hash),
    ('ha_file', 'HA Submit File', 'file path', 'ha', 'hafilecheck', (0,), sanitize_path),
    ('ha_batch', 'HA Batch', 'file with hashes', 'ha', 'habatchcheck', (), sanitize_path),
    ('ha_dir', 'HA Dir Scan', 'folder path', 'ha', 'habatchdircheck', (), sanitize_path),

    ('alien_ip', 'AlienVault IP', 'ip address', 'alien', 'alien_ipv4', (), sanitize_ip),
    ('alien_domain', 'AlienVault Domain', 'domain name', 'alien', 'alien_domain', (), sanitize_domain),
    ('alien_hash', 'AlienVault Hash', 'sha256, sha1, md5', 'alien', 'alien_hash', (), sanitize_hash),
    ('alien_url', 'AlienVault URL', 'full URL', 'alien', 'alien_url', (), sanitize_url),

    ('malpedia_actors', 'Malpedia Actors', 'no argument', 'malpedia', 'malpedia_actors', (), None),
    ('malpedia_families', 'Malpedia Families', 'no argument', 'malpedia', 'malpedia_families', (), None),
    ('malpedia_meta', 'Malpedia Families Meta', 'no argument', 'malpedia', 'malpedia_families_meta', (), None),
    ('malpedia_payloads', 'Malpedia Payloads', 'no argument', 'malpedia', 'malpedia_payloads', (), None),
    ('malpedia_actor', 'Malpedia Actor', 'actor id', 'malpedia', 'malpedia_get_actor', (), sanitize_general),
    ('malpedia_family', 'Malpedia Family', 'family id', 'malpedia', 'malpedia_get_family', (), sanitize_general),
    ('malpedia_sample', 'Malpedia Sample', 'sha256', 'malpedia', 'malpedia_get_sample', (), sanitize_hash),
    ('malpedia_yara', 'Malpedia YARA', 'family id', 'malpedia', 'malpedia_get_yara', (), sanitize_general),
    ('malpedia_ruleset', 'Malpedia Ruleset', 'tlp_white, tlp_green, tlp_amber, auto', 'malpedia', 'malpedia_get_yara_ruleset', (), sanitize_tag),

    ('malshare_download', 'MalShare Download', 'sha256, md5', 'malshare', 'malsharedown', (), sanitize_hash),
    ('malshare_types', 'MalShare File Types', 'no argument', 'malshare', 'malsharetypes', (), None),
    ('malshare_type', 'MalShare List Type', 'file type (see File Types)', 'malshare', 'malsharetypelist', (), sanitize_tag),
    ('malshare_list', 'MalShare Last List', 'type number (1-7)', SELF, '_malshare_list', (), lambda v: sanitize_integer(v, 1, 7)),

    ('poly_hash', 'PolySwarm Hash', 'sha256, sha1, md5', 'polyswarm', 'polyhashsearch', (0,), sanitize_hash),
    ('poly_ip', 'PolySwarm IP', 'ip address', 'polyswarm', 'polymetasearch', (5,), sanitize_ip),
    ('poly_domain', 'PolySwarm Domain', 'domain name', 'polyswarm', 'polymetasearch', (6,), sanitize_domain),
    ('poly_url', 'PolySwarm URL', 'full URL', 'polyswarm', 'polymetasearch', (7,), sanitize_url),
    ('poly_file', 'PolySwarm File', 'file path', 'polyswarm', 'polyfile', (), sanitize_path),

    ('ipinfo', 'IPInfo', 'ip address', 'ipinfo', 'get_ip_details', (), sanitize_ip),
    ('ip_multi', 'IP Multi (VT+OTX)', 'ip address', 'multipleip', 'get_multiple_ip_details', (), sanitize_ip),
    ('ip_all', 'IP All Services', 'ip address', 'multipleipall', 'get_multiple_ip_details', (), sanitize_ip),
    ('shodan_ip', 'Shodan IP', 'ip address', 'shodan', 'shodan_ip', (), sanitize_ip),
    ('shodan_search', 'Shodan Search', 'search query', 'shodan', 'shodan_search', (), sanitize_general),
    ('abuseipdb', 'AbuseIPDB', 'ip address', 'abuseipdb', 'check_ip', (), sanitize_ip),
    ('greynoise', 'GreyNoise', 'ip address', 'greynoise', 'quick_check', (), sanitize_ip),

    ('whois_domain', 'Whois Domain', 'domain name', 'whois', 'domain_whois', (), sanitize_domain),
    ('whois_ip', 'Whois IP', 'ip address', 'whois', 'ip_whois', (), sanitize_ip),
    ('crtsh_subdomains', 'crt.sh Subdomains', 'domain name', 'crtsh', 'crtsh_subdomains', (), sanitize_domain),
    ('crtsh_certs', 'crt.sh Certificates', 'domain name', 'crtsh', 'crtsh_certificates', (), sanitize_domain),

    ('nist_cve', 'NIST CVE', 'CVE ID', SELF, '_nist_cve', (), sanitize_cve),
    ('nist_keyword', 'NIST Keyword', 'keyword', SELF, '_nist_keyword', (), sanitize_general),
    ('nist_component', 'NIST Component', 'component name or file', SELF, '_nist_component', (), sanitize_component),
    ('vulncheck_indexes', 'VulnCheck Indexes', 'no argument', 'vulncheck', 'vulncheck_list_indexes', (), None),
    ('vulncheck_kev', 'VulnCheck KEV', 'no argument', 'vulncheck', 'vulncheck_kev', (100,), None),
    ('vulncheck_cve', 'VulnCheck CVE', 'CVE ID', 'vulncheck', 'vulncheck_cve_search', (), sanitize_cve),
    ('vulncheck_mitre', 'VulnCheck MITRE', 'CVE ID', 'vulncheck', 'vulncheck_mitre_search', (), sanitize_cve),
    ('vulncheck_nist', 'VulnCheck NIST', 'CVE ID', 'vulncheck', 'vulncheck_nist_search', (), sanitize_cve),

    ('urlscanio_submit', 'URLScan Submit', 'full URL (https://...)', 'urlscanio', 'urlscanio_submit', (), sanitize_url),
    ('urlscanio_result', 'URLScan Result', 'scan UUID', 'urlscanio', 'urlscanio_result', (), sanitize_uuid),
    ('urlscanio_search', 'URLScan Search', 'query (e.g. task.tags:phishing)', 'urlscanio', 'urlscanio_search', (), sanitize_general),
    ('urlscanio_domain', 'URLScan Domain', 'domain name', 'urlscanio', 'urlscanio_domain', (), sanitize_domain),
    ('urlscanio_ip', 'URLScan IP', 'ip address', 'urlscanio', 'urlscanio_ip', (), sanitize_ip),

    ('correlate', 'Correlate (Multi)', 'sha256, sha1, md5', 'correlate', 'get_multiple_hash_details', (), sanitize_hash),
    ('android_ha', 'Android vs HA', 'no argument (adb device)', 'android', 'checkandroid', (1,), None),
    ('android_vtpublic', 'Android vs VT (public)', 'no argument (adb device)', 'android', 'checkandroid', (2,), None),
    ('android_vt', 'Android vs VT', 'no argument (adb device)', 'android', 'checkandroid', (3,), None),

    ('yara_scan', 'YARA Scan', 'rules path, space, target path', SELF, '_yara_scan', (), _sanitize_yara_args),
    ('extract_iocs', 'Extract IOCs', 'file path or URL', SELF, '_ioc_extract', (), _sanitize_ioc_source),
    ('pe_scan', 'Local PE Triage', 'file or folder path', SELF, '_pe_scan', (), sanitize_path),
    ('sig_check', 'Signature Check', 'file or folder path', SELF, '_sig_check', (), sanitize_path),
    ('cache_stats', 'Cache Stats', 'no argument', SELF, '_cache_stats', (), None),
]

SERVICES = [(key, label, hint) for key, label, hint, _, _, _, _ in SERVICE_TABLE]

_SERVICE_ACTIONS = {
    key: (module, method, extra)
    for key, _, _, module, method, extra, _ in SERVICE_TABLE
}

_SERVICE_SANITIZERS = {
    key: sanitizer
    for key, _, _, _, _, _, sanitizer in SERVICE_TABLE
    if sanitizer is not None
}

_CVE_SERVICES = ('nist_cve', 'nist_keyword', 'nist_component', 'vulncheck_kev',
                 'vulncheck_cve', 'vulncheck_mitre', 'vulncheck_nist', 'vulncheck_indexes')


KEY_LABELS = {
    'escape': 'Esc',
    'insert': 'Ins',
}


def key_label(key):
    parts = key.split('+')
    name = KEY_LABELS.get(parts[-1], parts[-1].upper())
    return '+'.join([part.capitalize() for part in parts[:-1]] + [name])


def help_line(bindings):
    parts = []
    for binding in bindings:
        if isinstance(binding, tuple):
            key, _action, description = binding[0], binding[1], binding[2]
        else:
            if not binding.show:
                continue
            key, description = binding.key, binding.description
        parts.append("%s %s" % (key_label(key), description))
    return " | ".join(parts)


class QueryInput(Input):
    BINDINGS = [
        Binding("ctrl+v", "app.paste", "Paste"),
        Binding("shift+insert", "app.paste", "Paste", show=False),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]


class ServiceItem(ListItem):
    def __init__(self, key, display_name, hints):
        super().__init__()
        self.service_key = key
        self.display_name = display_name
        self.hints = hints

    def compose(self):
        yield Label(f" {self.display_name}")


class MalwoverviewTUI(App):
    CSS = """
    Screen {
        layout: horizontal;
    }
    #sidebar {
        width: 30;
        dock: left;
        border-right: solid $accent;
        padding: 0;
    }
    #sidebar-title {
        text-align: center;
        text-style: bold;
        color: $text;
        padding: 1 0;
        background: $boost;
    }
    #services {
        height: 1fr;
    }
    #main-area {
        width: 1fr;
    }
    #input-bar {
        height: 3;
        padding: 0 1;
    }
    #query-input {
        width: 1fr;
    }
    #search-btn {
        width: 12;
    }
    #stop-btn {
        width: 10;
    }
    #hint {
        height: 1;
        padding: 0 1;
        color: $text-muted;
    }
    #results {
        height: 1fr;
        border-top: solid $accent;
        padding: 0 1;
    }
    ListView > ListItem.--highlight {
        background: $accent;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+l", "clear_results", "Clear"),
        ("ctrl+v", "paste", "Paste"),
        ("f3", "copy_result", "Copy"),
        ("f4", "pick_id", "Pick ID"),
        ("f5", "export_json", "Export json"),
        ("f6", "export_csv", "Export csv"),
        ("escape", "focus_input", "Focus input"),
        Binding("shift+insert", "paste", "Paste", show=False),
        Binding("ctrl+q", "quit", "Quit", show=False),
    ]

    def __init__(self, args):
        super().__init__()
        self.args = args
        self._modules = {}
        self._selected_service = SERVICE_TABLE[0][0]
        self._cancel = Event()
        self._last_result_text = ""
        self._enrich = False
        self._llm = None
        self._pick_ids = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static(" Services", id="sidebar-title")
                items = [ServiceItem(key, name, hints)
                         for key, name, hints in SERVICES]
                yield ListView(*items, id="services")
            with Vertical(id="main-area"):
                with Horizontal(id="input-bar"):
                    yield QueryInput(
                        placeholder="Enter sha256, sha1, or md5...",
                        id="query-input",
                    )
                    yield Button("Search", id="search-btn", variant="primary")
                    yield Button("Stop", id="stop-btn", variant="error")
                    yield Button("Enrich", id="enrich-btn", variant="default")
                yield Static("  VT Hash | Accepts: sha256, sha1, md5", id="hint")
                yield RichLog(id="results", highlight=False, markup=False)
        yield Footer()

    def on_mount(self):
        cv.bkg = 1
        cv.output_format = 'text'
        self._init_modules()
        results = self.query_one("#results", RichLog)
        results.write(Panel(
            Text.from_markup(
                "[bold cyan]Malwoverview TUI[/bold cyan]\n\n"
                "Select a service from the left panel,\n"
                "enter a query, and press Enter or click Search.\n\n"
                "[dim]%s[/dim]" % self.help_text()
            ),
            title="Welcome",
            border_style="cyan",
        ))
        self.query_one("#services").focus()

    def _init_modules(self):
        config_file = configparser.ConfigParser()
        config_file.read(self.args.config)

        def getoption(section, name):
            if config_file.has_option(section, name):
                return config_file.get(section, name)
            return ''

        from malwoverview.modules.virustotal import VirusTotalExtractor
        from malwoverview.modules.bazaar import BazaarExtractor
        from malwoverview.modules.threatfox import ThreatFoxExtractor
        from malwoverview.modules.urlhaus import URLHausExtractor
        from malwoverview.modules.triage import TriageExtractor
        from malwoverview.modules.hybrid import HybridAnalysisExtractor
        from malwoverview.modules.alienvault import AlienVaultExtractor
        from malwoverview.modules.malpedia import MalpediaExtractor
        from malwoverview.modules.malshare import MalshareExtractor
        from malwoverview.modules.polyswarm import PolyswarmExtractor
        from malwoverview.modules.ipinfo import IPInfoExtractor
        from malwoverview.modules.crtsh import CrtShExtractor
        from malwoverview.modules.shodan_mod import ShodanExtractor
        from malwoverview.modules.abuseipdb import AbuseIPDBExtractor
        from malwoverview.modules.greynoise import GreyNoiseExtractor
        from malwoverview.modules.whois_mod import WhoisExtractor
        from malwoverview.modules.urlscanio import URLScanIOExtractor
        from malwoverview.modules.nist import NISTExtractor
        from malwoverview.modules.vulncheck import VulnCheckExtractor
        from malwoverview.modules.multiplehash import MultipleHashExtractor
        from malwoverview.modules.multipleip import MultipleIPExtractor
        from malwoverview.modules.android import AndroidExtractor

        self._modules = {
            'vt': VirusTotalExtractor(getoption('VIRUSTOTAL', 'VTAPI')),
            'bazaar': BazaarExtractor(getoption('BAZAAR', 'BAZAARAPI')),
            'threatfox': ThreatFoxExtractor(getoption('THREATFOX', 'THREATFOXAPI')),
            'urlhaus': URLHausExtractor(getoption('URLHAUS', 'URLHAUSAPI')),
            'triage': TriageExtractor(getoption('TRIAGE', 'TRIAGEAPI')),
            'ha': HybridAnalysisExtractor(getoption('HYBRID-ANALYSIS', 'HAAPI')),
            'alien': AlienVaultExtractor(getoption('ALIENVAULT', 'ALIENAPI')),
            'malpedia': MalpediaExtractor(getoption('MALPEDIA', 'MALPEDIAAPI')),
            'malshare': MalshareExtractor(getoption('MALSHARE', 'MALSHAREAPI')),
            'polyswarm': PolyswarmExtractor(getoption('POLYSWARM', 'POLYAPI')),
            'ipinfo': IPInfoExtractor(getoption('IPINFO', 'IPINFOAPI')),
            'crtsh': CrtShExtractor(),
            'shodan': ShodanExtractor(getoption('SHODAN', 'SHODANAPI')),
            'abuseipdb': AbuseIPDBExtractor(getoption('ABUSEIPDB', 'ABUSEIPDBAPI')),
            'greynoise': GreyNoiseExtractor(getoption('GREYNOISE', 'GREYNOISEAPI')),
            'whois': WhoisExtractor(),
            'urlscanio': URLScanIOExtractor(getoption('URLSCANIO', 'URLSCANIOAPI')),
            'nist': NISTExtractor(),
            'vulncheck': VulnCheckExtractor(getoption('VULNCHECK', 'VULNCHECKAPI')),
        }

        self._modules['correlate'] = MultipleHashExtractor({
            "VirusTotal": self._modules['vt'],
            "HybridAnalysis": self._modules['ha'],
            "Triage": self._modules['triage'],
            "AlienVault": self._modules['alien'],
        })

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

        self._modules['android'] = AndroidExtractor(
            self._modules['ha'], self._modules['vt'])

        from malwoverview.utils.llm import LLMEnricher
        self._llm_config = {
            'claude_key': getoption('LLM', 'CLAUDE_API_KEY'),
            'claude_model': getoption('LLM', 'CLAUDE_MODEL'),
            'gemini_key': getoption('LLM', 'GEMINI_API_KEY'),
            'ollama_url': getoption('LLM', 'OLLAMA_URL'),
            'ollama_model': getoption('LLM', 'OLLAMA_MODEL'),
            'gemini_model': getoption('LLM', 'GEMINI_MODEL'),
            'openai_key': getoption('LLM', 'OPENAI_API_KEY'),
            'openai_model': getoption('LLM', 'OPENAI_MODEL'),
        }
        self._llm_providers = ['claude', 'gemini', 'openai', 'ollama']
        default_provider = getoption('LLM', 'PROVIDER').strip().lower()
        self._llm = LLMEnricher(default_provider, **self._llm_config)
        self._llm_cycle_index = -1

    def _select_service(self, item):
        if isinstance(item, ServiceItem):
            self._selected_service = item.service_key
            hint = self.query_one("#hint", Static)
            hint.update(f"  {item.display_name} | Accepts: {item.hints}")
            inp = self.query_one("#query-input", Input)
            if item.service_key in _SERVICE_SANITIZERS:
                inp.placeholder = f"Enter {item.hints}..."
            else:
                inp.placeholder = "No argument needed - press Enter or click Search"

    def on_list_view_highlighted(self, event: ListView.Highlighted):
        self._select_service(event.item)

    def on_list_view_selected(self, event: ListView.Selected):
        self._select_service(event.item)
        self.query_one("#query-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "search-btn":
            self._start_query()
        elif event.button.id == "stop-btn":
            self._cancel.set()
            self.workers.cancel_all()
            results = self.query_one("#results", RichLog)
            results.write(Text("\nQuery stopped.", style="bold yellow"))
        elif event.button.id == "enrich-btn":
            from malwoverview.utils.llm import LLMEnricher
            btn = self.query_one("#enrich-btn", Button)
            self._llm_cycle_index += 1
            if self._llm_cycle_index >= len(self._llm_providers):
                self._llm_cycle_index = -1
                self._enrich = False
                btn.variant = "default"
                btn.label = "Enrich"
                return
            provider = self._llm_providers[self._llm_cycle_index]
            self._llm = LLMEnricher(provider, **self._llm_config)
            if self._llm.is_configured():
                self._enrich = True
                btn.variant = "success"
                btn.label = f"Enrich: {provider}"
            else:
                btn.variant = "warning"
                btn.label = f"Enrich: {provider} (no key)"
                self._enrich = False

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "query-input":
            self._start_query()

    def _start_query(self):
        svc = self._selected_service
        if svc not in _SERVICE_ACTIONS:
            return

        query = self.query_one("#query-input", Input).value.strip()
        svc_name = next((name for k, name, _ in SERVICES if k == svc), svc)
        results = self.query_one("#results", RichLog)
        sanitizer = _SERVICE_SANITIZERS.get(svc)

        if sanitizer is None:
            query = ''
        else:
            if not query:
                return
            sanitized, error = sanitizer(query)
            if error:
                results = self._reset_results()
                results.write(Text(f"Input error: {error}", style="bold red"))
                return
            query = sanitized

        self._cancel.clear()
        results = self._reset_results()
        target = query.replace('\n', ' ') if query else '(no argument)'
        results.write(
            Text(f"Querying {svc_name} for: {target} ...", style="bold yellow")
        )
        self._execute_query(svc, query)

    def _run_service(self, service, query):
        module_key, method_name, extra = _SERVICE_ACTIONS[service]
        if module_key == SELF:
            func = getattr(self, method_name)
        else:
            func = getattr(self._modules[module_key], method_name)
        if service in _SERVICE_SANITIZERS:
            return run_captured(func, query, *extra)
        return run_captured(func, *extra)

    @work(thread=True, exclusive=True, exit_on_error=False)
    def _execute_query(self, service, query):
        results_log = self.query_one("#results", RichLog)

        try:
            ok, output, error = self._run_service(service, query)
            if self._cancel.is_set():
                return

            body = Text.from_ansi(output) if output else None
            self._last_result_text = body.plain if body else ""

            self.call_from_thread(results_log.clear)
            if body and body.plain.strip():
                self.call_from_thread(results_log.write, body)
            else:
                self.call_from_thread(
                    results_log.write,
                    Text("No results returned.", style="yellow"),
                )
            if not ok:
                self.call_from_thread(
                    results_log.write,
                    Text(f"Error: {strip_terminal_escapes(str(error))}", style="bold red"),
                )

            if self._enrich and self._llm and self._llm.is_configured():
                self._enrich_result(service, results_log)
        except Exception as e:
            if self._cancel.is_set():
                return
            self._last_result_text = ""
            self.call_from_thread(results_log.clear)
            self.call_from_thread(
                results_log.write,
                Text(f"Error: {strip_terminal_escapes(str(e))}", style="bold red"),
            )

    def _enrich_result(self, service, results_log):
        from malwoverview.utils.llm import (
            records_to_prompt_text, colorize_enrichment,
        )
        payload = records_to_prompt_text(collector.records) or self._last_result_text
        if not payload:
            return
        prompt_type = 'cve' if service in _CVE_SERVICES else 'threat'
        label = 'CVE Assessment' if prompt_type == 'cve' else 'Threat Assessment'
        self.call_from_thread(
            results_log.write,
            Text("\n Enriching with LLM...", style="bold cyan"),
        )
        try:
            analysis = self._llm.enrich(payload, prompt_type)
            if analysis:
                panel = Panel(
                    Text.from_ansi(colorize_enrichment(analysis, bkg=1)),
                    title=f"LLM {label}",
                    border_style="green",
                    expand=True,
                )
                self.call_from_thread(results_log.write, panel)
        except Exception as llm_err:
            self.call_from_thread(
                results_log.write,
                Text(f"LLM error: {strip_terminal_escapes(str(llm_err))}", style="red"),
            )

    def _malshare_list(self, value):
        self._modules['malshare'].malsharelastlist(int(value))

    def _nist_cve(self, value):
        nist = self._modules['nist']
        result = nist.query_cve(2, value, NIST_PAGE_SIZE, 0, None)
        if result:
            nist.print_results(result, verbose=False, color_scheme=cv.bkg,
                               max_cves=None)

    def _nist_keyword(self, value):
        nist = self._modules['nist']
        result = nist.query_cve(4, value, NIST_PAGE_SIZE, 0, None)
        if result:
            nist.print_results(result, verbose=False, color_scheme=cv.bkg,
                               max_cves=None)

    def _nist_component(self, value):
        self._modules['nist'].component_cve(value, None, None, NIST_PAGE_SIZE)

    def _yara_scan(self, value):
        from malwoverview.modules.yara_scan import YaraScanner
        rules, target = value.split('\n', 1)
        YaraScanner(rules).scan_and_display(target)

    def _ioc_extract(self, value):
        from malwoverview.utils.ioc_extract import IOCExtractor
        IOCExtractor().extract_and_display(value)

    def _pe_scan(self, value):
        from malwoverview.modules.pe_scan import PEScanner
        PEScanner().scan_and_display(value)

    def _sig_check(self, value):
        from malwoverview.modules.pe_scan import PEScanner
        PEScanner().signature_and_display(value)

    def _cache_stats(self):
        from malwoverview.utils.cache import cache_stats
        from malwoverview.utils.peinfo import humansize
        from malwoverview.utils.colors import mycolors
        info = cache_stats()
        colsize = 16
        infocolor = mycolors.foreground.info(cv.bkg)
        print()
        print(infocolor + "Cache file:".ljust(colsize) + mycolors.reset + str(info['db_path']))
        print(infocolor + "Entries:".ljust(colsize) + mycolors.reset + str(info['entries']))
        print(infocolor + "Expired:".ljust(colsize) + mycolors.reset + str(info['expired']))
        print(infocolor + "TTL:".ljust(colsize) + mycolors.reset + str(info['ttl']) + " seconds")
        print(infocolor + "Size on disk:".ljust(colsize) + mycolors.reset + humansize(info['size_bytes']))

    def action_quit(self):
        self._cancel.set()
        self.workers.cancel_all()
        self.exit()

    def help_text(self):
        return help_line(self.BINDINGS)

    def _reset_results(self):
        results = self.query_one("#results", RichLog)
        results.clear()
        results.write(Text(self.help_text(), style="dim"))
        return results

    def action_clear_results(self):
        self._reset_results()

    def action_focus_input(self):
        self.query_one("#query-input").focus()

    def on_paste(self, event: events.Paste):
        if self._paste_into_input(event.text):
            event.stop()

    def _paste_into_input(self, text):
        if not text:
            return False
        line = text.splitlines()[0].strip()
        if not line:
            return False
        inp = self.query_one("#query-input", Input)
        inp.value = line
        inp.cursor_position = len(line)
        inp.focus()
        return True

    def action_paste(self):
        text, error = read_clipboard()
        if error:
            self.query_one("#results", RichLog).write(
                Text(f"Paste failed: {error}", style="bold red")
            )
            return
        if not self._paste_into_input(text):
            self.query_one("#results", RichLog).write(
                Text("Paste failed: the clipboard holds no usable text.", style="bold red")
            )

    def action_export_json(self):
        self._export('json')

    def action_export_csv(self):
        self._export('csv')

    def _export(self, fmt):
        results_log = self.query_one("#results", RichLog)
        if not collector.records:
            results_log.write(
                Text("Nothing to export - run a query first.", style="yellow")
            )
            return
        directory = cv.output_dir or os.getcwd()
        path = os.path.join(directory, f"malwoverview_export.{fmt}")
        count = len(collector.records)
        old_format = cv.output_format
        try:
            cv.output_format = fmt
            with open(path, 'w', newline='', encoding='utf-8') as handle:
                collector.finalize(handle)
        except Exception as e:
            results_log.write(Text(f"Export failed: {e}", style="bold red"))
            return
        finally:
            cv.output_format = old_format
        results_log.write(
            Text(f"Exported {count} record(s) to {path}", style="bold green")
        )

    def action_copy_result(self):
        results_log = self.query_one("#results", RichLog)
        if not self._last_result_text:
            results_log.write(
                Text("Nothing to copy - no results yet.", style="yellow")
            )
            return
        if not _HAS_PYPERCLIP:
            results_log.write(
                Text(
                    "Cannot copy: pyperclip is not installed. "
                    "Install it with: pip install pyperclip",
                    style="bold red",
                )
            )
            return
        try:
            pyperclip.copy(self._last_result_text)
            results_log.write(
                Text("Result copied to clipboard.", style="bold green")
            )
        except Exception as e:
            results_log.write(
                Text(f"Failed to copy to clipboard: {e}", style="bold red")
            )

    def _extract_ids(self):
        text = self._last_result_text
        if not text:
            return []
        ids = []
        seen = set()
        patterns = [
            (re.compile(r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b'), 'UUID'),
            (re.compile(r'\b[a-fA-F0-9]{64}\b'), 'SHA256'),
            (re.compile(r'\b[a-fA-F0-9]{40}\b'), 'SHA1'),
            (re.compile(r'\b[a-fA-F0-9]{32}\b'), 'MD5'),
            (re.compile(r'\b\d{6}-[a-zA-Z0-9]{6,}\b'), 'Triage ID'),
            (re.compile(r'(?:https?://[^\s]+)'), 'URL'),
        ]
        for pattern, label in patterns:
            for m in pattern.finditer(text):
                val = m.group()
                if val not in seen:
                    seen.add(val)
                    ids.append((label, val))
        return ids

    def action_pick_id(self):
        results_log = self.query_one("#results", RichLog)
        inp = self.query_one("#query-input", Input)

        if self._pick_ids and inp.value.strip().isdigit():
            idx = int(inp.value.strip()) - 1
            if 0 <= idx < len(self._pick_ids):
                picked = self._pick_ids[idx][1]
                inp.value = ""
                inp.value = picked
                if _HAS_PYPERCLIP:
                    try:
                        pyperclip.copy(picked)
                    except Exception:
                        pass
                results_log.write(
                    Text(f"Picked: {picked} (copied to clipboard)", style="bold green")
                )
                self._pick_ids = []
                return
            else:
                results_log.write(
                    Text(f"Invalid selection. Enter 1-{len(self._pick_ids)}.", style="yellow")
                )
                return

        ids = self._extract_ids()
        if not ids:
            text_len = len(self._last_result_text)
            if text_len == 0:
                results_log.write(
                    Text("No result text captured - try running a query first.", style="yellow")
                )
            else:
                results_log.write(
                    Text(f"No IDs found in last result ({text_len} chars captured). "
                         f"Preview: {self._last_result_text[:200]}", style="yellow")
                )
            return

        if len(ids) == 1:
            inp.value = ""
            inp.value = ids[0][1]
            if _HAS_PYPERCLIP:
                try:
                    pyperclip.copy(ids[0][1])
                except Exception:
                    pass
            results_log.write(
                Text(f"Single ID found - filled input and copied to clipboard: {ids[0][1]}", style="bold green")
            )
            return

        self._pick_ids = ids
        table = Table(title="Pick an ID", box=None, padding=(0, 1))
        table.add_column("#", style="cyan bold", width=4)
        table.add_column("Type", style="cyan", width=10)
        table.add_column("Value")
        for i, (label, val) in enumerate(ids, 1):
            table.add_row(str(i), label, Text(val))
        results_log.write(table)
        results_log.write(Text(""))
        results_log.write(
            Text("Type the number in the input field and press F4 again to select.",
                 style="dim")
        )
        results_log.write(Text(""))
        inp.value = ""
        inp.focus()
