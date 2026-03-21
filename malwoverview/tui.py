import sys
import os
import builtins
import io
import re
import json
import base64
import configparser
import ipaddress
from datetime import datetime
from io import StringIO
from threading import Event
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Input, Button, RichLog, ListView, ListItem, Label, Static,
)
from textual import work
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.console import Console, Group

try:
    import pyperclip
    _HAS_PYPERCLIP = True
except ImportError:
    _HAS_PYPERCLIP = False

import malwoverview.modules.configvars as cv


ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

SERVICES = [
    ("vt_hash", "VT Hash", "sha256, sha1, md5"),
    ("vt_batch", "VT Batch Hash", "path to file with hashes"),
    ("vt_ip", "VT IP", "ip address"),
    ("vt_domain", "VT Domain", "domain name"),
    ("vt_url", "VT URL", "full URL (https://...)"),
    ("vt_behavior", "VT Behavior", "sha256, sha1, md5"),
    ("bazaar_hash", "Bazaar Hash", "sha256, sha1, md5"),
    ("bazaar_tag", "Bazaar Tag", "tag (e.g. Emotet)"),
    ("bazaar_imphash", "Bazaar Imphash", "import hash"),
    ("bazaar_latest", "Bazaar Latest", "100 or time"),
    ("bazaar_batch", "Bazaar Batch", "path to file with hashes"),
    ("bazaar_dir", "Bazaar Dir Scan", "folder path"),
    ("urlhaus_hash", "URLHaus Hash", "sha256, md5"),
    ("urlhaus_url", "URLHaus URL", "full URL"),
    ("urlhaus_tag", "URLHaus Tag", "tag (e.g. Emotet)"),
    ("triage_search", "Triage Search", "hash, family:, tag:"),
    ("triage_summary", "Triage Summary", "triage sample ID"),
    ("triage_dynamic", "Triage Dynamic", "triage sample ID"),
    ("triage_batch", "Triage Batch", "path to file with hashes"),
    ("triage_dir", "Triage Dir Scan", "folder path"),
    ("shodan_ip", "Shodan IP", "ip address"),
    ("shodan_search", "Shodan Search", "search query"),
    ("abuseipdb", "AbuseIPDB", "ip address"),
    ("whois_domain", "Whois Domain", "domain name"),
    ("whois_ip", "Whois IP", "ip address"),
    ("ipinfo", "IPInfo", "ip address"),
    ("nist", "NIST CVE", "CVE ID or keyword"),
    ("vulncheck_kev", "VulnCheck KEV", "CVE ID"),
    ("vulncheck_mitre", "VulnCheck MITRE", "CVE ID"),
    ("vulncheck_nist", "VulnCheck NIST", "CVE ID"),
    ("urlscanio_submit", "URLScan Submit", "full URL (https://...)"),
    ("urlscanio_result", "URLScan Result", "scan UUID"),
    ("urlscanio_search", "URLScan Search", "Elasticsearch query (e.g. task.tags:phishing)"),
    ("urlscanio_domain", "URLScan Domain", "domain name"),
    ("urlscanio_ip", "URLScan IP", "ip address"),
    ("correlate", "Correlate (Multi)", "sha256, sha1, md5"),
    ("folder_scan", "Folder Scan (VT)", "folder path"),
]


class _TUIExit(Exception):
    pass


def _strip_ansi(text):
    return ANSI_RE.sub('', text)


def _safe_str(value, default="N/A"):
    if value is None:
        return default
    return str(value)



from malwoverview.utils.sanitize import (
    sanitize_hash as _sanitize_hash,
    sanitize_ip as _sanitize_ip,
    sanitize_domain as _sanitize_domain,
    sanitize_url as _sanitize_url,
    sanitize_cve as _sanitize_cve,
    sanitize_path as _sanitize_path,
    sanitize_tag as _sanitize_tag,
    sanitize_general as _sanitize_general,
    sanitize_selector as _sanitize_selector,
    sanitize_triage_id as _sanitize_triage_id,
    sanitize_uuid as _sanitize_uuid,
)


_SERVICE_SANITIZERS = {
    'vt_hash': _sanitize_hash,
    'vt_batch': _sanitize_path,
    'vt_ip': _sanitize_ip,
    'vt_domain': _sanitize_domain,
    'vt_url': _sanitize_url,
    'vt_behavior': _sanitize_hash,
    'bazaar_hash': _sanitize_hash,
    'bazaar_tag': _sanitize_tag,
    'bazaar_imphash': _sanitize_hash,
    'bazaar_latest': _sanitize_selector,
    'bazaar_batch': _sanitize_path,
    'bazaar_dir': _sanitize_path,
    'urlhaus_hash': _sanitize_hash,
    'urlhaus_url': _sanitize_url,
    'urlhaus_tag': _sanitize_tag,
    'triage_search': _sanitize_general,
    'triage_summary': _sanitize_triage_id,
    'triage_dynamic': _sanitize_triage_id,
    'triage_batch': _sanitize_path,
    'triage_dir': _sanitize_path,
    'shodan_ip': _sanitize_ip,
    'shodan_search': _sanitize_general,
    'abuseipdb': _sanitize_ip,
    'whois_domain': _sanitize_domain,
    'whois_ip': _sanitize_ip,
    'ipinfo': _sanitize_ip,
    'nist': _sanitize_general,
    'vulncheck_kev': _sanitize_cve,
    'vulncheck_mitre': _sanitize_cve,
    'vulncheck_nist': _sanitize_cve,
    'urlscanio_submit': _sanitize_url,
    'urlscanio_result': _sanitize_uuid,
    'urlscanio_search': _sanitize_general,
    'urlscanio_domain': _sanitize_domain,
    'urlscanio_ip': _sanitize_ip,
    'correlate': _sanitize_hash,
    'folder_scan': _sanitize_path,
}


def _make_report(title, fields, highlights=None):
    """Build a Rich Panel with a two-column table of field:value pairs."""
    highlights = highlights or {}
    table = Table(show_header=False, expand=True, box=None, padding=(0, 1))
    table.add_column("Field", style="cyan bold", min_width=22, no_wrap=True)
    table.add_column("Value", ratio=1)

    for name, value in fields:
        val_str = _safe_str(value)
        if highlights.get(name) == 'danger':
            table.add_row(
                Text(name, style="red bold"),
                Text(val_str, style="red"),
            )
        else:
            table.add_row(Text(name), Text(val_str))

    return Panel(table, title=f"[bold]{title}[/bold]", border_style="cyan",
                 expand=True, padding=(1, 2))


def _av_table(analysis_results, title="AV Engine Results"):
    """Build a table of AV vendor detections from VT last_analysis_results."""
    if not analysis_results:
        return None

    file_vendors = [
        'Avast', 'Avira', 'BitDefender', 'ClamAV', 'DrWeb', 'Emsisoft',
        'ESET-NOD32', 'F-Secure', 'FireEye', 'Fortinet', 'GData',
        'Kaspersky', 'Malwarebytes', 'McAfee', 'Microsoft', 'Panda',
        'Sophos', 'Symantec', 'TrendMicro', 'ZoneAlarm',
    ]
    url_vendors = [
        'AlienVault', 'BitDefender', 'Avira', 'Dr.Web', 'Emsisoft',
        'ESET', 'Fortinet', 'G-Data', 'Google Safebrowsing', 'Kaspersky',
        'MalwarePatrol', 'OpenPhish', 'Phishtank', 'Sophos', 'Spamhaus',
        'Sucuri SiteCheck', 'Trustwave', 'URLhaus', 'Webroot',
    ]

    vendors = file_vendors
    found = sum(1 for v in vendors if v in analysis_results)
    if found < 3:
        vendors = url_vendors

    table = Table(title=title, show_header=True, expand=True,
                  border_style="cyan")
    table.add_column("Engine", style="cyan bold", min_width=20)
    table.add_column("Result", ratio=1)

    for vendor in vendors:
        if vendor in analysis_results:
            entry = analysis_results[vendor]
            result = entry.get('result') or 'CLEAN'
            cat = entry.get('category', '')
            if cat in ('malicious', 'suspicious') or (result and result != 'CLEAN'):
                table.add_row(
                    Text(vendor, style="red bold"),
                    Text(result, style="red"),
                )
            else:
                table.add_row(Text(vendor), Text(result, style="green"))

    return Panel(table, border_style="cyan", expand=True)



def _format_vt_ip(data):
    attrs = data.get('data', {}).get('attributes', {})
    if not attrs:
        return Text("No data returned from VirusTotal.", style="red")

    stats = attrs.get('last_analysis_stats', {})
    fields = [
        ("AS Owner", attrs.get('as_owner')),
        ("ASN", attrs.get('asn')),
        ("Country", attrs.get('country')),
        ("Network", attrs.get('network')),
        ("R.I.R", attrs.get('regional_internet_registry')),
        ("JARM", attrs.get('jarm')),
    ]
    if 'whois_date' in attrs:
        try:
            fields.append(("Whois Date", str(datetime.fromtimestamp(attrs['whois_date']))))
        except Exception:
            fields.append(("Whois Date", str(attrs['whois_date'])))

    fields += [
        ("Reputation", attrs.get('reputation')),
        ("Harmless", stats.get('harmless')),
        ("Malicious", stats.get('malicious')),
        ("Undetected", stats.get('undetected')),
        ("Suspicious", stats.get('suspicious')),
    ]

    highlights = {}
    if stats.get('malicious', 0) and int(stats['malicious']) > 0:
        highlights['Malicious'] = 'danger'
    if stats.get('suspicious', 0) and int(stats['suspicious']) > 0:
        highlights['Suspicious'] = 'danger'
    rep = attrs.get('reputation', 0)
    if rep and int(rep) < 0:
        highlights['Reputation'] = 'danger'

    panels = [_make_report("VirusTotal IP Report", fields, highlights)]

    av = attrs.get('last_analysis_results')
    if av:
        av_panel = _av_table(av, "AV Report")
        if av_panel:
            panels.append(av_panel)

    return Group(*panels)


def _format_vt_hash(data):
    attrs = data.get('data', {}).get('attributes', {})
    if not attrs:
        return Text("No data returned from VirusTotal.", style="red")

    stats = attrs.get('last_analysis_stats', {})
    threat = attrs.get('popular_threat_classification', {})

    fields = [
        ("SHA256", attrs.get('sha256')),
        ("SHA1", attrs.get('sha1')),
        ("MD5", attrs.get('md5')),
        ("Type", attrs.get('type_description')),
        ("Type Tag", attrs.get('type_tag')),
        ("Size", attrs.get('size')),
        ("Times Submitted", attrs.get('times_submitted')),
        ("Last Analysis Date", attrs.get('last_analysis_date')),
        ("Malicious", stats.get('malicious')),
        ("Undetected", stats.get('undetected')),
    ]

    if threat:
        label = threat.get('suggested_threat_label')
        if label:
            fields.append(("Threat Label", label))

    trid = attrs.get('trid')
    if trid and isinstance(trid, list):
        for entry in trid[:3]:
            fields.append(("TRID", f"{entry.get('file_type', '')} ({entry.get('probability', '')}%)"))

    names = attrs.get('names')
    if names and isinstance(names, list):
        fields.append(("Names", ", ".join(names[:5])))

    pe_info = attrs.get('pe_info', {})
    if pe_info:
        if pe_info.get('imphash'):
            fields.append(("Imphash", pe_info['imphash']))

    highlights = {}
    if stats.get('malicious', 0) and int(stats['malicious']) > 0:
        highlights['Malicious'] = 'danger'
        if threat.get('suggested_threat_label'):
            highlights['Threat Label'] = 'danger'

    panels = [_make_report("VirusTotal Hash Report", fields, highlights)]

    av = attrs.get('last_analysis_results')
    if av:
        av_panel = _av_table(av, "AV Engine Detections")
        if av_panel:
            panels.append(av_panel)

    return Group(*panels)


def _format_vt_domain(data):
    attrs = data.get('data', {}).get('attributes', {})
    if not attrs:
        return Text("No data returned from VirusTotal.", style="red")

    stats = attrs.get('last_analysis_stats', {})
    fields = []

    if 'creation_date' in attrs:
        try:
            fields.append(("Creation Date", str(datetime.fromtimestamp(attrs['creation_date']))))
        except Exception:
            fields.append(("Creation Date", str(attrs['creation_date'])))
    if 'last_update_date' in attrs:
        try:
            fields.append(("Last Update", str(datetime.fromtimestamp(attrs['last_update_date']))))
        except Exception:
            fields.append(("Last Update", str(attrs['last_update_date'])))

    fields += [
        ("Registrar", attrs.get('registrar')),
        ("Reputation", attrs.get('reputation')),
        ("JARM", attrs.get('jarm')),
        ("Harmless", stats.get('harmless')),
        ("Malicious", stats.get('malicious')),
        ("Undetected", stats.get('undetected')),
        ("Suspicious", stats.get('suspicious')),
    ]

    if 'whois_date' in attrs:
        try:
            fields.append(("Whois Date", str(datetime.fromtimestamp(attrs['whois_date']))))
        except Exception:
            pass

    highlights = {}
    if stats.get('malicious', 0) and int(stats['malicious']) > 0:
        highlights['Malicious'] = 'danger'
    if stats.get('suspicious', 0) and int(stats['suspicious']) > 0:
        highlights['Suspicious'] = 'danger'

    panels = [_make_report("VirusTotal Domain Report", fields, highlights)]

    av = attrs.get('last_analysis_results')
    if av:
        av_panel = _av_table(av, "AV Report")
        if av_panel:
            panels.append(av_panel)

    return Group(*panels)


def _format_vt_url(data):
    attrs = data.get('data', {}).get('attributes', {})
    if not attrs:
        return Text("No data returned from VirusTotal.", style="red")

    stats = attrs.get('last_analysis_stats', {})
    fields = [
        ("Last Final URL", attrs.get('last_final_url')),
        ("Harmless", stats.get('harmless')),
        ("Malicious", stats.get('malicious')),
        ("Undetected", stats.get('undetected')),
        ("Suspicious", stats.get('suspicious')),
        ("Last SHA256 Content", attrs.get('last_http_response_content_sha256')),
        ("HTTP Response Code", attrs.get('last_http_response_code')),
        ("Times Submitted", attrs.get('times_submitted')),
        ("Reputation", attrs.get('reputation')),
    ]

    if 'last_analysis_date' in attrs:
        try:
            fields.append(("Last Analysis Date", str(datetime.fromtimestamp(attrs['last_analysis_date']))))
        except Exception:
            fields.append(("Last Analysis Date", str(attrs['last_analysis_date'])))

    threat_names = attrs.get('threat_names')
    if threat_names:
        fields.append(("Threat Names", ", ".join(threat_names[:10])))

    chain = attrs.get('redirection_chain')
    if chain:
        fields.append(("Redirection Chain", "\n".join(chain[:5])))

    highlights = {}
    if stats.get('malicious', 0) and int(stats['malicious']) > 0:
        highlights['Malicious'] = 'danger'
    if stats.get('suspicious', 0) and int(stats['suspicious']) > 0:
        highlights['Suspicious'] = 'danger'

    panels = [_make_report("VirusTotal URL Report", fields, highlights)]

    av = attrs.get('last_analysis_results')
    if av:
        av_panel = _av_table(av, "AV Report")
        if av_panel:
            panels.append(av_panel)

    return Group(*panels)


def _format_vt_behavior(data):
    bd = data.get('data', {})
    if not bd:
        return Text("No behavior data found for this hash.", style="red")

    fields = []

    verdicts = bd.get('verdicts')
    if verdicts:
        fields.append(("Verdicts", " | ".join(verdicts)))
    if bd.get('verdict_confidence') is not None:
        fields.append(("Verdict Confidence", bd['verdict_confidence']))
    labels = bd.get('verdict_labels')
    if labels:
        fields.append(("Verdict Labels", " | ".join(labels)))

    for key, label in [
        ('processes_injected', 'Processes Injected'),
        ('calls_highlighted', 'Calls Highlighted'),
    ]:
        items = bd.get(key, [])
        if items:
            fields.append((label, "\n".join(items[:10])))

    dns = bd.get('dns_lookups', [])
    if dns:
        dns_items = []
        for lookup in dns[:10]:
            hostname = lookup.get('hostname', '')
            ips = lookup.get('resolved_ips', [])
            dns_items.append(f"{hostname} -> {', '.join(ips)}" if ips else hostname)
        fields.append(("DNS Lookups", "\n".join(dns_items)))

    procs = bd.get('processes_tree', [])
    if procs:
        proc_items = []
        for p in procs[:8]:
            proc_items.append(f"{p.get('process_id','')}: {p.get('name','')}")
            for child in p.get('children', [])[:3]:
                proc_items.append(f"  {child.get('process_id','')}: {child.get('name','')}")
        fields.append(("Process Tree", "\n".join(proc_items)))

    for key, label in [
        ('processes_terminated', 'Processes Terminated'),
        ('processes_killed', 'Processes Killed'),
        ('services_created', 'Services Created'),
        ('services_started', 'Services Started'),
        ('services_stopped', 'Services Stopped'),
        ('services_deleted', 'Services Deleted'),
    ]:
        items = bd.get(key, [])
        if items:
            fields.append((label, "\n".join(items[:8])))

    ja3 = bd.get('ja3_digests', [])
    if ja3:
        fields.append(("JA3 Digests", "\n".join(ja3[:5])))

    modules = bd.get('modules_loaded', [])
    if modules:
        fields.append(("Modules Loaded", ", ".join(modules[:20])))

    for key, label in [
        ('registry_keys_opened', 'Registry Keys Opened'),
        ('files_opened', 'Files Opened'),
        ('files_written', 'Files Written'),
        ('files_deleted', 'Files Deleted'),
    ]:
        items = bd.get(key, [])
        if items:
            fields.append((label, "\n".join(items[:10])))

    cmds = bd.get('command_executions', [])
    if cmds:
        fields.append(("Command Executions", "\n".join(cmds[:10])))

    mutexes = bd.get('mutexes_created', [])
    if mutexes:
        fields.append(("Mutexes Created", "\n".join(mutexes[:8])))

    windows = bd.get('windows_hidden', [])
    if windows:
        fields.append(("Windows Hidden", "\n".join(str(w) for w in windows[:5])))

    mitre = bd.get('mitre_attack_techniques', [])
    if mitre:
        techniques = []
        for m in mitre[:10]:
            if isinstance(m, dict):
                techniques.append(f"{m.get('id', '')} - {m.get('description', '')}")
            else:
                techniques.append(str(m))
        fields.append(("MITRE ATT&CK", "\n".join(techniques)))

    highlights = {}
    if verdicts and any('malicious' in v.lower() for v in verdicts):
        highlights['Verdicts'] = 'danger'
    for danger_key in ['Processes Injected', 'Calls Highlighted', 'Services Created']:
        if any(name == danger_key for name, _ in fields):
            highlights[danger_key] = 'danger'

    return _make_report("VirusTotal Behavior Report", fields, highlights)




def _format_bazaar_hash(data):
    if not data:
        return Text("No data returned from Malware Bazaar.", style="red")

    tags = data.get('tags')
    tag_str = ", ".join(tags) if isinstance(tags, list) else _safe_str(tags)

    fields = [
        ("SHA256", data.get('sha256_hash')),
        ("SHA1", data.get('sha1_hash')),
        ("MD5", data.get('md5_hash')),
        ("First Seen", data.get('first_seen')),
        ("Last Seen", data.get('last_seen')),
        ("File Name", data.get('file_name')),
        ("File Size", data.get('file_size')),
        ("File Type", data.get('file_type')),
        ("MIME Type", data.get('file_type_mime')),
        ("Origin Country", data.get('origin_country')),
        ("Imphash", data.get('imphash')),
        ("TLSH", data.get('tlsh')),
        ("Reporter", data.get('reporter')),
        ("Signature", data.get('signature')),
        ("Tags", tag_str),
    ]

    highlights = {}
    if data.get('signature'):
        highlights['Signature'] = 'danger'

    return _make_report("Malware Bazaar Hash Report", fields, highlights)


def _format_bazaar_list(data_list, title="Malware Bazaar Results"):
    """Format a list of Bazaar samples as a table."""
    if not data_list:
        return Text("No results found.", style="red")

    table = Table(title=title, show_header=True, expand=True, border_style="cyan")
    table.add_column("SHA256", style="cyan", width=20)
    table.add_column("File Name", ratio=1)
    table.add_column("Type", width=10)
    table.add_column("Size", width=10)
    table.add_column("Signature", style="red", width=20)
    table.add_column("Tags", ratio=1)
    table.add_column("First Seen", width=20)

    for d in data_list[:50]:
        sha = _safe_str(d.get('sha256_hash', ''))
        tags = d.get('tags', [])
        tag_str = ", ".join(tags) if isinstance(tags, list) else _safe_str(tags)

        table.add_row(
            Text(sha[:18] + ".." if len(sha) > 20 else sha),
            Text(_safe_str(d.get('file_name'))),
            Text(_safe_str(d.get('file_type'))),
            Text(_safe_str(d.get('file_size'))),
            Text(_safe_str(d.get('signature'))),
            Text(tag_str[:30] if len(tag_str) > 30 else tag_str),
            Text(_safe_str(d.get('first_seen'))),
        )

    return Panel(table, border_style="cyan", expand=True)


def _format_urlhaus_hash(data):
    if not data:
        return Text("No data returned from URLHaus.", style="red")

    status = data.get('query_status', '')
    if status != 'ok':
        if status == 'no_results':
            return Text("Hash not found in URLHaus.", style="yellow")
        return Text(f"Query status: {status}", style="red")

    fields = [
        ("MD5", data.get('md5_hash')),
        ("SHA256", data.get('sha256_hash')),
        ("File Type", data.get('file_type')),
        ("File Size", data.get('file_size')),
        ("First Seen", data.get('firstseen')),
        ("Last Seen", data.get('lastseen')),
        ("Signature", data.get('signature')),
        ("URLHaus Download", data.get('urlhaus_download')),
    ]

    urls = data.get('urls', [])
    if urls:
        for i, u in enumerate(urls[:5]):
            fields.append((f"URL #{i+1}", u.get('url')))
            fields.append(("  Status", u.get('url_status')))
            fields.append(("  Threat", u.get('threat')))

    vt = data.get('virustotal')
    if vt and isinstance(vt, dict):
        fields.append(("VT Result", f"{vt.get('result', 'N/A')} ({vt.get('percent', 'N/A')}%)"))

    highlights = {}
    if data.get('signature'):
        highlights['Signature'] = 'danger'

    return _make_report("URLHaus Hash Report", fields, highlights)


def _format_urlhaus_url(data):
    if not data:
        return Text("No data returned from URLHaus.", style="red")

    status = data.get('query_status', '')
    if status != 'ok':
        if status == 'no_results':
            return Text("URL not found in URLHaus.", style="yellow")
        return Text(f"Query status: {status}", style="red")

    fields = [
        ("ID", data.get('id')),
        ("URL", data.get('url')),
        ("URL Status", data.get('url_status')),
        ("Host", data.get('host')),
        ("Date Added", data.get('date_added')),
        ("Threat", data.get('threat')),
        ("Reporter", data.get('reporter')),
        ("URLHaus Link", data.get('urlhaus_reference')),
    ]

    bl = data.get('blacklists', {})
    if bl:
        for bname, bval in bl.items():
            fields.append((f"Blacklist: {bname}", bval))

    tags = data.get('tags')
    if tags and isinstance(tags, list):
        fields.append(("Tags", ", ".join(tags)))

    payloads = data.get('payloads', [])
    if payloads:
        for i, p in enumerate(payloads[:5]):
            fields.append((f"Payload #{i+1}", ""))
            fields.append(("  File Type", p.get('file_type')))
            fields.append(("  SHA256", p.get('response_sha256')))
            sig = p.get('signature')
            if sig:
                fields.append(("  Signature", sig))
            vt = p.get('virustotal')
            if vt and isinstance(vt, dict):
                fields.append(("  VT Result", f"{vt.get('result', '')} ({vt.get('percent', '')}%)"))

    highlights = {}
    url_status = _safe_str(data.get('url_status'))
    if url_status == 'online':
        highlights['URL Status'] = 'danger'
    threat = data.get('threat')
    if threat:
        highlights['Threat'] = 'danger'

    return _make_report("URLHaus URL Report", fields, highlights)


def _format_urlhaus_tag(data):
    if not data:
        return Text("No data returned from URLHaus.", style="red")

    status = data.get('query_status', '')
    if status != 'ok':
        if status == 'no_results':
            return Text("No URLs found for this tag.", style="yellow")
        return Text(f"Query status: {status}", style="red")

    fields = [
        ("First Seen", data.get('firstseen')),
        ("Last Seen", data.get('lastseen')),
        ("URL Count", data.get('url_count')),
    ]

    urls = data.get('urls', [])
    if urls:
        table = Table(title="URLs", show_header=True, expand=True, border_style="cyan")
        table.add_column("URL", ratio=2)
        table.add_column("Status", width=10)
        table.add_column("Threat", width=15)
        table.add_column("Date Added", width=20)
        table.add_column("Tags", ratio=1)

        for u in urls[:30]:
            url_str = _safe_str(u.get('url', ''))
            if len(url_str) > 60:
                url_str = url_str[:60] + "..."
            url_status = _safe_str(u.get('url_status'))
            status_text = Text(url_status, style="red" if url_status == "online" else "green")
            url_tags = u.get('tags') or []
            tag_str = ", ".join(url_tags) if isinstance(url_tags, list) else str(url_tags)

            table.add_row(
                url_str,
                status_text,
                _safe_str(u.get('threat')),
                _safe_str(u.get('dateadded')),
                tag_str,
            )

        header = _make_report("URLHaus Tag Report", fields)
        return Group(header, Panel(table, border_style="cyan", expand=True))

    return _make_report("URLHaus Tag Report", fields)


def _format_triage_search(data):
    """Format Triage search results with Rich tables."""
    if not data:
        return Text("No data returned from Triage.", style="red")
    if 'error' in data:
        return Text(data.get('message', data['error']), style="red")

    entries = data.get('data', [])
    if not entries:
        return Text("No results found.", style="yellow")

    table = Table(title="Triage Search Results", show_header=True,
                  expand=True, border_style="cyan")
    table.add_column("ID", style="cyan bold", width=28)
    table.add_column("Status", width=12)
    table.add_column("Kind", width=10)
    table.add_column("Filename", ratio=1)
    table.add_column("Submitted", width=22)
    table.add_column("Completed", width=22)

    for d in entries[:30]:
        table.add_row(
            _safe_str(d.get('id')),
            _safe_str(d.get('status')),
            _safe_str(d.get('kind')),
            _safe_str(d.get('filename')),
            _safe_str(d.get('submitted')),
            _safe_str(d.get('completed')),
        )

    panels = [Panel(table, border_style="cyan", expand=True)]

    if entries and entries[0].get('tasks'):
        task_table = Table(title="Tasks (first result)", show_header=True,
                          expand=True, border_style="cyan")
        task_table.add_column("Task ID", style="cyan", width=20)
        task_table.add_column("Status", width=12)
        task_table.add_column("Target", ratio=1)
        task_table.add_column("Pick", width=20)

        for t in entries[0]['tasks'][:10]:
            task_table.add_row(
                _safe_str(t.get('id')),
                _safe_str(t.get('status')),
                _safe_str(t.get('target')),
                _safe_str(t.get('pick')),
            )
        panels.append(Panel(task_table, border_style="cyan", expand=True))

    return Group(*panels)


def _format_triage_dynamic(data):
    """Format Triage dynamic analysis report with Rich panels."""
    if not data:
        return Text("No data returned from Triage.", style="red")
    if 'error' in data:
        return Text(data.get('message', data['error']), style="red")

    panels = []

    sample = data.get('sample', {})
    if sample:
        sample_fields = [
            ("ID", sample.get('id')),
            ("Target", sample.get('target')),
            ("Score", sample.get('score')),
            ("Submitted", sample.get('submitted')),
            ("Size", sample.get('size')),
            ("MD5", sample.get('md5')),
            ("SHA1", sample.get('sha1')),
            ("SHA256", sample.get('sha256')),
        ]
        static_tags = sample.get('static_tags', [])
        if static_tags:
            sample_fields.append(("Static Tags", ", ".join(static_tags)))

        highlights = {}
        score = sample.get('score')
        if score is not None:
            try:
                if int(score) >= 7:
                    highlights['Score'] = 'danger'
            except (ValueError, TypeError):
                pass
        panels.append(_make_report("Sample", sample_fields, highlights))

    analysis = data.get('analysis', {})
    if analysis:
        analysis_fields = [
            ("Score", analysis.get('score')),
            ("Reported", analysis.get('reported')),
            ("Platform", analysis.get('platform')),
            ("Resource", analysis.get('resource')),
            ("Max Time Network", analysis.get('max_time_network')),
            ("Max Time Kernel", analysis.get('max_time_kernel')),
        ]
        tags = analysis.get('tags', [])
        if tags:
            analysis_fields.append(("Tags", ", ".join(tags)))
        ttps = analysis.get('ttp', [])
        if ttps:
            analysis_fields.append(("TTPs", ", ".join(ttps)))
        features = analysis.get('features', [])
        if features:
            analysis_fields.append(("Features", ", ".join(features)))

        highlights = {}
        ascore = analysis.get('score')
        if ascore is not None:
            try:
                if int(ascore) >= 7:
                    highlights['Score'] = 'danger'
            except (ValueError, TypeError):
                pass
        panels.append(_make_report("Analysis", analysis_fields, highlights))

    processes = data.get('processes', [])
    if processes:
        proc_table = Table(title="Processes", show_header=True,
                          expand=True, border_style="cyan")
        proc_table.add_column("PID", width=8)
        proc_table.add_column("PPID", width=8)
        proc_table.add_column("Image", ratio=1)
        proc_table.add_column("Command", ratio=2)

        for p in processes[:15]:
            cmd = _safe_str(p.get('cmd', ''))
            if len(cmd) > 80:
                cmd = cmd[:80] + "..."
            proc_table.add_row(
                _safe_str(p.get('pid')),
                _safe_str(p.get('ppid')),
                _safe_str(p.get('image')),
                cmd,
            )
        panels.append(Panel(proc_table, border_style="cyan", expand=True))

    signatures = data.get('signatures', [])
    if signatures:
        sig_fields = []
        iocs = set()
        for s in signatures[:15]:
            name = s.get('name', '')
            score = s.get('score', '')
            sig_fields.append(("Signature", f"{name} (score: {score})"))
            indicators = s.get('indicators', [])
            for ind in indicators:
                ioc = ind.get('ioc', '')
                if ioc:
                    iocs.add(ioc)

        if iocs:
            sig_fields.append(("IOCs", "\n".join(list(iocs)[:20])))

        panels.append(_make_report("Signatures & IOCs", sig_fields,
                                   {f.replace(' ', ''): 'danger' for f, _ in sig_fields if f == 'Signature'}))

    network = data.get('network', {})
    if network:
        flows = network.get('flows', [])
        if flows:
            domains = set()
            for f in flows:
                d = f.get('domain', '')
                if d:
                    domains.add(d)
            if domains:
                net_fields = [("Network Domains", "\n".join(list(domains)[:20]))]
                panels.append(_make_report("Network", net_fields))

    return Group(*panels) if panels else Text("No dynamic analysis data.", style="yellow")


def _format_triage_summary(data):
    if not data:
        return Text("No data returned from Triage.", style="red")
    if 'error' in data:
        return Text(data.get('message', data['error']), style="red")

    sample = data.get('sample', {}) or {}
    analysis = data.get('analysis', {}) or {}
    tasks = data.get('tasks', {}) or {}
    targets = data.get('targets', []) or []

    fields = [
        ("ID", sample.get('id')),
        ("Target", sample.get('target')),
        ("Size", sample.get('size')),
        ("MD5", sample.get('md5')),
        ("SHA1", sample.get('sha1')),
        ("SHA256", sample.get('sha256')),
        ("Completed", sample.get('completed')),
        ("Score", analysis.get('score')),
    ]

    for task_name, task_data in list(tasks.items())[:5]:
        fields.append((f"Task: {task_name}", ""))
        fields.append(("  Kind", task_data.get('kind')))
        fields.append(("  Status", task_data.get('status')))
        fields.append(("  Score", task_data.get('score')))
        task_tags = task_data.get('tags', [])
        if task_tags:
            fields.append(("  Tags", ", ".join(task_tags)))

    for i, target in enumerate(targets[:5]):
        fields.append((f"Target #{i+1}", target.get('target')))
        fields.append(("  Score", target.get('score')))
        family = target.get('family', [])
        if family:
            fields.append(("  Family", ", ".join(family)))
        iocs = target.get('iocs', {})
        if iocs:
            for ioc_type in ('ips', 'domains', 'urls'):
                items = iocs.get(ioc_type, [])
                if items:
                    fields.append((f"  IOC {ioc_type.title()}", ", ".join(items[:8])))

    sigs = data.get('signatures', []) or []
    if sigs:
        sig_items = []
        for s in sigs[:10]:
            sig_items.append(f"{s.get('name', '')} (score: {s.get('score', '')})")
        fields.append(("Signatures", "\n".join(sig_items)))

    highlights = {}
    score = analysis.get('score')
    if score is not None:
        try:
            if int(score) >= 7:
                highlights['Score'] = 'danger'
        except (ValueError, TypeError):
            pass

    return _make_report("Triage Summary Report", fields, highlights)


def _format_shodan_ip(data):
    if 'error' in data:
        return Text(data['error'], style="red")

    ports = ', '.join(str(p) for p in data.get('ports', []))
    vulns = ', '.join(data.get('vulns', []))
    hostnames = ', '.join(data.get('hostnames', []))

    fields = [
        ("IP", data.get('ip_str')),
        ("Organization", data.get('org')),
        ("ISP", data.get('isp')),
        ("OS", data.get('os')),
        ("Ports", ports or "N/A"),
        ("Vulns", vulns or "None"),
        ("Hostnames", hostnames or "N/A"),
        ("City", data.get('city')),
        ("Country", data.get('country_name')),
        ("Last Update", data.get('last_update')),
    ]

    highlights = {}
    if vulns:
        highlights['Vulns'] = 'danger'

    return _make_report("Shodan IP Report", fields, highlights)


def _format_shodan_search(data):
    if 'error' in data:
        return Text(data['error'], style="red")

    matches = data.get('matches', [])
    if not matches:
        return Text("No results found.", style="yellow")

    table = Table(title="Shodan Search Results", show_header=True,
                  expand=True, border_style="cyan")
    table.add_column("IP", style="cyan bold", width=18)
    table.add_column("Port", width=8)
    table.add_column("Organization", ratio=1)
    table.add_column("Data Snippet", ratio=2)

    for match in matches[:30]:
        snippet = str(match.get('data', ''))[:80].replace('\n', ' ').replace('\r', '')
        table.add_row(
            _safe_str(match.get('ip_str')),
            _safe_str(match.get('port')),
            _safe_str(match.get('org')),
            snippet,
        )

    return Panel(table, border_style="cyan", expand=True)


def _format_abuseipdb(data):
    if 'error' in data:
        return Text(data['error'], style="red")

    report = data.get('data', {})
    abuse_score = _safe_str(report.get('abuseConfidenceScore'))

    fields = [
        ("IP", report.get('ipAddress')),
        ("Abuse Score", abuse_score),
        ("ISP", report.get('isp')),
        ("Usage Type", report.get('usageType')),
        ("Country", report.get('countryCode')),
        ("Domain", report.get('domain')),
        ("Total Reports", report.get('totalReports')),
        ("Distinct Users", report.get('numDistinctUsers')),
        ("Last Reported", report.get('lastReportedAt')),
    ]

    highlights = {}
    try:
        if int(report.get('abuseConfidenceScore', 0)) >= 50:
            highlights['Abuse Score'] = 'danger'
    except (ValueError, TypeError):
        pass
    try:
        if int(report.get('totalReports', 0)) > 0:
            highlights['Total Reports'] = 'danger'
    except (ValueError, TypeError):
        pass

    return _make_report("AbuseIPDB IP Report", fields, highlights)


def _format_ipinfo(data):
    if 'error' in data:
        msg = data['error']
        if isinstance(msg, dict):
            msg = msg.get('message', str(msg))
        return Text(str(msg), style="red")

    fields = [
        ("IP", data.get('ip')),
        ("Hostname", data.get('hostname')),
        ("Organization", data.get('org')),
        ("Country", data.get('country')),
        ("Region", data.get('region')),
        ("City", data.get('city')),
        ("Location", data.get('loc')),
        ("Postal", data.get('postal')),
        ("Timezone", data.get('timezone')),
    ]

    return _make_report("IPInfo Report", fields)


def _format_whois_domain(data):
    if not data:
        return Text("No WHOIS data available.", style="red")

    def _list_or_str(v):
        if isinstance(v, list):
            return ', '.join(str(x) for x in v)
        return _safe_str(v)

    fields = [
        ("Domain Name", _list_or_str(data.get('domain_name'))),
        ("Registrar", _safe_str(data.get('registrar'))),
        ("Creation Date", _list_or_str(data.get('creation_date'))),
        ("Expiration Date", _list_or_str(data.get('expiration_date'))),
        ("Updated Date", _list_or_str(data.get('updated_date'))),
        ("Name Servers", _list_or_str(data.get('name_servers'))),
        ("Status", _list_or_str(data.get('status'))),
        ("Emails", _list_or_str(data.get('emails'))),
        ("Organization", _safe_str(data.get('org'))),
        ("Country", _safe_str(data.get('country'))),
    ]

    highlights = {}
    highlights['Expiration Date'] = 'danger'

    return _make_report("WHOIS Domain Report", fields, highlights)


def _format_whois_ip(data):
    if not data:
        return Text("No WHOIS data available.", style="red")

    network = data.get('network', {}) or {}
    entities = data.get('entities', []) or []

    fields = [
        ("ASN", data.get('asn')),
        ("ASN Description", data.get('asn_description')),
        ("ASN Country Code", data.get('asn_country_code')),
        ("Network Name", network.get('name')),
        ("Network CIDR", network.get('cidr')),
        ("Entities", ', '.join(entities) if entities else 'N/A'),
    ]

    highlights = {'ASN': 'danger'}

    return _make_report("WHOIS IP Report", fields, highlights)



def _format_urlscanio_submit(data):
    if 'error' in data:
        return Text(data['error'], style="red")

    fields = [
        ("UUID", data.get('uuid')),
        ("Submitted URL", data.get('url')),
        ("Result Page", data.get('result')),
        ("API Result", data.get('api')),
        ("Visibility", data.get('visibility')),
    ]

    report = _make_report("URLScan.io Submission", fields)
    note = Text("\nResults take ~15 seconds. Use 'URLScan Result' with the UUID to retrieve.",
                style="bold yellow")
    return Group(report, note)


def _format_urlscanio_result(data):
    if 'error' in data:
        return Text(data['error'], style="red")

    task = data.get('task', {})
    page = data.get('page', {})
    stats = data.get('stats', {})
    lists = data.get('lists', {})
    verdicts = data.get('verdicts', {})

    overall = verdicts.get('overall', {})
    malicious = overall.get('malicious', False)
    score = overall.get('score', 0)
    categories = ', '.join(overall.get('categories', [])) or 'None'
    tags = ', '.join(overall.get('tags', [])) or 'None'

    ips_list = lists.get('ips', [])
    domains_list = lists.get('domains', [])
    countries_list = lists.get('countries', [])

    ips_str = ', '.join(ips_list[:10])
    if len(ips_list) > 10:
        ips_str += f' (+{len(ips_list) - 10} more)'
    domains_str = ', '.join(domains_list[:10])
    if len(domains_list) > 10:
        domains_str += f' (+{len(domains_list) - 10} more)'

    fields = [
        ("URL", task.get('url')),
        ("Domain", task.get('domain')),
        ("IP", page.get('ip')),
        ("Country", page.get('country')),
        ("ASN", page.get('asn')),
        ("ASN Name", page.get('asnname')),
        ("Server", page.get('server')),
        ("Status Code", page.get('status')),
        ("MIME Type", page.get('mimeType')),
        ("Page Title", str(page.get('title', 'N/A'))[:80]),
        ("Scan Time", task.get('time')),
        ("Visibility", task.get('visibility')),
        ("Unique IPs", stats.get('uniqIPs')),
        ("Total Links", stats.get('totalLinks')),
        ("Malicious", str(malicious)),
        ("Verdict Score", str(score)),
        ("Categories", categories),
        ("Tags", tags),
        ("Contacted IPs", ips_str or 'None'),
        ("Contacted Domains", domains_str or 'None'),
        ("Countries", ', '.join(countries_list) if countries_list else 'N/A'),
    ]

    highlights = {}
    if malicious:
        highlights['Malicious'] = 'danger'
        highlights['Verdict Score'] = 'danger'
    elif score and int(score) > 0:
        highlights['Verdict Score'] = 'danger'

    items = [_make_report("URLScan.io Scan Result", fields, highlights)]

    certs = lists.get('certificates', [])
    if certs:
        cert_table = Table(title="SSL Certificates", show_header=True,
                           expand=True, border_style="cyan")
        cert_table.add_column("Subject", ratio=2)
        cert_table.add_column("Issuer", ratio=2)
        cert_table.add_column("Valid From", width=12)
        cert_table.add_column("Valid To", width=12)
        for cert in certs[:5]:
            cert_table.add_row(
                _safe_str(cert.get('subjectName')),
                _safe_str(cert.get('issuer')),
                _safe_str(cert.get('validFrom')),
                _safe_str(cert.get('validTo')),
            )
        items.append(Panel(cert_table, border_style="cyan", expand=True))

    return Group(*items)


def _format_urlscanio_search(data):
    if 'error' in data:
        return Text(data['error'], style="red")

    results = data.get('results', [])
    if not results:
        return Text("No results found.", style="yellow")

    total = data.get('total', len(results))
    shown = min(len(results), 30)

    table = Table(
        title=f"URLScan.io Search Results ({shown} of {total})",
        show_header=True, expand=True, border_style="cyan",
    )
    table.add_column("Domain", style="cyan bold", ratio=2)
    table.add_column("IP", width=18)
    table.add_column("Country", width=9)
    table.add_column("Status", width=8)
    table.add_column("ASN", width=10)
    table.add_column("Score", width=7)
    table.add_column("Date", width=20)
    table.add_column("UUID", width=38)

    for result in results[:30]:
        task = result.get('task', {})
        page = result.get('page', {})
        overall = result.get('verdicts', {}).get('overall', {})
        v_score = str(overall.get('score', 0))
        mal = overall.get('malicious', False)

        score_style = "red bold" if mal or (v_score.isdigit() and int(v_score) > 0) else ""

        table.add_row(
            _safe_str(page.get('domain')),
            _safe_str(page.get('ip')),
            _safe_str(page.get('country')),
            _safe_str(page.get('status')),
            _safe_str(page.get('asn')),
            Text(v_score, style=score_style),
            str(task.get('time', 'N/A'))[:19],
            _safe_str(result.get('_id')),
        )

    return Panel(table, border_style="cyan", expand=True)


def _format_nist_cve(data):
    if not data:
        return Text("No CVE data found.", style="red")

    vulns = data.get('vulnerabilities', [])
    if not vulns:
        return Text(f"Total results: {data.get('totalResults', 0)} - No vulnerabilities returned.", style="yellow")

    table = Table(title=f"NIST CVE Results ({data.get('totalResults', '?')} total)",
                  show_header=True, expand=True, border_style="cyan")
    table.add_column("CVE ID", style="cyan bold", width=18)
    table.add_column("Score", width=8)
    table.add_column("Severity", width=12)
    table.add_column("Published", width=12)
    table.add_column("Description", ratio=2)

    for v in vulns[:30]:
        cve = v.get('cve', {})
        cve_id = cve.get('id', '')
        published = _safe_str(cve.get('published', ''))[:10]
        desc = ''
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break
        if len(desc) > 100:
            desc = desc[:100] + "..."

        score = ''
        severity = ''
        metrics = cve.get('metrics', {})
        for metric_key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss = metric_list[0].get('cvssData', {})
                score = str(cvss.get('baseScore', ''))
                severity = cvss.get('baseSeverity', '')
                break

        sev_text = Text(severity, style="red bold" if severity in ('CRITICAL', 'HIGH') else "yellow" if severity == 'MEDIUM' else "")

        table.add_row(Text(cve_id), Text(score), sev_text, Text(published), Text(desc))

    return Panel(table, border_style="cyan", expand=True)


def _format_vulncheck_kev(data):
    """Format VulnCheck KEV results."""
    if not data:
        return Text("No data returned from VulnCheck.", style="red")

    items = data.get('data', [])
    if not items:
        return Text("CVE not found in VulnCheck KEV.", style="yellow")

    table = Table(title="VulnCheck KEV Results", show_header=True,
                  expand=True, border_style="cyan")
    table.add_column("CVE ID", style="cyan bold", width=18)
    table.add_column("Vendor", width=15)
    table.add_column("Product", width=15)
    table.add_column("Vuln Name", ratio=1)
    table.add_column("Ransomware", width=12)
    table.add_column("Due Date", width=12)

    for item in items[:30]:
        cve_val = item.get('cveID', item.get('cve', ''))
        if isinstance(cve_val, list):
            cve_val = ', '.join(cve_val)
        cve = _safe_str(cve_val)
        vendor = _safe_str(item.get('vendorProject'))
        product = _safe_str(item.get('product'))
        vuln_name = _safe_str(item.get('vulnerabilityName', ''))
        if len(vuln_name) > 40:
            vuln_name = vuln_name[:40] + "..."
        ransomware = _safe_str(item.get('knownRansomwareCampaignUse', 'Unknown'))
        ransomware_text = Text(ransomware, style="red bold" if ransomware == "Known" else "")
        due = _safe_str(item.get('dueDate', ''))[:10]

        table.add_row(Text(cve), Text(vendor), Text(product), Text(vuln_name), ransomware_text, Text(due))

    return Panel(table, border_style="cyan", expand=True)


def _format_vulncheck_mitre(data):
    """Format VulnCheck MITRE CVE search results."""
    if not data:
        return Text("No data returned from VulnCheck.", style="red")

    items = data.get('data', [])
    if not items:
        return Text("CVE not found in MITRE CVE database.", style="yellow")

    vuln = items[0]
    cve_val = vuln.get('cve', '')
    if isinstance(cve_val, list):
        cve_val = ', '.join(cve_val)

    fields = [
        ("CVE ID", cve_val),
        ("Title", vuln.get('title')),
        ("Summary", vuln.get('summary')),
        ("URL", vuln.get('url')),
        ("Date Added", vuln.get('date_added')),
        ("Last Updated", vuln.get('updated_at')),
    ]

    refs = vuln.get('references', [])
    if refs and isinstance(refs, list):
        for i, ref in enumerate(refs[:5]):
            fields.append((f"Reference #{i+1}", str(ref)))

    return _make_report("VulnCheck MITRE CVE Report", fields)


def _format_vulncheck_nist(data):
    """Format VulnCheck NIST NVD2 search results."""
    if not data:
        return Text("No data returned from VulnCheck.", style="red")

    items = data.get('data', [])
    if not items:
        return Text("CVE not found in NIST NVD2 database.", style="yellow")

    vuln = items[0]

    fields = [
        ("CVE ID", vuln.get('id')),
        ("Status", vuln.get('vulnStatus')),
        ("Published", vuln.get('published')),
        ("Last Modified", vuln.get('lastModified')),
    ]

    descriptions = vuln.get('descriptions', [])
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get('lang') == 'en':
                fields.append(("Description", d.get('value')))
                break

    metrics = vuln.get('metrics', {})
    if isinstance(metrics, dict):
        for metric_key in ('cvssMetricV31', 'cvssMetricV30'):
            cvss_list = metrics.get(metric_key, [])
            if isinstance(cvss_list, list) and cvss_list:
                cvss = cvss_list[0]
                if isinstance(cvss, dict) and 'cvssData' in cvss:
                    cvss_data = cvss['cvssData']
                    if isinstance(cvss_data, dict):
                        score = cvss_data.get('baseScore', '')
                        severity = cvss_data.get('baseSeverity', '')
                        fields.append(("CVSS Score", f"{score} ({severity})"))
                        fields.append(("CVSS Vector", cvss_data.get('vectorString')))
                break

    if vuln.get('cisaExploitAdd'):
        fields.append(("CISA KEV Added", vuln.get('cisaExploitAdd')))
    if vuln.get('cisaActionDue'):
        fields.append(("CISA Action Due", vuln.get('cisaActionDue')))
    if vuln.get('cisaVulnerabilityName'):
        fields.append(("CISA Vuln Name", vuln.get('cisaVulnerabilityName')))
    if vuln.get('cisaRequiredAction'):
        fields.append(("CISA Action", vuln.get('cisaRequiredAction')))

    weaknesses = vuln.get('weaknesses', [])
    if isinstance(weaknesses, list):
        for w in weaknesses:
            if isinstance(w, dict) and 'description' in w:
                desc_list = w['description']
                if isinstance(desc_list, list) and desc_list:
                    for dl in desc_list:
                        if isinstance(dl, dict) and 'value' in dl:
                            fields.append(("CWE", dl['value']))
                            break
                    break

    refs = vuln.get('references', [])
    if isinstance(refs, list):
        for i, ref in enumerate(refs[:5]):
            if isinstance(ref, dict):
                fields.append((f"Reference #{i+1}", ref.get('url', str(ref))))
            else:
                fields.append((f"Reference #{i+1}", str(ref)))

    highlights = {}
    for name, val in fields:
        if name == 'CVSS Score' and val:
            try:
                s = float(str(val).split()[0])
                if s >= 7.0:
                    highlights['CVSS Score'] = 'danger'
            except (ValueError, IndexError):
                pass

    return _make_report("VulnCheck NIST NVD2 Report", fields, highlights)


def _format_correlate(results):
    """Format correlate results with proper Rich panels per service."""
    if not results:
        return Text("No correlation data available.", style="red")

    panels = []

    vt_data = results.get('VirusTotal')
    if vt_data:
        if isinstance(vt_data, dict) and 'error' in vt_data:
            panels.append(Panel(Text(str(vt_data['error']), style="red"),
                                title="[bold]VirusTotal[/bold]", border_style="red"))
        else:
            attrs = vt_data.get('data', {}).get('attributes', {})
            if attrs:
                stats = attrs.get('last_analysis_stats', {})
                classification = attrs.get('popular_threat_classification', {})
                vt_fields = [
                    ("Meaningful Name", attrs.get('meaningful_name')),
                    ("Type Description", attrs.get('type_description')),
                    ("Size", attrs.get('size')),
                    ("Times Submitted", attrs.get('times_submitted')),
                    ("SHA256", attrs.get('sha256')),
                    ("MD5", attrs.get('md5')),
                    ("Malicious", stats.get('malicious')),
                    ("Undetected", stats.get('undetected')),
                    ("Suspicious", stats.get('suspicious')),
                ]
                if classification:
                    vt_fields.append(("Threat Label", classification.get('suggested_threat_label')))

                highlights = {}
                if stats.get('malicious', 0) and int(stats.get('malicious', 0)) > 0:
                    highlights['Malicious'] = 'danger'
                    highlights['Threat Label'] = 'danger'
                if stats.get('suspicious', 0) and int(stats.get('suspicious', 0)) > 0:
                    highlights['Suspicious'] = 'danger'

                panels.append(_make_report("VirusTotal", vt_fields, highlights))

    bazaar_data = results.get('MalwareBazaar')
    if bazaar_data:
        if isinstance(bazaar_data, dict) and 'error' in bazaar_data:
            panels.append(Panel(Text(str(bazaar_data['error']), style="red"),
                                title="[bold]Malware Bazaar[/bold]", border_style="red"))
        elif isinstance(bazaar_data, dict):
            tags = bazaar_data.get('tags', [])
            tag_str = ", ".join(tags[:3]) if isinstance(tags, list) else ''
            bz_fields = [
                ("SHA256", bazaar_data.get('sha256_hash')),
                ("MD5", bazaar_data.get('md5_hash')),
                ("File Name", bazaar_data.get('file_name')),
                ("File Type", bazaar_data.get('file_type')),
                ("File Size", bazaar_data.get('file_size')),
                ("First Seen", bazaar_data.get('first_seen')),
                ("Signature", bazaar_data.get('signature')),
                ("Tags", tag_str),
            ]
            highlights = {}
            if bazaar_data.get('signature'):
                highlights['Signature'] = 'danger'
            panels.append(_make_report("Malware Bazaar", bz_fields, highlights))

    triage_data = results.get('Triage')
    if triage_data:
        if isinstance(triage_data, dict) and 'error' in triage_data:
            panels.append(Panel(Text(str(triage_data['error']), style="red"),
                                title="[bold]Triage[/bold]", border_style="red"))
        else:
            sample = triage_data.get('sample', {})
            targets = triage_data.get('targets', [])
            triage_fields = [
                ("Sample ID", sample.get('id')),
                ("Target", sample.get('target')),
                ("Size", sample.get('size')),
                ("MD5", sample.get('md5')),
                ("SHA256", sample.get('sha256')),
                ("Score", sample.get('score')),
                ("Status", sample.get('status')),
            ]
            signatures = []
            for target in targets:
                for sig in target.get('signatures', []):
                    name = sig.get('name', '')
                    if name and name not in signatures:
                        signatures.append(name)
            if signatures:
                triage_fields.append(("Signatures", "\n".join(signatures[:15])))

            highlights = {}
            score = sample.get('score')
            if score is not None:
                try:
                    if int(score) >= 7:
                        highlights['Score'] = 'danger'
                except (ValueError, TypeError):
                    pass
            if signatures:
                highlights['Signatures'] = 'danger'
            panels.append(_make_report("Triage", triage_fields, highlights))

    return Group(*panels) if panels else Text("No results.", style="red")


SCAN_COL_FILE = "File"
SCAN_COL_TYPE = "Type"
SCAN_COL_THREAT = "Threat Label"
SCAN_COL_MAL = "Malicious"

TRIAGE_COL_FILE = "File"
TRIAGE_COL_FILENAME = "Filename"
TRIAGE_COL_SCORE = "Score"
TRIAGE_COL_TAGS = "Tags"


def _format_scan_results(results, title="Scan Results"):
    """Format file scan results (folder scan, VT batch, Bazaar batch) as a table."""
    if not results:
        return Text("No files found or no results.", style="red")

    table = Table(title=title, show_header=True, expand=True, border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column(SCAN_COL_FILE, style="cyan", ratio=2)
    table.add_column(SCAN_COL_TYPE, width=20)
    table.add_column(SCAN_COL_THREAT, ratio=1)
    table.add_column(SCAN_COL_MAL, width=10)

    for i, r in enumerate(results, 1):
        status = r.get('status', 'unknown')
        details = r.get('details') or {}

        type_desc = _safe_str(details.get(SCAN_COL_TYPE), '')
        threat_label = _safe_str(details.get(SCAN_COL_THREAT), '')
        mal_count = _safe_str(details.get(SCAN_COL_MAL), '')

        if status == 'malicious':
            mal_text = Text(mal_count, style="red bold")
            label_text = Text(threat_label, style="red")
        elif status == 'clean':
            mal_text = Text(mal_count, style="green")
            label_text = Text(threat_label, style="green")
        elif status == 'not found':
            mal_text = Text("N/F", style="dim")
            label_text = Text("NOT FOUND", style="dim")
        else:
            mal_text = Text(mal_count, style="yellow")
            label_text = Text(threat_label)

        table.add_row(
            Text(str(i)),
            Text(r.get('filename', '')),
            Text(type_desc),
            label_text,
            mal_text,
        )

    return Panel(table, border_style="cyan", expand=True)


def _format_triage_scan_results(results, title="Triage Scan Results"):
    """Format Triage batch/dir scan results as a colored table."""
    if not results:
        return Text("No files found or no results.", style="red")

    table = Table(title=title, show_header=True, expand=True, border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column(TRIAGE_COL_FILE, style="cyan", ratio=2)
    table.add_column(TRIAGE_COL_FILENAME, ratio=1)
    table.add_column(TRIAGE_COL_SCORE, width=8)
    table.add_column(TRIAGE_COL_TAGS, ratio=1)

    for i, r in enumerate(results, 1):
        status = r.get('status', 'unknown')
        filename = r.get('filename', '')
        triage_name = r.get('triage_filename', '')
        score = r.get('score', '')
        tags = r.get('tags', '')

        if status == 'found':
            score_val = 0
            try:
                score_val = int(score) if score else 0
            except (ValueError, TypeError):
                pass
            if score_val >= 7:
                score_text = Text(str(score), style="red bold")
                tags_text = Text(tags, style="red")
            elif score_val >= 4:
                score_text = Text(str(score), style="yellow")
                tags_text = Text(tags, style="yellow")
            else:
                score_text = Text(str(score), style="green")
                tags_text = Text(tags, style="green")
        elif status == 'not found':
            score_text = Text("-", style="dim")
            tags_text = Text("NOT FOUND", style="dim")
        else:
            score_text = Text("-", style="yellow")
            tags_text = Text(status, style="yellow")

        table.add_row(str(i), filename, triage_name, score_text, tags_text)

    return Panel(table, border_style="cyan", expand=True)



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
        width: 26;
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
        ("f3", "copy_result", "F3 Copy"),
        ("f4", "pick_id", "F4 Pick ID"),
        ("escape", "focus_input", "Input"),
    ]

    def __init__(self, args):
        super().__init__()
        self.args = args
        self._modules = {}
        self._selected_service = "vt_hash"
        self._cancel = Event()
        self._last_result_text = ""
        self._enrich = False
        self._llm = None

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
                    yield Input(
                        placeholder="Enter sha256, sha1, or md5...",
                        id="query-input",
                    )
                    yield Button("Search", id="search-btn", variant="primary")
                    yield Button("Stop", id="stop-btn", variant="error")
                    yield Button("Enrich", id="enrich-btn", variant="default")
                yield Static("  VT Hash | Accepts: sha256, sha1, md5", id="hint")
                yield RichLog(id="results", highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        self._init_modules()
        results = self.query_one("#results", RichLog)
        results.write(Panel(
            "[bold cyan]Malwoverview TUI[/bold cyan]\n\n"
            "Select a service from the left panel,\n"
            "enter a query, and press Enter or click Search.\n\n"
            "[dim]Press Q to quit, Ctrl+L to clear, Stop to cancel.[/dim]",
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
        from malwoverview.modules.urlhaus import URLHausExtractor
        from malwoverview.modules.triage import TriageExtractor
        from malwoverview.modules.ipinfo import IPInfoExtractor
        from malwoverview.modules.shodan_mod import ShodanExtractor
        from malwoverview.modules.abuseipdb import AbuseIPDBExtractor
        from malwoverview.modules.whois_mod import WhoisExtractor
        from malwoverview.modules.nist import NISTExtractor
        from malwoverview.modules.vulncheck import VulnCheckExtractor
        from malwoverview.modules.multiplehash import MultipleHashExtractor
        from malwoverview.modules.urlscanio import URLScanIOExtractor

        self._modules = {
            'vt': VirusTotalExtractor(getoption('VIRUSTOTAL', 'VTAPI')),
            'bazaar': BazaarExtractor(getoption('BAZAAR', 'BAZAARAPI')),
            'urlhaus': URLHausExtractor(getoption('URLHAUS', 'URLHAUSAPI')),
            'triage': TriageExtractor(getoption('TRIAGE', 'TRIAGEAPI')),
            'ipinfo': IPInfoExtractor(getoption('IPINFO', 'IPINFOAPI')),
            'shodan': ShodanExtractor(getoption('SHODAN', 'SHODANAPI')),
            'abuseipdb': AbuseIPDBExtractor(getoption('ABUSEIPDB', 'ABUSEIPDBAPI')),
            'whois': WhoisExtractor(),
            'urlscanio': URLScanIOExtractor(getoption('URLSCANIO', 'URLSCANIOAPI')),
            'nist': NISTExtractor(),
            'vulncheck': VulnCheckExtractor(getoption('VULNCHECK', 'VULNCHECKAPI')),
        }

        self._modules['correlate'] = MultipleHashExtractor({
            "VirusTotal": self._modules['vt'],
            "MalwareBazaar": self._modules['bazaar'],
            "Triage": self._modules['triage'],
        })

        from malwoverview.utils.llm import LLMEnricher
        self._llm_config = {
            'claude_key': getoption('LLM', 'CLAUDE_API_KEY'),
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
            inp.placeholder = f"Enter {item.hints}..."

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
        query = self.query_one("#query-input", Input).value.strip()
        if not query:
            return

        svc = self._selected_service
        svc_name = next((name for k, name, _ in SERVICES if k == svc), svc)

        sanitizer = _SERVICE_SANITIZERS.get(svc)
        if sanitizer:
            sanitized, error = sanitizer(query)
            if error:
                results = self.query_one("#results", RichLog)
                results.clear()
                results.write(Text(f"Input error: {error}", style="bold red"))
                return
            query = sanitized

        self._cancel.clear()
        results = self.query_one("#results", RichLog)
        results.clear()
        results.write(
            Text(f"Querying {svc_name} for: {query} ...", style="bold yellow")
        )
        self._execute_query(svc, query)

    def action_quit(self):
        self._cancel.set()
        self.workers.cancel_all()
        self.exit()

    def _renderable_to_text(self, renderable):
        """Render a Rich renderable to plain text, stripping box-drawing frames."""
        buf = StringIO()
        console = Console(file=buf, width=200, no_color=True, highlight=False)
        console.print(renderable)
        raw = buf.getvalue()
        lines = []
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if any(c in '╭╮╰╯─┌┐└┘━╔╗╚╝' for c in stripped):
                title = stripped.strip('╭╮╰╯─┌┐└┘━╔╗╚╝│║ ')
                if title:
                    lines.append('[+] ' + title)
                continue
            clean = stripped.lstrip('│║ ').rstrip('│║ ')
            if clean:
                lines.append('[+] ' + clean)
        return '\n'.join(lines)

    @work(thread=True, exit_on_error=False)
    def _execute_query(self, service, query):
        results_log = self.query_one("#results", RichLog)

        try:
            renderable = self._dispatch_formatted(service, query)
            if self._cancel.is_set():
                return
            if renderable is not None:
                try:
                    self._last_result_text = self._renderable_to_text(renderable)
                except Exception:
                    self._last_result_text = ""
                self.call_from_thread(results_log.clear)
                self.call_from_thread(results_log.write, renderable)

                if self._enrich and self._llm and self._llm.is_configured() and self._last_result_text:
                    _cve_services = ('nist', 'vulncheck_kev', 'vulncheck_mitre', 'vulncheck_nist')
                    _ptype = 'cve' if service in _cve_services else 'threat'
                    _label = 'CVE Assessment' if _ptype == 'cve' else 'Threat Assessment'
                    self.call_from_thread(results_log.write, Text("\n Enriching with LLM...", style="bold cyan"))
                    try:
                        analysis = self._llm.enrich(self._last_result_text, _ptype)
                        if analysis:
                            enrich_panel = Panel(
                                Text(analysis),
                                title=f"[bold]LLM {_label}[/bold]",
                                border_style="green",
                                expand=True,
                            )
                            self.call_from_thread(results_log.write, enrich_panel)
                    except Exception as llm_err:
                        self.call_from_thread(results_log.write, Text(f"LLM error: {llm_err}", style="red"))
            else:
                self._last_result_text = ""
                self.call_from_thread(results_log.clear)
                self.call_from_thread(
                    results_log.write,
                    Text("No results or unsupported query type.", style="red"),
                )
        except Exception as e:
            if self._cancel.is_set():
                return
            self._last_result_text = ""
            self.call_from_thread(results_log.clear)
            self.call_from_thread(
                results_log.write,
                Text(f"Error: {e}", style="bold red"),
            )

    def _raw_vt_call(self, endpoint, timeout=60):
        """Make a raw VT API call and return parsed JSON."""
        from malwoverview.utils.session import create_session
        vt = self._modules['vt']
        session = create_session()
        session.headers.update({'x-apikey': vt.VTAPI, 'content-type': 'application/json'})
        response = session.get(endpoint, timeout=timeout)
        if response.status_code == 404:
            return None
        return response.json()

    def _raw_vc_call(self, index, params):
        """Make a raw VulnCheck API call."""
        from malwoverview.utils.session import create_session
        vc = self._modules['vulncheck']
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {vc.VULNCHECKAPI}'
        }
        session = create_session(headers)
        response = session.get(
            f'{vc.base_url}/index/{index}',
            params=params, timeout=30)
        return response.json()

    def _dispatch_formatted(self, service, query):
        mod = self._modules

        if service == 'vt_hash':
            data = mod['vt']._raw_hash_info(query)
            return _format_vt_hash(data) if data else None

        if service == 'vt_batch':
            return self._vt_batch_scan(query)

        if service == 'vt_ip':
            resp = mod['vt']._raw_ip_info(query)
            data = resp.json() if hasattr(resp, 'json') else resp
            return _format_vt_ip(data) if data else None

        if service == 'vt_domain':
            data = self._raw_vt_call(f'https://www.virustotal.com/api/v3/domains/{quote(query, safe="")}')
            return _format_vt_domain(data) if data else None

        if service == 'vt_url':
            urlid = base64.urlsafe_b64encode(query.encode()).decode().strip("=")
            data = self._raw_vt_call(f'https://www.virustotal.com/api/v3/urls/{urlid}')
            return _format_vt_url(data) if data else None

        if service == 'vt_behavior':
            data = self._raw_vt_call(
                f'https://www.virustotal.com/api/v3/files/{quote(query, safe="")}/behaviour_summary')
            if data is None:
                return Text("No behavior report found for this hash.", style="red")
            return _format_vt_behavior(data)

        if service == 'bazaar_hash':
            data = mod['bazaar']._raw_hash_info(query)
            return _format_bazaar_hash(data) if data else None

        if service == 'bazaar_tag':
            return self._bazaar_query({'query': 'get_taginfo', 'tag': query},
                                      "Malware Bazaar Tag Results")

        if service == 'bazaar_imphash':
            return self._bazaar_query({'query': 'get_imphash', 'imphash': query},
                                      "Malware Bazaar Imphash Results")

        if service == 'bazaar_latest':
            return self._bazaar_query({'query': 'get_recent', 'selector': query},
                                      "Malware Bazaar Latest Samples")

        if service == 'bazaar_batch':
            return self._bazaar_batch_scan(query)

        if service == 'bazaar_dir':
            return self._bazaar_dir_scan(query)

        if service == 'urlhaus_hash':
            return self._urlhaus_hash_query(query)

        if service == 'urlhaus_url':
            return self._urlhaus_url_query(query)

        if service == 'urlhaus_tag':
            return self._urlhaus_tag_query(query)

        if service == 'triage_search':
            return self._triage_search_query(query)

        if service == 'triage_summary':
            triage = mod['triage']
            try:
                from malwoverview.utils.session import create_session
                triage_url = triage.triageurl
                session = create_session()
                session.headers.update({
                    'accept': 'application/json',
                    'Authorization': 'Bearer ' + triage.TRIAGEAPI
                })
                resp = session.get(
                    triage_url + 'samples/' + quote(query, safe='') +
                    '/overview.json', timeout=60)
                data = resp.json()
                return _format_triage_summary(data)
            except Exception as e:
                return Text(f"Error: {e}", style="bold red")

        if service == 'triage_dynamic':
            return self._triage_dynamic_query(query)

        if service == 'triage_batch':
            return self._triage_batch_scan(query)

        if service == 'triage_dir':
            return self._triage_dir_scan(query)

        if service == 'shodan_ip':
            data = mod['shodan']._raw_ip_info(query)
            return _format_shodan_ip(data) if data else None

        if service == 'shodan_search':
            shodan = mod['shodan']
            try:
                from malwoverview.utils.session import create_session
                url = "https://api.shodan.io/shodan/host/search"
                session = create_session({'Accept': 'application/json'})
                response = session.get(url, params={'key': shodan.SHODANAPI, 'query': query}, timeout=30)
                data = response.json()
                return _format_shodan_search(data)
            except Exception as e:
                return Text(f"Error: {e}", style="bold red")

        if service == 'abuseipdb':
            data = mod['abuseipdb']._raw_ip_info(query)
            return _format_abuseipdb(data) if data else None

        if service == 'ipinfo':
            data = mod['ipinfo']._raw_ip_info(query)
            return _format_ipinfo(data) if data else None

        if service == 'whois_domain':
            try:
                import whois
                w = whois.whois(query)
                return _format_whois_domain(w)
            except ImportError:
                return Text("python-whois package not installed.", style="red")
            except Exception as e:
                return Text(f"WHOIS error: {e}", style="red")

        if service == 'whois_ip':
            try:
                from ipwhois import IPWhois
                obj = IPWhois(query)
                result = obj.lookup_rdap()
                return _format_whois_ip(result)
            except ImportError:
                return Text("ipwhois package not installed.", style="red")
            except Exception as e:
                return Text(f"WHOIS error: {e}", style="red")

        if service == 'urlscanio_submit':
            urlscanio = mod['urlscanio']
            try:
                from malwoverview.utils.session import create_session
                url = f"{urlscanio.urlbase}/scan/"
                headers = {
                    'API-Key': urlscanio.URLSCANIOAPI,
                    'Content-Type': 'application/json',
                }
                session = create_session(headers)
                response = session.post(url, json={'url': query, 'visibility': 'public'}, timeout=30)
                data = response.json()
                return _format_urlscanio_submit(data)
            except Exception as e:
                return Text(f"Error: {e}", style="bold red")

        if service == 'urlscanio_result':
            data = mod['urlscanio']._raw_result(query)
            return _format_urlscanio_result(data) if data else None

        if service == 'urlscanio_search':
            return self._urlscanio_search_query(query)

        if service == 'urlscanio_domain':
            return self._urlscanio_search_query(f"domain:{query}")

        if service == 'urlscanio_ip':
            return self._urlscanio_search_query(f"page.ip:{query}")

        if service == 'nist':
            nist = mod['nist']
            if query.upper().startswith('CVE-'):
                data = nist.query_cve(2, query, 10, 0, None)
            else:
                data = nist.query_cve(4, query, 30, 0, None)
            return _format_nist_cve(data) if data else None

        if service == 'vulncheck_kev':
            try:
                data = self._raw_vc_call('vulncheck-kev', {'cve': query})
                return _format_vulncheck_kev(data)
            except Exception as e:
                return Text(f"Error: {e}", style="bold red")

        if service == 'vulncheck_mitre':
            try:
                data = self._raw_vc_call('mitre-cvelist-v5', {'cve': query})
                return _format_vulncheck_mitre(data)
            except Exception as e:
                return Text(f"Error: {e}", style="bold red")

        if service == 'vulncheck_nist':
            try:
                data = self._raw_vc_call('nist-nvd2', {'cve': query})
                return _format_vulncheck_nist(data)
            except Exception as e:
                return Text(f"Error: {e}", style="bold red")

        if service == 'correlate':
            results = {}
            for name, extractor in mod['correlate'].extractors.items():
                if self._cancel.is_set():
                    return Text("Query cancelled.", style="yellow")
                try:
                    raw = extractor._raw_hash_info(query)
                    if raw:
                        results[name] = raw
                except Exception:
                    results[name] = {"error": "Query failed or timed out"}
            return _format_correlate(results) if results else None

        if service == 'folder_scan':
            return self._folder_scan(query)

        return None

    def _bazaar_query(self, params, title):
        """Make a raw Bazaar API query and return formatted results."""
        from malwoverview.utils.session import create_session
        bazaar = self._modules['bazaar']
        try:
            session = create_session()
            session.headers.update({
                'accept': 'application/json',
                'Auth-Key': bazaar.BAZAARAPI,
            })
            response = session.post('https://mb-api.abuse.ch/api/v1/',
                                    data=params, timeout=60)
            data = response.json()

            status = data.get('query_status', '')
            if status in ('unknown_selector', 'no_results', 'illegal_tag',
                          'no_tag_provided', 'illegal_imphash'):
                return Text(f"Query status: {status}", style="red")

            samples = data.get('data', [])
            if not samples:
                return Text("No results found.", style="yellow")

            return _format_bazaar_list(samples, title)

        except Exception as e:
            return Text(f"Error: {e}", style="bold red")

    def _urlhaus_hash_query(self, hash_value):
        """URLHaus hash lookup using the payload/ endpoint."""
        from malwoverview.utils.session import create_session
        try:
            session = create_session()
            session.headers.update({'accept': 'application/json'})
            urlhaus = self._modules['urlhaus']
            if urlhaus.URLHAUSAPI:
                session.headers.update({'Auth-Key': urlhaus.URLHAUSAPI})

            if len(hash_value) == 32:
                params = {'md5_hash': hash_value}
            else:
                params = {'sha256_hash': hash_value}

            response = session.post(
                'https://urlhaus-api.abuse.ch/v1/payload/',
                data=params, timeout=60)
            data = response.json()
            return _format_urlhaus_hash(data)
        except Exception as e:
            return Text(f"Error: {e}", style="bold red")

    def _urlhaus_url_query(self, url):
        """URLHaus URL lookup using the url/ endpoint."""
        from malwoverview.utils.session import create_session
        try:
            session = create_session()
            session.headers.update({'accept': 'application/json'})
            urlhaus = self._modules['urlhaus']
            if urlhaus.URLHAUSAPI:
                session.headers.update({'Auth-Key': urlhaus.URLHAUSAPI})

            response = session.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': url}, timeout=60)
            data = response.json()
            return _format_urlhaus_url(data)
        except Exception as e:
            return Text(f"Error: {e}", style="bold red")

    def _urlhaus_tag_query(self, tag):
        """URLHaus tag lookup using the tag/ endpoint."""
        from malwoverview.utils.session import create_session
        try:
            session = create_session()
            session.headers.update({'accept': 'application/json'})
            urlhaus = self._modules['urlhaus']
            if urlhaus.URLHAUSAPI:
                session.headers.update({'Auth-Key': urlhaus.URLHAUSAPI})

            response = session.post(
                'https://urlhaus-api.abuse.ch/v1/tag/',
                data={'tag': tag}, timeout=60)
            data = response.json()
            return _format_urlhaus_tag(data)
        except Exception as e:
            return Text(f"Error: {e}", style="bold red")

    def _urlscanio_search_query(self, query):
        """URLScan.io search with proper Rich formatting."""
        from malwoverview.utils.session import create_session
        urlscanio = self._modules['urlscanio']
        try:
            headers = {
                'API-Key': urlscanio.URLSCANIOAPI,
                'Accept': 'application/json',
            }
            session = create_session(headers)
            response = session.get(
                f"{urlscanio.urlbase}/search/",
                params={'q': query}, timeout=30)
            data = response.json()
            return _format_urlscanio_search(data)
        except Exception as e:
            return Text(f"Error: {e}", style="bold red")

    def _triage_search_query(self, query):
        """Triage search with proper Rich formatting."""
        from malwoverview.utils.session import create_session
        triage = self._modules['triage']
        try:
            triage_url = triage.triageurl
            session = create_session()
            session.headers.update({
                'accept': 'application/json',
                'Authorization': 'Bearer ' + triage.TRIAGEAPI
            })
            safe_query = quote(query, safe='')
            response = session.get(triage_url + 'search?query=' + safe_query, timeout=60)
            data = response.json()
            return _format_triage_search(data)
        except Exception as e:
            return Text(f"Error: {e}", style="bold red")

    def _triage_dynamic_query(self, sample_id):
        """Triage dynamic analysis with proper Rich formatting."""
        from malwoverview.utils.session import create_session
        triage = self._modules['triage']
        try:
            triage_url = triage.triageurl
            session = create_session()
            session.headers.update({
                'accept': 'application/json',
                'Authorization': 'Bearer ' + triage.TRIAGEAPI
            })
            safe_id = quote(sample_id, safe='')
            response = session.get(
                triage_url + 'samples/' + safe_id + '/behavioral1/report_triage.json',
                timeout=60)
            data = response.json()
            return _format_triage_dynamic(data)
        except Exception as e:
            return Text(f"Error: {e}", style="bold red")

    def _triage_lookup_hash(self, h, session, triage_url):
        """Query a single hash against Triage. Returns scan result dict."""
        try:
            safe_query = quote(h, safe='')
            response = session.get(triage_url + 'search?query=' + safe_query, timeout=60)
            search_data = response.json()

            triage_filename = ''
            score = ''
            tags = ''

            if not search_data.get('error') and search_data.get('data'):
                sample = search_data['data'][0]
                triage_filename = str(sample.get('filename', '')) if sample.get('filename') else ''

                sample_id = sample.get('id', '')
                if sample_id:
                    try:
                        summary_resp = session.get(
                            triage_url + 'samples/' + quote(sample_id, safe='') + '/overview.json',
                            timeout=60)
                        summary_data = summary_resp.json()
                        if 'error' not in summary_data:
                            sample_info = summary_data.get('sample', {})
                            score_val = sample_info.get('score')
                            if score_val is not None:
                                score = str(score_val)

                            families = []
                            for target in summary_data.get('targets', []):
                                for fam in target.get('family', []):
                                    if fam and fam not in families:
                                        families.append(fam)
                            if summary_data.get('analysis', {}).get('family', []):
                                for fam in summary_data['analysis']['family']:
                                    if fam and fam not in families:
                                        families.append(fam)
                            sample_tags = sample_info.get('tags', [])
                            if sample_tags:
                                for t in sample_tags:
                                    if t and t not in families:
                                        families.append(t)
                            if not families:
                                for target in summary_data.get('targets', []):
                                    for sig in target.get('signatures', []):
                                        sig_name = sig.get('name', '')
                                        if sig_name:
                                            short = sig_name.split(',')[0].split(':')[0].strip()
                                            if short and short not in families:
                                                families.append(short)
                                                break
                                    if families:
                                        break
                            tags = ', '.join(families[:5])
                    except Exception:
                        pass

                return {
                    'status': 'found',
                    'triage_filename': triage_filename[:20],
                    'score': score,
                    'tags': tags,
                }

            return {'status': 'not found', 'triage_filename': '', 'score': '', 'tags': ''}
        except Exception:
            return {'status': 'error', 'triage_filename': '', 'score': '', 'tags': ''}

    def _triage_batch_scan(self, filepath):
        """Read hashes from a file and query Triage for each one (multithreaded)."""
        from malwoverview.utils.session import create_session

        filepath = os.path.expanduser(filepath)
        if not os.path.isabs(filepath):
            filepath = os.path.abspath(filepath)

        if not os.path.isfile(filepath):
            return Text(f"Not a valid file: {filepath}", style="red")

        try:
            with open(filepath, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return Text(f"Error reading file: {e}", style="red")

        if not hashes:
            return Text("No hashes found in file.", style="yellow")

        triage = self._modules['triage']
        triage_url = triage.triageurl
        session = create_session()
        session.headers.update({
            'accept': 'application/json',
            'Authorization': 'Bearer ' + triage.TRIAGEAPI
        })

        results_log = self.query_one("#results", RichLog)
        results = [None] * len(hashes)
        done_count = [0]

        def _query(idx, h):
            if self._cancel.is_set():
                return idx, {'filename': h, 'status': 'cancelled',
                             'triage_filename': '', 'score': '', 'tags': ''}
            r = self._triage_lookup_hash(h, session, triage_url)
            r['filename'] = h
            done_count[0] += 1
            self.call_from_thread(
                results_log.write,
                Text(f"  [{done_count[0]}/{len(hashes)}] {h[:24]}...", style="dim"),
            )
            return idx, r

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(_query, i, h): i for i, h in enumerate(hashes)}
            for future in as_completed(futures):
                if self._cancel.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return Text("Scan cancelled.", style="yellow")
                idx, result = future.result()
                results[idx] = result

        return _format_triage_scan_results(results, "Triage Batch Hash Results")

    def _triage_dir_scan(self, folder_path):
        """Hash files in a directory and query Triage for each (multithreaded)."""
        from malwoverview.utils.hash import sha256hash
        from malwoverview.utils.session import create_session

        folder_path = os.path.expanduser(folder_path)
        if not os.path.isabs(folder_path):
            folder_path = os.path.abspath(folder_path)

        if not os.path.isdir(folder_path):
            return Text(f"Not a valid directory: {folder_path}", style="red")

        try:
            entries = os.listdir(folder_path)
        except PermissionError:
            return Text(f"Permission denied: {folder_path}", style="red")

        files = []
        for entry in sorted(entries):
            full_path = os.path.join(folder_path, entry)
            if os.path.isfile(full_path):
                files.append((entry, full_path))

        if not files:
            return Text("No files found in directory.", style="yellow")

        results_log = self.query_one("#results", RichLog)

        file_hashes = []
        for i, (filename, filepath) in enumerate(files):
            if self._cancel.is_set():
                return Text("Scan cancelled.", style="yellow")
            self.call_from_thread(
                results_log.write,
                Text(f"  [{i+1}/{len(files)}] Hashing {filename}...", style="dim"),
            )
            try:
                file_hash = sha256hash(filepath)
                file_hashes.append((filename, file_hash))
            except Exception:
                file_hashes.append((filename, None))

        triage = self._modules['triage']
        triage_url = triage.triageurl
        session = create_session()
        session.headers.update({
            'accept': 'application/json',
            'Authorization': 'Bearer ' + triage.TRIAGEAPI
        })

        results = [None] * len(file_hashes)
        done_count = [0]

        def _query(idx, filename, file_hash):
            if self._cancel.is_set():
                return idx, {'filename': filename, 'status': 'cancelled',
                             'triage_filename': '', 'score': '', 'tags': ''}
            if file_hash is None:
                return idx, {'filename': filename, 'status': 'error',
                             'triage_filename': '', 'score': '', 'tags': ''}
            r = self._triage_lookup_hash(file_hash, session, triage_url)
            r['filename'] = filename
            done_count[0] += 1
            self.call_from_thread(
                results_log.write,
                Text(f"  [{done_count[0]}/{len(file_hashes)}] Queried {filename}", style="dim"),
            )
            return idx, r

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(_query, i, fn, fh): i
                       for i, (fn, fh) in enumerate(file_hashes)}
            for future in as_completed(futures):
                if self._cancel.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return Text("Scan cancelled.", style="yellow")
                idx, result = future.result()
                results[idx] = result

        return _format_triage_scan_results(results, "Triage Directory Scan Results")

    def _vt_lookup_hash(self, h):
        """Query a single hash against VT. Returns scan result dict."""
        vt = self._modules.get('vt')
        status = 'not found'
        details = None
        if vt and vt.VTAPI:
            try:
                raw = vt._raw_hash_info(h)
                if raw:
                    attrs = raw.get('data', {}).get('attributes', {})
                    stats = attrs.get('last_analysis_stats', {})
                    mal = stats.get('malicious', 0)
                    threat = attrs.get('popular_threat_classification', {})
                    label = threat.get('suggested_threat_label', '')

                    details = {
                        SCAN_COL_TYPE: attrs.get('type_description', ''),
                        SCAN_COL_MAL: mal,
                        SCAN_COL_THREAT: label,
                    }
                    status = 'malicious' if mal and int(mal) > 0 else 'clean'
            except Exception:
                status = 'error'
        return {'filename': h, 'status': status, 'details': details}

    def _vt_batch_scan(self, filepath):
        """Read hashes from a file and query VT for each one (multithreaded)."""
        filepath = os.path.expanduser(filepath)
        if not os.path.isabs(filepath):
            filepath = os.path.abspath(filepath)

        if not os.path.isfile(filepath):
            return Text(f"Not a valid file: {filepath}", style="red")

        try:
            with open(filepath, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return Text(f"Error reading file: {e}", style="red")

        if not hashes:
            return Text("No hashes found in file.", style="yellow")

        results_log = self.query_one("#results", RichLog)
        results = [None] * len(hashes)
        done_count = [0]

        def _query(idx, h):
            if self._cancel.is_set():
                return idx, {'filename': h, 'status': 'cancelled', 'details': None}
            r = self._vt_lookup_hash(h)
            done_count[0] += 1
            self.call_from_thread(
                results_log.write,
                Text(f"  [{done_count[0]}/{len(hashes)}] {h[:24]}...", style="dim"),
            )
            return idx, r

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(_query, i, h): i for i, h in enumerate(hashes)}
            for future in as_completed(futures):
                if self._cancel.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return Text("Scan cancelled.", style="yellow")
                idx, result = future.result()
                results[idx] = result

        return _format_scan_results(results, "VT Batch Hash Results")

    def _bazaar_lookup_hash(self, h, session, api_key):
        """Query a single hash against Bazaar API. Used by batch/dir scans."""
        status = 'not found'
        details = None
        try:
            response = session.post('https://mb-api.abuse.ch/api/v1/',
                                    data={'query': 'get_info', 'hash': h}, timeout=60)
            data = response.json()
            if data.get('query_status') == 'ok' and data.get('data'):
                sample = data['data'][0]
                sig = sample.get('signature', '')
                tags = sample.get('tags', [])
                tag_str = ', '.join(tags[:3]) if isinstance(tags, list) else ''

                details = {
                    SCAN_COL_TYPE: sample.get('file_type', ''),
                    SCAN_COL_MAL: sig or '',
                    SCAN_COL_THREAT: tag_str,
                }
                status = 'malicious' if sig else 'clean'
        except Exception:
            status = 'error'
        return {'filename': h, 'status': status, 'details': details}

    def _bazaar_batch_scan(self, filepath):
        """Read hashes from a file and query Bazaar for each one (multithreaded)."""
        from malwoverview.utils.session import create_session
        filepath = os.path.expanduser(filepath)
        if not os.path.isabs(filepath):
            filepath = os.path.abspath(filepath)

        if not os.path.isfile(filepath):
            return Text(f"Not a valid file: {filepath}", style="red")

        try:
            with open(filepath, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return Text(f"Error reading file: {e}", style="red")

        if not hashes:
            return Text("No hashes found in file.", style="yellow")

        results_log = self.query_one("#results", RichLog)
        bazaar = self._modules['bazaar']

        session = create_session()
        session.headers.update({
            'accept': 'application/json',
            'Auth-Key': bazaar.BAZAARAPI,
        })

        results = [None] * len(hashes)
        done_count = [0]

        def _query(idx, h):
            if self._cancel.is_set():
                return idx, {'filename': h, 'status': 'cancelled', 'details': None}
            r = self._bazaar_lookup_hash(h, session, bazaar.BAZAARAPI)
            done_count[0] += 1
            self.call_from_thread(
                results_log.write,
                Text(f"  [{done_count[0]}/{len(hashes)}] {h[:24]}...", style="dim"),
            )
            return idx, r

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(_query, i, h): i for i, h in enumerate(hashes)}
            for future in as_completed(futures):
                if self._cancel.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return Text("Scan cancelled.", style="yellow")
                idx, result = future.result()
                results[idx] = result

        return _format_scan_results(results, "Bazaar Batch Hash Results")

    def _bazaar_dir_scan(self, folder_path):
        """Hash files in a directory and query Bazaar for each (multithreaded)."""
        from malwoverview.utils.hash import sha256hash
        from malwoverview.utils.session import create_session

        folder_path = os.path.expanduser(folder_path)
        if not os.path.isabs(folder_path):
            folder_path = os.path.abspath(folder_path)

        if not os.path.isdir(folder_path):
            return Text(f"Not a valid directory: {folder_path}", style="red")

        try:
            entries = os.listdir(folder_path)
        except PermissionError:
            return Text(f"Permission denied: {folder_path}", style="red")

        files = []
        for entry in sorted(entries):
            full_path = os.path.join(folder_path, entry)
            if os.path.isfile(full_path):
                files.append((entry, full_path))

        if not files:
            return Text("No files found in directory.", style="yellow")

        results_log = self.query_one("#results", RichLog)
        bazaar = self._modules['bazaar']

        file_hashes = []
        for i, (filename, filepath) in enumerate(files):
            if self._cancel.is_set():
                return Text("Scan cancelled.", style="yellow")
            self.call_from_thread(
                results_log.write,
                Text(f"  [{i+1}/{len(files)}] Hashing {filename}...", style="dim"),
            )
            try:
                file_hash = sha256hash(filepath)
                file_hashes.append((filename, file_hash))
            except Exception:
                file_hashes.append((filename, None))

        session = create_session()
        session.headers.update({
            'accept': 'application/json',
            'Auth-Key': bazaar.BAZAARAPI,
        })

        results = [None] * len(file_hashes)
        done_count = [0]

        def _query(idx, filename, file_hash):
            if self._cancel.is_set():
                return idx, {'filename': filename, 'status': 'cancelled', 'details': None}
            if file_hash is None:
                return idx, {'filename': filename, 'status': 'error', 'details': None}
            r = self._bazaar_lookup_hash(file_hash, session, bazaar.BAZAARAPI)
            r['filename'] = filename
            done_count[0] += 1
            self.call_from_thread(
                results_log.write,
                Text(f"  [{done_count[0]}/{len(file_hashes)}] Queried {filename}", style="dim"),
            )
            return idx, r

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(_query, i, fn, fh): i
                       for i, (fn, fh) in enumerate(file_hashes)}
            for future in as_completed(futures):
                if self._cancel.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return Text("Scan cancelled.", style="yellow")
                idx, result = future.result()
                results[idx] = result

        return _format_scan_results(results, "Bazaar Directory Scan Results")

    def _folder_scan(self, folder_path):
        from malwoverview.utils.hash import sha256hash

        folder_path = os.path.expanduser(folder_path)
        if not os.path.isabs(folder_path):
            folder_path = os.path.abspath(folder_path)

        if not os.path.isdir(folder_path):
            return Text(f"Not a valid directory: {folder_path}", style="red")

        try:
            entries = os.listdir(folder_path)
        except PermissionError:
            return Text(f"Permission denied: {folder_path}", style="red")

        files = []
        for entry in sorted(entries):
            full_path = os.path.join(folder_path, entry)
            if os.path.isfile(full_path):
                files.append((entry, full_path))

        if not files:
            return Text("No files found in directory.", style="yellow")

        results_log = self.query_one("#results", RichLog)
        vt = self._modules.get('vt')
        results = []

        for i, (filename, filepath) in enumerate(files):
            if self._cancel.is_set():
                return Text("Scan cancelled.", style="yellow")

            self.call_from_thread(
                results_log.write,
                Text(f"  [{i+1}/{len(files)}] Hashing {filename}...", style="dim"),
            )

            try:
                file_hash = sha256hash(filepath)
            except Exception as e:
                results.append({
                    'filename': filename, 'sha256': f'error: {e}',
                    'status': 'error', 'details': None,
                })
                continue

            status = 'not found'
            details = None

            if vt and vt.VTAPI:
                try:
                    raw = vt._raw_hash_info(file_hash)
                    if raw:
                        attrs = raw.get('data', {}).get('attributes', {})
                        stats = attrs.get('last_analysis_stats', {})
                        mal = stats.get('malicious', 0)
                        threat = attrs.get('popular_threat_classification', {})
                        label = threat.get('suggested_threat_label', '')

                        details = {
                            SCAN_COL_TYPE: attrs.get('type_description', ''),
                            SCAN_COL_MAL: mal,
                            SCAN_COL_THREAT: label,
                        }

                        status = 'malicious' if mal and int(mal) > 0 else 'clean'
                except Exception:
                    status = 'error'

            results.append({
                'filename': filename, 'sha256': file_hash,
                'status': status, 'details': details,
            })

        return _format_scan_results(results, "Folder Scan Results")

    def action_clear_results(self):
        self.query_one("#results", RichLog).clear()

    def action_focus_input(self):
        self.query_one("#query-input").focus()

    def action_copy_result(self):
        """Copy the last result text to the system clipboard."""
        results_log = self.query_one("#results", RichLog)
        if not self._last_result_text:
            results_log.write(
                Text("Nothing to copy — no results yet.", style="yellow")
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
        """Extract IDs (UUIDs, hashes, Triage IDs) from the last result text."""
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
        """Extract IDs from last result and let user pick one to fill the input."""
        results_log = self.query_one("#results", RichLog)
        inp = self.query_one("#query-input", Input)

        if hasattr(self, '_pick_ids') and self._pick_ids and inp.value.strip().isdigit():
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
                    Text("No result text captured — try running a query first.", style="yellow")
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
                Text(f"Single ID found — filled input and copied to clipboard: {ids[0][1]}", style="bold green")
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
