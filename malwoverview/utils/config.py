from malwoverview.utils.colors import mycolors


SERVICE_MAP = {
    'virustotal': ('VIRUSTOTAL', 'VTAPI'),
    'hybrid': ('HYBRID-ANALYSIS', 'HAAPI'),
    'malshare': ('MALSHARE', 'MALSHAREAPI'),
    'urlhaus': ('URLHAUS', 'URLHAUSAPI'),
    'polyswarm': ('POLYSWARM', 'POLYAPI'),
    'alienvault': ('ALIENVAULT', 'ALIENAPI'),
    'malpedia': ('MALPEDIA', 'MALPEDIAAPI'),
    'triage': ('TRIAGE', 'TRIAGEAPI'),
    'ipinfo': ('IPINFO', 'IPINFOAPI'),
    'bazaar': ('BAZAAR', 'BAZAARAPI'),
    'threatfox': ('THREATFOX', 'THREATFOXAPI'),
    'vulncheck': ('VULNCHECK', 'VULNCHECKAPI'),
    'shodan': ('SHODAN', 'SHODANAPI'),
    'abuseipdb': ('ABUSEIPDB', 'ABUSEIPDBAPI'),
    'greynoise': ('GREYNOISE', 'GREYNOISEAPI'),
    'urlscanio': ('URLSCANIO', 'URLSCANIOAPI'),
}


def validate_config(operation, config_dict):
    if operation in SERVICE_MAP:
        section, key = SERVICE_MAP[operation]
        if section in config_dict and config_dict[section].get(key):
            return True
        print(
            f"{mycolors.foreground.yellow}"
            f"Warning: API key for {operation} is not configured in .malwapi.conf"
            f"{mycolors.reset}"
        )
        return False
    return True
