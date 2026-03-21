import json
import os
import time
import requests
from pathlib import Path

from malwoverview.utils.colors import mycolors
import malwoverview.modules.configvars as cv
from malwoverview.utils.output import collector, is_text_output


ATTACK_URL = (
    'https://raw.githubusercontent.com/mitre/cti/master/'
    'enterprise-attack/enterprise-attack.json'
)
CACHE_FILE = os.path.join(str(Path.home()), '.malwoverview_attack.json')
CACHE_MAX_AGE = 7 * 24 * 3600  # 7 days


class AttackMapper:
    def __init__(self):
        self.techniques = {}
        if os.path.exists(CACHE_FILE):
            age = time.time() - os.path.getmtime(CACHE_FILE)
            if age < CACHE_MAX_AGE:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._load_techniques(data)
                return
        try:
            resp = requests.get(ATTACK_URL, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            self._load_techniques(data)
        except Exception as e:
            print(
                f"{mycolors.foreground.red}"
                f"Error downloading ATT&CK matrix: {e}"
                f"{mycolors.reset}"
            )

    def _load_techniques(self, data):
        for obj in data.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            ext_refs = obj.get('external_references', [])
            if not ext_refs:
                continue
            technique_id = ext_refs[0].get('external_id', '')
            url = ext_refs[0].get('url', '')
            kill_chain = []
            for phase in obj.get('kill_chain_phases', []):
                kill_chain.append(phase.get('phase_name', ''))
            self.techniques[technique_id] = {
                'name': obj.get('name', ''),
                'description': obj.get('description', ''),
                'kill_chain_phases': kill_chain,
                'url': url,
            }

    def map_tags(self, tags):
        matched = []
        for tag in tags:
            tag_lower = tag.lower()
            for tid, info in self.techniques.items():
                if (tag_lower in tid.lower() or
                        tag_lower in info['name'].lower()):
                    matched.append({'id': tid, **info})
        return matched

    def format_techniques(self, techniques):
        if is_text_output():
            for tech in techniques:
                tactics = ', '.join(tech.get('kill_chain_phases', []))
                if cv.bkg == 1:
                    print(
                        f"{mycolors.foreground.lightcyan}"
                        f"{tech['id']:<15}"
                        f"{mycolors.foreground.yellow}"
                        f"{tech['name']:<40}"
                        f"{mycolors.foreground.lightgreen}"
                        f"{tactics}"
                        f"{mycolors.reset}"
                    )
                else:
                    print(
                        f"{mycolors.foreground.cyan}"
                        f"{tech['id']:<15}"
                        f"{mycolors.foreground.blue}"
                        f"{tech['name']:<40}"
                        f"{mycolors.foreground.green}"
                        f"{tactics}"
                        f"{mycolors.reset}"
                    )
        for tech in techniques:
            collector.add({
                'technique_id': tech['id'],
                'name': tech['name'],
                'tactics': tech.get('kill_chain_phases', []),
                'url': tech.get('url', ''),
            })
