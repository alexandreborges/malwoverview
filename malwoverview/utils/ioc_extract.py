import re
import os
import ipaddress
from urllib.parse import urlparse
import socket

from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv
from malwoverview.utils.output import collector, is_text_output
from malwoverview.utils.session import create_session


class IOCExtractor:
    def __init__(self):
        self.patterns = {
            'ipv4': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            ),
            'ipv6': re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
                r'|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
                r'|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
            ),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'urls': re.compile(
                r'(?:https?|hxxps?|ftp)://[^\s<>\"\']+'
            ),
            'domains': re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
                r'+(?:[a-zA-Z]{2,})\b'
            ),
            'emails': re.compile(
                r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            ),
            'cves': re.compile(r'CVE-\d{4}-\d{4,}'),
        }

    def refang(self, text):
        text = text.replace('hxxp', 'http')
        text = text.replace('hxxps', 'https')
        text = text.replace('[.]', '.')
        text = text.replace('[:]', ':')
        return text

    def extract_from_text(self, text):
        text = self.refang(text)
        results = {}
        for name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            results[name] = list(set(matches))
        return results

    @staticmethod
    def is_url(value):
        return bool(re.match(r'^https?://', value, re.IGNORECASE))

    @staticmethod
    def _validate_url_target(url):
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, "Only http/https URLs are allowed."
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL: no hostname."
        try:
            resolved = socket.getaddrinfo(hostname, None)
            for _, _, _, _, addr in resolved:
                ip = ipaddress.ip_address(addr[0])
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    return False, f"URL resolves to private/reserved address ({addr[0]}). Blocked for security."
        except (socket.gaierror, ValueError):
            pass
        return True, ""

    def extract_from_url(self, url):
        MAX_SIZE = 10 * 1024 * 1024

        safe, reason = self._validate_url_target(url)
        if not safe:
            print(
                mycolors.foreground.error(cv.bkg)
                + reason
                + mycolors.reset
            )
            return {}

        try:
            session = create_session()
            response = session.get(url, timeout=30, stream=True)
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '')
            content_length = response.headers.get('Content-Length', '')
            if content_length and int(content_length) > MAX_SIZE:
                print(
                    mycolors.foreground.error(cv.bkg)
                    + f"URL content too large ({content_length} bytes, max {MAX_SIZE})."
                    + mycolors.reset
                )
                return {}

            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                total += len(chunk)
                if total > MAX_SIZE:
                    print(
                        mycolors.foreground.error(cv.bkg)
                        + f"URL content exceeded {MAX_SIZE} bytes limit. Truncated."
                        + mycolors.reset
                    )
                    break
                chunks.append(chunk)

            raw = b''.join(chunks)

            if 'application/pdf' in content_type or url.lower().endswith('.pdf'):
                try:
                    from PyPDF2 import PdfReader
                    import io
                    reader = PdfReader(io.BytesIO(raw))
                    text = ''
                    for page in reader.pages:
                        page_text = page.extract_text()
                        if page_text:
                            text += page_text + '\n'
                    return self.extract_from_text(text)
                except ImportError:
                    print(
                        mycolors.foreground.error(cv.bkg)
                        + "PDF extraction requires PyPDF2: pip install malwoverview[pdf]"
                        + mycolors.reset
                    )
                    return {}

            text = raw.decode('utf-8', errors='ignore')
            return self.extract_from_text(text)

        except Exception as e:
            print(
                mycolors.foreground.error(cv.bkg)
                + f"Error fetching URL: {str(e)}"
                + mycolors.reset
            )
            return {}

    def extract_from_file(self, filepath):
        ext = os.path.splitext(filepath)[1].lower()

        if ext == '.eml':
            import email
            from email import policy
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                msg = email.message_from_file(f, policy=policy.default)
            text = msg.get_body(preferencelist=('plain', 'html'))
            if text:
                text = text.get_content()
            else:
                text = str(msg)
            return self.extract_from_text(text)

        if ext == '.pdf':
            try:
                from PyPDF2 import PdfReader
            except ImportError:
                print(
                    mycolors.foreground.error(cv.bkg)
                    + "PDF extraction requires PyPDF2: pip install malwoverview[pdf]"
                    + mycolors.reset
                )
                return {}
            reader = PdfReader(filepath)
            text = ''
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + '\n'
            return self.extract_from_text(text)

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
        return self.extract_from_text(text)

    def extract_and_display(self, source):
        if self.is_url(source):
            results = self.extract_from_url(source)
            label = source
        else:
            results = self.extract_from_file(source)
            label = source
        if not results:
            return

        total_iocs = sum(len(v) for v in results.values())

        if is_text_output():
            print()
            print((mycolors.reset + "IOC EXTRACTION REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            COLSIZE = 20
            print(
                mycolors.foreground.info(cv.bkg)
                + "Source:".ljust(COLSIZE) + "\t"
                + mycolors.reset + label
            )
            print(
                mycolors.foreground.info(cv.bkg)
                + "Total IOCs:".ljust(COLSIZE) + "\t"
                + mycolors.reset + str(total_iocs)
            )
            print()

            for ioc_type, values in results.items():
                if not values:
                    continue
                print(
                    mycolors.foreground.info(cv.bkg)
                    + f"{ioc_type.upper()} ({len(values)}):"
                    + mycolors.reset
                )
                for val in sorted(values):
                    print("  " + val)
                print()

        collector.add({
            'source': label,
            'iocs': results,
        })
        printr()
