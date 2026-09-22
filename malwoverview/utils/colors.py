import re
import unicodedata
import malwoverview.modules.configvars as cv

_TERM_SEQ_RE = re.compile(
    r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?'
    r'|\x1b[PX^_][^\x1b]*(?:\x1b\\)?'
    r'|\x1b\[[0-?]*[ -/]*[@-~]?'
)
_TERM_CTRL_RE = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')


def strip_terminal_escapes(text):
    if not text:
        return text
    text = _TERM_SEQ_RE.sub('', text)
    return _TERM_CTRL_RE.sub('', text)


def strip_json_escapes(obj):
    if isinstance(obj, str):
        return strip_terminal_escapes(obj)
    if isinstance(obj, dict):
        return {strip_json_escapes(k): strip_json_escapes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [strip_json_escapes(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(strip_json_escapes(v) for v in obj)
    return obj


class mycolors:
    reset = '\033[0m'
    reverse = '\033[07m'
    bold = '\033[01m'

    class foreground:
        orange = '\033[33m'
        blue = '\033[34m'
        purple = '\033[35m'
        lightgreen = '\033[92m'
        lightblue = '\033[94m'
        pink = '\033[95m'
        lightcyan = '\033[96m'
        red = '\033[31m'
        green = '\033[32m'
        cyan = '\033[36m'
        lightgrey = '\033[37m'
        darkgrey = '\033[90m'
        nearwhite = '\033[97m'
        lightred = '\033[91m'
        yellow = '\033[93m'

        @staticmethod
        def error(bkg):
            if bkg == 1:
                return mycolors.foreground.lightred
            else:
                return mycolors.foreground.red

        @staticmethod
        def info(bkg):
            if bkg == 1:
                return mycolors.foreground.lightcyan
            else:
                return mycolors.foreground.blue
        
        @staticmethod
        def success(bkg):
            if bkg == 1:
                return mycolors.foreground.yellow
            else:
                return mycolors.foreground.blue

        @staticmethod
        def accent(bkg):
            if bkg == 1:
                return mycolors.foreground.pink
            else:
                return mycolors.foreground.purple

        @staticmethod
        def ok(bkg):
            if bkg == 1:
                return mycolors.foreground.lightgreen
            else:
                return mycolors.foreground.green

        @staticmethod
        def warning(bkg):
            return mycolors.foreground.orange

        @staticmethod
        def neutral(bkg):
            if bkg == 1:
                return mycolors.foreground.nearwhite
            else:
                return mycolors.foreground.darkgrey

    class background:
        black = '\033[40m'
        blue = '\033[44m'
        cyan = '\033[46m'
        lightgrey = '\033[47m'
        purple = '\033[45m'
        green = '\033[42m'
        orange = '\033[43m'
        red = '\033[41m'


def printc(text, color, *args, **kwargs):
    print(f'{color}{text}{mycolors.reset}', *args, **kwargs)


def printr():
    print(mycolors.reset)


_WIDE_EAW = ('W', 'F')


def char_width(char):
    if unicodedata.combining(char):
        return 0
    if unicodedata.east_asian_width(char) in _WIDE_EAW:
        return 2
    return 1


def display_width(text):
    return sum(char_width(char) for char in str(text))


def pad(text, width):
    text = str(text)
    return text + ' ' * max(0, width - display_width(text))


def fit(text, width, marker='...'):
    text = str(text)
    if display_width(text) <= width:
        return text
    if width <= len(marker):
        marker = ''
    budget = width - len(marker)
    kept = []
    used = 0
    for char in text:
        size = char_width(char)
        if used + size > budget:
            break
        kept.append(char)
        used = used + size
    return ''.join(kept) + marker


def column(header, values, cap=None, gutter=2):
    width = max([display_width(header)] + [display_width(v) for v in values])
    if cap is not None:
        width = min(width, cap)
    return width + gutter


def split_cells(word, width):
    chunks = []
    current = ''
    used = 0
    for char in str(word):
        size = char_width(char)
        if used + size > width and current:
            chunks.append(current)
            current = ''
            used = 0
        current = current + char
        used = used + size
    if current:
        chunks.append(current)
    return chunks or ['']


def wrap_cells(text, width, split_long=False):
    words = str(text).split()
    if not words:
        return ['']
    if split_long:
        words = [chunk for word in words for chunk in split_cells(word, width)]
    lines = []
    current = words[0]
    used = display_width(current)
    for word in words[1:]:
        size = display_width(word)
        if used + 1 + size <= width:
            current = current + ' ' + word
            used = used + 1 + size
        else:
            lines.append(current)
            current = word
            used = size
    lines.append(current)
    return lines


def wrap_field(text, width, indent, minimum=20, split_long=False):
    return ('\n' + ' ' * indent).join(
        wrap_cells(text, max(minimum, width - indent), split_long=split_long))


_SGR_RE = re.compile(r'\x1b\[[0-9;]*m')
_LIST_MARKER_RE = re.compile(r'^(\s*)((?:[-*+•]|\d{1,3}[.)])\s+)')
WRAP_MIN_BODY = 20


def _sgr_active(active, chunk):
    for code in _SGR_RE.findall(chunk):
        if code in ('\033[0m', '\033[m'):
            active = []
        else:
            active = active + [code]
    return active


def _ansi_words(line):
    words = []
    current = ''
    position = 0
    while position < len(line):
        match = _SGR_RE.match(line, position)
        if match:
            current = current + match.group(0)
            position = match.end()
            continue
        if line[position].isspace():
            if _SGR_RE.sub('', current):
                words.append(current)
                current = ''
            position = position + 1
            continue
        current = current + line[position]
        position = position + 1
    if current:
        words.append(current)
    return words


def _wrap_ansi_line(line, width):
    plain = _SGR_RE.sub('', line)
    if display_width(plain) <= width:
        return [line]

    marker = _LIST_MARKER_RE.match(plain)
    lead = plain[:len(plain) - len(plain.lstrip())]
    hang = len(marker.group(1)) + len(marker.group(2)) if marker else len(lead)
    hang = max(0, min(hang, width - WRAP_MIN_BODY))

    words = _ansi_words(line)
    if not words:
        return [line]

    budget = max(WRAP_MIN_BODY, width - display_width(lead))
    rest = max(WRAP_MIN_BODY, width - hang)

    lines = []
    active = []
    current = ''
    used = 0

    for word in words:
        size = display_width(_SGR_RE.sub('', word))
        if used and used + 1 + size > budget:
            lines.append(current)
            current = ''.join(active)
            used = 0
            budget = rest
        if used:
            current = current + ' '
            used = used + 1
        current = current + word
        used = used + size
        active = _sgr_active(active, word)

    lines.append(current)
    return [(lead if index == 0 else ' ' * hang) + content
            for index, content in enumerate(lines)]


def wrap_ansi(text, width):
    out = []
    for line in str(text).split('\n'):
        out.extend(_wrap_ansi_line(line, width))
    return '\n'.join(out)


def divider(width, color=None):
    color = mycolors.foreground.neutral(cv.bkg) if color is None else color
    return color + (width * '-') + mycolors.reset


def report_header(title, width, color=None):
    return (mycolors.reset + str(title).center(width).rstrip() + '\n'
            + divider(width, color))


BULLET = "[+] "
BULLET_MIN_WIDTH = 40


def bullet(text, width, color=None):
    body = max(BULLET_MIN_WIDTH, width - len(BULLET))
    color = mycolors.foreground.neutral(cv.bkg) if color is None else color
    lines = wrap_cells(str(text), body, split_long=True)
    out = []
    for index, line in enumerate(lines):
        prefix = BULLET if index == 0 else ' ' * len(BULLET)
        out.append(color + prefix + line + mycolors.reset)
    return '\n'.join(out)


def detect_background():
    import os
    colorfgbg = os.environ.get('COLORFGBG', '')
    if colorfgbg:
        parts = colorfgbg.split(';')
        if len(parts) >= 2:
            try:
                bg = int(parts[-1])
                return 0 if bg < 8 else 1
            except ValueError:
                pass
    return 1
