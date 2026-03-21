import os
import json
import tempfile
from datetime import datetime

from malwoverview.utils.colors import mycolors
import malwoverview.modules.configvars as cv


class ReportGenerator:
    def __init__(self, data, title="Malwoverview Report"):
        self.data = data
        self.title = title

    def to_html(self, output_path):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cards_html = ''
        for i, record in enumerate(self.data):
            rows = ''
            for key, value in record.items():
                escaped_key = str(key).replace('&', '&amp;').replace('<', '&lt;')
                if isinstance(value, (dict, list)):
                    escaped_val = (
                        json.dumps(value, indent=2, default=str)
                        .replace('&', '&amp;')
                        .replace('<', '&lt;')
                    )
                    escaped_val = f'<pre>{escaped_val}</pre>'
                else:
                    escaped_val = (
                        str(value).replace('&', '&amp;').replace('<', '&lt;')
                    )
                rows += (
                    f'<tr>'
                    f'<td class="key">{escaped_key}</td>'
                    f'<td class="value">{escaped_val}</td>'
                    f'</tr>\n'
                )
            cards_html += (
                f'<div class="card">'
                f'<h3>Record {i + 1}</h3>'
                f'<table>{rows}</table>'
                f'</div>\n'
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{self.title}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        background-color: #1a1a2e;
        color: #e0e0e0;
        font-family: 'Courier New', Courier, monospace;
        padding: 20px;
    }}
    h1 {{
        color: #00d4ff;
        text-align: center;
        margin-bottom: 5px;
        font-size: 1.8em;
    }}
    .timestamp {{
        text-align: center;
        color: #888;
        margin-bottom: 30px;
        font-size: 0.9em;
    }}
    .card {{
        background-color: #16213e;
        border: 1px solid #0f3460;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 20px;
    }}
    .card h3 {{
        color: #e94560;
        margin-bottom: 10px;
        border-bottom: 1px solid #0f3460;
        padding-bottom: 5px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
    }}
    tr:nth-child(even) {{
        background-color: #1a1a3e;
    }}
    td {{
        padding: 6px 10px;
        vertical-align: top;
        border-bottom: 1px solid #0f3460;
    }}
    td.key {{
        color: #00d4ff;
        width: 200px;
        font-weight: bold;
    }}
    td.value {{
        color: #e0e0e0;
        word-break: break-all;
    }}
    td.value pre {{
        margin: 0;
        white-space: pre-wrap;
        font-family: inherit;
    }}
</style>
</head>
<body>
<h1>{self.title}</h1>
<div class="timestamp">Generated: {timestamp}</div>
{cards_html}
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        if cv.bkg == 1:
            print(
                f"{mycolors.foreground.lightgreen}"
                f"Report saved to: {output_path}"
                f"{mycolors.reset}"
            )
        else:
            print(
                f"{mycolors.foreground.green}"
                f"Report saved to: {output_path}"
                f"{mycolors.reset}"
            )

    def to_pdf(self, output_path):
        try:
            import weasyprint
        except ImportError:
            print(
                f"{mycolors.foreground.yellow}"
                "Install weasyprint for PDF support: "
                "pip install malwoverview[pdf]"
                f"{mycolors.reset}"
            )
            return

        fd, html_path = tempfile.mkstemp(suffix='.html', prefix='malwoverview_')
        try:
            os.close(fd)
            self.to_html(html_path)
            weasyprint.HTML(filename=html_path).write_pdf(output_path)
        finally:
            try:
                os.remove(html_path)
            except OSError:
                pass

        if cv.bkg == 1:
            print(
                f"{mycolors.foreground.lightgreen}"
                f"PDF report saved to: {output_path}"
                f"{mycolors.reset}"
            )
        else:
            print(
                f"{mycolors.foreground.green}"
                f"PDF report saved to: {output_path}"
                f"{mycolors.reset}"
            )
