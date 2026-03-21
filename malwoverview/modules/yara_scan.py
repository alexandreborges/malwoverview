import os
import warnings

from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv
from malwoverview.utils.output import collector, is_text_output

COL_FILE = 30
COL_RULE = 30
COL_TAGS = 20
COL_STRINGS = 9
COL_DESC = 50
TABLE_WIDTH = COL_FILE + COL_RULE + COL_TAGS + COL_STRINGS + COL_DESC


class YaraScanner:
    def __init__(self, rules_path):
        self.rules_path = os.path.abspath(rules_path)
        self.available = False
        self.rules = None
        self.skipped = []
        self._compiled_count = 0

        if not os.path.isfile(self.rules_path):
            print(
                f"{mycolors.foreground.error(cv.bkg)}"
                f"YARA rules file not found: {self.rules_path}"
                f"{mycolors.reset}"
            )
            return

        try:
            import yara
            self._yara = yara
            try:
                self.rules = self._compile_in_context(self.rules_path)
                self.available = True
            except (yara.SyntaxError, yara.Error):
                self.rules, self.skipped = self._compile_with_fallback(self.rules_path)
                if self.rules:
                    self.available = True
                else:
                    print(
                        f"{mycolors.foreground.error(cv.bkg)}"
                        "All YARA rules failed to compile. Check your rules file."
                        f"{mycolors.reset}"
                    )
        except ImportError:
            print(
                f"{mycolors.foreground.yellow}"
                "YARA scanning requires yara-python: "
                "pip install malwoverview[yara]"
                f"{mycolors.reset}"
            )

    def _compile_in_context(self, rules_path):
        rules_dir = os.path.dirname(rules_path)
        saved_cwd = os.getcwd()
        try:
            if rules_dir:
                os.chdir(rules_dir)
            return self._yara.compile(filepath=rules_path)
        finally:
            os.chdir(saved_cwd)

    def _compile_with_fallback(self, rules_path):
        yara = self._yara
        rules_dir = os.path.dirname(rules_path)
        includes = []
        skipped = []

        try:
            with open(rules_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('include') and '"' in line:
                        inc_path = line.split('"')[1]
                        full_path = os.path.normpath(os.path.join(rules_dir, inc_path))
                        if os.path.isfile(full_path):
                            includes.append(full_path)
        except Exception:
            return None, []

        if not includes:
            return None, []

        valid_sources = {}
        for i, inc in enumerate(includes):
            try:
                self._compile_in_context(inc)
                valid_sources[f'rule_{i}'] = inc
            except (yara.SyntaxError, yara.Error) as e:
                skipped.append((os.path.basename(inc), str(e)))
            except Exception:
                skipped.append((os.path.basename(inc), 'unknown error'))

        if skipped:
            print(
                f"{mycolors.foreground.yellow}"
                f"Skipped {len(skipped)} rule file(s) with syntax errors:"
                f"{mycolors.reset}"
            )
            for name, err in skipped[:10]:
                msg = str(err).split('\n')[0][:120]
                print(f"  {name}: {msg}")
            if len(skipped) > 10:
                print(f"  ... and {len(skipped) - 10} more")
            print()

        if not valid_sources:
            return None, skipped

        self._compiled_count = len(valid_sources)
        saved_cwd = os.getcwd()
        try:
            if rules_dir:
                os.chdir(rules_dir)
            rules = yara.compile(filepaths=valid_sources)
        finally:
            os.chdir(saved_cwd)
        return rules, skipped

    def scan_file(self, filepath):
        if not self.available:
            return []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            matches = self.rules.match(filepath)
        results = []
        for match in matches:
            results.append({
                'rule': match.rule,
                'tags': list(match.tags),
                'meta': match.meta,
                'strings_count': len(match.strings),
            })
        return results

    def scan_directory(self, dirpath):
        results = []
        for root, _dirs, files in os.walk(dirpath):
            for fname in files:
                fpath = os.path.join(root, fname)
                file_results = self.scan_file(fpath)
                for r in file_results:
                    r['file'] = fpath
                results.extend(file_results)
        return results

    def _print_header(self):
        print()
        print((mycolors.reset + "YARA SCAN REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100 * '-').center(50))

        if self.skipped:
            print(
                mycolors.foreground.info(cv.bkg)
                + f"Compiled rules: {self._compiled_count} | "
                + f"Skipped: {len(self.skipped)}"
                + mycolors.reset
            )
            print()

    def _print_table_header(self):
        header = (
            mycolors.foreground.info(cv.bkg)
            + "File".ljust(COL_FILE)
            + "Rule".ljust(COL_RULE)
            + "Tags".ljust(COL_TAGS)
            + "Strings".ljust(COL_STRINGS)
            + "Description"
            + mycolors.reset
        )
        print(header)
        print(TABLE_WIDTH * '-')

    def _print_table_row(self, r):
        fname = os.path.basename(r.get('file', ''))
        rule = r['rule']
        tags = ', '.join(r['tags']) if r['tags'] else ''
        strings = str(r['strings_count'])
        desc = str(r.get('meta', {}).get('description', ''))

        print(
            fname[:COL_FILE - 2].ljust(COL_FILE)
            + rule[:COL_RULE - 2].ljust(COL_RULE)
            + tags[:COL_TAGS - 2].ljust(COL_TAGS)
            + strings.ljust(COL_STRINGS)
            + desc[:COL_DESC]
        )

    def _display_single_file(self, results):
        if not results:
            print(
                mycolors.foreground.info(cv.bkg)
                + "No YARA matches found."
                + mycolors.reset
            )
            return

        print(
            mycolors.foreground.info(cv.bkg)
            + f"Matches found: {len(results)}"
            + mycolors.reset
        )
        print()

        COLSIZE = 20
        for r in results:
            fields = {
                'Rule': r['rule'],
            }
            fields['Tags'] = ', '.join(r['tags']) if r['tags'] else 'none'
            fields['Strings matched'] = str(r['strings_count'])
            if r.get('meta'):
                for k, v in r['meta'].items():
                    fields[f'  {k}'] = str(v)

            for field, value in fields.items():
                print(
                    mycolors.foreground.info(cv.bkg)
                    + f"{field}:".ljust(COLSIZE) + "\t"
                    + mycolors.reset + value
                )
            print()

    def _display_directory(self, results):
        if not results:
            print(
                mycolors.foreground.info(cv.bkg)
                + "No YARA matches found."
                + mycolors.reset
            )
            return

        files_scanned = set()
        for r in results:
            if r.get('file'):
                files_scanned.add(r['file'])

        files_matched = len(files_scanned)
        print(
            mycolors.foreground.info(cv.bkg)
            + f"Matches found: {len(results)} across {files_matched} file(s)"
            + mycolors.reset
        )
        print()

        self._print_table_header()
        for r in results:
            self._print_table_row(r)

        print()

    def scan_and_display(self, target):
        target = os.path.abspath(target)
        is_dir = os.path.isdir(target)

        if is_dir:
            results = self.scan_directory(target)
        else:
            results = self.scan_file(target)

        if is_text_output():
            self._print_header()
            if is_dir:
                self._display_directory(results)
            else:
                self._display_single_file(results)

        collector.add(results)
        printr()
