import sys
import json
import csv
import io
import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors


class ResultCollector:
    def __init__(self):
        self.records = []
        self._current = {}

    def add(self, record):
        if isinstance(record, dict):
            self.records.append(record)
        elif isinstance(record, list):
            self.records.extend(record)

    def start_record(self):
        self._current = {}

    def field(self, key, value):
        self._current[key] = value

    def end_record(self):
        if self._current:
            self.records.append(self._current)
            self._current = {}

    def finalize(self, file=None):
        if file is None:
            file = sys.stdout

        if cv.output_format == 'json':
            json.dump(self.records, file, indent=2, default=str)
            print(file=file)
        elif cv.output_format == 'csv':
            if not self.records:
                return
            all_keys = []
            seen = set()
            for record in self.records:
                for key in record:
                    if key not in seen:
                        all_keys.append(key)
                        seen.add(key)
            writer = csv.DictWriter(file, fieldnames=all_keys, extrasaction='ignore')
            writer.writeheader()
            for record in self.records:
                writer.writerow({k: str(v) for k, v in record.items()})

    def clear(self):
        self.records = []
        self._current = {}


collector = ResultCollector()


def is_text_output():
    return cv.output_format == 'text'
