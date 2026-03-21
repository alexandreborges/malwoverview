import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import malwoverview.modules.configvars as cv


def _rate_limit_hook(response, *args, **kwargs):
    if response.status_code == 429:
        retry_after = response.headers.get('Retry-After')
        if retry_after:
            try:
                wait_time = min(int(retry_after), 300)
            except ValueError:
                wait_time = 60
        else:
            wait_time = 60

        if cv.verbosity >= 0:
            print(f"\nRate limited (429). Waiting {wait_time}s before retrying...")
        time.sleep(wait_time)

    return response


def create_session(headers=None):
    session = requests.Session()

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"],
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    if cv.proxy:
        session.proxies = {"http": cv.proxy, "https": cv.proxy}

    session.hooks['response'].append(_rate_limit_hook)

    if headers:
        session.headers.update(headers)

    return session
