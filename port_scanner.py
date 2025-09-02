# toolkit/port_scanner.py
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore

# logging config (module-level)
logger = logging.getLogger("port_scanner")

def scan_port(host, port, timeout=1.0):
    """Return True if port is open on host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception as e:
        logger.debug("scan_port exception: %s", e)
        return False

def scan_ports(host, ports, workers=100, concurrency_limit=200, timeout=1.0):
    """
    Scan ports with:
      - ThreadPoolExecutor for concurrency
      - Semaphore to limit in-flight tasks (rate limiting)
      - logging for results
    Returns: sorted list of open ports
    """
    open_ports = []
    sem = Semaphore(concurrency_limit)  # limits simultaneous active tasks

    def task(p):
        with sem:
            if scan_port(host, p, timeout):
                logger.info("Open port: %d", p)
                return p
            return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(task, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)

    return sorted(open_ports)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    host = "127.0.0.1"
    ports = range(1, 1025)
    print("Open ports:", scan_ports(host, ports, workers=200, concurrency_limit=200))
