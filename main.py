# main.py (use previous file, update brute/scan sections)
import argparse
import logging
from toolkit import port_scanner, brute_forcer

logging.basicConfig(level=logging.INFO)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan")
    ps.add_argument("host")
    ps.add_argument("--start", type=int, default=1)
    ps.add_argument("--end", type=int, default=1024)
    ps.add_argument("--workers", type=int, default=200)
    ps.add_argument("--concurrency", type=int, default=200)
    ps.add_argument("--timeout", type=float, default=1.0)

    bf = sub.add_parser("brute")
    bf.add_argument("url")
    bf.add_argument("user")
    bf.add_argument("--passfile", required=True)
    bf.add_argument("--concurrency", type=int, default=1)
    bf.add_argument("--rate", type=float, default=0.5)
    bf.add_argument("--mode", choices=("basic","form"), default="basic")
    bf.add_argument("--userfield", default="username")
    bf.add_argument("--passfield", default="password")

    args = ap.parse_args()

    if args.cmd == "scan":
        ports = range(args.start, args.end + 1)
        openp = port_scanner.scan_ports(args.host, ports,
                                       workers=args.workers,
                                       concurrency_limit=args.concurrency,
                                       timeout=args.timeout)
        print(f"Open ports: {openp}")

    elif args.cmd == "brute":
        with open(args.passfile) as f:
            pwds = [l.strip() for l in f if l.strip()]
        if args.mode == "basic":
            res = brute_forcer.http_basic_bruteforce(args.url, args.user, pwds,
                                                    concurrency=args.concurrency,
                                                    rate_delay=args.rate)
            print("Result:", res)
        else:
            res = brute_forcer.form_bruteforce(args.url, args.userfield, args.passfield,
                                               args.user, pwds,
                                               concurrency=args.concurrency,
                                               rate_delay=args.rate)
            print("Result:", res)

if __name__ == "__main__":
    main()
