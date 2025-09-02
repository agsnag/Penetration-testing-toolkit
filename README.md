# Pentoolkit (simple)

Modules:
- port_scanner: TCP port scanning using threads.
- brute_forcer: HTTP Basic and simple form brute force.

Install:
pip install requests

Run:
python main.py scan 192.168.1.10 --start 1 --end 1024
python main.py brute http://example.com/protected username --passfile wordlist.txt

LEGAL: Only test with permission.
