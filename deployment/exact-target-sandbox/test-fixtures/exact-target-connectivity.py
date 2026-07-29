import argparse
import socket


parser = argparse.ArgumentParser()
parser.add_argument("--target", action="append", required=True)
arguments = parser.parse_args()

if arguments.target != ["127.0.0.1"]:
    raise SystemExit("fixture received an unexpected target")

with socket.create_connection(("127.0.0.1", 3132), timeout=1):
    pass

try:
    with socket.create_connection(("1.1.1.1", 443), timeout=0.5):
        pass
except OSError:
    print("exact target reached; unlisted address blocked")
else:
    raise SystemExit("unlisted address unexpectedly reachable")
