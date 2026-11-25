#!/usr/bin/env python3
"""Start the Deco Wi-Fi Dashboard.

    python3 run.py            # your real network
    python3 run.py --demo     # sample data, nothing is sent anywhere

Then open the link it prints (normally http://127.0.0.1:8765/).
Press Ctrl+C in this window to stop.
"""

from __future__ import annotations

import sys

MIN_PYTHON = (3, 9)


def _check_python() -> None:
    if sys.version_info < MIN_PYTHON:
        sys.stderr.write(
            "Sorry, this dashboard needs Python %d.%d or newer, and this is Python %d.%d.\n"
            "Get the latest Python from https://www.python.org/downloads/ and run it again\n"
            "with: python3 run.py\n" % (MIN_PYTHON + tuple(sys.version_info[:2]))
        )
        sys.exit(1)


def _port(text: str) -> int:
    import argparse

    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("the port has to be a whole number, like 8765") from None
    if not 1024 <= value <= 65535:
        raise argparse.ArgumentTypeError("pick a port between 1024 and 65535 (8765 is the default)")
    return value


def main(argv=None) -> int:
    _check_python()

    import argparse
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)

    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Deco Wi-Fi Dashboard: reads your TP-Link Deco mesh (read-only) and tells you "
                    "how to make your Wi-Fi faster. Everything stays on this computer.",
    )
    parser.add_argument("--port", type=_port, default=8765,
                        help="port for the local web page (default: 8765)")
    parser.add_argument("--demo", action="store_true",
                        help="show made-up sample data instead of your network (nothing is sent anywhere)")
    parser.add_argument("--no-browser", action="store_true",
                        help="don't open the browser automatically")
    parser.add_argument("--deco-host", default="192.168.68.1",
                        help="address of your main Deco (default: 192.168.68.1)")
    args = parser.parse_args(argv)

    from decodash.server import ApiError, serve, validate_host

    try:
        deco_host = validate_host(args.deco_host)
    except ApiError as err:
        parser.error("--deco-host: %s" % err.message)
        return 2  # parser.error exits; this keeps linters happy

    try:
        serve(port=args.port, demo=args.demo, open_browser=not args.no_browser, deco_host=deco_host)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
