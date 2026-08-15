import socket
import threading
import argparse
import sys
from typing import List, Tuple

# Shared list to aggregate findings across worker threads
open_ports: List[Tuple[int, str, str]] = []

# Inline Comment 1 - Threading Lock Rationale:
# A threading.Lock ensures thread-safe write operations to the shared open_ports
# list, preventing race conditions and memory corruption when multiple worker
# threads discover open ports concurrently.
print_lock = threading.Lock()


def grab_banner(target_ip: str, port: int, timeout: float) -> str:
    """Attempts to retrieve the service banner from an open TCP port."""
    try:
        banner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Inline Comment 2 - Timeout Configuration:
        # A strict 1.0s timeout balances connection reliability with execution speed,
        # preventing slow-responding or non-interactive services from hanging the thread.
        banner_socket.settimeout(timeout)
        banner_socket.connect((target_ip, port))

        # Send generic probe to elicit an application layer service banner
        banner_socket.sendall(b"\r\n")
        raw_banner = banner_socket.recv(1024)
        banner_socket.close()

        # Inline Comment 3 - Banner Decoding and Sanitization:
        # Decoding with 'latin-1' or 'utf-8' with replacement prevents decoding crashes
        # when services return raw binary handshakes, and carriage returns are stripped
        # to ensure table alignment remains intact.
        banner = raw_banner.decode("utf-8", errors="replace").strip().replace("\r", "").replace("\n", " ")
        return banner if banner else "No banner response"
    except (socket.timeout, socket.error, OSError):
        return "No banner response"


def scan_port(target_ip: str, port: int, timeout: float):
    """Scans a single TCP port using a standard 3-way handshake."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            banner = grab_banner(target_ip, port, timeout)
            with print_lock:
                open_ports.append((port, "OPEN", banner))
    except (socket.timeout, socket.error, OSError):
        # Gracefully handle unreachable, filtered, or refused ports without crashing
        pass


def parse_port_range(port_range_str: str) -> range:
    """Parses a port range string formatted like '1-1024' or single port '80'."""
    try:
        if "-" in port_range_str:
            start_str, end_str = port_range_str.split("-")
            start = int(start_str.strip())
            end = int(end_str.strip())
            if start < 1 or end > 65535 or start > end:
                raise ValueError
            return range(start, end + 1)
        else:
            single = int(port_range_str.strip())
            if single < 1 or single > 65535:
                raise ValueError
            return range(single, single + 1)
    except ValueError:
        print(f"[-] Error: Invalid port range '{port_range_str}'. Use format '1-1024' (range 1-65535).")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Multithreaded TCP Port Scanner with Banner Grabbing")
    parser.add_argument("target", help="Target IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (e.g., 1-1024 or 80). Default: 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--max-threads", type=int, default=100, help="Maximum concurrent worker threads (default: 100)")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{args.target}'.")
        sys.exit(1)

    port_range = parse_port_range(args.ports)

    print("=" * 70)
    print(f"[*] Target IP Address : {target_ip} ({args.target})")
    print(f"[*] Scanning Ports    : {port_range.start} to {port_range.stop - 1}")
    print(f"[*] Timeout per Port  : {args.timeout}s")
    print(f"[*] Concurrency Limit : {args.max_threads} threads")
    print("=" * 70)

    threads = []
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(target_ip, port, args.timeout))
        threads.append(thread)
        thread.start()

        # Batch thread joins to prevent hitting OS thread exhaustion limits
        if len(threads) >= args.max_threads:
            for t in threads:
                t.join()
            threads = []

    # Clean up remaining running threads
    for t in threads:
        t.join()

    # Sort results numerically by port number
    open_ports.sort(key=lambda x: x[0])

    print("\n" + "=" * 70)
    print(f"{'Port':<10} | {'State':<10} | {'Banner'}")
    print("-" * 70)

    if not open_ports:
        print(f"{'No open ports discovered in range':<70}")
    else:
        for port, state, banner in open_ports:
            truncated_banner = banner if len(banner) <= 45 else banner[:42] + "..."
            print(f"{port:<10} | {state:<10} | {truncated_banner}")

    print("=" * 70)
    print(f"[*] Scan complete. Found {len(open_ports)} open port(s).\n")


if __name__ == "__main__":
    main()
