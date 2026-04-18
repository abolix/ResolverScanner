#!/usr/bin/env python3
"""
MasterDnsVPN Resolver Scanner v3 - Simple & Reliable, Windows Python 3.14
Uses raw blocking UDP sockets with dedicated receiver threads.
Bypasses Windows IOCP/ProactorEventLoop entirely – no silent stalls.
"""

import asyncio
import argparse
import ipaddress
import struct
import random
import time
import os
import sys
import socket
import threading

# ── CONFIG ─────────────────────────────────────────────────────────────────────
TEST_DOMAIN  = "example.com"
EXPECTED_IP  = None
PORTS        = [53]
TIMEOUT      = 3.0
CONCURRENCY  = 2000
NUM_SOCKETS  = 50
OUTPUT_FILE  = "found_resolvers.txt"
CIDR_FILE    = "iran.txt"
# ───────────────────────────────────────────────────────────────────────────────


def build_dns_a_query(domain: str, txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in domain.rstrip(".").split("."):
        enc = label.encode("ascii")
        qname += bytes([len(enc)]) + enc
    qname += b"\x00"
    # qtype=1 (A), qclass=1 (IN)
    return header + qname + struct.pack(">HH", 1, 1)


def _skip_name(data: bytes, offset: int) -> int:
    """Skip a DNS name (handles pointers and labels). Returns new offset."""
    while offset < len(data):
        length = data[offset]
        if length >= 0xC0:          # pointer
            return offset + 2
        if length == 0:             # root label
            return offset + 1
        offset += 1 + length
    return offset


def is_valid_dns_response(data: bytes, txid: int, expected_ip: str | None) -> bool:
    if len(data) < 12:
        return False
    if struct.unpack(">H", data[0:2])[0] != txid:
        return False
    flags = struct.unpack(">H", data[2:4])[0]
    qr = (flags >> 15) & 1
    rcode = flags & 0xF
    ancount = struct.unpack(">H", data[6:8])[0]
    if qr != 1 or rcode != 0 or ancount == 0:
        return False

    qdcount = struct.unpack(">H", data[4:6])[0]
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        offset += 4

    expected_bytes = socket.inet_aton(expected_ip) if expected_ip else None
    for _ in range(ancount):
        if offset >= len(data):
            break
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, _, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
        offset += 10
        if offset + rdlength > len(data):
            break
        if rtype == 1 and rclass == 1 and rdlength == 4:
            if expected_bytes is None or data[offset:offset+4] == expected_bytes:
                return True
        offset += rdlength

    return False


class UDPScanner:
    """
    Raw blocking UDP sockets with dedicated receiver threads.
    asyncio is only used for concurrency orchestration (futures/coroutines).
    Actual I/O uses plain socket.sendto / socket.recvfrom in threads,
    completely bypassing Windows IOCP which silently dies after heavy use.
    """

    def __init__(self, num_sockets: int, timeout: float):
        self.num_sockets = num_sockets
        self.timeout = timeout
        # Maps txid -> (future, expected_ip, expected_port)
        self._pending: dict[int, tuple[asyncio.Future, str, int]] = {}
        self._sockets: list[socket.socket] = []
        self._recv_threads: list[threading.Thread] = []
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None

    @staticmethod
    def _make_socket() -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.bind(("0.0.0.0", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        if sys.platform == "win32":
            try:
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except (OSError, AttributeError, ValueError):
                pass
        return sock

    async def start(self):
        self._loop = asyncio.get_running_loop()
        self._running = True
        for _ in range(self.num_sockets):
            sock = self._make_socket()
            self._sockets.append(sock)
            t = threading.Thread(target=self._recv_loop, args=(sock,), daemon=True)
            t.start()
            self._recv_threads.append(t)

    def _resolve_future(self, txid: int, result: bool):
        """Scheduled on the event-loop thread via call_soon_threadsafe."""
        entry = self._pending.get(txid)
        if entry and not entry[0].done():
            entry[0].set_result(result)

    def _recv_loop(self, sock: socket.socket):
        """Blocking receiver – runs in its own thread, one per socket."""
        while self._running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if not self._running:
                    return
                continue
            if len(data) < 12:
                continue
            txid = struct.unpack(">H", data[0:2])[0]
            entry = self._pending.get(txid)
            if entry is not None:
                _, expected_ip, expected_port = entry
                # Verify the response came from the IP:port we probed
                if addr[0] != expected_ip or addr[1] != expected_port:
                    continue
                result = is_valid_dns_response(data, txid, EXPECTED_IP)
                try:
                    self._loop.call_soon_threadsafe(self._resolve_future, txid, result)
                except RuntimeError:
                    return  # event loop closed

    async def probe(self, ip: str, port: int) -> bool:
        txid = random.randint(1, 65535)
        attempts = 0
        while txid in self._pending:
            txid = random.randint(1, 65535)
            attempts += 1
            if attempts > 500:
                return False

        fut = self._loop.create_future()
        self._pending[txid] = (fut, ip, port)

        pkt = build_dns_a_query(TEST_DOMAIN, txid)
        try:
            self._sockets[txid % self.num_sockets].sendto(pkt, (ip, port))
        except OSError:
            self._pending.pop(txid, None)
            fut.cancel()
            return False

        try:
            return await asyncio.wait_for(fut, timeout=self.timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return False
        finally:
            self._pending.pop(txid, None)

    def stop(self):
        self._running = False
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass
        for t in self._recv_threads:
            t.join(timeout=3.0)


async def worker(queue: asyncio.Queue, scanner: UDPScanner,
                 found: list, stats: dict, out_f):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        ip, port = item
        try:
            ok = await scanner.probe(ip, port)
            stats["done"] += 1
            if ok:
                entry = f"{ip}:{port}"
                found.append(entry)
                out_f.write(entry + "\n")
                out_f.flush()
                stats["last_found"] = entry
        except Exception:
            stats["done"] += 1
        queue.task_done()


def iter_all_ips(filepath: str, ports: list):
    """Generator: yields (ip, port) for every host in every CIDR. Zero RAM."""
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "]" in line:
                line = line.split("]")[-1].strip()
            if not line:
                continue
            if "/" not in line:
                try:
                    ipaddress.ip_address(line)
                    for port in ports:
                        yield str(line), port
                except ValueError:
                    pass
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                for host in net.hosts():
                    for port in ports:
                        yield str(host), port
            except ValueError:
                pass


def count_all_ips(filepath: str) -> int:
    total = 0
    seen = set()
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "]" in line:
                line = line.split("]")[-1].strip()
            if not line:
                continue
            if "/" not in line:
                try:
                    ipaddress.ip_address(line)
                    total += 1
                except ValueError:
                    pass
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                key = str(net)
                if key not in seen:
                    seen.add(key)
                    total += max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
            except ValueError:
                pass
    return total


async def run_scan(cidr_file: str, ports: list, total: int):
    found: list[str] = []
    stats = {"done": 0, "last_found": None}
    start = time.time()
    loop = asyncio.get_running_loop()

    print(f"\n{'='*65}")
    print(f"  MasterDnsVPN Resolver Scanner v3 — Raw Socket Mode")
    print(f"{'='*65}")
    mode_str = f"strict (expect {EXPECTED_IP})" if EXPECTED_IP else "open (any valid A response)"
    print(f"  Domain      : {TEST_DOMAIN}")
    print(f"  Mode        : {mode_str}")
    print(f"  Total IPs   : {total:,}")
    print(f"  Ports       : {ports}")
    print(f"  Workers     : {CONCURRENCY}")
    print(f"  UDP sockets : {NUM_SOCKETS} (raw, threaded receivers)")
    print(f"  Timeout     : {TIMEOUT}s")
    print(f"  Output      : {OUTPUT_FILE}")
    print(f"{'='*65}\n")

    scanner = UDPScanner(NUM_SOCKETS, TIMEOUT)
    await scanner.start()

    queue: asyncio.Queue = asyncio.Queue(maxsize=CONCURRENCY * 4)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f:
        out_f.write(f"# MasterDnsVPN resolver scan\n")
        out_f.write(f"# Domain: {TEST_DOMAIN}\n")
        out_f.write(f"# Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        workers = [
            asyncio.create_task(worker(queue, scanner, found, stats, out_f))
            for _ in range(CONCURRENCY)
        ]

        async def print_progress():
            last_reported_found = 0
            while True:
                await asyncio.sleep(1.0)
                done = stats["done"]
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else 0

                # Print new finds
                if len(found) > last_reported_found:
                    for entry in found[last_reported_found:]:
                        print(
                            f"\r  [+] FOUND {len(found):>4}: {entry:<38} | "
                            f"{done:>10,}/{total:,} | {rate:>7,.0f}/s",
                            flush=True
                        )
                    last_reported_found = len(found)

                pct = done / total * 100 if total > 0 else 0
                eta_h = int(eta // 3600)
                eta_m = int((eta % 3600) // 60)
                eta_s = int(eta % 60)
                if eta_h > 0:
                    eta_str = f"{eta_h}h{eta_m:02d}m"
                elif eta_m > 0:
                    eta_str = f"{eta_m}m{eta_s:02d}s"
                else:
                    eta_str = f"{eta_s}s"

                print(
                    f"\r  {pct:5.1f}% | {done:>10,}/{total:,} | "
                    f"{rate:>7,.0f}/s | ETA {eta_str:>8} | Found: {len(found)}   ",
                    end="", flush=True
                )
                if done >= total:
                    break

        progress_task = asyncio.create_task(print_progress())

        # Feed queue from generator
        for ip, port in iter_all_ips(cidr_file, ports):
            await queue.put((ip, port))

        for _ in workers:
            await queue.put(None)

        await queue.join()

        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    scanner.stop()

    elapsed = time.time() - start
    rate_avg = total / elapsed if elapsed > 0 else 0
    print(f"\n\n{'='*65}")
    print(f"  Finished in {elapsed/3600:.2f}h  ({elapsed:.0f}s)")
    print(f"  Average rate : {rate_avg:,.0f}/s")
    print(f"  Total probed : {total:,}")
    print(f"  Found        : {len(found)}")
    print(f"  Output       : {OUTPUT_FILE}")
    print(f"{'='*65}\n")

    if found:
        print("  Results:")
        for r in found[:20]:
            print(f"    {r}")
        if len(found) > 20:
            print(f"    ... and {len(found)-20} more in {OUTPUT_FILE}")


def main():
    global TEST_DOMAIN, EXPECTED_IP, PORTS, TIMEOUT, CONCURRENCY, NUM_SOCKETS, OUTPUT_FILE, CIDR_FILE

    parser = argparse.ArgumentParser(
        description="ResolverScanner — Fast DNS resolver discovery tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  py dns_scanner.py
  py dns_scanner.py --expected-ip 1.2.3.4
  py dns_scanner.py --sockets 100 --concurrency 3000 --timeout 0.8
  py dns_scanner.py --ports 53,5353,1053,8053,8888
  py dns_scanner.py --cidr-file mysubnets.txt --output results.txt
        """
    )
    parser.add_argument("--cidr-file",    default=CIDR_FILE,
                        help="File with CIDR ranges to scan (default: iran.txt)")
    parser.add_argument("--domain",       default=TEST_DOMAIN,
                        help="Domain to query (default: example.com)")
    parser.add_argument("--expected-ip",  default=None,
                        help="Only accept responses containing this IP (strict mode)")
    parser.add_argument("--ports",        default=",".join(map(str, PORTS)),
                        help="Comma-separated ports to probe (default: 53)")
    parser.add_argument("--timeout",      type=float, default=TIMEOUT,
                        help="Seconds to wait for each probe (default: 3.0)")
    parser.add_argument("--concurrency",  type=int, default=CONCURRENCY,
                        help="Number of concurrent workers (default: 2000)")
    parser.add_argument("--sockets",      type=int, default=NUM_SOCKETS,
                        help="Number of shared UDP sockets (default: 50)")
    parser.add_argument("--output",       default=OUTPUT_FILE,
                        help="Output file for found resolvers (default: found_resolvers.txt)")
    args = parser.parse_args()

    TEST_DOMAIN  = args.domain
    EXPECTED_IP  = args.expected_ip
    PORTS        = [int(p.strip()) for p in args.ports.split(",")]
    TIMEOUT      = args.timeout
    CONCURRENCY  = args.concurrency
    NUM_SOCKETS  = args.sockets
    OUTPUT_FILE  = args.output

    if not os.path.exists(args.cidr_file):
        print(f"[!] File not found: {args.cidr_file}")
        print(f"    Run: curl -o iran.txt https://raw.githubusercontent.com/mk990/iran-cidr/master/ir-cidr.txt")
        sys.exit(1)

    print(f"[*] Counting IPs in {args.cidr_file}...")
    total = count_all_ips(args.cidr_file) * len(PORTS)
    print(f"[*] Total probes: {total:,} ({total // len(PORTS):,} IPs × {len(PORTS)} ports)")

    asyncio.run(run_scan(args.cidr_file, PORTS, total))


if __name__ == "__main__":
    main()
