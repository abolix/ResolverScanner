# 🔍 ResolverScanner

A tool that finds open DNS resolvers. Give it a list of IP ranges, it sends a DNS question to every IP, and saves the ones that answer correctly.

> **Iran IPs are already included!** The file `iran.txt` comes with this project and has all Iran IP ranges. You can start scanning right away — no extra setup needed.

---

## Two Modes

### 🟢 Open Mode (default)

The scanner sends a DNS question to each IP. If the server sends back **any valid DNS answer**, it gets saved.

Use this when you just want to find working DNS resolvers in a range of IPs.

### 🎯 Strict Mode

The scanner sends a DNS question. But this time, it **only saves** servers that return a **specific IP address** you tell it to look for.

**Why would you use this?**

Imagine you run a VPN or a website. Your domain `vpn.example.com` points to your server IP `1.2.3.4`.

You want to find DNS servers (for example, in Iran) that give back the **real** answer for your domain — not a fake or blocked one.

You run:
```
python dns_scanner.py --expected-ip 1.2.3.4
```

Now the scanner **only saves** DNS servers that return `1.2.3.4`. This means those servers are not censored and have not been tampered with. Servers that return a wrong IP (or no IP) are ignored.

Think of it as a filter: only the "clean" DNS servers pass through. ✅

---

## Requirements

- Python 3.10 or newer
- No extra packages needed — uses only built-in Python tools

---

## Quick Start

1. **The Iran IP file is already there** — `iran.txt` is included with all Iran IP ranges. Nothing to download.

2. **Run the scanner:**
   ```
   python dns_scanner.py
   ```

3. **See results** in `found_resolvers.txt`

That's it! 🎉

---

## Usage

```
python dns_scanner.py [OPTIONS]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--cidr-file` | `iran.txt` | File with IP ranges to scan |
| `--domain` | `example.com` | The domain name to ask about |
| `--expected-ip` | *(none)* | Only save servers that return this IP (strict mode) |
| `--ports` | `53` | Port numbers to scan (separate with commas) |
| `--timeout` | `3.0` | How many seconds to wait for a reply |
| `--concurrency` | `2000` | How many IPs to check at the same time |
| `--sockets` | `50` | Number of UDP sockets to use |
| `--output` | `found_resolvers.txt` | File to save results in |

### Examples

**Find all open resolvers (default — uses iran.txt):**
```
python dns_scanner.py
```

**Strict mode — only resolvers that return a specific IP:**
```
python dns_scanner.py --expected-ip 1.2.3.4
```

**Scan extra ports:**
```
python dns_scanner.py --ports 53,5353,8053
```

**Use a different IP list file:**
```
python dns_scanner.py --cidr-file my_ranges.txt --output my_results.txt
```

**Faster scan (more sockets and workers, shorter wait time):**
```
python dns_scanner.py --sockets 100 --concurrency 3000 --timeout 1.0
```

---

## IP File Format

One IP range (or single IP) per line. Lines that start with `#` are skipped (comments).

```
# This is a comment
192.168.0.0/24
10.0.0.0/16
8.8.8.8
```

---

## Output

Results are saved as `IP:PORT`, one per line:

```
1.2.3.4:53
5.6.7.8:53
```
