# ResolverScanner

A fast DNS resolver scanner that finds open DNS resolvers across IP ranges. Scans millions of IPs quickly using raw UDP sockets with multithreaded receivers.

## What It Does

Give it a file with IP ranges (CIDR notation), and it checks every IP to see if it responds to DNS queries. Found resolvers are saved to a file.

**Two modes:**
- **Open mode (default):** Finds any server that responds with a valid DNS answer.
- **Strict mode:** Only accepts responses containing a specific IP address (use `--expected-ip`).

## Requirements

- Python 3.10+
- No external dependencies

## Quick Start

1. **Get a CIDR file** (list of IP ranges to scan):
   ```
   curl -o iran.txt https://raw.githubusercontent.com/mk990/iran-cidr/master/ir-cidr.txt
   ```

2. **Run the scanner:**
   ```
   python dns_scanner.py
   ```

3. **Check results** in `found_resolvers.txt`.

## Usage

```
python dns_scanner.py [OPTIONS]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--cidr-file` | `iran.txt` | File with CIDR ranges to scan |
| `--domain` | `example.com` | Domain to query |
| `--expected-ip` | *(none)* | Only accept responses with this IP (strict mode) |
| `--ports` | `53` | Comma-separated ports to probe |
| `--timeout` | `3.0` | Seconds to wait for each probe |
| `--concurrency` | `2000` | Number of concurrent workers |
| `--sockets` | `50` | Number of shared UDP sockets |
| `--output` | `found_resolvers.txt` | Output file for results |

### Examples

**Find all open resolvers (default):**
```
python dns_scanner.py
```

**Strict mode — only resolvers returning a specific IP:**
```
python dns_scanner.py --expected-ip 1.2.3.4
```

**Scan custom ports:**
```
python dns_scanner.py --ports 53,5353,8053
```

**Use a different CIDR file and output:**
```
python dns_scanner.py --cidr-file my_ranges.txt --output my_results.txt
```

**Faster scan (more sockets + workers, lower timeout):**
```
python dns_scanner.py --sockets 100 --concurrency 3000 --timeout 1.0
```

## CIDR File Format

One CIDR range or IP per line. Lines starting with `#` are ignored.

```
# Example
192.168.0.0/24
10.0.0.0/16
8.8.8.8
```

## Output

Results are saved as `IP:PORT`, one per line:

```
1.2.3.4:53
5.6.7.8:53
```

## License

[MIT](LICENSE)
