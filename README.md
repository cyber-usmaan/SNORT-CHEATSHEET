# Snort 3 IDS Cheatsheet, Packet Inspection Workflow

A sequential command reference for using Snort 3 as an IDS to inspect PCAP files: running detection, reading logs, writing rules, and verifying results with companion CLI tools.

---

## Step 1  Run Snort Against a PCAP File

These are the core commands you'll run, in the order you'd typically use them during an investigation.

### 1.1 Basic alert inspection (console output)

```bash
sudo snort -q -c local.rules -r mx-3.pcap -A console
```

**Use case:** Your first pass at a capture. You want to see, right in the terminal, whether any of your rules fire against the traffic  no files, no clutter.

**Explanation:**
- `-q`  quiet mode; suppresses Snort's startup banner and initialization noise so only alerts show.
- `-c local.rules`  loads your rule file (this is where your detection logic lives).
- `-r mx-3.pcap`  reads a previously captured PCAP file offline instead of sniffing a live interface.
- `-A console`  prints alerts directly to the terminal in a readable format.

**Expected output:**
```
09/08-14:32:10.123456 [**] [1:1000005:1] "FTP Username Submitted" [**]
[Priority: 0] {TCP} 192.168.1.10:1054 -> 192.168.1.20:21
```
One block like this per triggered rule, showing timestamp, SID, message, and the source/destination IP:port.

---

### 1.2 Console inspection with payload dump

```bash
sudo snort -q -c local.rules -r mx-3.pcap -A console -d
```

**Use case:** You've confirmed an alert fires and now need to *see the actual bytes* that triggered it  e.g., confirming an FTP username or a file signature.

**Explanation:**
- Same flags as above, plus `-d`, which dumps the application-layer payload (in ASCII and hex) alongside each alert.

**Expected output:** Same alert header as 1.1, followed by a hex/ASCII dump block, e.g.:
```
55 53 45 52 20 61 64 6D 69 6E 0D 0A   USER admin..
```

---

### 1.3 Save brief alerts to a log directory

```bash
mkdir -p ./logs
sudo snort -q -c local.rules -r mx-3.pcap -l ./logs -A alert_brief
```

**Use case:** You want a persistent, lightweight record of alerts you can grep/search later, instead of scrolling terminal history.

**Explanation:**
- `mkdir -p ./logs`  ensures the output directory exists first (Snort won't create nested paths for you).
- `-l ./logs`  tells Snort where to write output.
- `-A alert_brief`  writes a condensed, one-line-per-alert text format (faster to scan than full console output).

**Expected output:** A file at `./logs/alert` containing one line per alert, e.g.:
```
09/08-14:32:10.123456  [**] [1:1000005:1] FTP Username Submitted [**] [Priority: 0] {TCP} 192.168.1.10:1054 -> 192.168.1.20:21
```

---

### 1.4 Generate full binary packet logs

```bash
sudo snort -q -c local.rules -r mx-3.pcap -l ./logs
```

**Use case:** You need the *full packets* that matched your rules preserved for deeper forensic analysis (e.g., in Wireshark), not just an alert summary.

**Explanation:** Without an `-A` mode specified, Snort defaults to writing binary PCAP-format logs (`snort.log.*`) to the `-l` directory  these retain complete packet data, not just alert text.

**Expected output:** A binary file such as `./logs/snort.log.1694183530`  not human-readable directly (see Step 2.2).

---

## Step 2  Read and Extract Saved Logs

### 2.1 Read text alert logs

```bash
cat ./logs/alert
```

**Use case:** Quickly reviewing the brief alert log created in Step 1.3.

**Explanation:** Since `alert_brief` output is plain text, `cat` (or `grep`/`less`) works directly.

**Expected output:** The same brief alert lines shown in 1.3, printed to your terminal.

---

### 2.2 Read binary log files

Binary logs (`snort.log.*`) are **not** readable with `cat`  they must be re-parsed. Feed them straight back into Snort itself:

```bash
sudo snort -r ./logs/snort.log.* -A console
```

**Use case:** You captured full packets in Step 1.4 and want to re-inspect them  either to see the alerts again, or to re-run a *different* or updated rule set against packets you already captured, without needing the original PCAP.

**Explanation:**
- `-r ./logs/snort.log.*`  reads the binary log back in as the input source, exactly like reading a PCAP.
- `-A console`  re-applies your rule logic (add `-c local.rules` if you want to swap in a different rule file this time) and prints alerts as before.

**Expected output:** The same alert format shown in Step 1.1, generated from the previously captured packets instead of a fresh PCAP.

---

## Step 3  Snort Rule Anatomy

Every rule has a **header** (action, protocol, addresses, ports, direction) followed by **options** in parentheses:

```
[Action] [Proto] [Src IP] [Src Port] [Dir] [Dst IP] [Dst Port] ( [Rule Options] )
  alert    tcp      any       any      ->    any      80      ( msg:"..."; ... )
```

### Header Tags & Operators

| Tag / Symbol | Meaning | Example |
|---|---|---|
| `alert` | Action: log the packet and raise an alert | `alert tcp ...` |
| `tcp` / `udp` / `icmp` / `ip` | Protocol filter | `alert icmp any any ...` |
| `any` | Wildcard for any IP or port | `any any -> any 80` |
| `->` | Uni-directional traffic (left → right only) | `any any -> any 21` |
| `<>` | Bi-directional traffic (both directions) | `any any <> any any` |

**Suggested defaults:** Start rules broad (`any any -> any any`) while testing, then narrow src/dst IP and port once you've confirmed the rule fires correctly  this avoids missing traffic during development.

---

## Step 4  Rule Option Tags (What to Use and Why)

| Tag | Purpose | Example | When to use it |
|---|---|---|---|
| `msg` | Human-readable text shown when the alert fires | `msg:"FTP Login Failed";` | **Always**  every rule needs one for readability in logs |
| `sid` | Unique Signature ID; custom rules must be ≥ 1,000,001 | `sid:1000005;` | **Always**  required by Snort to even load the rule |
| `rev` | Revision number, bump it when you edit rule logic | `rev:1;` | **Always**  helps track rule history/tuning over time |
| `content` | Matches ASCII text or hex byte patterns in the payload | `content:"USER";` or `content:"\|89 50 4E 47\|";` | Core detection tag  use for keywords, commands, or file magic bytes |
| `nocase` | Makes the preceding `content` match case-insensitive | `content:"admin"; nocase;` | Use whenever the pattern could appear in mixed case (e.g., usernames, HTTP headers) |
| `depth` | Limits the search to the first N bytes of the payload | `content:"GIF8"; depth:4;` | Use for file-signature/magic-byte checks to avoid scanning the whole payload unnecessarily |
| `distance` | Relative byte offset from the *previous* content match | `content:"USER"; content:"admin"; distance:1;` | Use when chaining multiple `content` matches that must appear in a specific relative order |
| `dsize` | Filters by total payload byte length (`<`, `>`, `<>`) | `dsize:770<>855;` | Use to flag anomalous packet sizes (e.g., unusually large/small transfers) |
| `itype` | Filters ICMP type numbers (ICMP has no ports) | `itype:8;` (ping request) | Use for any ICMP-specific detection since port-based tags don't apply |
| `http_method` | Restricts match to the HTTP request-method buffer | `content:"GET"; http_method;` | Use to detect specific HTTP verbs cleanly, instead of matching raw payload |
| `http_uri` | Restricts match to the HTTP URI/path buffer | `content:".html"; http_uri;` | Use for detecting requests to specific paths/extensions |
| `http_header` | Restricts match strictly to HTTP headers | `content:"Content-Type: image/png"; http_header;` | Use for MIME-type or header-based detection, avoiding false positives from body content |

**Suggested tag combination for most rules:** `msg` + `sid` + `rev` are mandatory scaffolding. Pair `content` with `nocase` by default (protocol data is rarely case-consistent), and add `depth`/`distance`/`http_*` buffer tags to make matches precise and reduce false positives.

---

## Step 5  Complete Rule Set (mx-3.pcap example)

Save into `local.rules`, referenced by the `-c` flag in Step 1.

```
# 1. FTP Service / Login Detection
alert tcp any any -> any 21 (msg:"FTP Username Submitted"; content:"USER"; nocase; sid:1000005; rev:1;)
alert tcp any 21 -> any any (msg:"FTP Failed Login Attempt"; content:"530"; sid:1000003; rev:1;)

# 2. File & Extension Detection (Magic Bytes & Headers)
alert tcp any any -> any any (msg:"PNG Image Transferred"; content:"|89 50 4E 47 0D 0A 1A 0A|"; depth:8; sid:1000008; rev:1;)
alert tcp any any -> any any (msg:"GIF Image Transferred"; content:"GIF8"; depth:4; sid:1000009; rev:1;)
alert tcp any any -> any 80 (msg:"HTML Page Requested"; content:".html"; http_uri; nocase; sid:1000021; rev:1;)
alert tcp any 80 -> any any (msg:"MIME Type - PNG Image"; content:"Content-Type: image/png"; nocase; sid:1000014; rev:1;)

# 3. Protocol Specifics (BitTorrent & ICMP)
alert tcp any any <> any any (msg:"BitTorrent Handshake"; content:"|13|BitTorrent protocol"; depth:20; sid:1000011; rev:1;)
alert icmp any any -> any any (msg:"ICMP Ping Request"; itype:8; sid:1000019; rev:1;)

# 4. Traffic Constraint (Payload Size Range)
alert tcp any any <> any any (msg:"Payload Size Between 770 and 855 Bytes"; dsize:770<>855; sid:1000022; rev:1;)
```

**Rule-by-rule intent:**
- **1000005 / 1000003**  catch FTP credential activity: username submission (`USER`) going *to* port 21, and a `530` response code coming *from* port 21 (failed login).
- **1000008 / 1000009**  detect image transfers by matching each format's magic bytes at the very start of the payload (`depth` limits false matches deeper in the stream).
- **1000021 / 1000014**  detect HTTP-level activity: a request for an `.html` resource (via the URI buffer) and a PNG MIME type declared in a response header.
- **1000011**  flags the BitTorrent handshake string, direction-agnostic (`<>`) since either peer can initiate.
- **1000019**  flags outbound ICMP echo requests (pings) using `itype:8`.
- **1000022**  a size-based anomaly rule, unrelated to content, useful for spotting oddly-sized packets regardless of protocol.

---

## Step 6  Quick Verification, Snort Only

Before committing to a full rule (or after testing one), confirm the pattern actually exists in the capture  using nothing but Snort's own filtering and payload dump, piped to `grep`.

```bash
# Extract FTP Server Banner (Status 220)
sudo snort -q -r mx-3.pcap -A console -d 'tcp port 21' | grep "220"

# Find FTP Submitted Usernames
sudo snort -q -r mx-3.pcap -A console -d 'tcp port 21' | grep -A2 "USER"

# Find Failed FTP Logins (Status 530)
sudo snort -q -r mx-3.pcap -A console -d 'tcp port 21' | grep "530"

# Scan for GIF Headers in Raw Payload
sudo snort -q -r mx-3.pcap -A console -d | grep -i "GIF8"

# Scan for HTTP MIME Headers
sudo snort -q -r mx-3.pcap -A console -d 'tcp port 80' | grep -i "Content-Type:"
```

**Use case:** This is your ground truth check  confirming traffic exists *before* you invest time writing a rule for it, or double-checking *why* a rule didn't fire.

**Explanation:**
- Running `snort -r` without `-c` skips rule loading entirely; Snort just parses and prints the packets it reads.
- The trailing quoted string (e.g. `'tcp port 21'`) is a BPF filter  the same filter syntax Snort's underlying capture library uses  narrowing which packets get processed, much like a rule header narrows traffic.
- `-d` dumps the ASCII/hex payload for every matched packet, giving `grep` something to search inside.

**Expected output:** Payload-dump lines containing only the matches after `grep`, e.g.:
```
55 53 45 52 20 61 64 6D 69 6E 0D 0A   USER admin..
```

---

## Quick Reference Summary

| Goal | Command |
|---|---|
| Live-inspect alerts in terminal | `snort -q -c local.rules -r file.pcap -A console` |
| See payload bytes with alerts | add `-d` |
| Save condensed alert log | `-l ./logs -A alert_brief` |
| Save full packet log | `-l ./logs` (no `-A`) |
| Re-read binary log | `snort -r snort.log.* -A console` |
| Verify traffic exists before writing a rule | `snort -r file.pcap -A console -d 'bpf filter'` piped to `grep` |
