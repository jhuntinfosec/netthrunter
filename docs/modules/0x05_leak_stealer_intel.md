# Module 0x05: Leak & Stealer Intel

## Overview

Infostealers (Redline, Vidar, Lumma, Raccoon) represent one of the highest-velocity initial-access supply chains in modern cybercrime. By analyzing stealer leaks and interacting with Telegram or dark web telemetry, we can automate C2 discovery directly from the source.

This module covers the technical internals of the major stealer families, methods for extracting embedded configurations, using leaked Telegram bot tokens as operator pivots, parsing the structured log formats that stealers produce, and the dark web distribution ecosystem that monetizes them. An end-to-end case study ties it all together, followed by an OPSEC and ethics section that must be read before working with any real data.

## Key Concepts

* **Stealer Core Mechanics**: How stealers serialize configurations and connect back to drop servers.
* **Telegram Telemetry**: Interacting with bot API keys left inside malware binaries or logs.
* **Config Extraction**: Parsing obfuscated or structured C2 strings from binaries and `.txt` dump files.

---

## Stealer Family Deep Dive

Understanding the technical internals of each family lets you write targeted parsers, recognize artifacts under analysis, and anticipate what data each family steals and how it phones home. Behavioral differences map directly to hunting signatures.

### Redline Stealer

**Language & architecture:** C# targeting .NET Framework 4.x. Distributed as a single executable or packed loader. The core build is a .NET assembly, making it trivially decompilable with dnSpy or ILSpy.

**C2 mechanism:** Redline uses a gRPC-based C2 channel. Early versions (pre-2022) communicated over raw TCP with a protobuf-serialized command structure. Later versions added HTTPS transport. The server-side panel is sold as a standalone product separate from the builder, creating a consistent API surface hunters can target.

**Browser credential theft:** Redline locates browser profile directories by resolving `%LOCALAPPDATA%` and `%APPDATA%` environment variables, then opens the SQLite database at:

```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
```

The schema relevant to hunters:

| Table | Columns of interest |
|-------|---------------------|
| `logins` | `origin_url`, `username_value`, `password_value` (AES-256-GCM encrypted) |
| `cookies` | `host_key`, `name`, `value`, `encrypted_value`, `expires_utc` |

Chromium-based browsers protect `password_value` and `encrypted_value` with DPAPI (Windows Data Protection API) bound to the current user context. Stealers decrypt this at runtime before exfiltration.

**Configuration storage:** Redline embeds its C2 address, bot ID, and build tag in .NET managed resources. These are accessible without execution via tools like `de4dot` (deobfuscator) or directly in dnSpy under `Resources` → `<AssemblyName>.Properties.Resources`. The resource is typically a base64-encoded JSON blob or a serialized .NET object graph:

```json
{
  "IP": "185.220.101.xx",
  "Port": "4141",
  "BotID": "RedLineStealer_Build",
  "Version": "v3.7"
}
```

**Hunting signatures:** Search VirusTotal for `imphash` clusters or `.NET` assemblies importing `Google.Protobuf`. JARM fingerprint the gRPC listener port.

---

### Vidar Stealer

**Language & architecture:** C++ (MSVC-compiled, 32-bit PE). No .NET dependency. Heavy reliance on dynamic DLL loading — Vidar resolves API calls at runtime by walking the PEB (Process Environment Block) loader list, making static analysis harder.

**C2 mechanism:** HTTP POST to a panel path (commonly `/gate.php` or `/index.php`). The C2 URL is not stored plaintext. Vidar uses a **Telegram dead drop resolver** pattern:

1. The binary contains a Telegram bot token and a channel/chat ID (or username) encoded in the binary's string table — sometimes XOR-obfuscated.
2. At execution time, Vidar calls `api.telegram.org/bot<TOKEN>/getChat?chat_id=<ID>` or reads from a pinned message in a Telegram channel.
3. The C2 URL is published in that channel's pinned message or channel description (`bio` field).
4. Vidar fetches the URL, connects to the actual C2 panel.

This indirection lets operators change their C2 infrastructure without rebuilding the binary — only the Telegram channel content changes.

**DLL dependency loading:** Vidar downloads several legitimate DLLs (commonly `nss3.dll`, `mozglue.dll`, `msvcp140.dll`) from its C2 during the first stage. These are used for Firefox profile decryption. The DLL download is a behavioral signature visible in sandbox reports.

**Config extraction:** Extract the XOR key and ciphertext using a hex editor or `strings` + entropy analysis. The XOR key is often a short (4–8 byte) constant repeated across the block. Once decoded, the bot token is visible as `<numeric_id>:<alpha_string>`.

---

### Lumma Stealer (LummaC2)

**Language & architecture:** C (not C++), targeting Windows x86/x64. Sold as Malware-as-a-Service (MaaS) via a Telegram storefront. Highly active since 2022; notable for frequent anti-analysis updates.

**Anti-sandbox techniques:**
- **Mouse movement check:** Lumma queries cursor position at two time offsets (`GetCursorPos`). If the cursor has not moved, it assumes a sandbox and exits.
- **Screen resolution check:** Calls `GetSystemMetrics(SM_CXSCREEN)` / `SM_CYSCREEN`. Resolutions below 800×600 or exactly 800×600 trigger an exit (typical headless sandbox values).
- **Timing checks:** Uses `GetTickCount` or RDTSC instruction to detect accelerated execution.
- **Process list enumeration:** Checks for known analysis tool process names (`wireshark.exe`, `procmon.exe`, `x64dbg.exe`).

**Process injection:** Later Lumma builds use process hollowing or `NtMapViewOfSection` injection to execute payload code inside a legitimate host process (`explorer.exe`, `svchost.exe`).

**String encryption:** Lumma encrypts most strings (C2 URL, config key, version tag) with a custom XOR + rotation cipher. The decryption stub is typically a small function called early in `WinMain`. Recognizing this stub pattern in disassembly lets you write a YARA rule targeting the decryption routine regardless of payload content.

**Telegram distribution:** Lumma panels are sold and accessed via Telegram. Bot tokens in samples extracted by researchers have been used to enumerate operator chat histories using `getUpdates`, sometimes revealing other buyer conversations.

---

### Raccoon Stealer v2

**Language & architecture:** Rewritten in C/C++ for v2 (v1 was C++/COM-heavy). Leaner than v1, distributed as a DLL loaded by a shellcode stub, which helps evade import-based detection.

**C2 mechanism:** HTTP-based, similar to Vidar, but Raccoon v2 uses **Telegram for config distribution** in a slightly different pattern: the Telegram channel or bot returns a JSON object containing the panel URL, rather than embedding it in a Telegram message description.

**DLL-based architecture:** The core stealer functionality is a DLL. The loader stub (often a small `.exe` or injected shellcode) downloads and loads this DLL from the C2. This separation makes detection harder because the initial dropper has minimal malicious code.

**Exfiltration format:** Raccoon v2 packages stolen data into a `.zip` archive before POSTing to the C2, unlike Redline which streams data in structured messages.

---

### Brief Mentions: Emerging Families

| Family | Language | Notable Trait |
|--------|----------|---------------|
| **Stealc** | C | Modular plugin architecture, uses Telegram for C2 resolution like Vidar |
| **MetaStealer** | Go | Targets macOS in addition to Windows; uses HTTP C2 |
| **Aurora** | Go | Sold on dark web forums; cross-platform ambitions; relatively rare in the wild |

---

## Config Extraction Methods

Regardless of family, stealer configs follow a small set of embedding patterns. Mastering these patterns means you can extract C2 data without executing the binary.

### Embedded C2 in .NET Resources (Redline Pattern)

1. Open the sample in dnSpy or ILSpy.
2. Navigate to the `Resources` node in the assembly tree.
3. Look for `Properties.Resources` or a resource named after the build.
4. Resource data is often base64-encoded. Decode and parse as JSON or protobuf.
5. Alternatively, use `de4dot` to deobfuscate and then `strings` on the cleaned binary.

Command-line extraction without a GUI:

```bash
# Extract all managed resources from a .NET assembly
monodis --resources SampleRedline.exe 2>/dev/null
# or use ilspycmd
ilspycmd --list-resources SampleRedline.exe
```

### XOR-Decoded Config Blocks (Vidar Pattern)

1. Open binary in Ghidra or IDA.
2. Identify strings with high entropy that are short (16–64 bytes) followed immediately by a loop decoding them.
3. The decode loop is the XOR stub: it iterates over a buffer, XORing each byte with a rotating key.
4. Extract the key by noting the first decoded output character and XORing against the expected first byte of `https://api.telegram.org/`.

Python snippet to brute-force a single-byte XOR key given a ciphertext block and known plaintext prefix:

```python
# Educational: demonstrates XOR key recovery from known-plaintext prefix
ciphertext = bytes.fromhex("3e1d2f4a...")  # extracted from binary
known_prefix = b"https://"
key_byte = ciphertext[0] ^ known_prefix[0]
plaintext = bytes(b ^ key_byte for b in ciphertext)
print(plaintext)
```

### Telegram Bot Token Extraction from Binary Strings

The `strings` utility (or FLOSS for deobfuscated strings) will surface tokens matching the Telegram format: `\d{8,11}:[A-Za-z0-9_-]{35}`.

```bash
# Extract printable strings, filter for Telegram token pattern
strings -n 20 sample.exe | grep -E '[0-9]{8,11}:[A-Za-z0-9_-]{35}'

# FLOSS for obfuscated/stack strings (from Mandiant)
floss sample.exe | grep -E '[0-9]{8,11}:[A-Za-z0-9_-]{35}'
```

Once you have the token, the next section explains what to do with it.

### Stealer Config Structure

A typical Redline-style config JSON (values are research-reconstructed, not real):

```json
{
  "C2": "185.220.101.0:4141",
  "BotID": "Build_Campaign_2024",
  "Version": "3.9",
  "Key": "BuildEncryptionKey",
  "Delay": 0,
  "AntiAV": false,
  "Gate": "/gate.php"
}
```

Vidar-style configs (after Telegram dead drop resolution) typically contain only the panel URL and a campaign identifier.

---

## Telegram Bot Intelligence

When you extract a Telegram bot token from a stealer binary or log file, you have a direct API credential into the operator's command channel. The Telegram Bot API is a REST interface — no special tooling required.

**Important:** Only use tokens you have extracted from malware samples in an authorized research context. Using a bot token to read private messages or interfere with operations you are not authorized to monitor may violate laws in your jurisdiction. See the OPSEC & Ethics section.

### Core API Endpoints

All endpoints follow the pattern: `https://api.telegram.org/bot<TOKEN>/<method>`

#### `getMe` — Validate the token and identify the bot

```
GET https://api.telegram.org/bot<TOKEN>/getMe
```

Response fields of intelligence value:

| Field | Meaning |
|-------|---------|
| `id` | Unique bot ID — stable across renames, useful as a pivot key |
| `username` | Bot handle (e.g., `@RedlineC2Bot`) — searchable in Telegram |
| `first_name` | Display name — often reflects operator naming conventions |
| `can_read_all_group_messages` | If true, the bot was added to groups, extending its reach |

A successful `getMe` response confirms the token is live and the operator's infrastructure is still active.

#### `getUpdates` — Read messages delivered to the bot

```
GET https://api.telegram.org/bot<TOKEN>/getUpdates
```

Returns up to 100 messages (configurable with `limit`) that the bot has received. In stealer operations, these are exfiltrated log summaries sent by victim machines. Each update contains:

| Field | Meaning |
|-------|---------|
| `message.chat.id` | The chat or channel ID receiving victim data |
| `message.text` | May contain system info, IP, credentials summary |
| `message.from.id` | Sender's Telegram user ID — can pivot to operator identity |
| `message.date` | Unix timestamp — reveals operational tempo |

**Rate limits:** Telegram allows roughly 30 `getUpdates` polls per second per token. For bulk token validation, implement a brief sleep between requests to avoid triggering Telegram's flood protection (429 responses).

#### `getChat` — Inspect a channel or group

```
GET https://api.telegram.org/bot<TOKEN>/getChat?chat_id=<CHAT_ID>
```

Where `CHAT_ID` can be a numeric ID (from `getUpdates` results) or a `@username`. Returns:

| Field | Meaning |
|-------|---------|
| `title` | Channel or group name |
| `description` | Often contains the C2 URL in Vidar-pattern malware |
| `pinned_message` | Pinned content — Vidar stores the gate URL here |
| `username` | Public channel handle — linkable to dark web storefronts |
| `invite_link` | If present, indicates the channel is accessible to others |

#### `getChatAdministrators` — Identify operators

```
GET https://api.telegram.org/bot<TOKEN>/getChatAdministrators?chat_id=<CHAT_ID>
```

Returns a list of admins for the chat. Each admin entry includes their `user.id`, `user.username`, and `user.first_name`. These identifiers can be cross-referenced with dark web forum accounts and other stealer infrastructure.

### Interpreting Bot API Behavior

| API Response | Interpretation |
|-------------|----------------|
| 200 with valid JSON | Token is live; operator infrastructure is active |
| `{"ok":false,"error_code":401}` | Token was revoked; operator rotated credentials |
| `{"ok":false,"error_code":403}` | Bot was blocked or deleted by operator |
| `{"ok":false,"error_code":429}` | Rate limited — back off and retry |
| Connection timeout | C2 domain may be sinkholed or offline |

A revoked token tells you the operator is opsec-aware and rotates credentials — this is itself a behavioral indicator worth noting in a threat intelligence profile.

---

## Stealer Log Structure

Stealers organize exfiltrated data into a predictable directory and file structure. Recognizing this structure lets you write targeted parsers rather than general-purpose text miners.

### Typical Directory Layout

```
<victim_id>/
├── Passwords.txt              # Browser-extracted credentials
├── Cookies/
│   ├── Chrome_Default.txt     # Cookie dumps per browser/profile
│   └── Firefox_default.txt
├── Autofill/
│   └── Chrome_Default.txt     # Form autofill data
├── CC/
│   └── Chrome_Default.txt     # Saved payment card data
├── SystemInfo.txt             # Victim machine details
├── Screenshot.jpg             # Desktop screenshot at time of infection
├── FileGrabber/               # Files matching operator-configured extensions
│   └── Desktop_*.docx
└── Wallets/                   # Cryptocurrency wallet files
    ├── Metamask/
    └── Exodus/
```

The `<victim_id>` directory name is typically the machine hostname or a generated GUID, used by the operator to track individual victims.

### Passwords.txt Format

The credential log is a structured flat file, not a database. A typical entry block:

```
URL: https://mail.example.com/login
Username: john.smith@example.com
Password: [REDACTED - example only]
Application: Google Chrome

URL: https://banking.example.com
Username: jsmith1987
Password: [REDACTED - example only]
Application: Mozilla Firefox
```

Parsers should look for alternating `URL:` / `Username:` / `Password:` / `Application:` line groups. The separator between entries is typically a blank line or `===` divider.

### SystemInfo.txt Format

```
Date: 2024-01-15 14:32:11
MachineID: DESKTOP-ABC1234\JohnSmith
HWID: A1B2C3D4E5F6A1B2
OS: Windows 10 Pro x64 (Build 19045)
CPU: Intel Core i7-10700K
RAM: 16 GB
Resolution: 1920x1080
IP (external): 203.0.113.88
Country: US
Timezone: America/New_York
Antivirus: Windows Defender
Installed Browsers: Chrome 120, Firefox 121, Edge 120
```

The `HWID` (Hardware ID) is a fingerprint of the machine, used by operators and by credential market platforms to deduplicate victims and price logs.

### Browser Database Schema

When stealers access browser SQLite databases directly (rather than decrypting and formatting), the raw schema is:

**`Login Data` (Chromium):**

```sql
SELECT origin_url, username_value, password_value
FROM logins
WHERE blacklisted_by_user = 0;
```

`password_value` is a BLOB: the first 3 bytes are the literal string `v10` or `v11` (Chromium version marker), followed by a 12-byte nonce, then AES-256-GCM ciphertext, then a 16-byte authentication tag.

**`Cookies` (Chromium):**

```sql
SELECT host_key, name, value, encrypted_value, expires_utc, is_httponly, is_secure
FROM cookies;
```

`value` is plaintext for non-sensitive cookies; `encrypted_value` uses the same DPAPI/AES-GCM scheme as passwords. The `expires_utc` field is a Windows FILETIME integer (microseconds since 1601-01-01).

**Firefox (`logins.json` + `key4.db`):**

Firefox does not use SQLite for passwords. Credentials are stored in `logins.json` as NSS (Network Security Services) encrypted blobs. The key is derived from the master password (default: empty string) and stored in `key4.db`. Most stealers call the NSS library functions directly to decrypt, which is why Vidar downloads `nss3.dll`.

---

## Dark Web Telemetry

### Telegram as a Stealer Distribution Network

Telegram channels are the primary distribution and notification mechanism for modern stealers:

1. **Notification channels:** Each victim infection triggers a message to a private Telegram channel — either a formatted summary (SystemInfo + credential counts) or the full `.zip` archive as a file attachment.
2. **Public log-sharing channels:** Some operators or resellers post sample logs publicly to advertise freshness and quality, functioning as a demo for potential buyers.
3. **Automated bot marketplaces:** Bot-driven shops (common on Telegram) accept cryptocurrency and deliver log archives automatically without human operator involvement.

### Marketplace Patterns

**Russian Market** and **Genesis Market** (before its 2023 seizure) established the log pricing model now widely copied:

- Logs are priced by **freshness** (days since infection), **credential count**, and **banking/crypto presence**.
- A fresh log with active banking session cookies fetches $5–50 USD. Older logs drop to under $1.
- Logs include a **bot ID** and **HWID** — buyers pay for unique victims, deduplication is enforced by the platform.

**Temporal patterns in dump releases:**

- Mass dump releases frequently follow major news events (data breach announcements, new stealer campaigns).
- Release cadence follows business hours in Eastern European time zones — operators are treating this as employment.
- Searching for Telegram channel activity spikes around patch Tuesdays correlates with campaigns exploiting newly disclosed vulnerabilities used for distribution.

### Automated Bot Marketplaces

Bot-driven shops accept commands like `/buy <log_id>` or `/search <domain>`. Researchers have mapped these by:

1. Finding the bot username from public forum advertisements.
2. Sending `/start` to enumerate the command menu.
3. Using `/search <domain>` with non-sensitive domain names to understand the product catalog size.

This reconnaissance is passive (no credential purchase) and reveals the operator's victim pool breadth.

---

## Tool References

| Tool | Purpose | URL |
|------|---------|-----|
| **VirusTotal** | File scanning, behavior reports, sandbox detonation, hash pivoting | virustotal.com |
| **MalwareBazaar** (abuse.ch) | Malware sample database, stealer-tagged samples, YARA rule matching | bazaar.abuse.ch |
| **Any.Run** | Interactive sandbox — execute in browser, observe behavior in real time | any.run |
| **Triage (Hatching)** | Automated sandbox — behavioral reports, config extraction built in | tria.ge |
| **URLhaus** | Malware delivery URL database — track stealer distribution URLs | urlhaus.abuse.ch |
| **InQuest Labs** | Deep file inspection, YARA scanning, IOC extraction from file structures | labs.inquest.net |

### Triage Config Extraction

Triage has built-in detonation profiles for major stealer families and extracts configs automatically. After submitting a sample:

1. Navigate to **Static** → **Configurations** in the report.
2. Triage reports the decoded C2 URL, bot ID, and campaign tag without manual extraction.
3. Use the Triage API (`api.tria.ge`) to bulk-query configs for campaigns.

### MalwareBazaar Tagging

Search MalwareBazaar for stealer samples by family tag:

```
https://bazaar.abuse.ch/browse/tag/RedLine/
https://bazaar.abuse.ch/browse/tag/Vidar/
https://bazaar.abuse.ch/browse/tag/LummaC2/
```

Each sample entry includes SHA256, submission date, file type, and any extracted tags. Cross-reference SHA256 against VirusTotal for additional behavioral reports.

---

## Case Study: From Stealer Log Dump to C2 Infrastructure Map

This walkthrough illustrates the full pivot chain — cross-referencing Module 0x03 clustering techniques at the infrastructure mapping stage.

### Step 1: Receive the Dump

A threat intelligence sharing partner provides a `.zip` file containing 47 individual victim log folders. This is a **research/authorized context** — you have written permission to analyze this data.

### Step 2: Parse and Triage

Run the module capstone parser (see project below) in `--mock` mode first to validate the pipeline, then point it at the actual dump:

```bash
python leak_parser.py -d ./dump_2024_01/ --format json --validate-tokens
```

The parser walks each victim folder, extracts:
- External IPs from `SystemInfo.txt`
- Telegram bot tokens from `Important.txt` or any `.txt` file
- C2 panel URLs from `Passwords.txt` and credential URL patterns

### Step 3: Validate Telegram Bot Tokens

For each extracted token, call `getMe`:

```
GET https://api.telegram.org/bot<TOKEN>/getMe
```

Suppose 3 of the 47 logs contain the same bot token. This collapses those 47 victims under a single operator's bot — confirming it's one campaign, not three separate actors.

Follow with `getChat` against any chat IDs found in `getUpdates` to retrieve the operator's active C2 URL from the channel description (Vidar-pattern).

### Step 4: Extract C2 URLs from Configs

The `getChat` response returns:
```json
{
  "description": "gate: https://185.220.101.0/panel/gate.php | build: campaign_jan2024"
}
```

Now you have a live C2 IP and panel path.

### Step 5: Map Infrastructure — Cross-Reference Module 0x03

Using the C2 IP `185.220.101.0`:

1. **ASN lookup:** The IP is in AS59930 (a bulletproof hosting provider). Query for all IPs in that ASN range.
2. **Certificate CT logs (Module 0x02):** Search for TLS certificates issued to domains resolving to this IP — find 3 additional panel subdomains.
3. **SSH key clustering (Module 0x03):** Banner-scan the ASN range for SSH. Two other IPs share the same SSH host key fingerprint — this operator is cloning VM images, not configuring each server independently.
4. **JARM fingerprinting (Module 0x01):** All panel IPs return the same JARM hash — the same nginx/TLS configuration. This becomes a hunting signature to find future infrastructure before it goes live.

### Step 6: Document and Report

Create a threat actor profile:
- Bot token (sanitized — last 6 chars redacted)
- Bot ID (stable pivot key)
- Campaign tag from config
- C2 IP range + ASN
- JARM fingerprint
- SSH key cluster
- Victim volume estimate (log count)
- Temporal activity window (log timestamps)

Submit IOCs to VirusTotal Graph, share indicators via MISP or a threat intel feed.

---

## OPSEC & Ethics

Working with stealer log data — even in a research context — carries significant legal and ethical obligations. Failure to follow these practices can result in criminal liability, GDPR enforcement actions, and harm to the real people whose data appears in these logs.

### Legal Frameworks

**CFAA (Computer Fraud and Abuse Act, USA):** Accessing a computer system without authorization, or in excess of authorization, is a federal crime. Possessing stolen credentials with intent to use them is also covered. Analysis of malware samples and log structure for defensive research has generally been treated as permissible, but the line between "analysis" and "unauthorized access" is fact-specific. Get a legal opinion before working with live credentials.

**GDPR (EU):** Stealer logs contain personal data of EU residents — names, email addresses, passwords. Possessing, processing, or transmitting this data without legal basis violates GDPR. The researcher exception is narrow. Data minimization applies: don't store more than necessary for your documented research purpose.

**Local law:** Many jurisdictions have computer fraud and data protection laws independent of (and sometimes stricter than) US federal law. Research the law in your jurisdiction before starting.

### Data Handling Policies

1. **Isolation:** Analyze log data only in isolated environments (airgapped VMs, no network access to production systems).
2. **Minimization:** Extract only the indicators you need (IPs, tokens, hashes). Do not retain full credential dumps beyond the analysis session.
3. **Destruction:** After analysis, securely delete the raw data. Use `shred` or equivalent. Document the destruction date and method.
4. **No use of credentials:** Never test, attempt to authenticate with, or reuse any credential found in a stealer log. This is both a legal bright line and an ethical one.
5. **Responsible disclosure:** If your analysis reveals an active C2 with victim data at risk, consider reporting to the C2 hosting provider, relevant national CERT, or law enforcement — not as an obligation but as an option worth evaluating.

### OPSEC for the Researcher

- Use dedicated research infrastructure (separate from personal/corporate accounts) when querying Telegram APIs or visiting C2 URLs.
- Use a VPN or Tor to prevent your researcher IP from appearing in the operator's access logs.
- Do not interact with the Telegram bot in ways that could generate messages (don't send commands — only query read-only endpoints like `getMe` and `getUpdates`).
- Keep notes on what you accessed, when, and why — this documentation is your legal defense if your activities are ever questioned.
- See Module 0x09 for comprehensive researcher OPSEC methodology.

---

## 🛠️ Module Project: Stealer Run-log Parsing

*Reference: Data Engineering for Cybersecurity*

We create a pipeline to process massive amounts of raw textual data (like stolen browser DBs and `Important.txt` bot logs) and extract C2 indicators or hardcoded API keys.

### The Objective

1. Load a `.zip` or a giant text file representing a parsed infostealer dump.
2. Use regular expressions to extract IP addresses, Discord Webhook URLs, and Telegram Bot API tokens.
3. Validate Telegram bot tokens against the Bot API (with mock fallback for offline use).
4. Detect the stealer family from the log directory structure.
5. Format the identified artifacts for further investigation.

See the capstone project at `projects/0x05_leak_parser/leak_parser.py` for the full implementation.

### Quick Start

```bash
# Demo mode — generates mock log structure and processes it
python leak_parser.py --mock

# Process a single file
python leak_parser.py -f raw_data/Important.txt

# Process a directory of logs
python leak_parser.py -d ./stealer_dumps/

# Output as JSON with token validation
python leak_parser.py -d ./stealer_dumps/ --format json --validate-tokens

# Output as CSV for bulk analysis
python leak_parser.py -d ./stealer_dumps/ --format csv
```

**Takeaway:** A standalone Python extractor to triage thousands of stealer records and immediately pivot to the adversary's management console — then cross-reference with Modules 0x01–0x03 to map the full infrastructure cluster.
