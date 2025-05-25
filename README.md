# OpenWRT Auto-Security System

**Enterprise-grade automated intrusion detection and blocking for OpenWRT routers**

[![OpenWRT Compatible](https://img.shields.io/badge/OpenWRT-22.03%2B-blue.svg)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Firewall](https://img.shields.io/badge/Firewall-nftables-red.svg)](https://netfilter.org/projects/nftables/)

## 🛡️ What is Auto-Security?

Auto-Security transforms your OpenWRT router into a professional-grade security appliance with automated threat detection and blocking capabilities. Based on real-world enterprise security research, it provides:

- **Real-time attack detection** and automated blocking
- **Clean threat intelligence** with noise reduction
- **Zero-configuration** automated protection
- **Enterprise-grade logging** and reporting
- **Resource-optimized** performance

## 🔥 Key Features

### Automated Protection
- ✅ **Auto-ban repeat attackers** (configurable threshold)
- ✅ **Silent dropping** of banned IPs (no resource waste)
- ✅ **Clean logging** (only new threats appear in logs)
- ✅ **Persistent bans** across reboots

### Professional Monitoring
- 📊 **Real-time attack monitoring**
- 📈 **Security status reports**
- 🎯 **Threat intelligence analysis**
- 📋 **Port/service targeting analysis**

### Enterprise Management
- ⚙️ **Simple command-line interface**
- 🔧 **Configurable thresholds and policies**
- 📂 **Comprehensive logging**
- 🔄 **Easy ban management**

## 🚀 Quick Installation

### One-Line Install
```bash
curl -fsSL https://raw.githubusercontent.com/yourusername/openwrt-auto-security/main/install.sh | sh
```

### Manual Installation
```bash
wget https://raw.githubusercontent.com/yourusername/openwrt-auto-security/main/install.sh
chmod +x install.sh
./install.sh
```

## 📋 Requirements

- **OpenWRT 22.03+** (firewall4/nftables required)
- **Logging enabled** in firewall configuration
- **Basic familiarity** with OpenWRT administration

### Firewall Configuration Required

Add these rules to `/etc/config/firewall` for attack logging:

```bash
config rule
    option name 'Log-Blocked-WAN-TCP'
    option src 'wan'
    option proto 'tcp'
    option target 'DROP'
    option log '1'
    option log_limit '10/minute'

config rule
    option name 'Log-Blocked-WAN-UDP'
    option src 'wan'
    option proto 'udp'
    option target 'DROP'
    option log '1'
    option log_limit '10/minute'
```

Then restart firewall: `/etc/init.d/firewall restart`

## 🎯 Usage

### Quick Status Check
```bash
auto-security status
```

### Monitor Live Attacks
```bash
auto-security live
```

### View Banned IPs
```bash
auto-security banned
```

### Manual Threat Scan
```bash
auto-security scan
```

### Unban Specific IP
```bash
auto-security unban 1.2.3.4
```

### Reset All Bans
```bash
auto-security reset
```

## ⚙️ Configuration

Edit `/opt/auto-security/auto-security.conf`:

```bash
# Attack detection threshold (attacks before auto-ban)
ATTACK_THRESHOLD=5

# Scan interval (minutes)
SCAN_INTERVAL=15

# Ban duration (0 = permanent)
BAN_DURATION=0

# Log retention (days)
LOG_RETENTION=30
```

## 📊 Example Output

### Security Status Report
```
🛡️  PROTECTION STATUS:
   Active banned IPs: 23
   Total attacks today: 156

🎯 TOP THREAT SOURCES (Last 24 hours):
   45.142.193.92: 27 attacks
   54.247.211.213: 24 attacks
   52.16.124.44: 18 attacks

🔍 TARGET PORT ANALYSIS:
   Port 22 (SSH): 45 attempts
   Port 443 (HTTPS): 32 attempts
   Port 3389 (RDP): 28 attempts
```

### Live Attack Monitoring
```
🔴 LIVE ATTACK MONITORING
Timestamp                 | Source IP      | Target Port
---------------------------------------------------------
Sun May 25 14:53:54 2025  | 18.217.194.148 | 4433
Sun May 25 14:54:04 2025  | 64.23.178.20   | 5972
Sun May 25 14:54:06 2025  | 185.47.172.136 | 5432
```

## 🏢 Business/Enterprise Use

### Multi-Site Deployment
```bash
# Deploy to multiple OpenWRT routers
for router in router1.local router2.local router3.local; do
    scp install.sh root@$router:/tmp/
    ssh root@$router "/tmp/install.sh"
done
```

### Centralized Monitoring
```bash
# Collect reports from multiple routers
ssh root@router1.local "auto-security status" > router1-report.txt
ssh root@router2.local "auto-security status" > router2-report.txt
```

## 🔧 Advanced Configuration

### Custom Ban Rules
```bash
# Manually ban entire subnets
nft add rule inet fw4 input_wan ip saddr 192.168.1.0/24 drop comment "manual-ban-subnet"

# Ban by country (requires geoip)
nft add rule inet fw4 input_wan ip saddr @country-blocklist drop
```

### Integration with External Systems
```bash
# Export banned IPs for SIEM integration
auto-security banned | cut -d' ' -f2 > banned-ips.txt

# Custom alerting
echo "auto-security status | mail -s 'Security Report' admin@company.com" >> /etc/crontabs/root
```

## 📁 File Structure

```
/opt/auto-security/
├── auto_ban.sh           # Core detection engine
├── monitor.sh            # Monitoring and reporting
├── auto-security.conf    # Configuration file
└── logs/
    ├── banned_ips.log    # Ban activity log
    └── banlist.txt       # Historical ban database

/usr/bin/auto-security    # Management command
```

## 🐛 Troubleshooting

### Common Issues

**Auto-ban not working:**
```bash
# Check if firewall logging is enabled
logread | grep "Log-Blocked-WAN-Access"

# Verify nftables rules
nft list chain inet fw4 input_wan
```

**No attacks being logged:**
```bash
# Check firewall configuration
uci show firewall | grep log

# Restart firewall
/etc/init.d/firewall restart
```

**Commands not found:**
```bash
# Reinstall management commands
/opt/auto-security/install.sh
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on real-world enterprise security research
- Inspired by the OpenWRT community's commitment to security
- Based on proven nftables/firewall4 architecture

## 📞 Support

- **Documentation**: [Wiki](https://github.com/yourusername/openwrt-auto-security/wiki)
- **Issues**: [GitHub Issues](https://github.com/yourusername/openwrt-auto-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/openwrt-auto-security/discussions)

---

**⚠️ Important**: This system provides automated protection but should be part of a comprehensive security strategy. Regular updates and monitoring are recommended.

**🛡️ Made with ❤️ for the OpenWRT community**