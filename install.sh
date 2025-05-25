#!/bin/sh
# OpenWRT Auto-Security System Installer
# Advanced automated intrusion detection and blocking for OpenWRT
# Version: 1.0
# Author: Rasmus Kjærbo (raskjaerbo / componental.co)
# Based on real-world enterprise security research

set -e

VERSION="1.0"
INSTALL_DIR="/opt/auto-security"
CONFIG_FILE="$INSTALL_DIR/auto-security.conf"
LOG_FILE="/tmp/auto-security.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "  OpenWRT Auto-Security System v${VERSION}"
    echo "  Enterprise-Grade Automated Threat Protection"
    echo "=================================================="
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date): $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$(date): WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date): ERROR: $1" >> "$LOG_FILE"
    exit 1
}

check_openwrt() {
    if [ ! -f /etc/openwrt_release ]; then
        error "This installer is designed for OpenWRT systems only"
    fi
    
    . /etc/openwrt_release
    log "Detected OpenWRT ${DISTRIB_RELEASE} on ${DISTRIB_TARGET}"
}

check_firewall4() {
    if ! which nft >/dev/null 2>&1; then
        error "This system requires firewall4 (nftables). Please upgrade to OpenWRT 22.03+"
    fi
    log "Firewall4 (nftables) detected"
}

create_directories() {
    log "Creating installation directories..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/config"
    mkdir -p "/etc/auto-security"
}

install_auto_ban_script() {
    log "Installing auto-ban detection script..."
    
    cat > "$INSTALL_DIR/auto_ban.sh" << 'EOF'
#!/bin/sh
# Auto-Ban Script - Detects and blocks repeat attackers
# Part of OpenWRT Auto-Security System

CONFIG_FILE="/opt/auto-security/auto-security.conf"
LOGFILE="/opt/auto-security/logs/banned_ips.log"

# Load configuration
if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"
else
    # Default configuration
    ATTACK_THRESHOLD=5
    BAN_DURATION=3600
    SCAN_PERIOD="$(date +'%b %d')"
fi

DATE="$SCAN_PERIOD"

log_ban() {
    echo "$(date): $1" | tee -a "$LOGFILE"
    logger -t AUTO-SECURITY "$1"
}

# Main detection logic
log_ban "Scanning for repeat attackers (threshold: $ATTACK_THRESHOLD attacks)..."

# Find IPs that attacked more than threshold today
logread | grep "Log-Blocked-WAN-Access" | grep "$DATE" | \
sed 's/.*SRC=\([0-9.]*\).*/\1/' | sort | uniq -c | \
awk -v threshold="$ATTACK_THRESHOLD" '$1 > threshold {print $2, $1}' | while read IP COUNT; do
    
    # Check if already banned
    if ! nft list ruleset | grep -q "ip saddr $IP drop"; then
        log_ban "THREAT DETECTED: Banning $IP after $COUNT attacks"
        
        # Insert at TOP of chain (before logging rules)
        nft insert rule inet fw4 input_wan ip saddr $IP counter drop comment "auto-banned-$IP"
        
        # Optional: Add to banlist with timestamp
        echo "$(date '+%Y-%m-%d %H:%M:%S') $IP $COUNT" >> "$INSTALL_DIR/logs/banlist.txt"
        
        log_ban "SUCCESS: $IP blocked permanently"
    fi
done

# Summary
TOTAL_BANNED=$(nft list ruleset | grep "auto-banned" | wc -l)
log_ban "Auto-ban scan complete. Active bans: $TOTAL_BANNED"
EOF

    chmod +x "$INSTALL_DIR/auto_ban.sh"
}

install_monitoring_script() {
    log "Installing monitoring and reporting script..."
    
    cat > "$INSTALL_DIR/monitor.sh" << 'EOF'
#!/bin/sh
# Monitoring Script - Provides security analytics and reports
# Part of OpenWRT Auto-Security System

INSTALL_DIR="/opt/auto-security"

generate_report() {
    echo "=============================================="
    echo "  OpenWRT Auto-Security Status Report"
    echo "  Generated: $(date)"
    echo "=============================================="
    echo ""
    
    echo "🛡️  PROTECTION STATUS:"
    echo "   Active banned IPs: $(nft list ruleset | grep 'auto-banned' | wc -l)"
    echo "   Total attacks today: $(logread | grep 'Log-Blocked-WAN-Access' | grep "$(date +'%b %d')" | wc -l)"
    echo ""
    
    echo "🎯 TOP THREAT SOURCES (Last 24 hours):"
    logread | grep "Log-Blocked-WAN-Access" | grep "$(date +'%b %d')" | \
    sed 's/.*SRC=\([0-9.]*\).*/\1/' | sort | uniq -c | sort -nr | head -5 | \
    while read count ip; do
        echo "   $ip: $count attacks"
    done
    echo ""
    
    echo "🔍 TARGET PORT ANALYSIS:"
    logread | grep "Log-Blocked-WAN-Access" | grep "$(date +'%b %d')" | \
    grep -o "DPT=[0-9]*" | sed 's/DPT=//' | sort | uniq -c | sort -nr | head -5 | \
    while read count port; do
        case $port in
            22) service="SSH" ;;
            80) service="HTTP" ;;
            443) service="HTTPS" ;;
            3389) service="RDP" ;;
            5432) service="PostgreSQL" ;;
            445) service="SMB" ;;
            *) service="Unknown" ;;
        esac
        echo "   Port $port ($service): $count attempts"
    done
    echo ""
    
    echo "📊 RECENT ACTIVITY:"
    echo "   Last 5 blocked attacks:"
    logread | grep "Log-Blocked-WAN-Access" | tail -5 | while read line; do
        timestamp=$(echo "$line" | cut -d' ' -f1-4)
        ip=$(echo "$line" | sed 's/.*SRC=\([0-9.]*\).*/\1/')
        port=$(echo "$line" | sed 's/.*DPT=\([0-9]*\).*/\1/')
        echo "   $timestamp - $ip → Port $port"
    done
    echo ""
    
    echo "=============================================="
}

case "$1" in
    "report")
        generate_report
        ;;
    "live")
        echo "🔴 LIVE ATTACK MONITORING (Press Ctrl+C to stop)"
        echo "Timestamp                 | Source IP      | Target Port"
        echo "---------------------------------------------------------"
        logread -f | grep "Log-Blocked-WAN-Access" | while read line; do
            timestamp=$(echo "$line" | cut -d' ' -f1-4)
            ip=$(echo "$line" | sed 's/.*SRC=\([0-9.]*\).*/\1/')
            port=$(echo "$line" | sed 's/.*DPT=\([0-9]*\).*/\1/')
            printf "%-25s | %-14s | %s\n" "$timestamp" "$ip" "$port"
        done
        ;;
    "banned")
        echo "🚫 CURRENTLY BANNED IPs:"
        nft list ruleset | grep "auto-banned" | sed 's/.*ip saddr \([0-9.]*\) .*/\1/' | \
        while read ip; do
            count=$(grep "$ip" "$INSTALL_DIR/logs/banlist.txt" 2>/dev/null | tail -1 | cut -d' ' -f4)
            echo "   $ip (${count:-unknown} attacks)"
        done
        ;;
    *)
        echo "Usage: $0 {report|live|banned}"
        echo ""
        echo "  report  - Generate security status report"
        echo "  live    - Monitor attacks in real-time"
        echo "  banned  - List currently banned IPs"
        ;;
esac
EOF

    chmod +x "$INSTALL_DIR/monitor.sh"
}

create_configuration() {
    log "Creating default configuration..."
    
    cat > "$CONFIG_FILE" << 'EOF'
# OpenWRT Auto-Security Configuration
# Adjust these values based on your security requirements

# Attack detection threshold (number of attacks before auto-ban)
ATTACK_THRESHOLD=5

# How often to run auto-ban detection (in minutes)
SCAN_INTERVAL=15

# Ban duration (in seconds, 3600 = 1 hour, 0 = permanent)
BAN_DURATION=0

# Log retention (in days)
LOG_RETENTION=30

# Enable/disable features
ENABLE_AUTO_BAN=1
ENABLE_MONITORING=1
ENABLE_ALERTS=1

# Email alerts (optional - requires additional setup)
ALERT_EMAIL=""
SMTP_SERVER=""
EOF
}

setup_logging() {
    log "Configuring enhanced firewall logging..."
    
    # Check if logging rules already exist
    if ! nft list chain inet fw4 input_wan | grep -q "Log-Blocked-WAN-Access"; then
        warn "Firewall logging rules not found. Please ensure your firewall is configured for logging."
        echo ""
        echo "Add these rules to your /etc/config/firewall:"
        echo ""
        echo "config rule"
        echo "    option name 'Log-Blocked-WAN-TCP'"
        echo "    option src 'wan'"
        echo "    option proto 'tcp'"
        echo "    option target 'DROP'"
        echo "    option log '1'"
        echo "    option log_limit '10/minute'"
        echo ""
        echo "config rule"
        echo "    option name 'Log-Blocked-WAN-UDP'"
        echo "    option src 'wan'"
        echo "    option proto 'udp'"
        echo "    option target 'DROP'"
        echo "    option log '1'"
        echo "    option log_limit '10/minute'"
        echo ""
    fi
}

setup_cron() {
    log "Setting up automated scanning..."
    
    # Remove any existing entries
    crontab -l 2>/dev/null | grep -v "auto_ban.sh" | crontab -
    
    # Add new cron entry
    (crontab -l 2>/dev/null; echo "*/15 * * * * $INSTALL_DIR/auto_ban.sh >/dev/null 2>&1") | crontab -
    
    log "Auto-ban will run every 15 minutes"
}

create_management_commands() {
    log "Creating management commands..."
    
    # Create convenient management script
    cat > "/usr/bin/auto-security" << EOF
#!/bin/sh
# OpenWRT Auto-Security Management Command

case "\$1" in
    "status"|"report")
        $INSTALL_DIR/monitor.sh report
        ;;
    "live")
        $INSTALL_DIR/monitor.sh live
        ;;
    "banned")
        $INSTALL_DIR/monitor.sh banned
        ;;
    "scan")
        echo "🔍 Running manual threat scan..."
        $INSTALL_DIR/auto_ban.sh
        ;;
    "unban")
        if [ -z "\$2" ]; then
            echo "Usage: auto-security unban <IP>"
            exit 1
        fi
        echo "🔓 Unbanning \$2..."
        nft delete rule inet fw4 input_wan ip saddr \$2 counter drop comment "auto-banned-\$2" 2>/dev/null || echo "IP not found in ban list"
        ;;
    "reset")
        echo "🔄 Removing all bans..."
        nft list ruleset | grep "auto-banned" | sed 's/.*ip saddr \([0-9.]*\) .*/\1/' | while read ip; do
            nft delete rule inet fw4 input_wan ip saddr \$ip counter drop comment "auto-banned-\$ip"
        done
        echo "All bans removed"
        ;;
    "install")
        echo "🚀 Auto-Security is already installed!"
        echo "Version: $VERSION"
        echo "Location: $INSTALL_DIR"
        ;;
    *)
        echo "OpenWRT Auto-Security System v$VERSION"
        echo ""
        echo "Usage: auto-security {command}"
        echo ""
        echo "Commands:"
        echo "  status   - Show security status report"
        echo "  live     - Monitor attacks in real-time"
        echo "  banned   - List currently banned IPs"  
        echo "  scan     - Run manual threat detection"
        echo "  unban    - Remove IP from ban list"
        echo "  reset    - Remove all bans"
        echo ""
        echo "Examples:"
        echo "  auto-security status"
        echo "  auto-security live"
        echo "  auto-security unban 1.2.3.4"
        ;;
esac
EOF

    chmod +x "/usr/bin/auto-security"
}

main() {
    print_banner
    
    log "Starting OpenWRT Auto-Security installation..."
    
    check_openwrt
    check_firewall4
    create_directories
    install_auto_ban_script
    install_monitoring_script
    create_configuration
    setup_logging
    setup_cron
    create_management_commands
    
    echo ""
    echo -e "${GREEN}=============================================="
    echo "✅ Installation completed successfully!"
    echo "=============================================="
    echo -e "${NC}"
    
    echo "🎯 Quick Start:"
    echo "   auto-security status    - View security report"
    echo "   auto-security live      - Monitor live attacks"
    echo "   auto-security scan      - Run manual scan"
    echo ""
    
    echo "📁 Installation Directory: $INSTALL_DIR"
    echo "⚙️  Configuration File: $CONFIG_FILE"
    echo "📊 Log Files: $INSTALL_DIR/logs/"
    echo ""
    
    echo "🛡️  Auto-ban is now active and will scan every 15 minutes"
    echo "📈 Run 'auto-security status' to see current protection level"
    echo ""
    
    log "Installation completed successfully"
}

# Run main installation
main "$@"