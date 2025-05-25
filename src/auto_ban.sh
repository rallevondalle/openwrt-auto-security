#!/bin/sh
# Auto-Ban Script - Detects and blocks repeat attackers
# Part of OpenWRT Auto-Security System

INSTALL_DIR="/opt/auto-security"
CONFIG_FILE="$INSTALL_DIR/auto-security.conf"
LOGFILE="$INSTALL_DIR/logs/banned_ips.log"

# Source utilities
. "$INSTALL_DIR/utils.sh"

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

# Main detection logic
log_operation "INFO" "Starting threat detection scan (threshold: $ATTACK_THRESHOLD attacks)..."

# Process logs and find IPs that exceeded threshold
track_performance "log_processing" process_logs "$DATE" "$ATTACK_THRESHOLD" | while read -r IP COUNT; do
    if ! validate_ip "$IP"; then
        log_operation "WARN" "Invalid IP detected: $IP"
        continue
    fi
    
    # Check if already banned
    if ! nft list ruleset | grep -q "ip saddr $IP drop"; then
        log_operation "INFO" "THREAT DETECTED: Banning $IP after $COUNT attacks"
        
        # Insert at TOP of chain (before logging rules)
        if ! nft insert rule inet fw4 input_wan ip saddr $IP counter drop comment "auto-banned-$IP ban_time=$(date +%s)"; then
            handle_ban_failure "$IP" "Failed to insert nft rule"
            continue
        fi
        
        # Track ban state
        track_ban_state "$IP"
        
        # Add to banlist with timestamp
        echo "$(date '+%Y-%m-%d %H:%M:%S') $IP $COUNT" >> "$INSTALL_DIR/logs/banlist.txt"
        
        log_operation "INFO" "SUCCESS: $IP blocked permanently"
    fi
done

# Cleanup old bans
track_performance "ban_cleanup" cleanup_old_bans

# Summary
TOTAL_BANNED=$(nft list ruleset | grep "auto-banned" | wc -l)
log_operation "INFO" "Auto-ban scan complete. Active bans: $TOTAL_BANNED" 