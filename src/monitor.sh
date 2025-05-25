#!/bin/sh
# Monitoring Script - Provides security analytics and reports
# Part of OpenWRT Auto-Security System

INSTALL_DIR="/opt/auto-security"

# Source utilities
. "$INSTALL_DIR/utils.sh"

generate_report() {
    track_performance "report_generation" {
        echo "=============================================="
        echo "  OpenWRT Auto-Security Status Report"
        echo "  Generated: $(date)"
        echo "=============================================="
        echo ""
        
        echo "🛡️  PROTECTION STATUS:"
        local active_bans=$(nft list ruleset | grep 'auto-banned' | wc -l)
        local total_attacks=$(logread | grep 'Log-Blocked-WAN-Access' | grep "$(date +'%b %d')" | wc -l)
        echo "   Active banned IPs: $active_bans"
        echo "   Total attacks today: $total_attacks"
        echo ""
        
        echo "🎯 TOP THREAT SOURCES (Last 24 hours):"
        process_logs "$(date +'%b %d')" 0 | sort -k2 -nr | head -5 | while read -r ip count; do
            echo "   $ip: $count attacks"
        done
        echo ""
        
        echo "🔍 TARGET PORT ANALYSIS:"
        logread | grep "Log-Blocked-WAN-Access" | grep "$(date +'%b %d')" | \
        grep -o "DPT=[0-9]*" | sed 's/DPT=//' | sort | uniq -c | sort -nr | head -5 | \
        while read -r count port; do
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
        logread | grep "Log-Blocked-WAN-Access" | tail -5 | while read -r line; do
            timestamp=$(echo "$line" | cut -d' ' -f1-4)
            ip=$(echo "$line" | sed 's/.*SRC=\([0-9.]*\).*/\1/')
            port=$(echo "$line" | sed 's/.*DPT=\([0-9]*\).*/\1/')
            echo "   $timestamp - $ip → Port $port"
        done
        echo ""
        
        echo "=============================================="
    }
}

case "$1" in
    "report")
        generate_report
        ;;
    "live")
        echo "🔴 LIVE ATTACK MONITORING (Press Ctrl+C to stop)"
        echo "Timestamp                 | Source IP      | Target Port"
        echo "---------------------------------------------------------"
        logread -f | grep "Log-Blocked-WAN-Access" | while read -r line; do
            timestamp=$(echo "$line" | cut -d' ' -f1-4)
            ip=$(echo "$line" | sed 's/.*SRC=\([0-9.]*\).*/\1/')
            port=$(echo "$line" | sed 's/.*DPT=\([0-9]*\).*/\1/')
            printf "%-25s | %-14s | %s\n" "$timestamp" "$ip" "$port"
        done
        ;;
    "banned")
        echo "🚫 CURRENTLY BANNED IPs:"
        nft list ruleset | grep "auto-banned" | sed 's/.*ip saddr \([0-9.]*\) .*/\1/' | \
        while read -r ip; do
            if validate_ip "$ip"; then
                count=$(grep "$ip" "$INSTALL_DIR/logs/banlist.txt" 2>/dev/null | tail -1 | cut -d' ' -f4)
                ban_time=$(nft list ruleset | grep "auto-banned-$ip" | grep -o 'ban_time=[0-9]*' | cut -d= -f2)
                if [ -n "$ban_time" ]; then
                    ban_date=$(date -d "@$ban_time" '+%Y-%m-%d %H:%M:%S')
                    echo "   $ip (${count:-unknown} attacks, banned since $ban_date)"
                else
                    echo "   $ip (${count:-unknown} attacks)"
                fi
            fi
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