#!/bin/sh
# OpenWRT Auto-Security Utilities
# Common functions for the security system

# IP validation function
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r -a ip_parts <<< "$ip"
    for part in "${ip_parts[@]}"; do
        if [ "$part" -gt 255 ] || [ "$part" -lt 0 ]; then
            return 1
        fi
    done
    # Check for private IP ranges
    if [[ $ip =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
        return 1
    fi
    return 0
}

# Performance tracking
track_performance() {
    local operation=$1
    local start_time=$(date +%s.%N)
    shift
    "$@"
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    echo "$(date): $operation took ${duration}s" >> "$INSTALL_DIR/logs/performance.log"
}

# Enhanced logging
log_operation() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "\033[0;32m[INFO]\033[0m $message"
            ;;
        "WARN")
            echo -e "\033[1;33m[WARN]\033[0m $message"
            ;;
        "ERROR")
            echo -e "\033[0;31m[ERROR]\033[0m $message"
            ;;
    esac
    
    echo "$timestamp [$level] $message" >> "$INSTALL_DIR/logs/operations.log"
}

# Atomic rule updates
update_rules() {
    local temp_file=$(mktemp)
    nft list ruleset > "$temp_file"
    if [ $? -ne 0 ]; then
        log_operation "ERROR" "Failed to backup current ruleset"
        return 1
    fi
    
    # Make changes to temp file
    nft -f "$temp_file"
    local result=$?
    
    rm "$temp_file"
    return $result
}

# State tracking
track_ban_state() {
    local ip=$1
    local timestamp=$(date +%s)
    echo "$timestamp|$ip" >> "$INSTALL_DIR/logs/ban_state.txt"
}

# Error recovery
handle_ban_failure() {
    local ip=$1
    local error=$2
    log_operation "ERROR" "Failed to ban $ip: $error"
    echo "$(date): Failed to ban $ip: $error" >> "$INSTALL_DIR/logs/ban_errors.log"
    
    # Implement retry logic
    if [ -f "$INSTALL_DIR/logs/ban_retries.txt" ]; then
        local retries=$(grep "^$ip:" "$INSTALL_DIR/logs/ban_retries.txt" | cut -d: -f2)
        retries=${retries:-0}
        if [ $retries -lt 3 ]; then
            echo "$ip:$((retries + 1))" >> "$INSTALL_DIR/logs/ban_retries.txt"
            log_operation "INFO" "Scheduled retry for $ip (attempt $((retries + 1)))"
        fi
    else
        echo "$ip:1" >> "$INSTALL_DIR/logs/ban_retries.txt"
    fi
}

# Log rotation setup
setup_log_rotation() {
    cat > "/etc/logrotate.d/auto-security" << 'EOF'
/opt/auto-security/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        /etc/init.d/auto-security reload >/dev/null 2>&1 || true
    endscript
}
EOF
}

# Cleanup old bans
cleanup_old_bans() {
    local current_time=$(date +%s)
    nft list ruleset | grep "auto-banned" | while read -r line; do
        local ban_time=$(echo "$line" | grep -o 'ban_time=[0-9]*' | cut -d= -f2)
        if [ -n "$ban_time" ] && [ $((current_time - ban_time)) -gt "$BAN_DURATION" ]; then
            local ip=$(echo "$line" | grep -o 'ip saddr [0-9.]*' | cut -d' ' -f3)
            if validate_ip "$ip"; then
                nft delete rule inet fw4 input_wan ip saddr "$ip" counter drop
                log_operation "INFO" "Removed expired ban for $ip"
            fi
        fi
    done
}

# Optimized log processing
process_logs() {
    local date=$1
    local threshold=$2
    logread | awk -v date="$date" -v threshold="$threshold" '
        /Log-Blocked-WAN-Access/ && $0 ~ date {
            match($0, /SRC=([0-9.]+)/, arr)
            if (arr[1]) {
                ip_count[arr[1]]++
            }
        }
        END {
            for (ip in ip_count) {
                if (ip_count[ip] > threshold) {
                    print ip, ip_count[ip]
                }
            }
        }
    '
} 