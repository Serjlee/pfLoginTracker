#!/bin/sh

AUTH_LOG="/var/log/auth.log"
SYSTEM_LOG="/var/log/system.log"
LAST_CHECK_FILE="/var/tmp/last_auth_check"
ALERT_SCRIPT="/root/Scripts/auth_alert.sh"

# If first run, set "last check" to 1 minute ago to avoid alert spam
if [ ! -f "$LAST_CHECK_FILE" ]; then
    touch -t "$(date -v-1M +%Y%m%d%H%M.%S)" "$LAST_CHECK_FILE"
fi

# Read last check time
LAST_CHECK=$(stat -f %m "$LAST_CHECK_FILE")

# Capture current time for the next run
CURRENT_RUN_TIME=$(date +%s)

get_log_timestamp() {
    local line="$1"
    local date_str=$(echo "$line" | awk '{print $1, $2, $3}')
    
    if echo "$date_str" | grep -q "^[0-9]\{4\}-.*T"; then
        date_str=$(echo "$line" | awk '{print $1}')
        date -j -f "%Y-%m-%dT%H:%M:%S" "${date_str%%.*}" +%s 2>/dev/null
    else
        date -j "$date_str" +%s 2>/dev/null
    fi
}

# --- PROCESS LOGS ---

# Parse successful authentication attempts
grep -h -E "(Successful login|Accepted keyboard-interactive|Accepted publickey)" "$AUTH_LOG" 2>/dev/null | while read -r line; do
    LOG_TIME=$(get_log_timestamp "$line")

    if [ -n "$LOG_TIME" ] && [ "$LOG_TIME" -gt "$LAST_CHECK" ]; then
        # Extract User
        USERNAME=$(echo "$line" | grep -o "user '[^']*'" | sed "s/user '//;s/'//")
        [ -z "$USERNAME" ] && USERNAME=$(echo "$line" | grep -o "for [a-zA-Z0-9]* from" | awk '{print $2}')
        
        # Extract IP
        IP_ADDRESS=$(echo "$line" | grep -oE "from(:)? [0-9.]+" | awk '{print $2}')

        if [ -n "$IP_ADDRESS" ]; then
             # Remove trailing dot if present
            IP_ADDRESS=${IP_ADDRESS%.}
            "$ALERT_SCRIPT" "$USERNAME" "$IP_ADDRESS" "Authentication Success"
        fi
    fi
done

# Parse failed authentication attempts
grep -h -E "(authentication error|Failed password|webConfigurator.*REJECT)" "$AUTH_LOG" 2>/dev/null | while read -r line; do
    LOG_TIME=$(get_log_timestamp "$line")
    
    if [ -n "$LOG_TIME" ] && [ "$LOG_TIME" -gt "$LAST_CHECK" ]; then
        USERNAME=$(echo "$line" | grep -o "user '[^']*'" | sed "s/user '//;s/'//")
        [ -z "$USERNAME" ] && USERNAME=$(echo "$line" | grep -o "for [a-zA-Z0-9]* from" | awk '{print $2}')
        [ -z "$USERNAME" ] && USERNAME="unknown"

        IP_ADDRESS=$(echo "$line" | grep -oE "from(:)? [0-9.]+" | awk '{print $2}')

        if [ -n "$IP_ADDRESS" ]; then
            IP_ADDRESS=${IP_ADDRESS%.}
            "$ALERT_SCRIPT" "$USERNAME" "$IP_ADDRESS" "Authentication Failure"
        fi
    fi
done

# Parse SSHGuard blocks
grep "sshguard.*Blocking" "$SYSTEM_LOG" 2>/dev/null | while read -r line; do
    LOG_TIME=$(get_log_timestamp "$line")

    if [ -n "$LOG_TIME" ] && [ "$LOG_TIME" -gt "$LAST_CHECK" ]; then
        IP_ADDRESS=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
        "$ALERT_SCRIPT" "blocked" "$IP_ADDRESS" "SSHGuard Block"
    fi
done

# Update the timestamp file using touch
touch -t "$(date -r $CURRENT_RUN_TIME +%Y%m%d%H%M.%S)" "$LAST_CHECK_FILE"