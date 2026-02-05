#!/bin/sh

AUTH_LOG="/var/log/auth.log"
SYSTEM_LOG="/var/log/system.log"
LAST_CHECK_FILE="/var/tmp/last_auth_check"
ALERT_SCRIPT="/root/Scripts/auth_alert.sh"
LOG_TAG="pfsense_login_check"

# If first run, set "last check" to 1 minute ago to avoid alert spam
if [ ! -f "$LAST_CHECK_FILE" ]; then
    touch -t "$(date -v-1m +%Y%m%d%H%M.%S)" "$LAST_CHECK_FILE"
fi

# Read last check time
LAST_CHECK=$(stat -f %m "$LAST_CHECK_FILE")

# Capture current time
CURRENT_RUN_TIME=$(date +%s)

logger -t "$LOG_TAG" "Starting. LAST_CHECK=$LAST_CHECK CURRENT_RUN_TIME=$CURRENT_RUN_TIME"

get_log_timestamp() {
    local line="$1"
    local date_str=$(echo "$line" | awk '{print $1, $2, $3}')
    local epoch=""

    if echo "$date_str" | grep -q "^[0-9]\{4\}-.*T"; then
        # ISO format: strip fractional seconds AND timezone (+HH:MM / Z)
        date_str=$(echo "$line" | awk '{print $1}' | sed 's/[.+Z].*//')
        logger -t "$LOG_TAG" "  [ISO] date_str='$date_str'"
        epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$date_str" +%s 2>/dev/null)
    else
        # Traditional syslog: "Mon DD HH:MM:SS"
        logger -t "$LOG_TAG" "  [syslog] date_str='$date_str'"
        epoch=$(date -j -f "%b %e %H:%M:%S" "$date_str" +%s 2>/dev/null)
    fi

    if [ -z "$epoch" ]; then
        logger -t "$LOG_TAG" "  [WARN] parse FAILED for date_str='$date_str'"
    else
        logger -t "$LOG_TAG" "  [OK] epoch=$epoch"
    fi

    echo "$epoch"
}

# --- PROCESS LOGS ---

# Parse successful authentication attempts
grep -h -E "(Successful login|Accepted keyboard-interactive|Accepted publickey)" "$AUTH_LOG" 2>/dev/null | while read -r line; do
    LOG_TIME=$(get_log_timestamp "$line")
    TRUNCATED=$(echo "$line" | cut -c1-80)

    if [ -n "$LOG_TIME" ] && [ "$LOG_TIME" -gt "$LAST_CHECK" ]; then
        logger -t "$LOG_TAG" "[PASS] success: '$TRUNCATED'"
        USERNAME=$(echo "$line" | grep -o "user '[^']*'" | sed "s/user '//;s/'//")
        [ -z "$USERNAME" ] && USERNAME=$(echo "$line" | grep -o "for [a-zA-Z0-9]* from" | awk '{print $2}')

        IP_ADDRESS=$(echo "$line" | grep -oE "from(:)? [0-9.]+" | awk '{print $2}')

        if [ -n "$IP_ADDRESS" ]; then
            IP_ADDRESS=${IP_ADDRESS%.}
            "$ALERT_SCRIPT" "$USERNAME" "$IP_ADDRESS" "Authentication Success"
        fi
    else
        logger -t "$LOG_TAG" "[SKIP] success: LOG_TIME='$LOG_TIME' LAST_CHECK='$LAST_CHECK' line='$TRUNCATED'"
    fi
done

# Parse failed authentication attempts
grep -h -E "(authentication error|Failed password|webConfigurator.*REJECT)" "$AUTH_LOG" 2>/dev/null | while read -r line; do
    LOG_TIME=$(get_log_timestamp "$line")
    TRUNCATED=$(echo "$line" | cut -c1-80)

    if [ -n "$LOG_TIME" ] && [ "$LOG_TIME" -gt "$LAST_CHECK" ]; then
        logger -t "$LOG_TAG" "[PASS] failure: '$TRUNCATED'"
        USERNAME=$(echo "$line" | grep -o "user '[^']*'" | sed "s/user '//;s/'//")
        [ -z "$USERNAME" ] && USERNAME=$(echo "$line" | grep -o "for [a-zA-Z0-9]* from" | awk '{print $2}')
        [ -z "$USERNAME" ] && USERNAME="unknown"

        IP_ADDRESS=$(echo "$line" | grep -oE "from(:)? [0-9.]+" | awk '{print $2}')

        if [ -n "$IP_ADDRESS" ]; then
            IP_ADDRESS=${IP_ADDRESS%.}
            "$ALERT_SCRIPT" "$USERNAME" "$IP_ADDRESS" "Authentication Failure"
        fi
    else
        logger -t "$LOG_TAG" "[SKIP] failure: LOG_TIME='$LOG_TIME' LAST_CHECK='$LAST_CHECK' line='$TRUNCATED'"
    fi
done

# Parse SSHGuard blocks
grep "sshguard.*Blocking" "$SYSTEM_LOG" 2>/dev/null | while read -r line; do
    LOG_TIME=$(get_log_timestamp "$line")
    TRUNCATED=$(echo "$line" | cut -c1-80)

    if [ -n "$LOG_TIME" ] && [ "$LOG_TIME" -gt "$LAST_CHECK" ]; then
        logger -t "$LOG_TAG" "[PASS] sshguard: '$TRUNCATED'"
        IP_ADDRESS=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
        "$ALERT_SCRIPT" "blocked" "$IP_ADDRESS" "SSHGuard Block"
    else
        logger -t "$LOG_TAG" "[SKIP] sshguard: LOG_TIME='$LOG_TIME' LAST_CHECK='$LAST_CHECK' line='$TRUNCATED'"
    fi
done

# Update timestamp file for next run
touch -t "$(date -r $CURRENT_RUN_TIME +%Y%m%d%H%M.%S)" "$LAST_CHECK_FILE"
logger -t "$LOG_TAG" "Done. Updated LAST_CHECK_FILE to $CURRENT_RUN_TIME."