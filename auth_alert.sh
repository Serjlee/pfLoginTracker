#!/bin/sh

# Place this file at: /root/Scripts/gotify_auth_alert.sh
# Make it executable with: chmod +x /root/Scripts/gotify_auth_alert.sh

# Get authentication details from system
USERNAME="$1"
IP_ADDRESS="$2"
EVENT_TYPE="$3"  # Authentication Success/Failure, SSHGuard Block/Release
SERVICE="$4"     # Service type for SSHGuard (sshd, ftpd, etc.)
HOSTNAME=$(hostname)

# Build message
TITLE="Security Alert from $HOSTNAME"

# Customize message based on event type
if [ "$EVENT_TYPE" = "SSHGuard Block" ]; then
    MESSAGE="Event: $EVENT_TYPE
Service: $SERVICE
IP Address: $IP_ADDRESS
Action: Blocked by SSHGuard
Time: $(date)"
    PRIORITY=7  # Higher priority for blocks

elif [ "$EVENT_TYPE" = "SSHGuard Release" ]; then
    MESSAGE="Event: $EVENT_TYPE
IP Address: $IP_ADDRESS
Action: Released from block by SSHGuard
Time: $(date)"
    PRIORITY=4  # Lower priority for releases

else
    # Standard auth success/failure
    MESSAGE="Event: $EVENT_TYPE
User: $USERNAME
IP Address: $IP_ADDRESS
Time: $(date)"
    
    # Higher priority for failures
    if [ "$EVENT_TYPE" = "Authentication Failure" ]; then
        PRIORITY=6
    else
        PRIORITY=5
    fi
fi

# 2. Use pfSense's built-in notification system to send email
# Create a PHP script to send email via pfSense's notification system
PHP_SCRIPT=$(mktemp)
cat > "$PHP_SCRIPT" << 'EOF'
#!/usr/local/bin/php
<?php
require_once("config.inc");
require_once("notices.inc");
require_once("util.inc");

$event_type = $argv[1];
$username = $argv[2];
$ip_address = $argv[3];
$hostname = $argv[4];
$time = $argv[5];
$service = isset($argv[6]) ? $argv[6] : "N/A";

$message = "Event Type: {$event_type}\n";

// Customize message based on event type
if (strpos($event_type, "SSHGuard") !== false) {
    $message .= "Service: {$service}\n";
    $message .= "IP Address: {$ip_address}\n";
    if ($event_type == "SSHGuard Block") {
        $message .= "Action: Blocked by SSHGuard\n";
    } else {
        $message .= "Action: Released from block by SSHGuard\n";
    }
} else {
    $message .= "User: {$username}\n";
    $message .= "IP Address: {$ip_address}\n";
}

$message .= "System: {$hostname}\n";
$message .= "Time: {$time}\n";
$message .= "\nThis notification was generated automatically by the authentication monitoring system.";

// Create unique ID for notification
$id = "SecurityAlert_" . time();
$subject = "SECURITY ALERT: {$event_type} on {$hostname}";

// Send notification (will use configured SMTP settings)
send_smtp_message($message, $subject, '', '', '', $error);
if ($error) {
    log_error("Failed to send email notification: " . $error);
} else {
    log_error("Email notification sent successfully using pfSense's notification system");
}

// Also add to notification system
notify_via_smtp($id, $subject, $message);
file_notice($id, $subject, $message, "Security Alert");
?>
EOF

# Make the script executable
chmod +x "$PHP_SCRIPT"

# Run the PHP script with the authentication details
logger -t pfsense_auth_alert "Attempting to send email via pfSense notification system"
/usr/local/bin/php "$PHP_SCRIPT" "$EVENT_TYPE" "$USERNAME" "$IP_ADDRESS" "$HOSTNAME" "$(date)" "$SERVICE" >/dev/null 2>&1

# Check if the script executed successfully
if [ $? -eq 0 ]; then
    logger -t pfsense_auth_alert "Email notification request sent to pfSense system"
else
    logger -t pfsense_auth_alert "Failed to execute PHP script for email notification"
fi

# Clean up
rm -f "$PHP_SCRIPT"
