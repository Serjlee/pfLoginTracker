#!/bin/sh

# Place this file at: /root/Scripts/auth_alert.sh
# Make it executable with: chmod +x /root/Scripts/auth_alert.sh

# Get authentication details from system
USERNAME="$1"
IP_ADDRESS="$2"
EVENT_TYPE="$3"  # Authentication Success/Failure, SSHGuard Block/Release
HOSTNAME=$(hostname)

# Create a PHP script to send notification via pfSense's notice system
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
$message = "Event Type: {$event_type}\n";

// Customize message based on event type
if (strpos($event_type, "SSHGuard") !== false) {
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
$message .= "\nView notices: https://{$hostname}/status_notices.php\n";
$message .= "\nThis notification was generated automatically by the authentication monitoring system.";

// Create unique ID for notification
$id = "SecurityAlert_" . uniqid();
$subject = "SECURITY ALERT: {$event_type} on {$hostname}";

// file_notice($id, $notice, $link, $level) — notice text is subject + full message
file_notice($id, $subject . "\n\n" . $message, "status_notices.php", 1);
?>
EOF

# Make the script executable
chmod +x "$PHP_SCRIPT"

# Run the PHP script with the authentication details
logger -t pfsense_auth_alert "Attempting to send email via pfSense notification system"
/usr/local/bin/php "$PHP_SCRIPT" "$EVENT_TYPE" "$USERNAME" "$IP_ADDRESS" "$HOSTNAME" "$(date)" >/dev/null 2>&1

# Check if the script executed successfully
if [ $? -eq 0 ]; then
    logger -t pfsense_auth_alert "Email notification request sent to pfSense system"
else
    logger -t pfsense_auth_alert "Failed to execute PHP script for email notification"
fi

# Clean up
rm -f "$PHP_SCRIPT"
