# pfSense Authentication Monitoring System

A lightweight system for monitoring authentication events on pfSense firewalls with email and Gotify notifications, including SSH connections and SSHGuard blocking events.

## Overview

This project provides two shell scripts that work together to:

1. Monitor the pfSense authentication log file (`/var/log/auth.log`) for successful and failed login attempts
2. Track SSH connections and SSHGuard blocking activities
3. Send notifications via:
   - Email (using pfSense's built-in notification system)

## Installation

### Prerequisites

- A pfSense firewall with shell access
- SMTP configuration set up in pfSense System > Advanced > Notifications

### Setup

1. Create a directory for the scripts:

   ```bash
   mkdir -p /root/Scripts
   ```

2. Create the `check_pfsense_login.sh` script:

   ```bash
   vi /root/Scripts/check_pfsense_login.sh
   ```

   (or use the WebUI at Diagnostics > Edit File)

   Copy the contents from the file in this repository

3. Create the `auth_alert.sh` script:

   ```bash
   vi /root/Scripts/auth_alert.sh
   ```

   Copy the contents from the file in this repository

4. Make both scripts executable:

   ```bash
   chmod +x /root/Scripts/check_pfsense_login.sh
   chmod +x /root/Scripts/auth_alert.sh
   ```

5. Set up a cron job to run the monitoring script periodically. Add the following to Services > Cron (requires package installation):
   - Command: `/root/Scripts/check_pfsense_login.sh`
   - Schedule: `*/5 * * * *` (runs every 5 minutes)

## Configuration

### Email Configuration

The script uses pfSense's built-in notification system, so make sure your SMTP settings are correctly configured in pfSense at:

System > Advanced > Notifications > E-Mail

## How It Works

1. `check_pfsense_login.sh` scans the auth.log file for new entries since the last check
2. The script detects different types of events:
   - Standard authentication successes and failures
   - SSH connection attempts
   - SSHGuard blocking actions
3. When it finds an event, it extracts the relevant information (username, IP address)
4. It calls `auth_alert.sh` with these details
5. `auth_alert.sh` sends notifications via email

## Troubleshooting

Check the system logs for error messages:

```bash
tail -f /var/log/system.log | grep pfsense_auth_alert
```

## License

MIT License - See LICENSE file for details.
