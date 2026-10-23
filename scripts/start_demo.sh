#!/bin/bash
echo "🚀 Initializing KloudSentinel SIEM Pipeline..."

# 1. Stop any stale instances
pkill -f "node server.js" 2>/dev/null
pkill -f "tail -f /var/log/auth.log" 2>/dev/null

# 2. Start Node.js Correlation Engine in background
cd ~/cloudsentinel-engine 2>/dev/null || cd "$(dirname "$0")/../engine"
nohup node server.js > app.log 2>&1 &
sleep 1
echo "[✔] Node.js Engine active on port 3000"

# 3. Start SSH Log Forwarder pipe into Wazuh Docker Container
nohup bash -c 'sudo tail -f /var/log/auth.log | sudo docker exec -i single-node-wazuh.manager-1 bash -c "cat >> /var/ossec/logs/active-responses.log"' > /dev/null 2>&1 &
sleep 1
echo "[✔] Host SSH Log Forwarder active"

echo ""
echo "✅ KloudSentinel Pipeline initialized!"
echo "----------------------------------------------------"
echo "Custom Dashboard: http://$(curl -s ifconfig.me):3000/dashboard"
echo "Wazuh Dashboard:  https://$(curl -s ifconfig.me)"
echo "----------------------------------------------------"