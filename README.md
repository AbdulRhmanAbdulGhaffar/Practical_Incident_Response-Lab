# Practical_Incident_Response-Lab 🚨🛡️

<p align="center">
  <img src="https://i.postimg.cc/rwhj5w4r/design.png" alt="HomeLab Design" width="720"/>
</p>

---

## Preface — How to use this README (Read first)
This document is the single authoritative guide for reproducing the lab and preparing the demo video (`end.mp4`).  
Read the **Preface** and **Exact reproduction steps** sections before running any script.  
- Use the **copyable single‑line commands** (marked `COPY`) for quick execution.  
- Use multi‑line blocks only when you need to edit configuration snippets.  
- Always replace placeholders like `<ATTACKER_IP>`, `<UBUNTU_IP>`, `<WINDOWS_IP>`, and `<WEBSERVER_IP>` with actual addresses.  
- This README assumes you run commands with appropriate privileges (sudo / administrator).

---

## Overview
**Practical_Incident_Response-Lab** is a production-minded, hands‑on Incident Response lab.  
It documents and reproduces the **Blocking a known malicious actor** use case using **Wazuh SIEM** (CDB lists + Active Response).

This README contains:
- Architecture & roles
- Exact commands (copyable)
- Configuration snippets
- Automation helpers (functions)
- Playbook steps
- References & video

The demo video file is `end.mp4` placed in the repository root. Use it for presentations or to record playback.

---

## Quick links
- Wazuh quickstart: https://documentation.wazuh.com/current/quickstart.html  
- Wazuh PoC (blocking malicious actor): https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html  
- My Wazuh install guide: https://github.com/AbdulRhmanAbdulGhaffar/Wazuh_Installation_Guide

---

## Lab summary — blocking a known malicious actor
- **Goal:** Detect and automatically block a malicious IP address using an IP reputation list and Wazuh Active Response.  
- **Attacker:** RHEL 9.0 (simulated).  
- **Victims:** Ubuntu 22.04 (Apache) and Windows 11 (Apache binary).  
- **Manager:** Wazuh Manager with CDB lists.  
- **Response:** Active Response runs `firewall-drop` / `netsh` to block the IP for **60 seconds**.

---

## Infrastructure & roles

| Host / Location | OS       | Role                          |
|-----------------|----------|-------------------------------|
| RHEL 9.0        | attacker | Simulated malicious endpoint  |
| Ubuntu 22.04    | victim   | Apache web server + Wazuh agent |
| Windows 11      | victim   | Apache web server + Wazuh agent |
| Wazuh Manager   | RHEL/CentOS | Wazuh Manager & CDB lists  |
| Google Cloud    | optional | Host VMs for public IP testing |

> If using GCP, ensure VM firewall and GCP network firewall allow HTTP (tcp:80) and agent management ports.

---

## Exact reproduction steps (tested sequence)
Follow in order. Replace placeholders before running.

### 1) Ubuntu victim — Apache + Wazuh agent

Single-line quick install (COPY):
```bash
# COPY: update, install Apache and enable
sudo apt update && sudo apt install -y apache2 && sudo systemctl enable --now apache2
```

Verify site (COPY):
```bash
# COPY: test site
curl http://<UBUNTU_IP>
```

Add Apache log monitoring to Wazuh (use multi-line; copy block then paste):
```bash
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<'XML'
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
XML
```

Restart agent (COPY):
```bash
# COPY: restart wazuh agent
sudo systemctl restart wazuh-agent
```

Notes:
- Confirm agent installed and connected to manager before testing.
- If agent path differs, update the ossec.conf path.

---

### 2) Windows victim — Apache + Wazuh agent (summary)

Steps (manual; copy the config snippet):

- Install Visual C++ Redistributable.
- Extract Apache to `C:\Apache24` and run `C:\Apache24\bin\httpd.exe` as Administrator.
- Allow Windows Defender Firewall when prompted.
- Test: `http://<WINDOWS_IP>` from another host.

Wazuh agent config snippet (copy and paste into agent `ossec.conf`):
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>C:\Apache24\logs\access.log</location>
</localfile>
```

Restart agent (COPY PowerShell):
```powershell
# COPY: restart wazuh agent (run as admin)
Restart-Service -Name wazuh
```

---

### 3) Wazuh Manager — prepare reputation list (CDB) & converter

Single-line to fetch and prepare (COPY):
```bash
# COPY: prepare lists dir, download ipset and converter, convert to cdb
sudo yum update -y && sudo yum install -y wget python3 && sudo mkdir -p /var/ossec/etc/lists && sudo chown -R wazuh:wazuh /var/ossec/etc/lists && sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset && sudo bash -c 'echo "<ATTACKER_IP>" >> /var/ossec/etc/lists/alienvault_reputation.ipset' && sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py && sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault && sudo chown wazuh:wazuh /var/ossec/etc/lists/blacklist-alienvault && sudo rm -f /var/ossec/etc/lists/alienvault_reputation.ipset /tmp/iplist-to-cdblist.py
```

Step-by-step (copyable blocks if you prefer separate lines):

```bash
# 1. create lists dir & set permissions
sudo mkdir -p /var/ossec/etc/lists
sudo chown -R wazuh:wazuh /var/ossec/etc/lists

# 2. download AlienVault ipset
sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset

# 3. append attacker IP
sudo bash -c 'echo "<ATTACKER_IP>" >> /var/ossec/etc/lists/alienvault_reputation.ipset'

# 4. download converter
sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py

# 5. convert to cdb (adjust python interpreter if needed)
sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault

# 6. set ownership
sudo chown wazuh:wazuh /var/ossec/etc/lists/blacklist-alienvault

# 7. cleanup (optional)
sudo rm -f /var/ossec/etc/lists/alienvault_reputation.ipset /tmp/iplist-to-cdblist.py
```

Notes:
- If `/var/ossec/framework/python/bin/python3` is missing, use `python3` or the Wazuh venv path.
- Verify `/var/ossec/etc/lists/blacklist-alienvault` exists and is readable by `wazuh`.

---

### 4) Wazuh Manager — add detection rule (local_rules.xml)

Create / edit `/var/ossec/etc/rules/local_rules.xml` and add:

```xml
<group name="attack">
  <rule id="100100" level="10">
    <if_group>web,attack,attacks</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
    <description>IP address found in AlienVault reputation database - trigger Active Response</description>
  </rule>
</group>
```

Add the list to `/var/ossec/etc/ossec.conf` in the `<ruleset>` section (copy snippet):

```xml
<list>etc/lists/blacklist-alienvault</list>
```

Then restart the manager (COPY):
```bash
sudo systemctl restart wazuh-manager
```

---

### 5) Wazuh Manager — Active Response configuration

Add the following active-response blocks to `/var/ossec/etc/ossec.conf`:

**Ubuntu (firewall-drop)**:
```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>60</timeout>
</active-response>
```

**Windows (netsh)**:
```xml
<active-response>
  <disabled>no</disabled>
  <command>netsh</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>60</timeout>
</active-response>
```

Apply and verify (COPY):
```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Notes:
- Confirm `firewall-drop` and `netsh` scripts exist under `/var/ossec/active-response/bin/`.
- Adjust timeout as needed.

---

### 6) Emulate the attack (RHEL attacker)

Quick test (COPY):
```bash
curl http://<WEBSERVER_IP>
curl http://<WEBSERVER_IP>
```

Expected:
- First request logged, subsequent request triggers block for 60s.
- Check Wazuh alerts and agent logs to confirm.

---

### 7) Visualize alerts & troubleshooting

- Open Wazuh Dashboard → *Threat Hunting* or *Alerts*.  
- Filter: `rule.id:(651 OR 100100)` or search by time/victim IP.  
- Save sample alerts under `/logs/sample_alerts.json` for documentation.

Troubleshooting tips:
- Use `agent_control -l` to list agents.  
- Inspect manager logs: `/var/ossec/logs/ossec.log`.  
- Inspect agent logs on victims: `/var/ossec/logs/ossec.log`.  
- Ensure file permissions for CDB lists (`wazuh:wazuh`).

---

## Automation helpers — ready-to-use functions & scripts

### Bash function — append IP and convert to CDB (manager)
Copy this into an interactive shell or a script on the manager:

```bash
# Usage: sudo add_attacker_ip <ATTACKER_IP>
add_attacker_ip() {
  ATT="$1"
  LIST_PATH="/var/ossec/etc/lists/alienvault_reputation.ipset"
  CDB_PATH="/var/ossec/etc/lists/blacklist-alienvault"
  TMP_SCRIPT="/tmp/iplist-to-cdblist.py"

  sudo mkdir -p /var/ossec/etc/lists
  sudo chown wazuh:wazuh /var/ossec/etc/lists || true

  if [ ! -f "$LIST_PATH" ]; then
    sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O "$LIST_PATH"
  fi

  sudo bash -c "echo '${ATT}' >> ${LIST_PATH}"

  if [ ! -f "$TMP_SCRIPT" ]; then
    sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O "$TMP_SCRIPT"
  fi

  sudo /var/ossec/framework/python/bin/python3 "$TMP_SCRIPT" "$LIST_PATH" "$CDB_PATH"
  sudo chown wazuh:wazuh "$CDB_PATH"
  echo "Added ${ATT} and converted to ${CDB_PATH}"
}
```

### Bash helper — local block (victim)
Save as `/usr/local/bin/block_ip_local.sh` and make executable:

```bash
#!/usr/bin/env bash
# Usage: sudo block_ip_local 1.2.3.4
IP="$1"
if command -v ufw >/dev/null 2>&1; then
  sudo ufw insert 1 deny from "$IP" to any
else
  sudo iptables -I INPUT -s "$IP" -j DROP
fi
echo "Blocked ${IP} locally."
```

### PowerShell helper — Windows local block
Save as `block_ip.ps1` and run as admin:

```powershell
param([string]$IP)
Write-Output "Blocking $IP via netsh"
netsh advfirewall firewall add rule name="Block-IR-$IP" dir=in action=block remoteip=$IP enable=yes
```

> Review scripts before running. They are designed for lab use, not production.

---

## Incident Response Playbook (concise)
1. **Detection** — Wazuh alert triggers.  
2. **Triage** — Collect context: srcip, dst, timestamp, user-agent, request path.  
3. **Containment** — Run Active Response or `block_ip_local`/`block_ip.ps1`.  
4. **Eradication** — Remove malicious files, close exploited vectors, patch.  
5. **Recovery** — Restore services, verify integrity.  
6. **Lessons Learned** — Update detection rules, improve automation.

For printable checklists and step-by-step procedures, see `/docs/playbooks.md`.

---

## Files & scripts (what to commit)
- `/scripts/setup_webserver.sh` — Apache install + demo site creation.  
- `/scripts/install_wazuh_agent.sh` — Agent install (platform-specific snippets).  
- `/scripts/block_ip.sh` — Wrapper that calls ufw/iptables or invokes PowerShell via WinRM.  
- `/lab-config/detection_rules/001-blacklist-alienvault.xml` — example rule.  
- `/docs/playbooks.md` — printable IR playbook.  
- `/logs/sample_alerts.json` — sample alert JSON.  
- `end.mp4` — demo video of the full lab (place in repo root).

---

## Video — `end.mp4`
Place your recorded demo named `end.mp4` in the repository root.  
Suggested video sections:
1. Title slide with project name and your name.  
2. Brief architecture diagram (2–3 slides).  
3. Live terminal: show agent logs and manager alert triggering.  
4. Show Active Response blocking the IP (live test).  
5. Wrap-up slide with links to repo, LinkedIn, and portfolio.

Suggested video length: 90–180 seconds. Keep commands visible and use zoom-in on terminal for clarity.

---

## Cloud notes — Google Cloud specifics
- Allow `tcp:80` and any management ports in GCP firewall and VM OS firewall.  
- Use reserved static external IP for victim VMs when testing public-IP blocking.  
- Consider network tags and routes to simplify firewall rules.

---

## References & learning resources
- Wazuh docs — Quickstart & PoC: https://documentation.wazuh.com  
- Blocking PoC: https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html  
- Wazuh install guide (used): https://github.com/AbdulRhmanAbdulGhaffar/Wazuh_Installation_Guide

---

## Credits & acknowledgments
- **Dr. Shehab Elbatal** — mentorship, technical guidance, and patience.  
- **AMIT Learning** — training and support.  
- **Digital Egypt Pioneers Initiative (DEPI)** & **Ministry of Communications and Information Technology (MCIT), Egypt** — opportunity and support.

---

## Author & contact
**AbdulRhman AbdulGhaffar**  
- LinkedIn: https://www.linkedin.com/in/abdulrhmanabdulghaffar/  
- Portfolio: https://abdulrhmanabdulghaffar.github.io/Portfolio/  
- Email: abdulrhman.abdulghaffar001@gmail.com

---

## License
MIT — see `LICENSE`.

---

> *This README is intentionally complete and exact. Review scripts and commands before running in production.*  
> *“وَقُل رَبِّ زِدْنِي عِلْمًا”* ✨
