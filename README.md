# Practical_Incident_Response-Lab 🚨🛡️

<p align="center">
  <img src="https://i.postimg.cc/rwhj5w4r/design.png" alt="HomeLab Design" width="720"/>
</p>

---

## Overview
**Practical_Incident_Response-Lab** is a production-minded, hands‑on Incident Response lab.  
It documents and reproduces the **Blocking a known malicious actor** use case using **Wazuh SIEM** (CDB lists + Active Response).

This single-file README contains everything needed to reproduce the lab: architecture, exact commands, configuration snippets, automation helpers (functions), playbook steps, and references. Use this file as the authoritative guide when you build the lab or prepare a demo video (`end.mp4` placed in the repository root).

---

## Quick links
- Wazuh quickstart: https://documentation.wazuh.com/current/quickstart.html
- Wazuh PoC (blocking malicious actor): https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html
- My Wazuh install guide: https://github.com/AbdulRhmanAbdulGhaffar/Wazuh_Installation_Guide

---

## Lab summary — blocking a known malicious actor (concise)
- Goal: Detect and automatically block a malicious IP address using an IP reputation list and Wazuh Active Response.
- Attacker: RHEL 9.0 (simulated malicious host).
- Victims: Ubuntu 22.04 (Apache), Windows 11 (Apache binary).
- Wazuh: Manager + Agents monitoring Apache access logs.
- Response: Custom Wazuh rule triggers an Active Response that runs a local block command (Ubuntu: firewall-drop / iptables or ufw; Windows: netsh) for **60 seconds**.

---

## Infrastructure & roles

| Host / Location | OS       | Role                          |
|-----------------|----------|-------------------------------|
| RHEL 9.0        | attacker | Simulated malicious endpoint  |
| Ubuntu 22.04    | victim   | Apache web server + Wazuh agent |
| Windows 11      | victim   | Apache web server + Wazuh agent |
| Wazuh Manager   | RHEL/CentOS | Wazuh Manager & CDB lists  |
| Google Cloud    | optional | Host VMs for public IP testing |

> Note: lab runs on local VMs or cloud. If using GCP, open HTTP and management ports in the VM firewall and GCP network firewall.

---

## Exact reproduction steps (tested sequence)

> Follow these steps in order. Replace `<ATTACKER_IP>`, `<UBUNTU_IP>`, `<WINDOWS_IP>`, and `<WEBSERVER_IP>` with your real addresses.

### 1) Ubuntu victim — Apache + Wazuh agent

```bash
# 1. update & install Apache
sudo apt update
sudo apt install -y apache2

# 2. enable & verify
sudo systemctl enable --now apache2
sudo systemctl status apache2

# 3. allow HTTP (if using ufw)
sudo ufw allow 'Apache'   # skip if firewall disabled

# 4. test site
curl http://<UBUNTU_IP>

# 5. configure Wazuh Agent to monitor Apache access log
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<'XML'
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
XML

# 6. restart agent
sudo systemctl restart wazuh-agent
```

Notes:
- If the Wazuh agent is installed in a custom path, adapt the `ossec.conf` file path accordingly.
- Confirm `/var/ossec/etc/ossec.conf` is writable by the user or use `sudo` as above.

---

### 2) Windows victim — Apache + Wazuh agent (summary)

1. Install Visual C++ Redistributable (required by some Apache builds).
2. Download an Apache Win64 ZIP (prebuilt) and extract to `C:\Apache24`.
3. Run `C:\Apache24\bin\httpd.exe` as Administrator.
   - Allow access when Windows Defender Firewall prompts.
4. Verify: browse `http://<WINDOWS_IP>` from another host.
5. Configure Wazuh agent (edit the agent ossec.conf):

Add to `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>C:\Apache24\logs\access.log</location>
</localfile>
```

6. Restart Wazuh agent (PowerShell as admin):

```powershell
Restart-Service -Name wazuh
```

Notes:
- If your agent is 64-bit installed elsewhere, adapt the path.
- If using Windows Defender or third-party AV, ensure the agent binary is whitelisted.

---

### 3) Wazuh Manager — prepare reputation list (CDB) & converter

> On the Wazuh Manager host (RHEL/CentOS).

```bash
# 1. install wget if needed
sudo yum update -y && sudo yum install -y wget python3

# 2. create lists dir if missing
sudo mkdir -p /var/ossec/etc/lists
sudo chown -R wazuh:wazuh /var/ossec/etc/lists

# 3. download AlienVault ipset
sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset

# 4. append attacker IP (use sudo tee or bash -c)
sudo bash -c 'echo "<ATTACKER_IP>" >> /var/ossec/etc/lists/alienvault_reputation.ipset'

# 5. download converter script
sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py

# 6. convert ipset -> CDB list (adjust python path if needed)
sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault

# 7. set ownership
sudo chown wazuh:wazuh /var/ossec/etc/lists/blacklist-alienvault

# 8. cleanup optional
sudo rm -f /var/ossec/etc/lists/alienvault_reputation.ipset /tmp/iplist-to-cdblist.py
```

Notes:
- The converter script path and python interpreter may vary by Wazuh version. If `/var/ossec/framework/python/bin/python3` does not exist, use `python3` or the installed Wazuh Python virtualenv.
- The resulting file `/var/ossec/etc/lists/blacklist-alienvault` must be readable by the Wazuh process (user `wazuh`).

---

### 4) Wazuh Manager — add detection rule (local_rules.xml)

Add a custom rule to `/var/ossec/etc/rules/local_rules.xml` (create file if missing):

```xml
<group name="attack">
  <rule id="100100" level="10">
    <if_group>web,attack,attacks</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
    <description>IP address found in AlienVault reputation database - trigger Active Response</description>
  </rule>
</group>
```

Then ensure the list is included in `/var/ossec/etc/ossec.conf` under the `<ruleset>` section:

```xml
<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/blacklist-alienvault</list>
    <!-- other lists -->
  </ruleset>
</ossec_config>
```

---

### 5) Wazuh Manager — Active Response configuration

Add Active Response blocks to `/var/ossec/etc/ossec.conf`:

**Ubuntu (firewall-drop / local iptables/ufw):**

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>60</timeout>
</active-response>
```

**Windows (netsh):**

```xml
<active-response>
  <disabled>no</disabled>
  <command>netsh</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>60</timeout>
</active-response>
```

Apply changes:

```bash
sudo systemctl restart wazuh-manager
# verify manager status
sudo systemctl status wazuh-manager
```

Notes:
- `firewall-drop` and `netsh` active-response commands are provided by Wazuh by default. Confirm presence in `/var/ossec/active-response/bin/`.
- Timeout is in seconds (60s here). Tune for your lab.

---

### 6) Emulate the attack (RHEL attacker)

From the RHEL attacker host run:

```bash
# first request (observed and logged)
curl http://<WEBSERVER_IP>

# repeat to trigger blocking behavior
curl http://<WEBSERVER_IP>
```

Expected behavior:
- Wazuh Agent on the victim sends Apache access logs to the Manager.
- Manager checks `srcip` against CDB `blacklist-alienvault` list.
- Rule `100100` matches and Wazuh triggers Active Response.
- Active Response blocks the IP on victim for the configured timeout (60s).

---

### 7) Visualize alerts & troubleshooting

- Open Wazuh Dashboard → *Threat Hunting* or *Alerts*.
- Filter: `rule.id:(651 OR 100100)` or search by the victim hostname/IP/time window.
- Store sample alerts in `/logs/sample_alerts.json` for reference.

Troubleshooting tips:
- Confirm agent-manager connectivity (`agent_control -l` / Wazuh > Agents UI).
- Check Wazuh manager logs: `/var/ossec/logs/ossec.log`.
- Check agent logs on victims: `/var/ossec/logs/ossec.log`.
- Validate that the `blacklist-alienvault` file exists and is readable by `wazuh` user.

---

## Automation helpers — ready-to-use functions & scripts

### Bash function — append IP and convert to CDB (manager)
```bash
# Usage: sudo add_attacker_ip <ATTACKER_IP>
add_attacker_ip() {
  ATT="$1"
  LIST_PATH="/var/ossec/etc/lists/alienvault_reputation.ipset"
  CDB_PATH="/var/ossec/etc/lists/blacklist-alienvault"
  TMP_SCRIPT="/tmp/iplist-to-cdblist.py"

  sudo mkdir -p /var/ossec/etc/lists
  sudo chown wazuh:wazuh /var/ossec/etc/lists || true

  # ensure source file exists
  if [ ! -f "$LIST_PATH" ]; then
    sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O "$LIST_PATH"
  fi

  # append IP
  sudo bash -c "echo '${ATT}' >> ${LIST_PATH}"

  # download converter if missing
  if [ ! -f "$TMP_SCRIPT" ]; then
    sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O "$TMP_SCRIPT"
  fi

  # convert to CDB
  sudo /var/ossec/framework/python/bin/python3 "$TMP_SCRIPT" "$LIST_PATH" "$CDB_PATH"
  sudo chown wazuh:wazuh "$CDB_PATH"
  echo "Added ${ATT} and converted to ${CDB_PATH}"
}
```

### Bash helper — local block (victim)
```bash
# Usage: sudo block_ip_local 1.2.3.4
block_ip_local() {
  IP="$1"
  if command -v ufw >/dev/null 2>&1; then
    sudo ufw insert 1 deny from "$IP" to any
  else
    sudo iptables -I INPUT -s "$IP" -j DROP
  fi
  echo "Blocked ${IP} locally."
}
```

### PowerShell helper — Windows local block
```powershell
# Usage: .\block_ip.ps1 -IP "1.2.3.4"
param([string]$IP)
Write-Output "Blocking $IP via netsh"
netsh advfirewall firewall add rule name="Block-IR-$IP" dir=in action=block remoteip=$IP enable=yes
```

> These helpers are examples. Review and adapt to your environment before running.

---

## Incident Response Playbook (concise)
1. **Detection** — Wazuh alerts on suspicious activity / CDB match.  
2. **Triage** — Gather context: timestamp, srcip, dst, user agent, request path.  
3. **Containment** — Execute Active Response / run `block_ip_local` / isolate VM.  
4. **Eradication** — Remove web shells, malicious files; patch vulnerable software.  
5. **Recovery** — Rebuild or harden affected services; validate integrity.  
6. **Lessons Learned** — Document root cause, update rules, automate defenses.

Include a detailed `docs/playbooks.md` for printed procedures and checklists.

---

## Files & scripts (what to commit)
- `/scripts/setup_webserver.sh` — Apache install + demo site creation.
- `/scripts/install_wazuh_agent.sh` — Agent install (platform-specific snippets).
- `/scripts/block_ip.sh` — Simple wrapper calling `ufw`/`iptables` or `netsh`.
- `/lab-config/detection_rules/001-blacklist-alienvault.xml` — example rule.
- `/docs/playbooks.md` — printable IR playbook with checklists.
- `/logs/sample_alerts.json` — sample alert JSON for reference.
- `end.mp4` — demo video of the full lab (place in repo root).

---

## Cloud notes — Google Cloud specifics
- If you use **GCP**, allow `tcp:80` on the VM network tag and open the VM external IP for test traffic.  
- GCP internal firewall and OS-level firewall (ufw/iptables) must both allow HTTP or the Wazuh agent will not receive expected logs.  
- For public IP testing, ensure the external IP is reachable from the attacker VM and that routes are correct.

---

## References & learning resources
- Wazuh docs — Quickstart & PoC: https://documentation.wazuh.com
- Blocking PoC: https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html
- My Wazuh install guide: https://github.com/AbdulRhmanAbdulGhaffar/Wazuh_Installation_Guide

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
MIT — see `LICENSE` for details.

---

> *This README is intentionally complete and exact. Review every script and command before running in production.*
> 
> *“وَقُل رَبِّ زِدْنِي عِلْمًا”* ✨
