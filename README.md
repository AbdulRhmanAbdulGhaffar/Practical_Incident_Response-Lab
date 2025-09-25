# Practical_Incident_Response-Lab
# Sentinel-Response

<p align="center">
  <img src="https://i.postimg.cc/rwhj5w4r/design.png" alt="HomeLab Design" width="600"/>
</p>

---

> **A practical, production-minded Incident Response lab.**
>
> End‑to‑end workflow: attack simulation → detection (Wazuh SIEM) → automated containment → forensic notes.
> Designed for hands‑on learning in Threat Detection, Threat Hunting, and Blue Team operations.

---

## About

**Sentinel-Response** documents a reproducible Home Lab for Incident Response.
This README explains the exact steps used to reproduce the `Blocking a known malicious actor` use case, the artifacts used, and how to run the lab on local machines or cloud (Google Cloud).
Technical terms are left in English for clarity.

## Project assets

* Lab image (above).
* Video demonstration: `end.mp4` (placed in repository root).
* Scripts folder: `/scripts` (setup\_webserver.sh, install\_wazuh\_agent.sh, block\_ip.sh).
* Lab configuration: `/lab-config` (detection rules, wazuh configs).
* Documentation: `/docs` (architecture, playbooks, wazuh\_rules).

---

## Quick links

* Wazuh quickstart: [https://documentation.wazuh.com/current/quickstart.html](https://documentation.wazuh.com/current/quickstart.html)
* Wazuh PoC (block malicious actor): [https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html](https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html)
* Wazuh install guide used: [https://github.com/AbdulRhmanAbdulGhaffar/Wazuh\_Installation\_Guide](https://github.com/AbdulRhmanAbdulGhaffar/Wazuh_Installation_Guide)

---

## Lab use case — Blocking a known malicious actor (summary)

This lab demonstrates detection and temporary blocking of a malicious IP using a public IP reputation list, Wazuh CDB lists, and Active Response.
Attacker: RHEL host. Victims: Ubuntu and Windows hosts running Apache web servers.

Workflow:

1. Attacker (RHEL) makes HTTP requests to victim web servers.
2. Wazuh agents on victims forward logs to the Wazuh manager.
3. Wazuh checks the source IP against a CDB reputation list (AlienVault).
4. A custom rule triggers when the IP matches the list.
5. Active Response runs a local action to block the IP for a configurable timeout (60s in this lab).

---

## Infrastructure (as implemented)

* **Attacker endpoint**: RHEL 9 (simulated malicious host).
* **Victim endpoints**: Ubuntu 22.04 (Apache2), Windows 11 (Apache2 binary).
* **Wazuh Manager**: RHEL/CentOS or compatible host running Wazuh Manager.
* **Cloud**: Google Cloud Platform used to host some lab VMs (optional).

---

## Step-by-step reproduction (exact commands)

> These steps are the tested sequence used in the demo. Follow them in order.

### 1) Prepare victim — Ubuntu (Apache + Wazuh agent)

```bash
# update and install apache2
sudo apt update
sudo apt install -y apache2
sudo systemctl enable --now apache2

# allow HTTP if using ufw
sudo ufw allow 'Apache'

# verify site
curl http://<UBUNTU_IP>

# configure Wazuh agent to monitor apache logs
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<'EOF'
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
EOF

sudo systemctl restart wazuh-agent
```

---

### 2) Prepare victim — Windows (Apache + Wazuh agent)

* Install Visual C++ Redistributable.

* Download prebuilt Apache Win64 zip, extract to `C:/Apache24`.

* Run `C:/Apache24/bin/httpd.exe` as administrator. Allow in Windows Firewall when prompted.

* Verify: open `http://<WINDOWS_IP>` from another host.

* Configure Wazuh agent (edit `C:/Program Files (x86)/ossec-agent/ossec.conf`):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>C:/Apache24/logs/access.log</location>
</localfile>
```

* Restart Wazuh agent (PowerShell as administrator):

```powershell
Restart-Service -Name wazuh
```

---

### 3) Wazuh server — prepare reputation list (CDB)

```bash
# install wget (example on RHEL/CentOS)
sudo yum update -y && sudo yum install -y wget

# download AlienVault ipset
sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset

# append attacker IP
sudo bash -c 'echo "<ATTACKER_IP>" >> /var/ossec/etc/lists/alienvault_reputation.ipset'

# download converter script
sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py

# convert to .cdb
sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault

# set ownership
sudo chown wazuh:wazuh /var/ossec/etc/lists/blacklist-alienvault

# cleanup (optional)
sudo rm -f /var/ossec/etc/lists/alienvault_reputation.ipset /tmp/iplist-to-cdblist.py
```

---

### 4) Wazuh server — add detection rule (local\_rules.xml)

Add the following rule to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="attack">
  <rule id="100100" level="10">
    <if_group>web,attack,attacks</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
    <description>IP address found in AlienVault reputation database.</description>
  </rule>
</group>
```

Then include the list in `/var/ossec/etc/ossec.conf` under `<ruleset>` (example excerpt):

```xml
<list>etc/lists/blacklist-alienvault</list>
```

---

### 5) Wazuh server — Active Response configuration

Add active-response blocks to `/var/ossec/etc/ossec.conf`.

**Ubuntu (firewall-drop):**

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

Restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

---

### 6) Emulate the attack (from RHEL attacker)

```bash
curl http://<WEBSERVER_IP>
# repeat a second request to trigger the active response block behavior
curl http://<WEBSERVER_IP>
```

After the first connection the IP is observed and checked against the CDB list. When the rule triggers, the active response will block subsequent connections for the configured timeout (60s).

---

### 7) Visualize alerts

* Open Wazuh Dashboard → Threat Hunting or Alerts.
* Filter by `rule.id:(651 OR 100100)` to find the generated alerts.

Add screenshots or sample JSON alerts to `/logs/sample_alerts.json` for reference.

---

## Cloud note — Google Cloud

This lab was executed partially on **Google Cloud** VMs for network segmentation and public‑IP testing. The same steps apply to local VMs; adjust network/firewall settings accordingly.
If you run on GCP, ensure the VM external IPs and firewall rules allow HTTP and the required management ports.

---

## Files & scripts (what to expect)

* `/scripts/setup_webserver.sh` — Automated Apache install and demo site setup.
* `/scripts/install_wazuh_agent.sh` — Simplified Wazuh Agent install + basic config snippet.
* `/scripts/block_ip.sh` — Helper to block an IP locally (ufw / iptables fallback).
* `/lab-config/detection_rules/001-blacklist-alienvault.xml` — local rules snippet.
* `/docs/playbooks.md` — Incident Response playbook (detection → triage → containment → eradication → recovery → lessons learned).

---

## Credits & references

* Wazuh docs and PoC: [https://documentation.wazuh.com](https://documentation.wazuh.com)
* Wazuh installation guide used: [https://github.com/AbdulRhmanAbdulGhaffar/Wazuh\_Installation\_Guide](https://github.com/AbdulRhmanAbdulGhaffar/Wazuh_Installation_Guide)
* Blocking PoC: [https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html](https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html)

---

## License

This project is released under the MIT License. See `LICENSE`.

---

## Contact

Owner: AbdulRhman AbdulGhaffar
LinkedIn: ([add your profile](https://www.linkedin.com/in/abdulrhmanabdulghaffar/))
Email: [abdulrhman.abdulghaffar001@gmail.com](mailto:abdulrhman.abdulghaffar001@gmail.com)

---

> **Note:** Follow the files in `/docs` for printable playbooks and exact copy‑paste commands. The repo includes tested scripts; review them before running in production.

