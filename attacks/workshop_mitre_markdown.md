# Workshop Attack Commands — Module 3
> **Verified:** Jun 11, 2026 | All paths, rules, and alerts confirmed on live environment

## Environment

| Host | IP | Access |
|---|---|---|
| Attacker VM | `10.30.5.20` | Direct SSH |
| Honeypot VM | `10.30.5.40` | `ssh -i HoneyPotController.pem -p 4567 admin@10.30.5.40` |
| Wazuh Manager | `10.30.5.10` | `ssh -i WazuhServer24.pem ubuntu@10.30.5.10` |
| Wazuh Dashboard | `https://10.30.5.10:443` | Browser |

---

## Log Paths (confirmed on live system)

| Service | Path on Honeypot VM |
|---|---|
| Cowrie | `/home/admin/tpotce/data/cowrie/log/cowrie.json` |
| Dionaea | `/home/admin/tpotce/data/dionaea/log/dionaea.json` |
| Suricata | `/home/admin/tpotce/data/suricata/log/eve.json` |
| H0neytr4p | `/home/admin/tpotce/data/h0neytr4p/log/log.json` |
| Heralding | `/home/admin/tpotce/data/heralding/log/log_session.json` |
| Conpot | `/home/admin/tpotce/data/conpot/log/conpot_IEC104.json` |
| Wazuh agent config | `/var/ossec/etc/ossec.conf` |
| Wazuh agent log | `/var/ossec/logs/ossec.log` |

> ⚠️ **Not** `/data/tpot/` — correct root is `/home/admin/tpotce/data/`

---

## Rule Reference (all verified in wazuh-logtest)

| Rule ID | Service | Level | Trigger |
|---|---|---|---|
| 101100 | Cowrie | 5 | SSH/Telnet connection |
| 101101 | Cowrie | 7 | SSH login failed |
| 101102 | Cowrie | 12 | SSH login SUCCESS |
| 101103 | Cowrie | 10 | Command executed in fake shell |
| 101104 | Cowrie | 12 | Malware file downloaded |
| 101105 | Cowrie | 14 | SSH brute force (5 failures / 60s) |
| 101200 | Dionaea | 5 | Connection accepted |
| 101201 | Dionaea | 10 | SMB connection — possible EternalBlue |
| 101202 | Dionaea | 12 | Connection rejected |
| 101300 | H0neytr4p | 5 | HTTPS probe (not trapped) |
| 101301 | H0neytr4p | 12 | TRAPPED request (e.g. /.env, /wp-admin) |
| 101302 | H0neytr4p | 14 | Port scan (10 probes / 30s) |
| 101400 | Heralding | 5 | Connection on monitored port |
| 101401 | Heralding | 9 | Credential attempt |
| 101500 | Conpot | 10 | ICS/SCADA probe |
| 101800 | Redis | 7 | Redis honeypot connection |
| 101900 | Correlation | 15 | **Same IP hits 3+ honeypot services in 5 min** |
| 86601 | Suricata | 3 | IDS alert on honeypot traffic |

---

## Module 1 — Introducing SIEM

### Task 4.1 — Single Failed SSH Login
> Run on: **Linux Agent VM (localhost)**
```bash
ssh thisuserdoesnotexist@localhost
```
**Expected alert:** Rule 5710 — `sshd: Attempt to login using a non-existent user`

---

### Task 4.3 — Brute Force Simulation
```bash
for i in {1..5}; do ssh wronguser@localhost; done
```
**Expected alerts:** Rule 5710 × 5, then brute-force correlation rule

---

### Task 6 — Web 404 (Nginx/Apache)
```bash
curl http://localhost/
curl http://localhost/this-page-does-not-exist
```
**Expected alert:** Web rule, 404 visible under `rule.groups:web`

---

## Module 3 — Honeypots

### Pre-Attack: Watch Logs Live (run on Honeypot VM)
```bash
# Cowrie — live credential capture
sudo tail -f /home/admin/tpotce/data/cowrie/log/cowrie.json \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        if 'login' in e.get('eventid','') or 'command' in e.get('eventid',''):
            print(f\"{e['eventid']} | user={e.get('username','')} pass={e.get('password','')} cmd={e.get('input','')} from={e.get('src_ip','')}\" )
    except: pass
"
```

```bash
# H0neytr4p — live trap monitor
sudo tail -f /home/admin/tpotce/data/h0neytr4p/log/log.json \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        trapped = e.get('trapped','false')
        mark = ' TRAPPED' if trapped == 'true' else '   probe  '
        print(f\"{mark} | {e.get('request_method','')} {e.get('request_uri','')} from {e.get('src_ip','')}\" )
    except: pass
"
```

---

### Attack 1 — Nmap Port Scan
> Run on: **Attacker VM (10.30.5.20)**
```bash
sudo nmap -sS -p 21,22,23,80,443,445,1433,3306,5900,6379,8080 10.30.5.40
```
**Expected alerts:**
- Suricata: ET SCAN / Nmap detection (rule 86601)
- Cowrie logs TCP knock on port 22
- Dionaea logs connection attempts on 21, 445, 3306

**Dashboard WQL:**
```
rule.groups:honeypot AND agent.name:Honeypot
```

---

### Attack 2 — SSH Brute Force on Cowrie
> Run on: **Attacker VM (10.30.5.20)**

#### Create wordlist
```bash
cat > /tmp/passwords.txt << 'EOF'
123456
password
admin
root
letmein
qwerty
toor
password123
test
welcome
EOF
```

#### Run Hydra
```bash
hydra -l root -P /tmp/passwords.txt -t 4 ssh://10.30.5.40
```

**Expected alerts:**
- Rule 101101 — `Cowrie: SSH login failed` (level 7) — fires per attempt
- Rule 101102 — `Cowrie: SSH login SUCCESS` (level 12) — Cowrie accepts after a few tries
- Rule 101103 — `Cowrie: Command executed` (level 10) — if Hydra runs post-login commands
- Rule 101105 — `Cowrie: SSH brute force` (level 14) — fires after 5 failures in 60s

**Dashboard WQL:**
```
rule.id:101101 AND agent.name:Honeypot
```
```
data.src_ip:10.30.5.20
```

---

### Attack 3 — SMB Probe on Dionaea
> Run on: **Attacker VM (10.30.5.20)**
```bash
nmap -sV -p 445 --script smb-vuln-ms17-010 10.30.5.40
```
**Expected alerts:**
- Rule 101201 — `Dionaea: SMB connection — possible EternalBlue` (level 10)
- Suricata may also fire NTLM/SMB signatures

**Dashboard WQL:**
```
data.honeypot:dionaea
```
```
rule.id:101201
```

---

### Attack 4 — H0neytr4p Web Probe
> Run on: **Attacker VM (10.30.5.20)**
```bash
# Basic probes — will NOT trap
curl -sk https://10.30.5.40/ -o /dev/null
curl -sk https://10.30.5.40/admin -o /dev/null
curl -sk https://10.30.5.40/login -o /dev/null

# Sensitive paths — WILL trap (rule 101301)
curl -sk https://10.30.5.40/.env -o /dev/null
curl -sk https://10.30.5.40/wp-config.php -o /dev/null
curl -sk https://10.30.5.40/.git/config -o /dev/null
```

**Expected alerts:**
- Rule 101300 — `H0neytr4p: Probe` (level 5) — basic paths
- Rule 101301 — `H0neytr4p: TRAPPED attacker` (level 12) — sensitive paths

**Dashboard WQL:**
```
rule.id:101301
```
```
rule.groups:honeytrap
```

---

### Trigger Multi-Service Correlation (Rule 101900)
Run all attacks from same IP within 5 minutes. Rule 101900 fires when same IP hits 3+ honeypot services.

```bash
# Quick sequence from attacker VM — all in ~2 minutes
sudo nmap -sS -p 22,445,443 10.30.5.40 &&
hydra -l root -P /tmp/passwords.txt -t 4 -f ssh://10.30.5.40 &&
curl -sk https://10.30.5.40/.env -o /dev/null
```

**Expected:** Rule 101901 level 15 — `T-POT: Multi-honeypot attack campaign from 10.30.5.20`

**Dashboard WQL:**
```
rule.id:101900
```

---

## Dashboard WQL Quick Reference

```
# All honeypot alerts
rule.groups:honeypot

# Cowrie only
rule.groups:tpotcowrie

# Cowrie login failures
rule.id:101101

# Cowrie login success
rule.id:101102

# Cowrie commands executed
rule.id:101103

# Cowrie brute force correlation
rule.id:101105

# Dionaea SMB / EternalBlue
rule.id:101201

# H0neytr4p trapped
rule.id:101301

# Multi-service campaign (CRITICAL)
rule.id:101900

# All events from attacker
data.src_ip:10.30.5.20

# High severity honeypot only
rule.groups:honeypot AND rule.level:>=10

# Suricata IDS alerts
rule.id:86601

# SSH non-existent user (Module 1)
rule.id:5710

# All auth failures across all agents
rule.groups:authentication_failed
```

---

## Wazuh Manager — Admin Commands

```bash
# SSH to manager
ssh -i WazuhServer24.pem ubuntu@10.30.5.10

# Run logtest
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest

# List agents
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

# Edit custom rules (persistent)
sudo nano /home/ubuntu/wazuh-docker-prod/single-node/custom/local_rules.xml

# Edit custom decoders (persistent)
sudo nano /home/ubuntu/wazuh-docker-prod/single-node/custom/local_decoder.xml

# Reload after rule/decoder changes
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

# Apply NAT rules if agents disconnected
sudo ./access.sh
```

---

## Honeypot VM — Admin Commands

```bash
# SSH to honeypot
ssh -i HoneyPotController.pem -p 4567 admin@10.30.5.40

# Check all containers running
sudo docker ps --format "table {{.Names}}\t{{.Status}}" | sort

# Check agent connected
sudo tail -5 /var/ossec/logs/ossec.log

# Restart agent if disconnected
sudo systemctl restart wazuh-agent

# Read any log line by line
sudo tail -20 /home/admin/tpotce/data/cowrie/log/cowrie.json \
  | python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin if l.strip()]"
```
