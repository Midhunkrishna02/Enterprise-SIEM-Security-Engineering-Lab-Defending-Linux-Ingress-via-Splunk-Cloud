# Enterprise SIEM Security Engineering Lab: Defending Linux Ingress via Splunk Cloud

## 📌 Architectural Overview
This defensive security engineering project implements an end-to-end telemetry pipeline and monitoring capability designed to capture, parse, and alert on automated password-spraying and authentication-driven brute force vectors. 

The lab configures an internal Linux target node to stream native OS auditing logs (auth.log) securely over an encrypted transport line into a Splunk Cloud SIEM distributed cluster. An aggressive authentication attack simulation is launched from a separate offensive virtual layer using Hydra, establishing a benchmark data vector. This telemetry is then parsed using advanced Splunk Search Processing Language (SPL) token extractions, leading to the deployment of a noise-throttled security monitoring rule.

### 🌐 System Topology & Tool Stack
* SIEM Platform: Splunk Cloud Infrastructure Enterprise (v10.4.260)
* Target OS Endpoint: Ubuntu Server Virtual Machine (Victim_IP)
* Telemetry Agent: Splunk Universal Forwarder
* Adversary Utility: Hydra Framework (Kali Linux Platform Host - Attacker_IP)
* Languages & Parsing: Splunk SPL, Regular Expressions (PCRE Regex Syntax)
* Target Monitored Ingress Vector: SSH (Secure Shell) Protocol (Port 22)

---

## 🛠️ Phase 1: Operational Logging Pipeline Deployment

To establish a unified monitoring pane, the target Ubuntu host was provisioned with the Splunk Universal Forwarder application. The local outputs configuration (outputs.conf) was tied into the cloud-hosted indexing cluster endpoints.

The secure access tracking infrastructure was configured by creating a dedicated monitor rule in inputs.conf pointing directly to the system's authorization log file:

    [monitor:///var/log/auth.log]
    disabled = false
    sourcetype = linux_secure
    index = main

Following a daemon reload cycle, data synchronization with the Cloud SIEM engine was validated, establishing raw log intake consistency.

---

## ⚔️ Phase 2: Adversary Emulation (Automated Password Spraying)

Using a distinct network adapter point on a Kali Linux node, an aggressive dictionary credential attack was directed against the target server user profile. This attack simulated an automated botnet login sequence attempting to harvest a shells footprint.

Command executed from the offensive host:

    hydra -l midhun -P /usr/share/wordlists/rockyou.txt ssh://Victim_IP -t 4 -V

* Command Parameters Decoded:
  * -l midhun: Dictates targeting the target account discovered on the destination host.
  * -P rockyou.txt: References the industry-standard wordlist array containing millions of leaked text keys.
  * -t 4: Sets 4 parallel connection threads to strike a balance between network stability and throughput velocity.
  * -V: Forces verbose logging execution to output every failed attempt live into stdout.

---

## 🔍 Phase 3: Defensive SPL Query & Detection Engineering

During initial log evaluation, the out-of-the-box syslog parser on the default Ubuntu platform failed to map internal variables into indexable token fields. To bypass this metadata restriction, a modular forensic query path was engineered.

### 1. Ingestion Baseline Discovery Search
The first step verified that malicious password failure telemetry was actively crossing the network plane into the Splunk indexes:

    index=* sourcetype="linux_secure" "Failed password"

### 2. Regex Token Field Generation & Intrusion Grouping
Because standard field variables like src_ip or user were unmapped, custom PCRE regular expression extractions were developed inside an inline rex command block. This permitted the extraction of names and target nodes instantly from the _raw text segment, mapping entries into structured statistical tables:

    index=* sourcetype="linux_secure" "Failed password"
    | rex field=_raw "Failed password for (?<Targeted_User>\S+) from (?<Attacker_IP>\S+)"
    | stats count by Attacker_IP, Targeted_User
    | rename Attacker_IP as "Attacker IP", Targeted_User as "Targeted Username", count as "Total Failed Attempts"

(Insert your Brute-Force Detection Table screenshot here)

### 3. Triage & Incident Mapping (Unix Epoch Breakdown)
Once the bulk attack vectors were validated, finding system compromise events became the primary objective. This query isolated successful authorization triggers:

    index=* sourcetype="linux_secure" "Accepted password"
    | rex field=_raw "Accepted password for (?<Targeted_User>\S+) from (?<Attacker_IP>\S+)"
    | table _time, Attacker_IP, Targeted_User
    | rename _time as "Timestamp", Attacker_IP as "Attacker IP", Targeted_User as "Compromised Account"

### 4. Production-Grade Incident Timelining
To transform raw Unix time integers (e.g., 1782278979.912) into actionable human logs for executive briefing tables, an evaluation filter (eval) coupled with string-formatting elements (strftime) was engineered:

    index=* sourcetype="linux_secure" "Accepted password"
    | rex field=_raw "Accepted password for (?<Targeted_User>\S+) from (?<Attacker_IP>\S+)"
    | eval Human_Time=strftime(_time, "%Y-%m-%d %H:%M:%S")
    | table Human_Time, Attacker_IP, Targeted_User
    | rename Human_Time as "Timestamp", Attacker_IP as "Attacker IP", Targeted_User as "Compromised Account"

(Insert your Successful Breach Timeline screenshot here)

---

## 🚨 Phase 4: Automated Detection Rule & Alert Policy Design

To transform this reactive diagnostic sequence into an automated active defensive shield, the logic was deployed as an integrated SIEM detection rule with precise scheduling and throttle configurations.

### ⚙️ Rule Configuration Architecture
* Alert Label: Brute Force SSH Attack Detected
* Execution Logic Type: Scheduled Cron Optimization
* Cron Interval String: */5 * * * * (Triggers evaluation loop precisely every 5 minutes)
* Trigger Threshold Filter: Number of Results > 5
* Trigger Suppression/Throttling Logic: Enabled for 60 Seconds
* Throttling Suppress Field Token: Attacker_IP
* Incident Action Mapping: Log entries prioritized directly to the Triggered Alerts Console
* Assigned Incident Priority: Medium Severity

### 🧠 Architectural Note on Throttling Design
During active automated intrusions, attackers generate thousands of unique text logging lines within seconds. If a notification engine triggered on every match, the system would create severe alert exhaustion and dashboard flood states. By constraining notifications utilizing the custom Attacker_IP token window set to 60 seconds, Splunk clusters identical consecutive logs into a unified actionable case marker, ensuring crisp operations for responding analysts.

---

## 🏁 Phase 5: Incident Validation & Verification Loop

To rigorously verify the rule's operational status, a secondary attack sequence was executed via Hydra. The scheduled alert executed successfully, tracking the data spike and generating an incident record inside the tracking console.

(Insert your Triggered Alerts Dashboard screenshot here)

### 🛡️ Analytical Findings & Response Checklist
1. Malicious Actor Identified: Ingress IP Attacker_IP tracked attempting high-velocity authentication.
2. Impact Assessment: System compromised via user target profile midhun at the designated timestamp values.
3. Remediation Profile: Recommended blocking source Attacker_IP at the edge firewall level, applying immediate system-wide public key-based authentication requirements (disabling raw passwords), and disabling remote root/administrative login permissions over WAN boundaries.
