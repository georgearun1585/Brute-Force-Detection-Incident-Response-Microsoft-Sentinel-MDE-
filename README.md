# Brute-Force-Detection-Incident-Response-Microsoft-Sentinel-MDE-

<p>
This project demonstrates how SOC teams use <strong>Microsoft Sentinel</strong> (SIEM) and
<strong>Microsoft Defender for Endpoint</strong> (MDE) telemetry to detect brute-force login attempts against cloud virtual machines,
automatically generate incidents, and investigate them using the <strong>NIST 800-61 Incident Response Lifecycle</strong>.
</p>

<hr />

<h2>🎯 What This Project Demonstrates</h2>
<ul>
  <li>Built a Sentinel scheduled analytics rule to detect repeated failed logons (<strong>10+ failures within 5 hours</strong>)</li>
  <li>Mapped entities (Remote IP and Device Name) for investigation-ready alerts</li>
  <li>Automatically generated Sentinel incidents and grouped alerts to reduce noise</li>
  <li>Worked the incident end-to-end following <strong>NIST 800-61</strong></li>
  <li>Validated whether brute-force attempts resulted in successful authentication</li>
  <li>Recommended cloud hardening controls using NSGs and Azure Policy</li>
</ul>

<hr />

<h2>🧠 MITRE ATT&CK Mapping</h2>

<table>
  <thead>
    <tr>
      <th align="left">Observed Activity</th>
      <th align="left">ATT&CK Tactic</th>
      <th align="left">ATT&CK Technique</th>
      <th align="left">ID</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Repeated failed authentication attempts from external IPs</td>
      <td>Credential Access</td>
      <td>Brute Force</td>
      <td><strong>T1110</strong></td>
    </tr>
    <tr>
      <td>Targeting exposed RDP/VM login services</td>
      <td>Initial Access</td>
      <td>External Remote Services</td>
      <td><strong>T1133</strong></td>
    </tr>
    <tr>
      <td>Attempted authentication against multiple hosts</td>
      <td>Discovery</td>
      <td>Network Service Discovery</td>
      <td><strong>T1046</strong></td>
    </tr>
    <tr>
      <td>Post-detection validation of successful logons</td>
      <td>Credential Access</td>
      <td>Valid Accounts</td>
      <td><strong>T1078</strong></td>
    </tr>
  </tbody>
</table>

<hr />

<h2>🧰 Tools & Technologies</h2>
<ul>
  <li>Microsoft Sentinel (SIEM)</li>
  <li>Microsoft Defender for Endpoint (EDR)</li>
  <li>Log Analytics Workspace</li>
  <li>KQL (Kusto Query Language)</li>
  <li>Azure Virtual Machines</li>
  <li>Network Security Groups (NSGs)</li>
  <li>NIST 800-61 Incident Response Framework</li>
</ul>

<hr />

<h2>🧪 Detection Logic Overview</h2>
<p>
Failed logon events generated on Windows virtual machines are collected by Microsoft Defender for Endpoint
and stored in the <strong>DeviceLogonEvents</strong> table. These events are forwarded to Microsoft Sentinel, where a scheduled
analytics rule evaluates whether the same <strong>Remote IP</strong> has failed authentication against the same
<strong>Device</strong> ten or more times within a five-hour window.
</p>

<hr />

<h2>🧯 Incident Response Summary (NIST 800-61)</h2>
<ul>
  <li><strong>Preparation:</strong> Logging, entity mapping, and detection rules in place</li>
  <li><strong>Detection & Analysis:</strong> Sentinel alert and incident generation</li>
  <li><strong>Containment:</strong> NSG lockdown to block public internet access</li>
  <li><strong>Eradication & Recovery:</strong> Verified no successful brute-force logins occurred</li>
  <li><strong>Post-Incident Activity:</strong> Recommended Azure Policy to enforce hardened NSG baselines</li>
</ul>

<hr />

<h2>🏆 Why This Matters</h2>
<p>
Brute-force attacks remain one of the most common entry points into cloud environments.
This project shows hands-on experience with <strong>detection engineering</strong>,
<strong>incident response</strong>, and <strong>cloud security hardening</strong>—core responsibilities of SOC Analysts and Cloud Security Engineers.
</p>
