<h1>🧪 Hands-On Lab: Brute Force Alerting & Incident Response (Sentinel + MDE)</h1>

<hr />

<h2>✅ Pre-Lab Setup</h2>
<ul>
  <li>Ensure a Windows VM exists and is onboarded to Microsoft Defender for Endpoint (MDE)</li>
  <li>Confirm device telemetry is flowing into Sentinel via Log Analytics</li>
</ul>

<img width="1105" height="427" alt="image" src="https://github.com/user-attachments/assets/8eebc1a4-9101-4145-89ea-abdcf9969417" />


<hr />

<h2>🧠 Explanation (What We’re Building)</h2>
<p>
Failed and successful logons on the VM are captured in <strong>DeviceLogonEvents</strong> by MDE and forwarded to the
Log Analytics Workspace used by Microsoft Sentinel. We create a <strong>scheduled analytics rule</strong> that triggers when
the same <strong>Remote IP</strong> fails to log into the same <strong>Device</strong> repeatedly (example: 10+ failures in 5 hours).
</p>

<hr />

<h2>🛠️ Part 1 — Create the Brute Force Analytics Rule</h2>
<p><strong>Goal:</strong> Detect repeated failed logons from the same Remote IP to the same VM.</p>

<details>
  <summary><strong>🧩 KQL (Brute Force Attempt Detection)</strong></summary>
  <pre><code>
//Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same remote IP address has failed to log in to the same local 
//host (Azure VM) 10 times or more within the last 5 hours


DeviceLogonEvents
| where ActionType == "LogonFailed" and  TimeGenerated > ago(5h)
| summarize Eventcount = count() by RemoteIP, DeviceName, ActionType
| where Eventcount >= 10
| order by Eventcount
  </code></pre>
</details>

<p><strong>📸 <img width="1901" height="948" alt="image" src="https://github.com/user-attachments/assets/b5cbc695-5c43-4359-bc7c-e3a74623ebf4" />


<h3>⚙️ Create the Rule</h3>
<ul>
  <li>Go to: <strong>Sentinel → Analytics → Scheduled query rule</strong></li>
  <li>Enable the rule</li>
  <li>Set schedule: <strong>Run every 4 hours</strong></li>
  <li>Lookup data: <strong>Last 5 hours</strong> (and/or enforce in the query)</li>
  <li>Stop running query after alert is generated: <strong>Yes</strong></li>
  <li>Entity mappings:
    <ul>
      <li>✅ Remote IP → <code>RemoteIP</code></li>
      <li>✅ Host/Device → <code>DeviceName</code></li>
    </ul>
  </li>
  <li>Incident settings:
    <ul>
      <li>✅ Automatically create an incident</li>
      <li>✅ Group alerts into a single incident per 24 hours</li>
      <li>✅ Stop running after alert generated for 24 hours</li>
    </ul>
  </li>
  <li>MITRE mapping: used AI to map relevant techniques</li>
</ul>

<img width="1872" height="974" alt="image" src="https://github.com/user-attachments/assets/d5e15b80-1523-48ce-9ca4-5c9fd17b9f7b" />



<hr />

<h2>💥 Part 2 — Trigger the Alert (Create the Incident)</h2>
<ul>
  <li>If logs already exist: wait for the scheduled query to run</li>
  <li>If logs do not exist: generate failures by intentionally failing login attempts enough times</li>
  <li>Confirm the incident appears in: <strong>Sentinel → Threat Management → Incidents</strong></li>
</ul>

<img width="439" height="321" alt="image" src="https://github.com/user-attachments/assets/f3a375e4-1698-4ab7-bf8b-53336268416c" />


<hr />

<h2>🧯 Part 3 — Work the Incident (NIST 800-61)</h2>

<h3>🧰 Preparation</h3>
<ul>
  <li>Document roles, procedures, and tools used</li>
</ul>

<h3>🔍 Detection &amp; Analysis</h3>
<ul>
  <li>Assign the incident to myself</li>
  <li>Set status to <strong>Active</strong></li>
  <li>Actions → <strong>Investigate</strong> (wait for entities if needed)</li>
  <li>Recorded:
    <ul>
      <li>Number of IPs involved</li>
      <li>Number of devices targeted</li>
      <li>Time window and event volume</li>
    </ul>
  </li>
</ul>

<img width="1739" height="293" alt="image" src="https://github.com/user-attachments/assets/5ed74e47-375d-4858-80e5-0fa01c9f0739" />

<img width="275" height="565" alt="image" src="https://github.com/user-attachments/assets/8cb450d6-9787-4f5b-9acb-f3ab4abf07d5" />

<h3>✅ Check for Brute Force Success (Did Any IP Log In?)</h3>
<details>
  <summary><strong>🧩 KQL (Validate Successful Login From Suspect IP)</strong></summary>
  <pre><code>
let TargetDevice = "jinks-ir-scenes"; // Replace with target VM
let SuspectIP = "xxx.xxx.xxx.xxx";       // Replace with suspect IP
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
  </code></pre>
</details>

<h3>🛡️ Containment, Eradication &amp; Recovery</h3>
<ul>
  <li>In a real environment:
    <ul>
      <li>Isolate the device via MDE</li>
      <li>Run antivirus scan</li>
    </ul>
  </li>
  <li>For this lab:
    <ul>
      <li>Locked down the VM’s NSG so only my IP could reach the VM</li>
      <li>Documented: “NSG was locked down to prevent RDP attempts from the public internet”</li>
      <li>Proposed: Azure Policy to prevent wide-open NSGs org-wide</li>
    </ul>
  </li>
</ul>

<img width="1780" height="272" alt="image" src="https://github.com/user-attachments/assets/1cc907ae-fa62-4c93-892b-38a96e955c2c" />


<h3>📝 Post-Incident Activities</h3>
<ul>
  <li>Recorded findings and lessons learned in the incident</li>
  <li>Noted improvement opportunities:
    <ul>
      <li>Require NSG hardening baseline</li>
      <li>Enforce with Azure Policy</li>
      <li>Optional: enhance detection to trigger only when failures are followed by success</li>
    </ul>
  </li>
</ul>

<h3>✅ Closure</h3>
<ul>
  <li>Reviewed notes and evidence</li>
  <li>Closed the incident as <strong>True Positive</strong></li>
</ul>

<img width="503" height="511" alt="image" src="https://github.com/user-attachments/assets/b6f414dd-0430-4a18-a063-a72122c130e3" />


<hr />
<h2>✅ Outcome</h2>
<ul>
  <li>Built and validated a brute-force detection rule in Sentinel</li>
  <li>Generated an incident and investigated entity mappings</li>
  <li>Verified whether brute force attempts resulted in successful access</li>
  <li>Documented mitigation via NSG lockdown and policy recommendations</li>
</ul>
