\[COMPANY LOGO\]

PHISHING RESPONSE PLAYBOOK

\[COMPANY NAME\] 

**Document Objectives:**

The playbook is to be used by the cyber incident response team. It focuses on helping them prioritize their actions and engage the right people during a confirmed phishing incident throughout the initial analysis & containment, detailed analysis, eradication, and recovery phases.

**Document Properties:**

| Version: | \[VERSION\] |
| :---- | :---- |
| Last Revised Date: | \[DATE\] |
| Confidentiality Level: | \[CONFIDENTIALITY\] |
| Document Owner | \[OWNER\] |
| Publication Date: | \[DATE\] |

**Table of Contents:**

**[1\. Overview	3](#1.-overview)**

[**2\. Phishing Response Process	3**](#2.-phishing-response-process)

[2.1 Detection	3](#2.1-detection)

[2.2 Initial Analysis and Containment	4](#2.2-initial-analysis-and-containment)

[2.3 Analysis	5](#2.3-analysis)

[2.4 Eradication	7](#2.4-eradication)

[2.5 Recovery	7](#2.5-recovery)

[2.6 Post-Incident Activity	8](#2.6-post-incident-activity)

[**3\. Phishing Response Checklist	8**](#3.-phishing-response-checklist)

[3.1 Detection and Analysis	8](#3.1-detection-and-analysis)

[3.2 Containment and Eradication	9](#3.2-containment-and-eradication)

[3.3 Recovery and Post-Incident	11](#3.3-recovery-and-post-incident)

# 

# 1\. Overview {#1.-overview}

The playbook is to be used by the cyber incident response team. It focuses on helping them prioritize their actions and engage the right people during a confirmed phishing incident throughout the initial analysis & containment, detailed analysis, eradication, and recovery phases. The audience for these playbooks is the Cybersecurity Incident Response Team (CSIRT), therefore playbook steps may be technical. Additionally, the playbook may reference responsibilities of other teams, but only informationally. The focus of the steps of the playbook is the investigation piece by the CSIRT.

The playbook shall be reviewed and updated as needed. This is necessary to address:

* Changes to regulatory requirements  
* Industry standards  
* Changes to malware/phishing trends  
* Lessons learned via exercises and/or actual events

This playbook will usually be activated when a possible phishing attempt is detected. Initial triage is performed to confirm whether accounts were successfully compromised. If the initial triage shows that the compromise was not successful or was related to some other activity determined to be a false positive, then no further escalation through the playbook is required.

# 2\. Phishing Response Process {#2.-phishing-response-process}

## 2.1 Detection {#2.1-detection}

The initial detection will most often come from one of the following:

* **Analysis efforts in a previous cybersecurity incident.**  
* **Automated detection systems:** \[EDR\], \[SIEM\], and \[EMAIL SECURITY SOLUTION\].  
* **Findings during threat hunting:** \[EDR\], \[SIEM\], and \[EMAIL SECURITY SOLUTION\].  
* **Managed security service providers:** \[MSSP/MDR\].  
* **Reporting:** User, partner, provider, or third-party.

### Decision to Stand Up Cyber Incident Response Team (CSIRT)

Following the initial detection and confirmation of a successful phishing attempt. The severity should be determined following the criteria specified in the [Incident Response Playbook](https://github.com/dhiggins19/IR-Playbooks/tree/main/Incident-Response-Overview). 

If the determination is made that the incident has a “Low” or “Medium” level of severity, then the internal Standard Operating Procedures can be followed to remediate the incident without activation of the Incident Response team.

If the severity has been determined to be “High” or “Critical” the incident response team must be activated as quickly as possible. That process is detailed in the [Incident Response Playbook](https://github.com/dhiggins19/IR-Playbooks/tree/main/Incident-Response-Overview).

## 2.2 Initial Analysis and Containment {#2.2-initial-analysis-and-containment}

### First Pass Analysis

The primary objective of the first pass is to quickly identify the scope of the impacted accounts, and whether the activity is ongoing. While other activities like root-cause analysis are critical components of the response process, the priority is to revoke access from the compromised accounts.

Details about the email (such as the sending email address/IP, subject, or attachment names) can be collected for later searching in \[EMAIL SECURITY SOLUTION\].

If a phishing email was interacted with the subsequent processes and network connections can be examined on one of the impacted hosts in \[EDR\]. The most obvious indicators of compromise should be immediately pulled out and used to identify additional affected hosts.

### Identify Affected Accounts

In the event that the incident is the result of malicious activities, a list of impacted hosts can be generated based on the IOCs collected during the first pass in \[EDR\], \[SIEM\], and \[EMAIL SECURITY SOLUTION\]. Detailed in: \[EDR\] IOC-based Hunting \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\] and \[SIEM\] IOC-based Hunting \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\], and \[EMAIL SECURITY SOLUTION\] Searching \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\]. Any accounts which can be correlated with the suspected malicious IOCs, and any accounts which were created by a compromised account, should be noted.

### Disable Impacted User/Host Credentials

Once the scope of impacted accounts has been identified, the account’s subsequent activities should be investigated. If the account has been used to perform malicious activities, then it is critical that the impacted user/host credentials be disabled. This can be accomplished by creating a \[ITSM\] request and messaging the relevant account management SME directly:

* Active Directory – \[SME\]  
* Entra ID – \[SME\]  
* \[IAM SOLUTION\] – \[SME\]

### Remove the Phishing Email from Targeted User Inboxes

Once one of the phishing emails have been reported via the \[EMAIL SECURITY SOLUTION\] plugin in Outlook, the \[EMAIL SECURITY SOLUTION\] platform can be utilized to find and remove that email from the impacted users’ inbox. Detailed in: \[EMAIL SECURITY SOLUTION\] Email Removal \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\].

Whether a user opened an email can be determined during the \[EMAIL SECURITY SOLUTION\] email removal process. The network connections/file processes should be reviewed for any user that opened the email to determine whether they interacted with malicious email. Depending on the observed activities, the user account credentials may need to be reset and/or their host may need to be contained and reimaged.

### Contain Affected Hosts

Any hosts which were being accessed by the compromised accounts should be closely examined. If there is suspicion of subsequent malicious activities, they can be individually contained via the \[EDR\] platform if the scope is relatively small. Detailed in: Host Containment \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\].

An automated workflow can be created in \[SOAR\] to automate the containment of impacted systems if the malicious activities are widespread. Detailed in: Creating Workflows \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\]. Utilize the indicators of compromise identified in the first pass analysis as a trigger for the automated containment workflow in \[SOAR\].

Custom indicators of attack (IOAs) and custom indicators of compromise (IOCs) can also be leveraged in \[EDR\] to proactively prevent machines from being infected. A custom IOA/IOC can be added with an action of “block execution” to prevent the infection mechanism from running. Detailed in Adding Custom Indicators \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\].

In cases where the impacted systems are not running the \[EDR\] sensor, it may be necessary to segment parts of the network to contain the spread of malware or to prevent malicious egress altogether. Network containment is available at the node, VLAN, switch, or site levels. This activity requires a network change request in \[ITSM\], but the change can proceed prior to \[ITSM\] approval in emergency circumstances with approval from the incident manager. Network containments to the LAN can be performed by the network management SMEs.

If systems are not able to be contained at the host or network levels, it may be required to physically unplug the networking cables or power down the impacted systems. This is reserved as a last-resort method because powering down systems can result in the loss of volatile forensic data.

## 2.3 Analysis {#2.3-analysis}

### Preserve Evidence

Ideally, it will not be required to power down systems during the initial containment efforts. All volatile evidence should still be accessible. Storage constraints may limit the ability to capture complete memory dumps of all the impacted systems.

[Various tools](https://github.com/meirwah/awesome-incident-response?tab=readme-ov-file#memory-imaging-tools) can be leveraged to capture full memory dumps. Detailed in: Capturing Memory \[LINK TO TOOL-SPECIFIC PLAYBOOK\]. 

When possible, a [full disk image capture](https://github.com/meirwah/awesome-incident-response?tab=readme-ov-file#disk-image-creation-tools) of the impacted systems is ideal. It is sometimes more useful to capture this image while the host is still live as information on encrypted drives may not be accessible after it has been powered off. Depending on the scope of compromise, this process could require a centralized storage server with or portal external drives. Detailed in: Full Disk Capture \[LINK TO TOOL-SPECIFIC PLAYBOOK\].

A [Velociraptor](https://docs.velociraptor.app/) offline collector or [Kroll Artifact Parser/Extractor](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) can be pushed to the impacted machines via \[DEPLOYMENT TECHNOLOGY\] and utilized to acquire the most commonly useful forensic artifacts, without taking a complete image of the disk. Detailed in: Artifact Collection \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\]

### Gather Indicators of Compromise

Build on the list of IOCs composed in the first pass analysis. While the specific indicators will vary, generally the following can be seen in cybersecurity incidents:

* Exploit toolkits  
* RDP activity  
* Malicious file hashes  
* Uncommon log files/events  
* PowerShell scripts   
* Newly created user accounts  
* Domains  
* Directory or machines added to the network during the exploitation  
* Email addresses  
* Phishing emails   
* IP addresses  
* URLs

### Validate Data Backup Availability and Integrity

Backup integrity and availability can be confirmed with administrators depending on which systems were impacted. These backups may be required in the event that hosts need to be reimaged.

* **Windows Servers** – \[SME\]: \[BACKUP UTILITY\]  
* **Linux Servers** – \[SME\]: \[BACKUP UTILITY\]  
* **Workstations** – \[SME\]: \[BACKUP UTILITY\]  
* **Cloud Instances** – \[SME\]:  \[BACKUP UTILITY\]

### Data Exfiltration

If there was confirmed or suspected data exfiltration, refer to the data exfiltration playbook for remediation steps. Detailed in: [Data Exfiltration Playbook](https://github.com/dhiggins19/IR-Playbooks/tree/main/Data-Exfiltration)**.**

## 2.4 Eradication {#2.4-eradication}

### Add Indicator of Compromise (IOC) to Existing Threat Detection Platform

All indicators of compromise identified during the comprehensive analysis process should be added to \[SIEM\], \[EMAIL SECURITY SOLUTION\], \[EDR\], \[WAF\], and the \[FIREWALL\] network firewalls to reduce the risk of reinfection. Follow the standard operating procedures for each technology. Detailed in: \[EDR\] – Adding Custom Indicators \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\] and \[SIEM\]– Adding Custom IOCs \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\]. 

### Validate all Mechanisms of Persistence have been Removed

Impacted systems will be reimaged during the recovery process. The reimaging should address any boot/autostart executions and scripts, as well as scheduled tasks/jobs. Validate that any impacted accounts/credentials have reset. Detailed in: Password Reset Verification \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\].

### Sweep for IOCs

Threat hunting for the comprehensive list of IOCs should be performed across all technologies to identify potentially impacted systems which were not detected in earlier response efforts or by automated systems. Detailed in: \[EDR\] IOC-based hunting \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\] and \[SIEM\] IOC-based Hunting \[LINK TO TECHNOLOGY-SPECIFIC PLAYBOOK\].

### Submit Samples/IOCs to Vendors as Necessary

Upon successful eradication of the malware, IOCs (without sensitive \[COMPANY\] information) should be submitted to VirusTotal to help the security community better detect and block similar attempts targeting other organizations.

## 2.5 Recovery {#2.5-recovery}

### Restore Infected Hosts to Known Good State

Impacted systems should be reimaged and restored from confirmed-clean backups. If backups are not available, systems will need to be reimaged and rebuilt. These efforts will be managed by the SMEs for the respective impacted systems.

### Close Control Gaps

Any gaps in security controls that lead to the conditions allowing a malicious infection must be closed prior to restoring business operations either by patching systems or implementing sufficient compensating controls.

### Restore All Affected Files

Once the systems have been restored to a known-clean state. The impacted files can be restored to the systems. Files can first be restored from backups after they have been confirmed to be malware-free.

### Reset Impacted User/Host Credentials

Validate that all user, service account, and system account credentials have been reset. A majority of this work likely occurred during the eradication phase, but another verification is recommended.

### User Education

Any users who interacted with the malicious email should be coached in an encouraging way on the specific indicators that marked the email as suspicious.

## 2.6 Post-Incident Activity {#2.6-post-incident-activity}

## A lessons-learned analysis is conducted by the Corporate Security Team (CST) following the closure of a security incident to verify the following:

* ##  The root-cause has been eliminated or adequately mitigated.

* ## Organizational problems and/or procedures that may have created the conditions which lead to the initial compromise have been adequately remediated.

* ## Identify technical or operational training needs.

* ## Identify needed improvements to tools (or usage of tools) or threat intelligence to better perform prevention, detection, analysis, and response actions.

## A lesson-learned report is to be generated, and the recommended improvements will be implemented in future incident preparation and response activities. 

## A complete incident report is developed including all evidence gathered and details of affected systems and data. This report is forwarded to relevant leadership and evidence and findings are forwarded to law enforcement if applicable.

# 3\. Phishing Response Checklist {#3.-phishing-response-checklist}

The following checklists can be utilized to track incident response efforts throughout the playbook.

## 3.1 Detection and Analysis {#3.1-detection-and-analysis}

☐ 1\. Determine which accounts were impacted, and immediately disable them. If malicious activities were performed by the compromised accounts, then the impacted systems should be immediately contained: 

☐ If several systems or subnets appear impacted, take the network offline at the switch level. It may not be feasible to disconnect individual systems during an incident. 

☐ If taking the network temporarily offline is not immediately possible, locate the network cable and unplug affected devices from the network or remove them from Wi-Fi to contain the infection.

☐ After an initial compromise, malicious actors may monitor \[COMPANY\]’s activity or communications to understand if their actions have been detected. Be sure to isolate systems in a coordinated manner and use out-of-band communication methods like phone calls or other means to avoid tipping off actors that they have been discovered and that mitigation actions are being undertaken. Not doing so could cause actors to move laterally to preserve their access—already a common tactic—or deploy ransomware widely prior to networks being taken offline.

☐ 2\. Only in the event you are unable to disconnect devices from the network, power them down to avoid further malicious activities. 

☐ 3\. Utilize \[EMAIL SECURITY SOLUTION\] to identify all instances of the malicious email and remove it from the targeted users inboxes.

☐ 4\. Triage impacted accounts/systems for restoration and recovery.

☐ Identify and prioritize critical systems for restoration and confirm the nature of data housed on impacted systems.  Prioritize restoration and recovery based on a predefined critical asset list that includes information systems for critical services, as well as systems they depend on. 

☐ Keep track of systems and devices that are not perceived to be impacted so they can be deprioritized for restoration and recovery. This will enable the organization to get back to business in a more efficient manner.

☐ 5\. The CST will confer to develop and document an initial understanding of what has occurred based on initial analysis.

☐ 6\. Engage \[COMPANY\]’s internal and external teams and stakeholders with an understanding of what they can provide to help you mitigate, respond to, and recover from the incident.

☐ Share the available information to receive the most timely and relevant assistance. Keep management and senior leaders informed via regular updates as the situation develops. Relevant stakeholders may include your IT department, managed security service providers, cyber insurance company, and departmental or elected leaders.

## 3.2 Containment and Eradication {#3.2-containment-and-eradication}

☐ 7\. Take a system image and memory capture of a sample of affected devices (e.g., workstations and servers). Additionally, collect any relevant logs as well as samples of any precursor (dropper) malware binaries and associated observables or indicators of compromise (e.g., suspected command and control IP addresses, suspicious registry entries, or other relevant files detected).

☐ 8\. Research the trusted guidance (i.e., published by sources from reputable security vendors) to determine the type of malwares impacting the organization and follow any additional recommended steps to identify and contain systems or networks that are confirmed to be impacted.

☐ Use custom IOCs/IOAs to block the execution of known malicious binaries; this will minimize damage and impact to your systems. Delete other known, associated registry values and files.

☐ 9\. Identify the systems, accounts, and data involved in the initial breach. This can include email accounts.

☐ 10\. Based on the compromise details determined above, contain any associated systems that may be used for further or continued unauthorized access. Breaches often involve mass credential exfiltration. Securing the network and other information sources from continued credential-based unauthorized access may include the following actions:

☐ Disabling virtual private networks, remote access servers, single sign-on resources, and cloud-based or other public-facing assets.

☐ 11\. Conduct an examination of existing organizational detection or prevention systems (\[EDR\], \[FIREWALL\] firewalls, \[SIEM\]) and logs. Doing so can highlight evidence of additional systems or malware involved in earlier stages of the attack.

☐ Look for evidence of precursor “dropper” malware. An account compromise event may be evidence of a previous, unresolved network compromise.

☐ 12\. Conduct extended analysis to identify outside-in and inside-out persistence mechanisms.

☐ Outside-in persistence may include authenticated access to external systems via rogue accounts, backdoors on perimeter systems, exploitation of external vulnerabilities, etc.

☐Inside-out persistence may include malware implants on the internal network or a variety of living-off-the-land style modifications (e.g., use of commercial penetration testing tools like Cobalt Strike; use of PsTools suite, including PsExec, to remotely install and control malware and gather information regarding—or perform remote management of—Windows systems; use of PowerShell scripts).

☐ Identification may involve events searches in \[EDR\], audits of local and domain accounts, examination of data found in \[SIEM\], or deeper forensic analysis of specific systems once movement within the environment has been mapped out.

☐ 13\. Rebuild systems based on a prioritization of critical services using pre-configured standard images, if possible.

☐ 14\. Once the environment has been fully cleaned and rebuilt (including any associated impacted accounts and the removal or remediation of malicious persistence mechanisms) issue password resets for all affected systems and address any associated vulnerabilities and gaps in security or visibility. This can include applying patches, upgrading software, and taking other security precautions not previously taken.

☐ 15\. Based on established criteria, which may include taking the steps above or seeking outside assistance, the designated incident manager declares the incident over.

☐ 16\. Educate any users who interacted with the malicious email on the ways that it could have been identified as malicious.

## 3.3 Recovery and Post-Incident {#3.3-recovery-and-post-incident}

## ☐ 17\. Reconnect systems and restore data from offline, encrypted backups based on a prioritization of critical services.

## ☐ 18\. Document lessons learned from the incident and associated response activities to inform updates to organizational policies, plans, and procedures and guide future exercises.