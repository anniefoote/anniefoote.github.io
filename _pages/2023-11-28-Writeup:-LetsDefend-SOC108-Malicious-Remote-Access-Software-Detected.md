layout: post
title: Writeup: LetsDefend SOC108 - Malicious Remote Access Software Detected
date: 2023-11-28 
categories: LetsDefend Writeup Incident-Response

# Writeup: SOC108 - Malicious Remote Access Software Detected

## Basic Info
**Category:** Incident Responder\
**Rating:** High\
**Type:** Malware\
**Event ID:** 179

<img width="1627" alt="Screenshot 2023-11-28 at 11 50 59 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/047bf883-d3a2-452e-9078-074f5acfef4c"> <br />

## Playbook
<img width="631" alt="Analyze Malware" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/aa26b4c3-08c6-4a84-9001-3a80f4f61c37"> <br />
Analysing the hash of the malware in VirusTotal flags the file as malicious.
<img width="1293" alt="Screenshot 2023-11-28 at 11 57 10 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/4158684f-bec2-4364-8f5d-308be3aaadd6"> <br />
The FileScan.io report shows the file contacts these IPs woth the 136.243.18.118 address also being contacted by the file on the endpoint as recorded in the logs indicating it may be the C2 address for the malware.
<img width="494" alt="2023-08-14 083617 684" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/d31add75-1d0c-4dd0-a6fd-584ccfd43732"> <br />
Based on this, the file should be marked as malicious.
<img width="634" alt="Malware Type" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/3cfb33f2-4a1c-4cb9-a8b9-15079e0c2eb6"> <br />
Analysing the malware in the Recorded Future Triage tool confirms the file is malicious and marks it as a trojan.
<img width="1509" alt="Screenshot 2023-11-28 at 12 09 07 PM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/3325d278-f480-4b61-9f1a-9ef54aab9cc0"> <br />
<img width="630" alt="What is the initial access method used in the" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/f2b6efc9-dc55-4043-9a95-7dd29505d20f"> <br />
Looking at the L1 notes for the alert, we see the user recieved an email from support@microsoftonlinesupport.cf prompting the user to download ammyy admin. 
<img width="1639" alt="Screenshot 2023-11-28 at 12 12 42 PM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/fb361736-de2f-427f-b122-0a22c77d7619"> <br />
The following are the emails sent by the attacker to the user.
<img width="1188" alt="Screenshot 2023-11-28 at 11 33 28 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/ccd341a9-2d97-4812-9b4f-714a5ce62c1e"> <br />
The user then responds to the email confirming they have installed ammyy admin and provides the attacker their ammyy admin login information in the email.
<img width="1601" alt="Screenshot 2023-11-28 at 11 34 35 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/ccad6a96-bec0-46e6-81c5-3a884646f28f"> <br />
This shows that the initial access method used by the attacker was phishing.
<img width="630" alt="Define Scope" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/23c5c0ce-12f9-494a-9ec9-bbfbe85a180f"> <br />
Searching the logs for requests with a destination address of 136.243.18.118 (the C2 address identified earlier), we can see the only requests made to the address are from the current users device.
<img width="1596" alt="Screenshot 2023-11-28 at 12 11 25 PM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/1b38c290-c249-4542-99a6-33fb608b3845"> <br />
This shows that no other users have had the malware execute on their device and access the C2 address.
Searching email logs for the phishing address, we can see the phishing email was only sent to carlos.
<img width="1639" alt="Screenshot 2023-11-28 at 12 12 42 PM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/fd5db0ae-8707-4be5-9046-dcad73a9f524"> <br />
Based on this, it appears that this is the only device affected and no other machines had any IOCs on them.
<img width="634" alt="Check if the malware is quarantinedcleaned" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/f2b656b2-dfdb-45e4-afb7-7299bdb1ab17"> <br />
Connecting to the affected machine, we can see the malicious files and applications are still in the users Downloads folder.
<img width="812" alt="Screenshot 2023-11-28 at 12 15 07 PM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/accc2b4b-1c84-466e-8e71-ecb49a9ec176"> <br />
This indicates that the malware is still on the device and it has not been quarantined or cleaned.
<img width="635" alt="Has the malware been executed on the device" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/e2f80074-d5af-4dfc-b6a7-c2b182a9eca8"> <br />
Looking at the device logs, we can see the malware executing on the system. Comparing the execution and commands observed in the logs to those seen in the sandbox and reports online, we can see the same commands have been executed, indicating the malware has executed.
<img width="1014" alt="Screenshot 2023-11-28 at 11 40 39 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/94553482-9d71-4136-aeab-bde9b9ec0a24"> <br />
<img width="1008" alt="Screenshot 2023-11-28 at 11 40 52 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/5cd580ce-6f44-4266-92ea-577ada5b9711"> <br />
<img width="629" alt="Which technique(s) was used as an execution" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/7cfe73ef-7277-4fe8-8548-9165bb5cc6f4"> <br />
Looking back at the phishing emails, we can see the attacker requests that the user execute the file themselves using admin / elevated privileges.
<img width="1008" alt="Screenshot 2023-11-28 at 11 40 52 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/613ceef3-6be3-43d4-be16-7a38544081a5"> <br />
This shows the technique used is user execution.
<img width="631" alt="Containment" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/510a5412-445c-4bb1-b616-2fa06d1741c2"> <br />
As the malware has executed on the users device, we need to quarantine the device to prevent further damage by the malware.
<img width="983" alt="Screenshot 2023-11-28 at 12 25 42 PM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/53581e28-1b2d-480e-aa83-774b619d0d13"> <br />
<img width="636" alt="Eradication" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/4447924b-a0a9-4206-b3a2-73da962445f8"> <br />
To eradicate the malware, we need to delete the malicious ammyy admin and edge files from the system.

## Mitre Analysis
### Initial Access
**Tactic Used:** T1566.002 - Phishing: Spearphishing Link, T1133 - External Remote Services
The attacker contacts the user via email requesting the user download the ammyy admin remote access tool so that the attacker can remotely upload a file for the user.
<img width="1188" alt="Screenshot 2023-11-28 at 11 33 28 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/51ee2417-d89c-4b61-95ad-5bdfb5c32d0b">

### Execution
**Tactic Used:** T1204.002 - User Execution: Malicious File
The attacker prompts the user to execute the malicious executable using elevated permissions. Logs show successful user execution of the file.
<img width="1601" alt="Screenshot 2023-11-28 at 11 34 35 AM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/560df181-011d-49c2-8a0a-a6e421d84cf6"> <br />

### Persistence
**Tactic Used:** T1542.003 - Pre-OS Boot: Bootkit
Sandbox analysis shows the malware writes to the master boot record to maintain persistence. 
<img width="1244" alt="Screenshot 2023-11-28 at 1 25 12 PM" src="https://github.com/anniefoote/LetsDefend-Writeups/assets/84354375/56c2aab8-45f4-443f-999e-771bfce56018">

### Privilege Escalation
**Tactic Used:** T1055 - Process Injection
