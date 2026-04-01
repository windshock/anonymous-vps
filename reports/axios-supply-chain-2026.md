# Axios npm Supply‑Chain Compromise Deep Research Report

## Executive summary

Between March 30–31, 2026 (UTC), attackers used a **compromised axios maintainer npm account** to publish **trojanized releases** axios@1.14.1 (tagged latest) and axios@0.30.4 (tagged legacy/0.x line), adding a single malicious dependency plain-crypto-js@4.2.1 whose postinstall executes an obfuscated dropper (setup.js). [\[1\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

Multiple independent analyses (Elastic, StepSecurity, Socket, SafeDep) converge on the same technical core: setup.js decodes a string table via **reversed Base64 \+ XOR** using the key **OrDeR\_7077**, then branches on os.platform() to fetch platform-specific stage-2 payloads from **sfrclak\[.\]com:8000** (commonly via http://sfrclak\[.\]com:8000/6202033). [\[2\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

Key operational questions you asked, answered from the available public analyses in the last \~24 hours (and explicitly marking gaps where a primary source could not be retrieved in this session):

**Can npm install inside a Docker container infect the macOS host?**  
No evidence in public reverse engineering indicates a Docker escape exploit in this malware chain. The dropper’s OS branching delivers a **Linux Python RAT** when os.platform() resolves to linux (typical for containers), and the macOS Mach‑O chain is only selected on darwin. Therefore, a “standard” Docker container run does **not** directly deploy the macOS payload to the host. [\[3\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
However, “host impact from inside containers” can still occur through **configuration exposures** (e.g., sensitive bind mounts, privileged containers, Docker socket exposure). These are not described as explicit tactics in the malware writeups retrieved here, so this part is assessed as a **risk inference** rather than confirmed actor behavior.

**Does the Linux payload persist across container restart/recreate?**  
The Linux stage‑2 is described as a **Python RAT** that beacons and executes commands, but public analyses do **not** describe built‑in Linux persistence mechanisms (e.g., cron/systemd) in this campaign. Persistence is explicitly described for Windows (Run key \+ batch script), while macOS/Linux are described as lacking native persistence. [\[4\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
In container terms, the implant remains active **while the container process continues**, but will not inherently survive a restart/recreate unless (a) the attacker deploys persistence as a follow-on action via the RAT command channel, or (b) filesystem/state is preserved through volumes or image commits (not evidenced in the retrieved writeups).

Immediate defensive priority: treat any environment that installed axios@1.14.1 or axios@0.30.4 during the exposure window as potentially compromised; rotate secrets, hunt for artifacts/IOCs, and downgrade to safe versions (1.14.0 / 0.30.3). [\[5\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

## What was published in the last 24 hours and what each source contributed

The following sources were successfully retrieved and are “analysis-like” (technical vendor writeups and detailed incident reporting) with publication dates in the March 31–April 1, 2026 window. Sources explicitly requested but **not successfully retrieved in this session** (SANS, Sophos, TechCrunch, Axios Media, and a dedicated Snyk incident writeup) are listed in the gaps section.

| Source | Pub date shown | What it adds that’s uniquely useful |
| :---- | ----: | :---- |
| Elastic Security Labs (detailed analysis) | Apr 1, 2026 | End-to-end technical breakdown of dropper \+ unified cross-platform RAT design, including identical protocol, commands, beacon cadence, and the XOR key and reversal/Base64 scheme; notes Windows persistence and attributes macOS overlap to WAVESHAPER/UNC1069. [\[6\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) |
| Elastic Security Labs (detections \+ IOC table) | Apr 1, 2026 | High-signal behavioral detections and a consolidated IOC section including shasums for axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1; platform execution chains and macOS launch command showing /Library/Caches/com.apple.act.mond. [\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) |
| StepSecurity | Mar 30, 2026 (site date) | Registry timeline details (decoy plain-crypto-js@4.2.0 → malicious 4.2.1 → axios publishes; inferred unpublish timing) plus anti-forensics: self-delete of setup.js and replacement of package.json with package.md “clean” stub reporting version 4.2.0. [\[8\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) |
| Socket | Mar 31, 2026 | Automated static-analysis summary of setup.js (dropper flow, obfuscation reconstruction, decoded string categories) and highlights about “release outside normal workflow” signals. [\[9\]](https://socket.dev/blog/axios-npm-package-compromised) |
| SafeDep | Mar 31, 2026 | IOC-rich incident post with explicit C2 IP resolution (142.11.206.73), additional hashes and file indicators, and explicit provenance/attestation comparisons. [\[10\]](https://safedep.io/axios-npm-supply-chain-compromise) |
| The Hacker News | Mar 31, 2026 | Consolidated media-style technical summary referencing vendor findings; includes OS-specific artifact paths and notes related ecosystem packages also distributing the payload via vendored dependencies (as reported). [\[11\]](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html) |
| BleepingComputer | Mar 31, 2026 09:53 AM | Incident reporting with attention to OIDC/provenance absence signals and the broad potential blast radius; references multiple vendor analyses (Endor, Socket, Aikido, StepSecurity). [\[12\]](https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/) |
| Nextgov | Mar 31, 2026 | Attribution statement: Google Threat Intelligence Group investigating and attributing to UNC1069, via quoted GTIG leadership. [\[13\]](https://www.nextgov.com/cybersecurity/2026/03/north-korea-linked-hackers-suspected-axios-open-source-hijack-google-analysts-say/412523/) |

## Timeline and attack flow confirmed across primary sources

### Timeline of malicious publishing and takedown

Public sources converge on a staged timeline designed to avoid “brand-new package” heuristics: a clean decoy release of plain-crypto-js@4.2.0, followed by a malicious plain-crypto-js@4.2.1 with the postinstall hook and dropper, then the two axios versions published to cover both the modern and legacy branches within \~39 minutes. [\[14\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

StepSecurity reports inferred removal/unpublish timing using npm registry metadata fields (because npm does not provide a clean per-version unpublish timestamp in the public API) and that npm replaced plain-crypto-js with a security-holder stub (plain-crypto-js@0.0.1-security.0). [\[8\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

### Mermaid timeline diagram

timeline  
  title Axios npm compromise (UTC)  
  2026-03-30 05:57 : plain-crypto-js@4.2.0 published (decoy history)  
  2026-03-30 23:59 : plain-crypto-js@4.2.1 published (postinstall \+ setup.js)  
  2026-03-31 00:21 : axios@1.14.1 published (tagged latest at the time)  
  2026-03-31 01:00 : axios@0.30.4 published (legacy/0.x line)  
  2026-03-31 \~03:15 : axios malicious versions unpublished (inferred)  
  2026-03-31 04:26 : plain-crypto-js security-holder stub published

(Exact inferred unpublish timing methodology is described in StepSecurity’s writeup.) [\[8\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

### Mermaid attack flow diagram

flowchart TD  
  A\[npm install axios\] \--\> B\[axios@1.14.1 or axios@0.30.4\]  
  B \--\> C\[Dependency added: plain-crypto-js@4.2.1\]  
  C \--\> D\[postinstall: node setup.js\]  
  D \--\> E\[Decode strings: reverse Base64 \+ XOR OrDeR\_7077\]  
  E \--\> F{os.platform()}  
  F \--\>|darwin| G\[AppleScript via osascript\]  
  G \--\> G1\[Download Mach-O to /Library/Caches/com.apple.act.mond\]  
  G1 \--\> G2\[Execute with URL arg; beacon to C2\]  
  F \--\>|win32| H\[VBScript \+ renamed PowerShell in %PROGRAMDATA%\\\\wt.exe\]  
  H \--\> H1\[Fetch PS stage-2; registry persistence\]  
  F \--\>|linux| I\[/bin/sh curl \-\> /tmp/ld.py\]  
  I \--\> I1\[nohup python3 /tmp/ld.py; beacon loop\]  
  D \--\> J\[Anti-forensics: delete setup.js; swap package.json via package.md\]

Core branching, payload paths, and anti-forensic behavior are consistently described by Elastic, StepSecurity, and Socket. [\[15\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

## Static code artifacts and payload behavior validated across sources

### Stage 1: setup.js dropper and obfuscation

Elastic and Socket both describe the dropper as using a **two-layer encoding scheme**:

* **Layer 1:** reverse the string then Base64-decode

* **Layer 2:** XOR cipher using key **OrDeR\_7077** with a position-dependent digit selection (described by Elastic as 7 \* i² % 10) [\[16\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

Socket reports the obfuscated string table (stq\[\]) contains **18 critical strings** (modules, URLs, commands, extensions) and that static decoding reveals the C2 base URL and platform logic. [\[9\]](https://socket.dev/blog/axios-npm-package-compromised)

Elastic describes the C2 interaction pattern: setup.js POSTs to a single endpoint (shown as http://sfrclak\[.\]com:8000/6202033) and uses a platform-specific POST body (packages.npm.org/product0|1|2) to select stage‑2. [\[17\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

### Anti-forensics in node\_modules

Multiple sources describe explicit anti-forensic cleanup:

* setup.js self-deletes after execution

* package.md (a clean manifest) is renamed to package.json to remove the postinstall evidence afterward [\[14\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

StepSecurity highlights an additional deception detail: the replacement package.json reports version 4.2.0, so npm list may show plain-crypto-js@4.2.0 even though 4.2.1 executed during install. [\[8\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

### Stage 2 payloads by OS and known artifact paths

Elastic provides a concise mapping of platform delivery and stage‑2 locations, mirrored by other sources:

* macOS: AppleScript downloads Mach‑O to /Library/Caches/com.apple.act.mond and executes it (passing the C2 URL as an argument) [\[18\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

* Windows: VBScript \+ a renamed PowerShell (%PROGRAMDATA%\\wt.exe) runs a PowerShell RAT and establishes persistence via a Run key \+ batch mechanism [\[19\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

* Linux: curl to /tmp/ld.py followed by backgrounded python3 execution; Linux stage‑2 is a Python RAT with polling/beacon behavior [\[20\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

### C2 infrastructure, IP, and protocol notes

All technical sources align on the primary C2:

* Domain/port: sfrclak\[.\]com:8000 [\[21\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

* SafeDep reports resolution to 142.11.206.73 and notes server behavior (Express.js; only responds meaningfully to POST). [\[10\]](https://safedep.io/axios-npm-supply-chain-compromise)

Elastic and Socket emphasize a distinctive network indicator: a spoofed legacy IE/XP User-Agent used consistently by stage‑2 implants: mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0) [\[22\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

### Hashes and package integrity signals

Elastic publishes shasums for the malicious packages, including the widely circulated plain-crypto-js@4.2.1 hash: 07d889e2dadce6f3910dcbc253317d28ca61c766. [\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

Elastic and SafeDep both highlight “supply chain provenance break” signals: legitimate axios@1.14.0 used GitHub Actions OIDC trusted publishing with SLSA provenance attestations, whereas the malicious publish was a direct CLI publish without provenance attestations and with a publisher email change to a Proton address. [\[23\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

Also, npm’s current package page shows axios@1.14.0 as latest, consistent with rollback after the incident. [\[24\]](https://www.npmjs.com/package/axios?activeTab=versions)

## Docker-focused evaluation

### Can a Docker container run lead to macOS host infection?

**What the malware actually does (evidence-backed):**  
The dropper explicitly branches on os.platform() and uses **darwin vs win32 vs linux** routines, with Linux fetching /tmp/ld.py and macOS fetching /Library/Caches/com.apple.act.mond. [\[18\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

**Assessment for standard Docker on macOS (Docker Desktop):**  
Running npm install **inside a Linux container** will cause the malware to take the **Linux branch** (because inside the container os.platform() resolves to linux), meaning the stage‑2 delivered by the C2 is the Linux Python RAT, not the macOS Mach‑O implant. [\[3\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

**Search for Docker escape code or container breakout logic (within retrieved analyses):**  
None of the vendor deep dives retrieved here describe a Docker escape exploit in setup.js or the Linux RAT command set. The observed Linux chain is node \-\> sh \-\> curl \-\> nohup python3 /tmp/ld.py &, i.e., execution and backgrounding, not a kernel/VM escape. [\[25\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

**Conclusion for question one:**  
Within the publicly retrieved analyses, the compromise chain **does not include** Docker escape functionality; therefore, **a standard containerized install does not, by itself, infect the macOS host with the macOS payload**. Host impact from within containers remains possible via misconfigurations that effectively dissolve isolation (e.g., powerful mounts), but that is not described as a documented technique in the sources retrieved in this session.

### Does the Linux payload persist across container restart/recreate?

**Linux implant behavior (evidence-backed):**  
Elastic describes the Linux stage‑2 as a Python RAT that runs a loop and beacons about every 60 seconds, supports flexible tasking (runscript / rundir / peinject), and drops/executes additional payloads into /tmp when commanded. [\[26\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

**Persistence evidence:**  
Elastic explicitly contrasts persistence across platforms, stating Windows establishes persistence, while macOS and Linux do not implement persistence “of their own.” [\[27\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

**Conclusion for question two:**  
Based on the technical analyses retrieved, the **Linux payload does not implement an automatic persistence mechanism** comparable to the Windows variant. In container environments, that typically means it remains active only while the container and the backgrounded Python process remain alive. Persistence across restarts/recreates would require follow-on attacker actions or externalized state (not demonstrated in retrieved writeups).

### Practical host-impact risk scenarios for Docker-for-Mac environments

Although explicit “Docker abuse” behavior is not described in the retrieved malware analyses, the RAT’s capabilities imply material risk when developers run container builds with high-trust host integrations. Elastic notes the malware enumerates sensitive directories and collects process/system info across OSes, and the Linux implant can execute arbitrary commands and drop additional payloads (including hidden /tmp/.\<random\> binaries). [\[28\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

The following Docker configuration patterns are therefore “high risk” in the presence of any install-time compromise like this (risk-based inference grounded in the malware’s observed capabilities, not a claim of attacker use in this incident):

| Docker configuration | Why it matters for this malware family | Practical risk outcome |
| :---- | :---- | :---- |
| Bind-mounting developer secrets into container (SSH keys, cloud configs, .env) | Linux RAT enumerates user paths and can run arbitrary shell scripts via tasking [\[26\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) | Secret theft even without host escape |
| Long-lived containers used as dev workspaces | Linux Python RAT is designed to stay resident and receive commands while running [\[26\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) | Interactive attacker access to the container environment |
| Containers used to build/sign/release with privileged tokens inside | Malware triggers during install; anti-forensics hides evidence quickly [\[29\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) | CI/CD credential compromise; supply-chain pivot opportunity |

## IOC list, detection, and remediation

### High-confidence IOCs consolidated from primary analyses

**Malicious packages / versions** \- axios@1.14.1 (malicious) [\[30\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
\- axios@0.30.4 (malicious) [\[30\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
\- plain-crypto-js@4.2.1 (malicious) [\[30\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

**Network** \- sfrclak\[.\]com:8000 and commonly observed http://sfrclak\[.\]com:8000/6202033 [\[17\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
\- Resolved IP: 142.11.206.73 [\[10\]](https://safedep.io/axios-npm-supply-chain-compromise)  
\- POST body markers: packages.npm.org/product0|product1|product2 used as platform identifiers [\[31\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
\- Stage‑2 RAT User-Agent: mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0) [\[32\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

**File artifacts (stage‑2 and droppers)** \- macOS: /Library/Caches/com.apple.act.mond [\[18\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
\- Linux: /tmp/ld.py [\[33\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
\- Windows: %PROGRAMDATA%\\wt.exe [\[34\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

**Package/file hashes (partial list)** \- plain-crypto-js@4.2.1 shasum: 07d889e2dadce6f3910dcbc253317d28ca61c766 [\[35\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)  
\- Elastic also lists shasums for axios@1.14.1 and axios@0.30.4 in its IOC table. [\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

### Practical detection commands and forensic checks

These checks focus on **lockfiles \+ node\_modules artifacts \+ process/network telemetry**, because the malware intentionally deletes setup.js and swaps package.json. [\[14\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

**Dependency/lockfile triage (any OS)**

\# Quick check for known-bad versions in lockfiles  
rg \-n "axios@1\\.14\\.1|axios@0\\.30\\.4|plain-crypto-js@4\\.2\\.1|plain-crypto-js" package-lock.json pnpm-lock.yaml yarn.lock 2\>/dev/null

\# If you use npm, show resolved tree (may be deceived by package.json swap; use directory presence too)  
npm ls axios plain-crypto-js 2\>/dev/null  
ls \-la node\_modules/plain-crypto-js 2\>/dev/null

The “directory presence vs reported version” nuance is specifically called out because the manifest may be replaced after execution. [\[36\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

**Host artifact triage**

macOS:

ls \-la /Library/Caches/com.apple.act.mond 2\>/dev/null  
codesign \-dv \--verbose=4 /Library/Caches/com.apple.act.mond 2\>/dev/null

Elastic notes the binary masquerades as an Apple-looking path and triggers detections around dubious signing characteristics. [\[26\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

Linux (including containers):

ls \-la /tmp/ld.py 2\>/dev/null  
ps auxww | rg "python3 /tmp/ld\\.py|nohup python3 /tmp/ld\\.py"  
ss \-plant 2\>/dev/null | rg ":8000|sfrclak"

Elastic explicitly shows the Linux chain including curl fetching /tmp/ld.py and nohup python3 /tmp/ld.py ... &. [\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

Windows (PowerShell / encoded): \- Look for C:\\ProgramData\\wt.exe and unusual Run keys / batch files; Elastic documents a Run key persistence mechanism and a hidden .bat. [\[26\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

### Recommended immediate actions

A minimal, high-confidence response plan consistent across the retrieved analyses:

1. **Stop installing** axios without version pinning until you verify you are pulling a safe release (currently 1.14.0 is shown as latest on npm). [\[37\]](https://www.npmjs.com/package/axios?activeTab=versions)

2. **Identify exposure**:

3. Search lockfiles/build logs for axios@1.14.1, axios@0.30.4, and plain-crypto-js. [\[38\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

4. **Assume credential compromise** if the malicious versions were installed, and **rotate secrets** used on that machine/runner (cloud creds, npm tokens, SSH keys). StepSecurity and media summaries explicitly advise treating installations as compromise due to the immediate “call home” behavior and anti-forensics. [\[39\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

5. **Hunt at the endpoint level** using artifact paths and process ancestry patterns (node → shell/interpreter → curl → backgrounded payload). Elastic provides behavioral detections precisely for this. [\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

6. **Block egress** to known C2 infrastructure (sfrclak\[.\]com:8000) while triage is ongoing. [\[40\]](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)

### Prioritized checklist for Docker Desktop for Mac environments

This checklist is tuned to the malware’s observed “install-time RCE” \+ “RAT tasking” model and to typical developer workflows; items are ordered by risk reduction impact:

* Ensure containers that run dependency installs do **not** include production secrets or long-lived credentials in environment variables or mounted filesystems (because the Linux RAT can execute arbitrary scripts and enumerate directories). [\[26\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

* Prefer **ephemeral build containers** and reproducible builds (reduce how long any implant can remain active). Elastic’s model shows a backgrounded long-running process after install, so “time alive” matters. [\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

* Add build-time detections for “node spawns curl/wget” and “backgrounded shell execution,” matching Elastic’s detection logic. [\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

* Pin dependencies and/or use controlled registries with allowlists; the malicious axios releases were designed to be picked up by default (latest) and caret-ranged installs. [\[41\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

## Attribution and confidence

Elastic reports the macOS Mach‑O overlaps with **WAVESHAPER**, tracked by Mandiant and attributed to **UNC1069**, a DPRK-linked cluster. [\[6\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)  
Separately, Nextgov reports that Google Threat Intelligence Group is investigating and attributing the attack to UNC1069 (as stated by GTIG’s chief analyst). [\[13\]](https://www.nextgov.com/cybersecurity/2026/03/north-korea-linked-hackers-suspected-axios-open-source-hijack-google-analysts-say/412523/)

**Confidence statement:** Attribution is inherently probabilistic; in this case, multiple sources tie UNC1069 to the tooling overlap and investigation, but full public evidence and methodology are not included in the retrieved media excerpt. The overlap claim is strongest where it appears in Elastic’s malware-analysis context with explicit reference to WAVESHAPER. [\[42\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

## Gaps, uncertainties, and what could not be verified here

Some requested “explicit sources” were not successfully collected in this session (likely due to tool/time constraints rather than absence in the ecosystem). Therefore, this report should be treated as **high-confidence on the technical chain** (because multiple vendor analyses align), but **incomplete as an exhaustive inventory** of every analysis published in the last 24 hours.

* **SANS Institute, Sophos, TechCrunch, Axios Media:** not retrieved here; any unique findings from those outlets (e.g., additional IOCs, confirmed victimology, new infrastructure) are not incorporated.

* **Snyk:** no dedicated Snyk incident analysis for this specific Axios compromise was found/retrieved here; only general Snyk supply-chain posts were discoverable, and Snyk appears in third-party reporting as providing commentary rather than a primary technical post (within the sources retrieved).

* **Artifact reproduction:** while vendors provide reconstructed deobfuscation logic, decoded strings, and observed command lines, this session did not directly fetch raw setup.js from a still-available package artifact. Indicators are therefore “verified by multiple independent analysts” rather than “reproduced from raw samples” within this report. [\[43\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

Despite these gaps, the central questions (Docker host infection likelihood; Linux persistence across container lifecycles) can be answered with high practical confidence from the described OS-branching behavior and explicit persistence comparisons in Elastic’s analysis. [\[27\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

---

[\[1\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[2\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[3\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[4\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[6\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[14\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[15\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[16\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[17\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[18\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[21\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[22\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[23\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[27\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[29\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[30\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[31\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[32\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[33\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[41\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[42\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) [\[43\]](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all

[https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)

[\[5\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) [\[8\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) [\[36\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) [\[39\]](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan

[https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

[\[7\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[19\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[20\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[25\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[26\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[28\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[34\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[35\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) [\[38\]](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections) https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections

[https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

[\[9\]](https://socket.dev/blog/axios-npm-package-compromised) https://socket.dev/blog/axios-npm-package-compromised

[https://socket.dev/blog/axios-npm-package-compromised](https://socket.dev/blog/axios-npm-package-compromised)

[\[10\]](https://safedep.io/axios-npm-supply-chain-compromise) https://safedep.io/axios-npm-supply-chain-compromise

[https://safedep.io/axios-npm-supply-chain-compromise](https://safedep.io/axios-npm-supply-chain-compromise)

[\[11\]](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html) [\[40\]](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html) https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html

[https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)

[\[12\]](https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/) https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/

[https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/](https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/)

[\[13\]](https://www.nextgov.com/cybersecurity/2026/03/north-korea-linked-hackers-suspected-axios-open-source-hijack-google-analysts-say/412523/) https://www.nextgov.com/cybersecurity/2026/03/north-korea-linked-hackers-suspected-axios-open-source-hijack-google-analysts-say/412523/

[https://www.nextgov.com/cybersecurity/2026/03/north-korea-linked-hackers-suspected-axios-open-source-hijack-google-analysts-say/412523/](https://www.nextgov.com/cybersecurity/2026/03/north-korea-linked-hackers-suspected-axios-open-source-hijack-google-analysts-say/412523/)

[\[24\]](https://www.npmjs.com/package/axios?activeTab=versions) [\[37\]](https://www.npmjs.com/package/axios?activeTab=versions) https://www.npmjs.com/package/axios?activeTab=versions

[https://www.npmjs.com/package/axios?activeTab=versions](https://www.npmjs.com/package/axios?activeTab=versions)