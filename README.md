# CrowdStrike Falcon Advanced Event Search (AES) & LogScale Toolkit

A comprehensive, production-grade reference and interactive offline dashboard for threat hunting, incident response, and forensic queries in CrowdStrike Falcon Next-Gen SIEM / LogScale (CQL / FQL).

---

## 🚀 Interactive Offline Web Dashboard (`crowdstrike_adavance event search.html`)

The centerpiece of this repository is a **standalone, zero-dependency interactive HTML portal**:

* **Zero-Setup & Offline First**: Open [`crowdstrike_adavance event search.html`](./crowdstrike_adavance%20event%20search.html) directly in any browser (Chrome, Safari, Edge, Firefox). No servers, build tools, or internet access required.
* **100+ Production-Ready Queries**: Curated queries covering all MITRE ATT&CK stages—Process Execution, Persistence, Lateral Movement, Exfiltration, and Credential Dumping.
* **Log Index Schema Catalog**: Detailed map of all 10 indexed fields (`#repo`, `#event_simpleName`, `#event.module`, etc.) and physical block-skipping rules for sub-second query performance.
* **5 Master Threat Recipes**:
  1. **🎯 Block 1 (Host Snapshot)**: Single-pane chronological timeline of an endpoint (processes, logins, sockets, DNS, and file drops).
  2. **👤 Block 2 (User Dossier)**: Complete identity tracking across every host a user touched.
  3. **📡 Block 3 (Lateral Tracer)**: Bidirectional source $\leftrightarrow$ destination network and remote CLI auditor.
  4. **💾 Block 4 (USB DLP)**: Removable media data exfiltration and sensitive archive staging detector.
  5. **🐧 Block 5 (Privilege Escalation)**: Linux / macOS SUID/SGID root drift and permission tampering.
* **Instant Search & 1-Click Copy**: Real-time filtering across operators, event types, and tactics with instant clipboard copy buttons.
* **Regex Masterclass**: Tested PCRE patterns for LOLBins, Base64 strings, obfuscated PowerShell, and file paths.

---

## 📚 Repository Structure

| File | Description |
| :--- | :--- |
| **[`crowdstrike_adavance event search.html`](./crowdstrike_adavance%20event%20search.html)** | Interactive web reference portal with real-time search, code syntax blocks, and quick-copy tools. |
| **[`crowdstrike_advance_event_search.md`](./crowdstrike_advance_event_search.md)** | Comprehensive markdown reference guide with 100+ production queries, schema mappings, and hunting tips. |
| **[`crowdstrike_eventsearch_visualization_guide.md`](./crowdstrike_eventsearch_visualization_guide.md)** | In-depth guide for dashboard creation, `groupBy()`, `timechart()`, bucketing, and SOC analytics. |

---

## ⚡ Quick Start

1. Clone this repository:
   ```bash
   git clone git@github.com:bhupenderbhardwaj83/csaes.git
   ```
2. Double-click **`crowdstrike_adavance event search.html`** in your file manager to open it in your browser.
3. Search for the scenario you need, copy the query, and paste directly into the Falcon console.
