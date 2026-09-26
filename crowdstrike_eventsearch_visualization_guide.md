# CrowdStrike Falcon Event Search: Visualizations, Tables, Graphs & Analytics Guide

[![Platform](https://img.shields.io/badge/Platform-CrowdStrike%20Falcon%20AES%20%7C%20LogScale-red.svg)](#)
[![Focus](https://img.shields.io/badge/Focus-Dashboards%20%26%20Visualizations-blue.svg)](#)
[![Analytics](https://img.shields.io/badge/Analytics-Tables%20%7C%20Graphs%20%7C%20Timecharts-green.svg)](#)
[![Skill Level](https://img.shields.io/badge/Level-Basic%20to%20Advanced-orange.svg)](#)

> A masterclass on turning raw CrowdStrike Falcon telemetry into high-impact SOC dashboards, forensic data tables, time-series graphs, heatmaps, and executive metrics. This guide details visualization widgets, pipeline data transformations, multi-column sorting, bucketing, and advanced statistical outlier detection across **Basic**, **Medium**, **High**, and **Advanced** tiers.

---

## Table of Contents

- [1. Visualization Architecture & Operational Pipeline](#1-visualization-architecture--operational-pipeline)
  - [1.1 Widget Selection Matrix](#widget-selection-matrix)
  - [1.04 Log Index Schema & Ingest Query Anchoring for Visualizations](#104-log-index-schema--ingest-query-anchoring-for-visualizations)
  - [1.05 The Master CrowdStrike Telemetry & Field Hierarchy Mind Map](#105-the-master-crowdstrike-telemetry--field-hierarchy-mind-map)
  - [1.06 Subsystem Field Lineage & Hunting Architecture](#106-subsystem-field-lineage--hunting-architecture)
  - [1.2 The Master's Operation Order & Pipeline Execution Logic](#12-the-masters-operation-order--pipeline-execution-logic)
    - [1.2.1 The Fundamental 7-Stage Pipeline Order](#121-the-fundamental-7-stage-pipeline-order)
    - [1.2.2 The Two Master Laws: Why Order Matters](#122-the-two-master-laws-why-order-matters)
    - [1.2.3 Universal Visualization Decision Matrix](#123-universal-visualization-decision-matrix)
    - [1.2.4 16 Production-Grade Structured Queries](#124-16-production-grade-structured-queries)
    - [1.2.5 The Hunter's Pipeline Construction Checklist](#125-the-hunters-pipeline-construction-checklist)
- [2. Tier 1: Basic — Tables, Projections & Elementary Sorting](#2-tier-1-basic--tables-projections--elementary-sorting)
  - [1.1 Clean Tabular Projection (`table()`)](#11-clean-tabular-projection-table)
  - [1.2 Renaming Columns with Aliases (`as`)](#12-renaming-columns-with-aliases-as)
  - [1.3 Single-Field Sorting (`sort()`)](#13-single-field-sorting-sort)
  - [1.4 Limiting & Paging Results (`head()`, `tail()`)](#14-limiting--paging-results-head-tail)
  - [1.5 Simple Event Volume Counter (Single Value KPI)](#15-simple-event-volume-counter-single-value-kpi)
  - [1.6 Simple Categorical Breakdown (Pie / Donut Chart)](#16-simple-categorical-breakdown-pie--donut-chart)
- [3. Tier 2: Medium — Grouping, Time Bucketing & Multi-Axis Graphs](#3-tier-2-medium--grouping-time-bucketing--multi-axis-graphs)
  - [2.1 Multi-Key Grouping & Joint Frequencies](#21-multi-key-grouping--joint-frequencies)
  - [2.2 Multi-Column Compound Sorting](#22-multi-column-compound-sorting)
  - [2.3 Time Bucketing for Bar / Area Charts (`bucket()`)](#23-time-bucketing-for-bar--area-charts-bucket)
  - [2.4 Native Timecharts (`timechart()`)](#24-native-timecharts-timechart)
  - [2.5 Top-N / Long-Tail Slicing with Sorting](#25-top-n--long-tail-slicing-with-sorting)
  - [2.6 Deduplication & Cardinality Extraction (`selectDistinct`)](#26-deduplication--cardinality-extraction-selectdistinct)
  - [2.7 Multi-User Target Hunt with User & Machine Breakdown Counts](#27-multi-user-target-hunt-with-user--machine-breakdown-counts)
- [4. Tier 3: High — Multi-Metric Stats, Heatmaps & GeoIP Visualizations](#4-tier-3-high--multi-metric-stats-heatmaps--geoip-visualizations)
  - [3.1 Multi-Metric Aggregation Functions (`min`, `max`, `avg`, `sum`)](#31-multi-metric-aggregation-functions-min-max-avg-sum)
  - [3.2 2D Matrix Heatmaps (Day of Week vs. Hour of Day)](#32-2d-matrix-heatmaps-day-of-week-vs-hour-of-day)
  - [3.3 Geographic World Map Visualization (`ipLocation()`)](#33-geographic-world-map-visualization-iplocation)
  - [3.4 Stacked Multi-Series Timecharts](#34-stacked-multi-series-timecharts)
  - [3.5 Human-Readable Time Formatting (`formatTime()`)](#35-human-readable-time-formatting-formattime)
  - [3.6 Dynamic Byte/Size Unit Conversion for Charts](#36-dynamic-bytesize-unit-conversion-for-charts)
- [5. Tier 4: Advanced — Statistical Outliers, Ratios, Sankey & Correlated Dashboards](#5-tier-4-advanced--statistical-outliers-ratios-sankey--correlated-dashboards)
  - [4.1 Statistical Outlier Detection with Percentiles (`percentile()`, `stdDev()`)](#41-statistical-outlier-detection-with-percentiles-percentile-stddev)
  - [4.2 Authentication Success vs. Failure Ratio (Gauge / Dual-Line)](#42-authentication-success-vs-failure-ratio-gauge--dual-line)
  - [4.3 Sankey Flow Preparation: Process Execution Hierarchy](#43-sankey-flow-preparation-process-execution-hierarchy)
  - [4.4 Sliding Window Aggregation & Burst Detection](#44-sliding-window-aggregation--burst-detection)
  - [4.5 Master SOC Threat Hunting Visual Dashboard Query](#45-master-soc-threat-hunting-visual-dashboard-query)
- [6. Quick Syntax Cheatsheet for Visual Commands](#6-quick-syntax-cheatsheet-for-visual-commands)

---

## 1. Visualization Architecture & Widget Types in Falcon

In CrowdStrike Falcon Advanced Event Search (LogScale), the structure of your query's final output determines what visualizations can be rendered.

```
┌─────────────────────────────────┐
│     Raw Telemetry Events        │
└────────────────┬────────────────┘
                 │ | groupBy() / bucket() / timechart()
                 ▼
┌─────────────────────────────────┐
│      Aggregated Data Matrix     │
└────────────────┬────────────────┘
                 ├──────────────────────────────┬─────────────────────────────┐
                 ▼                              ▼                             ▼
       ┌──────────────────┐           ┌──────────────────┐          ┌──────────────────┐
       │   Table Widget   │           │ Timechart / Area │          │  Bar / Donut     │
       │ Columns + Rows   │           │ X=@timestamp     │          │ Categories +     │
       │ Formatted text   │           │ Y=Series Values  │          │ Numerical counts │
       └──────────────────┘           └──────────────────┘          └──────────────────┘
```

### Widget Selection Matrix

| Widget Type | Required Query Shape | Example Output Schema | Primary Use Case |
| :--- | :--- | :--- | :--- |
| **Table** | List of events or aggregated rows | `[@timestamp, Host, User, CMD]` | Detailed forensic investigation |
| **Timechart (Line/Area)** | Time bucket + Numeric metric (+ optional series) | `[_bucket, MetricValue, SeriesName]` | Volume spikes, baseline trends |
| **Bar / Column Chart** | Categorical key + Numeric metric | `[ComputerName, _count]` | Top talking hosts, top blocked files |
| **Pie / Donut Chart** | Low-cardinality category (2–7 keys) + Count | `[event_platform, _count]` | OS distribution, verdict breakdown |
| **Single Value (KPI)** | Single row with single scalar number | `[TotalIncidents]` | Active alert counters, MTTR metric |
| **Heatmap** | Two categorical axes (X, Y) + Intensity count | `[DayOfWeek, HourOfDay, _count]` | After-hours activity profiling |
---

### 1.04 Log Index Schema & Ingest Query Anchoring for Visualizations

Before executing visualization aggregation operators (`groupBy()`, `bucket()`, `timechart()`, `table()`), every performant dashboard query must anchor to the **10 Primary Ingestion Index Tags (`#`)**:

| Index Tag (`#`) | Standard Values | Storage & Visualization Significance |
| :--- | :--- | :--- |
| `#event_simpleName` | `ProcessRollup2`, `UserLogon`, `NetworkConnectIP4` | Primary event verb. Dictates the core schema of records fed into visual pipelines. |
| `#Vendor` | `crowdstrike` | Scopes native Falcon sensor streams vs third-party ingested data in NGSIEM. |
| `#event.module` | `falcon` / `sensor` | Separates core EDR sensor streams from identity protection, cloud, or FDR feeds. |
| `#event.dataset` | `falcon.sensor` | ECS dataset categorization for cross-source dashboard widget scoping. |
| `#event.kind` | `event` | High-level event category (`event` vs `alert`). |
| `#repo` | `base_sensor` | Routes query execution to the raw endpoint sensor storage partition. |
| `#repo.cid` | 32-character hexadecimal string | Isolates customer tenant partition in multi-tenant environments. |
| `#type` | `falcon-raw-data` | Direct binary-parsed sensor stream descriptor. |
| `#Cps.version` | `1.2.0` | CrowdStrike Parser Service version contract. |
| `#ecs.version` | `9.3.0` | Elastic Common Schema compliance release for normalized widgets. |

> **⚡ Visual Dashboard Golden Law: Always Anchor by Index Tags First**
> In LogScale, tags prefixed with `#` are physically indexed in segment block headers. 
> If you start a dashboard query with an aggregation directly (e.g., `| groupBy(ComputerName)` without an index tag), the engine is forced to scan every uncompressed segment across all repositories on disk. 
> Always anchor your visualization queries:
> ```cql
> #repo="base_sensor" #event_simpleName="UserLogon" | in(field=LogonType, values=[3, 9, 10])
> | timeChart(span=1h, function=count(), series=LogonType)
> ```
> This guarantees **99%+ physical block skipping**, enabling dashboards to refresh in milliseconds rather than timing out.

---

### 1.05 The Master CrowdStrike Telemetry & Field Hierarchy Mind Map

CrowdStrike Falcon is engineered around an operating system kernel sensor that intercepts low-level syscalls across Windows (`ntoskrnl`), Linux (`eBPF`/`auditd`), and macOS (`EndpointSecurity` framework). Every endpoint transaction is categorized into a strongly typed telemetry subsystem and indexed by `#event_simpleName`.

```
                                  ┌────────────────────────────────────────────────────────────────────────────┐
                                  │                     OPERATING SYSTEM KERNEL SYSCALLS                       │
                                  │      Windows (NTOSKRNL), Linux (Kernel eBPF/Auditd), macOS (EndpointSec)   │
                                  └─────────────────────────────────────┬──────────────────────────────────────┘
                                                                        │ Intercepted by Falcon Sensor Engine
                                                                        ▼
                 ┌───────────────────────────────────────┬───────────────────────────────────────┬───────────────────────────────────────┐
                 │       PROCESS & EXECUTION             │          FILESYSTEM & I/O             │        NETWORK & SOCKETS              │
                 │   Process Spawns, CLI, Lineage        │   Creation, Writes, Renames, USB      │   TCP/UDP Connections, DNS Lookups    │
                 └──────────────────┬────────────────────┘└──────────────────┬────────────────────┘└──────────────────┬────────────────────┘
                                    │                                        │                                        │
                 ┌──────────────────┴────────────────────┐┌──────────────────┴────────────────────┐┌──────────────────┴────────────────────┐
                 ▼                                       ▼▼                                       ▼▼                                       ▼
         ProcessRollup2                     SyntheticProcessRollup2FileCreateForce             FileRenameInfo NetworkConnectIP4               DnsRequest
         Primary process spawn              Long-lived / Pre-boot Filesystem write / drop     Ransomware renames Outbound socket open            DNS query resolution
                 │                                                        │                                        │
                 ├─ GrandParentBaseFileName ⭐                            ├─ TargetFileName ⭐                     ├─ RemoteAddressIP4 ⭐
                 ├─ ParentBaseFileName ⭐                                 ├─ FilePath ⭐                           ├─ RemotePort ⭐
                 ├─ FileName ⭐                                           ├─ Size ⭐                               ├─ DomainName ⭐
                 ├─ CommandLine ⭐                                        ├─ IsOnRemovableDisk ⭐                  ├─ ContextBaseFileName ⭐
                 ├─ TargetProcessId / ROCId                               ├─ ContextBaseFileName ⭐                ├─ LocalAddressIP4 / LocalPort
                 ├─ SHA256HashData ⭐                                     ├─ FileIdentifier                        └─ ComputerName ⭐ / aip
                 └─ UserName ⭐ / ComputerName ⭐                         └─ UserName ⭐ / ComputerName ⭐

                 ┌───────────────────────────────────────┬───────────────────────────────────────┬───────────────────────────────────────┐
                 │       IDENTITY & AUTHENTICATION       │        PERSISTENCE & REGISTRY         │       IN-MEMORY & SCRIPTING           │
                 │   Logons, Token Elevations, Kerberos  │   ASEP Run Keys, Services, Drivers    │   AMSI Interception, Code Injection   │
                 └──────────────────┬────────────────────┘└──────────────────┬────────────────────┘└──────────────────┬────────────────────┘
                                    │                                        │                                        │
                 ┌──────────────────┴────────────────────┐┌──────────────────┴────────────────────┐┌──────────────────┴────────────────────┐
                 ▼                                       ▼▼                                       ▼▼                                       ▼
         UserLogon                              UserLogonFailed2  AsepValueUpdate          RegKeyCreate    ScriptControl                   InjectedThread
         Successful interactive / net logons    Failed logon / BF Auto-start Run key mods  Registry changesAMSI PowerShell/VBS scripts     Cross-process injection
                 │                                                        │                                        │
                 ├─ UserName ⭐ / UserSid ⭐                              ├─ TargetValueName ⭐                    ├─ ScriptContent ⭐
                 ├─ LogonType ⭐ (2=Local, 3=Net, 10=RDP)                 ├─ TargetValueData ⭐                    ├─ ScriptPath ⭐
                 ├─ aip ⭐ (Remote Source IP)                             ├─ RegObjectName ⭐                      ├─ HashData / ByteCount
                 ├─ ComputerName ⭐ / aid ⭐                              ├─ ContextBaseFileName ⭐                ├─ SourceProcessId
                 └─ AuthenticationPackage / LogonServer                   └─ UserName ⭐ / ComputerName ⭐         └─ TargetProcessId / CallStack
```

> **Legend**:
> - `⭐ High-Value Field`: Primary hunting key used in 90%+ of SOC detection rules and investigations.
> - `# Indexed Tag`: Pre-computed block header index (`#event_simpleName`, `#event.module`). Always filter on these first to bypass 99% of scanned disk data.
> - `Context*`: Links non-process events (network, filesystem, registry) back to the originating process that triggered the syscall.

---

### 1.06 Subsystem Field Lineage & Hunting Architecture

#### 1. Process Execution & Lineage Sub-System
- **Core Events**: `ProcessRollup2` (new process creation), `SyntheticProcessRollup2` (processes running prior to sensor boot), `CommandHistory` (shell terminal history).
- **Process Lineage Hierarchy**:
  ```
  GrandParentBaseFileName  [e.g. explorer.exe / winword.exe / w3wp.exe]
           │
           ▼
    ParentBaseFileName     [e.g. cmd.exe / outlook.exe / powershell.exe]
           │
           ▼
        FileName           [e.g. whoami.exe / certutil.exe / curl.exe] (Target Process)
           │
           └─ CommandLine   [Full CLI arguments, switches, flags, and payloads]
  ```
- **Primary Hunting Keys**:
  - `GrandParentBaseFileName` ⭐: Root initiator (e.g. `winword.exe` launching a payload).
  - `ParentBaseFileName` ⭐: Direct spawning parent. Invaluable for spotting anomalous parent-child execution (e.g. `sqlservr.exe` spawning `powershell.exe`).
  - `FileName` ⭐: The spawned target executable.
  - `CommandLine` ⭐: Full command-line text string containing decoded switches, URLs, or script blocks.
  - `SHA256HashData` ⭐: Cryptographic hash of the executable for threat intelligence matching.
  - `TargetProcessId` & `ROCId`: Unique 64-bit Falcon identifiers connecting the process across multi-event joins.
- **Production Hunter Example (Suspicious Process Lineage)**:
  ```cql
  #event_simpleName="ProcessRollup2"
  AND GrandParentBaseFileName=/(winword|excel|powerpnt|outlook)\.exe$/i
  AND ParentBaseFileName=/(cmd|powershell|wscript|cscript)\.exe$/i
  AND FileName=/(whoami|certutil|bitsadmin|curl|powershell)\.exe$/i
  | table([@timestamp, ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine])
  | sort(@timestamp, order=desc)
  ```

#### 2. Filesystem & Disk I/O Sub-System
- **Core Events**: `FileCreateForce` (file dropped/created), `FileWrite` (data appended/modified), `FileRenameInfo` (file renamed/extension modified), `FileDeleteInfo` (file deleted).
- **Primary Hunting Keys**:
  - `TargetFileName` ⭐: Name of the file written or modified (e.g. `payload.ps1`, `ransom.locked`).
  - `FilePath` ⭐: Absolute directory location (e.g. `C:\Users\*\AppData\Local\Temp`).
  - `Size` ⭐: File size in bytes (crucial for detecting large exfiltration staging or small 0-byte drops).
  - `IsOnRemovableDisk` ⭐: Boolean (`1` = USB flash drive / external media, `0` = Fixed local disk).
  - `ContextBaseFileName` ⭐: The process that executed the file write (e.g. `explorer.exe` vs `powershell.exe`).
- **Production Hunter Example (USB Staging / Exfiltration)**:
  ```cql
  (#event_simpleName="FileCreateForce" OR #event_simpleName="FileWrite")
  | IsOnRemovableDisk=1
  | TargetFileName=/\.(?:zip|7z|rar|kdbx|docx|xlsx|pdf|csv)$/i
  | FileSizeMB := Size / (1024 * 1024)
  | FileSizeMB > 5
  | table([@timestamp, ComputerName, UserName, ContextBaseFileName, TargetFileName, FileSizeMB])
  | sort(FileSizeMB, order=desc)
  ```

#### 3. Network & Communications Sub-System
- **Core Events**: `NetworkConnectIP4` (outbound IPv4 TCP/UDP socket), `NetworkListenIP4` (local listening port bound), `DnsRequest` (DNS query initiated by endpoint).
- **Primary Hunting Keys**:
  - `RemoteAddressIP4` ⭐: Remote destination IPv4 address.
  - `RemotePort` ⭐: Remote TCP/UDP port (e.g. `4444`, `1337`, `8080`).
  - `DomainName` ⭐: FQDN requested by endpoint (essential for DGA and fast-flux hunting).
  - `ContextBaseFileName` ⭐: Executable making the network socket connection (e.g. `powershell.exe` connecting directly to an external IP).
- **Production Hunter Example (LOLBin Non-Standard Port Egress)**:
  ```cql
  #event_simpleName="NetworkConnectIP4"
  | ContextBaseFileName=/(powershell|cmd|rundll32|mshta|certutil|regsvr32)\.exe$/i
  | !in(field=RemotePort, values=[80, 443, 8080, 8443])
  | groupBy([ContextBaseFileName, RemoteAddressIP4, RemotePort], function=count())
  | sort(_count, order=desc)
  | head(25)
  ```

#### 4. Authentication, Identity & Access Sub-System
- **Core Events**: `UserLogon` (successful authentication), `UserLogonFailed2` (failed logon / brute force), `UserIdentity` (domain user profile mapping).
- **Primary Hunting Keys**:
  - `UserName` ⭐: The account authenticating (e.g. `SYSTEM`, `Administrator`, `bhupender`).
  - `UserSid` ⭐: Windows Security Identifier.
  - `LogonType` ⭐: Critical numerical indicator:
    - `2` = Interactive / Console (user physically typed password at keyboard).
    - `3` = Network (SMB, file share, RPC, lateral movement).
    - `7` = Screen Unlock.
    - `9` = NewCredentials (Pass-the-Hash / `RunAs /netonly`).
    - `10` = RemoteInteractive (Remote Desktop Protocol / RDP).
    - `11` = CachedInteractive.
  - `aip` ⭐: IP address of the remote originating device.
- **Production Hunter Example (RDP & Pass-the-Hash Lateral Movement Hunt)**:
  ```cql
  #event_simpleName="UserLogon"
  | in(field=LogonType, values=[9, 10])
  | case {
    LogonType=9          | LogonMechanism := "Pass-the-Hash (Type 9)" ;
    LogonType=10         | LogonMechanism := "Remote Desktop (Type 10 RDP)" ;
    *                    | LogonMechanism := format("Type-%s", field=[LogonType]) ;
  }
  | groupBy([ComputerName, UserName, LogonMechanism, aip], function=count(as=Sessions))
  | sort(Sessions, order=desc)
  | table([ComputerName, UserName, LogonMechanism, aip, Sessions])
  ```

#### 5. Registry & Persistence (ASEP) Sub-System
- **Core Events**: `AsepValueUpdate` (Auto-Start Extensibility Point modified), `RegKeyCreate` (new key created), `RegValueSetValue` (registry data written).
- **Primary Hunting Keys**:
  - `TargetValueName` ⭐: Registry value name (e.g. `Run`, `RunOnce`, `Debugger`).
  - `TargetValueData` ⭐: The payload path or CLI configured to run at boot.
  - `RegObjectName` ⭐: Full registry hive path (e.g. `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).
  - `ContextBaseFileName` ⭐: Executable that performed the registry edit.
- **Production Hunter Example (Run Key Persistence Inspection)**:
  ```cql
  #event_simpleName="AsepValueUpdate"
  | RegObjectName=/CurrentVersion\\(?:Run|RunOnce|Policies\\Explorer\\Run)/i
  | table([@timestamp, ComputerName, UserName, ContextBaseFileName, TargetValueName, TargetValueData, RegObjectName])
  | sort(@timestamp, order=desc)
  ```

---

### 1.07 The Threat Hunter's 6-Step Command & Filter Construction Workflow

The primary obstacle for security analysts in CrowdStrike AES is knowing **how to logically construct the query from scratch** without getting lost in syntax or causing query timeouts. Follow this deterministic 6-step framework:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               THE 6-STEP COGNITIVE THREAT HUNTING WORKFLOW                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
  Step 1: HYPOTHESIS           "What physical OS action did the adversary perform?"
          ▼                     Select starting #event_simpleName (ProcessRollup2, FileCreate, NetworkConnect)
  Step 2: SCOPING              "Where am I looking and how do I prevent query timeouts?"
          ▼                     Always place indexed tags (#) and host/user scopes BEFORE the first pipe (|)
  Step 3: FILTERING            "What indicates malicious or anomalous activity?"
          ▼                     Apply regex patterns, exclusions (LOLBins, non-standard ports, strange paths)
  Step 4: AGGREGATING          "Do I need raw incident evidence or macro summary patterns?"
          ▼                     Use groupBy([Keys], function=count()) or bucket(span=15m)
  Step 5: SORTING              "Is the adversary loud or stealthy?"
          ▼                     Loud/Brute-Force: sort(desc) | Rare Long-Tail Outlier: sort(asc)
  Step 6: VISUALIZING          "How should the output be consumed?"
                                Forensic Table (table()), Timeline (timechart()), or Matrix (heatmap)
```

#### Step-by-Step Construction Guide with Concrete Query Evolution

##### Step 1: Formulate the Hypothesis & Select the Starting `#event_simpleName`
Ask: *What is the adversary trying to accomplish on the host?*
- Spawning a shell or payload $\rightarrow$ `#event_simpleName="ProcessRollup2"`
- Writing or dropping a file $\rightarrow$ `#event_simpleName="FileCreateForce"`
- Connecting to external infrastructure $\rightarrow$ `#event_simpleName="NetworkConnectIP4"`
- Authenticating or spraying passwords $\rightarrow$ `#event_simpleName="UserLogon"`
- Registering persistence $\rightarrow$ `#event_simpleName="AsepValueUpdate"`

##### Step 2: Apply High-Performance Header Scoping (`#` Tags)
*Cardinal Performance Rule*: Filter on indexed tags **before** the first pipe (`|`). Never put `#event_simpleName` inside a pipe.
```cql
// GOOD: Blazing fast, scans only ProcessRollup2 blocks
#event_simpleName="ProcessRollup2" ComputerName="MACN-*"

// BAD: Scans terabytes of raw blocks across every event type before filtering
* | #event_simpleName="ProcessRollup2"
```

##### Step 3: Filter & Dissect Forensic Fields
Narrow down to anomalous indicators using PCRE regex, case-insensitivity (`/i`), or field exclusions:
```cql
#event_simpleName="ProcessRollup2"
AND FileName=/(powershell|pwsh|cmd)\.exe$/i
AND CommandLine=/(bypass|-nop|-enc|downloadstring|invoke-)/i
AND ParentBaseFileName!="explorer.exe"
```

##### Step 4: Aggregate Data (Macro vs Micro)
- **Micro (Incident Forensics)**: Skip aggregation. Output individual chronological records using `table()`.
- **Macro (Fleet Pattern Hunting)**: Aggregate using `groupBy()`:
```cql
#event_simpleName="ProcessRollup2"
AND FileName=/(powershell|pwsh|cmd)\.exe$/i
AND CommandLine=/(bypass|-nop|-enc|downloadstring|invoke-)/i
| groupBy([ComputerName, UserName, ParentBaseFileName, FileName], function=count(as=ExecutionCount))
```

##### Step 5: Sort to Surface Threats (Loud vs Stealthy)
- **Top Talkers (Loud Attacks, Scanners, Floods)**: `sort(ExecutionCount, order=desc) | head(10)`
- **Rare Outliers (Stealthy LOLBins, Single-host Persistence)**: `sort(ExecutionCount, order=asc) | head(10)`
- **Compound Hierarchical Sorting**: `sort([ComputerName, ExecutionCount], order=[asc, desc])`

##### Step 6: Visual Presentation & Column Formatting
Project the final columns cleanly using `table()` or format for dashboards:
```cql
#event_simpleName="ProcessRollup2"
AND FileName=/(powershell|pwsh|cmd)\.exe$/i
AND CommandLine=/(bypass|-nop|-enc|downloadstring|invoke-)/i
| groupBy([ComputerName, UserName, ParentBaseFileName, FileName], function=count(as=ExecutionCount))
| sort(ExecutionCount, order=desc)
| table([ComputerName, UserName, ParentBaseFileName, FileName, ExecutionCount])
```

---

## 1.2 The Master's Operation Order & Pipeline Execution Logic

> *"Listen carefully, apprentice: LogScale queries are not static filters. They are a directional assembly line. What you do at stage 1 determines what data exists at stage 4. If you sort too early, you melt the cluster. If you filter too late, the fields have already vanished into the void. Master this deterministic sequence."*

---

### 1.2.1 The Fundamental 7-Stage Pipeline Order

Every high-performance visualization query flows strictly from left to right through seven logical stages:

```
┌─────────────┐     ┌───────────────┐     ┌─────────────┐     ┌─────────────────┐     ┌────────────┐     ┌──────────┐     ┌─────────────┐
│  1. FILTER  │ ──► │ 2. TRANSFORM  │ ──► │3. AGGREGATE │ ──► │ 4. POST-FILTER  │ ──► │ 5. FORMAT  │ ──► │ 6. SORT  │ ──► │ 7. DISPLAY  │
│ Scope Data  │     │ Normalize/Der │     │ groupBy/time│     │ Threshold Count │     │ Rename/Drop│     │ Top/Tail │     │ table/chart │
└─────────────┘     └───────────────┘     └─────────────┘     └─────────────────┘     └────────────┘     └──────────┘     └─────────────┘
```

1. **Stage 1: FILTER (Scope Dataset)**: Narrow raw volume using indexed tags (`#event_simpleName`) and exact boundary matches before piping.
   ```cql
   #repo="base_sensor" #event_simpleName="ProcessRollup2" | FileName=/powershell\.exe$/i
   ```
2. **Stage 2: TRANSFORM (Derive Fields)**: Extract regex tokens, normalize case, or compute boolean indicator flags.
   ```cql
   | case {
    CommandLine=/-enc/i | is_encoded := 1 ;
    *                   | is_encoded := 0 ;
  }
   ```
3. **Stage 3: AGGREGATE (Condense Data)**: Compress millions of raw records into discrete summary groups using `groupBy()`, `bucket()`, or `timechart()`.
   ```cql
   | groupBy([ComputerName, UserName], function=count(as=attempts))
   ```
4. **Stage 4: POST-FILTER (Apply Thresholds)**: Filter on the aggregated metrics calculated in Stage 3.
   ```cql
   | attempts >= 5
   ```
5. **Stage 5: FORMAT (Structure Output)**: Select, alias, or rename fields for reporting.
   ```cql
   | rename(field=attempts, as="Failed Logons")
   ```
6. **Stage 6: SORT (Order Records)**: Rank the summarized rows by count or timestamp. Always attach a `limit`.
   ```cql
   | sort(attempts, order=desc, limit=100)
   ```
7. **Stage 7: DISPLAY (Render Presentation)**: Final presentation projection into a table or chart.
   ```cql
   | table([ComputerName, UserName, "Failed Logons"])
   ```

---

### 1.2.2 The Two Master Laws: Why Order Matters

#### Law 1: Aggregate BEFORE Sorting (Performance Law)
* **The Fatal Mistake**: Sorting raw events before `groupBy()` forces the cluster to sort millions of multi-kilobyte records in RAM.
* **The Master Fix**: Aggregate first to condense the data into hundreds of groups, then sort the small summary matrix.
```cql
// ❌ WRONG (Cluster Killer): Sorts 5,000,000 raw events in memory before counting
#event_simpleName="ProcessRollup2" | sort(@timestamp) | groupBy(ComputerName, function=count())

// ✅ CORRECT: Condenses to 500 host rows, then sorts in milliseconds
#event_simpleName="ProcessRollup2" | groupBy(ComputerName, function=count(as="ExecCount")) | sort(ExecCount, order=desc, limit=100)
```

#### Law 2: Filter BEFORE Aggregation (Correctness Law)
* **The Fatal Mistake**: Attempting to filter on raw fields *after* `groupBy()`. After aggregation, all original fields are discarded unless preserved in a `collect()`.
* **The Master Fix**: Apply raw telemetry filters before `groupBy()`. Post-aggregation filters must target only aggregated variables.
```cql
// ❌ WRONG: CommandLine does not exist after groupBy!
#event_simpleName="ProcessRollup2" | groupBy(ComputerName, function=count()) | CommandLine=/enc/i

// ✅ CORRECT: Filter raw command line first, then group
#event_simpleName="ProcessRollup2" | CommandLine=/enc/i | groupBy(ComputerName, function=count())
```

---

### 1.2.3 Universal Visualization Decision Matrix

| Analytical Goal | Optimal Widget | Database / CQL Syntax Pattern | When to Use (Universal Rule) | Anti-Pattern (Avoid) |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Evidence & Triage** | Forensic Table | `\| table([@timestamp, ComputerName, UserName, ...])` | Inspecting individual events, verifying parameters, forensic exports. | Aggregating millions of events without `head()` or `groupBy()`. |
| **Frequency & Volume Ranking** | Bar / Column Chart | `\| groupBy(Field, count(as=C)) \| sort(C, order=desc) \| head(10)` | Comparing discrete categories (Top talkers, suspect accounts). | Using bar charts for continuous timestamps without bucketing. |
| **Chronological Cadence & Spikes** | Line / Area Chart | `\| bucket(span=15m) \| groupBy(_bucket, count())` | Tracking event rates over time; spotting sudden bursts or dead times. | Using line charts for discrete categorical data with no time dimension. |
| **Proportions & Composition** | Donut / Pie Chart | `\| groupBy(Dimension, function=count())` | Showing percentage contribution for 2–6 distinct classes (e.g. Windows/Mac/Linux). | Pie charts with > 8 categories (creates unreadable rainbow slivers). |
| **Bi-Dimensional Pattern Density** | 2D Matrix Heatmap | `\| groupBy([Dim1, Dim2], function=count())` | Discovering clusters across two dimensions (e.g. Activity by Hour & Day). | Pairing continuous floating-point fields without discrete binning. |
| **Causality & Ancestry Routing** | Sankey Flow Graph | `\| groupBy([Parent, Child], count(as=Weight))` | Visualizing hierarchical traversal (Spawning chains, authentication hops). | Flat datasets with no natural directed graph topology. |

---

### 1.2.4 16 Production-Grade Structured Queries (groupBy, table, sort, timechart, bucket & Functions)

Below is an analytical catalog of 16 battle-tested queries covering all visualization paradigms, statistical functions, and column name translations:

#### 1. Executive Process Forensics with Localized Timestamps
* **Target Widget**: **Forensic Table**
* **Key Operators**: `table()`, `formatTime()`, `rename()`, Column Name Translation
```cql
#repo="base_sensor" #event_simpleName="ProcessRollup2"
| FileName=/powershell\.exe$/i
| eval(ExecutionTime = formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, as=ExecutionTime))
| rename(field=ComputerName, as="Target Host")
| rename(field=UserName, as="Executing Account")
| rename(field=CommandLine, as="CLI Invocation")
| table([ExecutionTime, "Target Host", "Executing Account", FileName, "CLI Invocation"])
| sort(@timestamp, order=desc, limit=100)
```

#### 2. Top 10 Talking Endpoints by Process Creation Volume
* **Target Widget**: **Bar / Column Chart**
* **Key Operators**: `groupBy()`, `count()`, `as`, `sort()`, `head()`
```cql
#repo="base_sensor" #event_simpleName="ProcessRollup2"
| groupBy(ComputerName, function=count(as="Process Creations"))
| sort("Process Creations", order=desc)
| head(10)
```

#### 3. Authentication Type Distribution with Enum Code Translation
* **Target Widget**: **Donut / Pie Chart**
* **Key Operators**: `case`, `eval()`, `groupBy()`, `count()`, Categorical Mapping
```cql
#repo="base_sensor" #event_simpleName="UserLogon"
| case {
    LogonType=2          | LogonCategory := "Interactive (Console)" ;
    LogonType=3          | LogonCategory := "Network (SMB/RPC)" ;
    LogonType=7          | LogonCategory := "Screen Unlock" ;
    LogonType=9          | LogonCategory := "NewCredentials (PtH)" ;
    LogonType=10         | LogonCategory := "Remote Desktop (RDP)" ;
    *                    | LogonCategory := format("Type-%s", field=[LogonType]) ;
  }
| groupBy(LogonCategory, function=count(as="Total Sessions"))
| sort("Total Sessions", order=desc)
```

#### 4. Multi-Series Process Execution Cadence Over Time
* **Target Widget**: **Line Timechart**
* **Key Operators**: `timeChart()`, `span=1h`, `series=FileName`, `limit=5`
```cql
#repo="base_sensor" #event_simpleName="ProcessRollup2"
| in(field=FileName, values=["powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe", "rundll32.exe"])
| timeChart(span=1h, function=count(), series=FileName, limit=5)
```

#### 5. Custom 15-Minute Interval Socket Opening Rate
* **Target Widget**: **Area Graph / Histogram**
* **Key Operators**: `bucket()`, `_bucket`, `groupBy()`, `count()`, `formatTime()`
```cql
#repo="base_sensor" #event_simpleName="NetworkConnectIP4"
| in(field=RemotePort, values=[443, 80, 8080])
| bucket(span=15m)
| eval(TimeSlot = formatTime("%H:%M", field=_bucket, as=TimeSlot))
| groupBy([TimeSlot, RemotePort], function=count(as="Connections"))
| sort(TimeSlot, order=asc)
```

#### 6. Brute Force Threshold Alert with Post-Grouping Filter
* **Target Widget**: **Threshold Table / Alert Metric**
* **Key Operators**: `groupBy()`, `count()`, Stage 4 Post-Filter (`>= 5`), `collect()`
```cql
#repo="base_sensor" #event_simpleName="UserLogon"
| Status_decimal != 0
| groupBy([UserName, RemoteAddressIP4], function=[
    count(as=FailedAttempts),
    count(ComputerName, distinct=true, as=TargetHosts),
    max(@timestamp, as=LastSeen)
  ])
| FailedAttempts >= 5
| LastFailed := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort(FailedAttempts, order=desc, limit=50)
| table([UserName, RemoteAddressIP4, FailedAttempts, TargetHosts, LastFailed])
```

#### 7. Multi-Metric Host File I/O Statistical Profiling
* **Target Widget**: **Statistical Table**
* **Key Operators**: `groupBy()`, `sum()`, `avg()`, `max()`, `round()`, Unit Byte Conversion
```cql
#repo="base_sensor" #event_simpleName="FileCreateForce"
| groupBy(ComputerName, function=[
    count(as=TotalFiles),
    sum(Size, as=TotalBytes),
    avg(Size, as=AvgBytes),
    max(Size, as=MaxBytes)
  ])
| TotalMB := TotalBytes / 1048576 | round(TotalMB)
| AvgKB   := AvgBytes / 1024       | round(AvgKB)
| MaxMB   := MaxBytes / 1048576   | round(MaxMB)
| sort(TotalMB, order=desc, limit=25)
| table([ComputerName, TotalFiles, TotalMB, AvgKB, MaxMB])
```

#### 8. 2D Matrix Heatmap: Day of Week vs. Hour of Day
* **Target Widget**: **2D Matrix Heatmap**
* **Key Operators**: `time:dayOfWeek()`, `formatTime()`, `case`, `groupBy([Day, Hour])`, `count()`
```cql
#repo="base_sensor" #event_simpleName="UserLogon"
| eval(DayNum = time:dayOfWeek(@timestamp))
| case {
    DayNum=1             | DayName := "Mon" ;
    DayNum=2             | DayName := "Tue" ;
    DayNum=3             | DayName := "Wed" ;
    DayNum=4             | DayName := "Thu" ;
    DayNum=5             | DayName := "Fri" ;
    DayNum=6             | DayName := "Sat" ;
    DayNum=7             | DayName := "Sun" ;
    *                    | DayName := "Unknown" ;
  }
| eval(HourOfDay = formatTime("%H", field=@timestamp, as=HourOfDay))
| groupBy([DayName, HourOfDay], function=count(as="LoginDensity"))
```

#### 9. Process Execution Lineage Hierarchy (Sankey Flow Graph)
* **Target Widget**: **Sankey Flow Diagram**
* **Key Operators**: `regex`, `groupBy([Parent, Child])`, `count(as=Weight)`, `head()`
```cql
#repo="base_sensor" #event_simpleName="ProcessRollup2"
| ParentBaseFileName=/(explorer|cmd|powershell|winword|w3wp|wmiprvse)\.exe$/i
| FileName=/(cmd|powershell|certutil|bitsadmin|mshta|rundll32|cscript)\.exe$/i
| groupBy([ParentBaseFileName, FileName], function=count(as=Weight))
| sort(Weight, order=desc)
| head(25)
```

#### 10. Outbound C2 Geographic Destination Mapping (GeoIP)
* **Target Widget**: **World Map**
* **Key Operators**: `ipLocation()`, `groupBy()`, `count()`, Public IP Filtering
```cql
#repo="base_sensor" #event_simpleName="NetworkConnectIP4"
| RemoteAddressIP4!=/^10\./ AND RemoteAddressIP4!=/^192\.168\./ AND RemoteAddressIP4!=/^172\.(1[6-9]|2[0-9]|3[0-1])\./
| ipLocation(RemoteAddressIP4)
| groupBy([RemoteAddressIP4.country, RemoteAddressIP4.city], function=count(as="Outbound Connections"))
| sort("Outbound Connections", order=desc, limit=100)
```

#### 11. Statistical Outlier Detection via Standard Deviation (3-Sigma Rule)
* **Target Widget**: **Forensic Outlier Table**
* **Key Operators**: `groupBy()`, `count()`, `stats(avg(), stdDev())`, Dynamic Math Threshold
```cql
#repo="base_sensor" #event_simpleName="DnsRequest"
| groupBy(ComputerName, function=count(as=QueryCount))
| groupBy([], function=[avg(QueryCount, as=MeanQueries), stdDev(QueryCount, as=StdDeviation)])
| AnomalyThreshold := MeanQueries + (3 * StdDeviation)
| QueryCount > AnomalyThreshold
| sort(QueryCount, order=desc)
| table([ComputerName, QueryCount, MeanQueries, StdDeviation])
```

#### 12. Executive Authentication Success vs. Failure KPI Ratio
* **Target Widget**: **KPI Gauge / Dual-Metric Counter**
* **Key Operators**: `eval(if())`, `stats(sum())`, `round()`, Ratio Percentage
```cql
#repo="base_sensor" #event_simpleName="UserLogon"
| case { Status_decimal != 0 | is_fail := 1 ; * | is_fail := 0 }
| case { Status_decimal == 0 | is_success := 1 ; * | is_success := 0 }
| groupBy([], function=[
    count(as=TotalAttempts),
    sum(is_fail, as=FailedLogons),
    sum(is_success, as=SuccessLogons)
  ])
| FailureRate := (FailedLogons / TotalAttempts) * 100
| round(FailureRate)
| table([TotalAttempts, SuccessLogons, FailedLogons, FailureRate])
```

#### 13. Rare Long-Tail Binary Hunt (Endpoint Cardinality <= 2)
* **Target Widget**: **Threat Hunting Table**
* **Key Operators**: `groupBy()`, `selectDistinct()`, `length()`, Long-Tail Filtering
```cql
#repo="base_sensor" #event_simpleName="ProcessRollup2"
| groupBy([SHA256HashData, FileName], function=[
    count(ComputerName, distinct=true, as=HostCount),
    count(as=ExecCount)
  ])
| HostCount <= 2 AND ExecCount < 10
| sort(HostCount, order=asc, limit=50)
| table([FileName, SHA256HashData, HostCount, ExecCount])
```

#### 14. Lateral Movement Matrix with Named Protocol Mapping
* **Target Widget**: **Grouped Bar / Categorical Matrix**
* **Key Operators**: `case`, `eval()`, `groupBy([Process, Protocol, IP])`, `count()`, `sort()`
```cql
#repo="base_sensor" #event_simpleName="NetworkConnectIP4"
| case {
    RemotePort=445       | LateralVector := "SMB / IPC$ Admin Share" ;
    RemotePort=3389      | LateralVector := "RDP Terminal Service" ;
    RemotePort=5985      | LateralVector := "WinRM HTTP" ;
    RemotePort=5986      | LateralVector := "WinRM HTTPS" ;
    RemotePort=22        | LateralVector := "SSH Remote Shell" ;
    *                    | LateralVector := "Other Protocol" ;
  }
| LateralVector != "Other Protocol"
| groupBy([ContextImageFileName, LateralVector, RemoteAddressIP4], function=count(as="Session Count"))
| sort("Session Count", order=desc, limit=50)
```

#### 15. Stacked Area Cadence of Network Protocols (30m Buckets)
* **Target Widget**: **Stacked Area Timechart**
* **Key Operators**: `timeChart()`, `span=30m`, `series=RemotePort`, `limit=5`
```cql
#repo="base_sensor" #event_simpleName="NetworkConnectIP4"
| in(field=RemotePort, values=[443, 80, 445, 3389, 53])
| timeChart(span=30m, function=count(), series=RemotePort, limit=5)
```

#### 16. Correlated Lineage Breadcrumbs & Obfuscation Severity Tagging
* **Target Widget**: **Correlated Forensic Summary**
* **Key Operators**: `format()`, `regex()`, `eval()`, `groupBy()`, `collect()`, `sort()`, `table()`
```cql
#repo="base_sensor" #event_simpleName="ProcessRollup2"
| ParentBaseFileName=/(powershell|cmd|wscript|cscript)\.exe$/i
| LineageChain := format("%s -> %s", field=[ParentBaseFileName, FileName])
| case {
    CommandLine=/-(?:enc|encodedcommand)/i | is_enc := "HIGH" ;
    *                                      | is_enc := "MEDIUM" ;
  }
| groupBy([ComputerName, UserName, LineageChain, is_enc], function=[
    count(as=InvocationCount),
    max(@timestamp, as=LastSeen),
    collect(CommandLine, limit=1, as=SampleCLI)
  ])
| LastExecution := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort(InvocationCount, order=desc, limit=100)
| table([LastExecution, ComputerName, UserName, LineageChain, is_enc, InvocationCount, SampleCLI])
```

---

### 1.2.5 The Hunter's Pipeline Construction Checklist

1. ✅ **Filter first**: Put `#event_simpleName` and indexed tags before the first pipe.
2. ✅ **Transform if needed**: Normalizations (`lower()`) and evaluations (`if()`) belong before aggregation.
3. ✅ **Aggregate to combine**: Use `groupBy()` or `timechart()` whenever summarizing volume.
4. ✅ **Thresholds follow aggregation**: Write `_count >= 5` *after* `groupBy()`.
5. ✅ **Sort near the end**: Always sort the small aggregated dataset, never the raw event stream.
6. ✅ **Format last**: Use `table()` strictly for column layout and alias presentation.
7. ✅ **Always use limits**: Cap `sort(..., limit=100)` and `head()` to prevent UI freezes.
8. ✅ **Collect IDs for rules**: Include `@id` inside `collect()` when building detection alerts.

---

## 2. Tier 1: Basic — Tables, Projections & Elementary Sorting

### 1.1 Clean Tabular Projection (`table()`)
By default, LogScale returns dozens of raw metadata fields. Use `table()` to define a clean, analyst-ready tabular view.

```cql
#event_simpleName="ProcessRollup2"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

#### User-Targeted Forensic Projection
Target a specific user prefix using case-insensitive PCRE regex and immediately format into a forensic table:
```cql
#event_simpleName="ProcessRollup2" and user.name=~/^bhupender/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

* **Best Widget**: Table
* **Why it matters**: Drastically reduces browser memory consumption and strips non-essential JSON tags while isolating actions performed by a specific identity.

---

### 1.2 Renaming Columns with Aliases (`as`)
Create user-friendly column headers for non-technical stakeholders or executive export.

```cql
#event_simpleName="ProcessRollup2"
| table([
    @timestamp as "Time", 
    ComputerName as "Endpoint", 
    UserName as "Operator", 
    FileName as "Process", 
    CommandLine as "Executed Command"
  ])
```

* **Best Widget**: Table

---

### 1.3 Single-Field Sorting (`sort()`)
Order records chronologically or by numerical significance.

```cql
// Newest events first (Reverse Chronological)
#event_simpleName="UserLogon"
| sort(@timestamp, order=desc)
| table([@timestamp, ComputerName, UserName, LogonType])
```

```cql
// Oldest events first (Chronological Incident Playback)
#event_simpleName="ProcessRollup2" ComputerName="MACN-BHBHA-SB"
| sort(@timestamp, order=asc)
| table([@timestamp, ParentBaseFileName, FileName, CommandLine])
```

---

### 1.4 Limiting & Paging Results (`head()`, `tail()`)
Control dataset limits to prevent dashboard lag and speed up query iteration.

```cql
// Return the 25 most recent file modifications
#event_simpleName="FileCreateForce"
| sort(@timestamp, order=desc)
| head(25)
| table([@timestamp, ComputerName, TargetFileName, FilePath])
```

```cql
// Return the bottom 10 results in an aggregate list
#event_simpleName="ProcessRollup2"
| groupBy(FileName, function=count(as=Runs))
| sort(Runs, order=desc)
| tail(10)
```

---

### 1.5 Simple Event Volume Counter (Single Value KPI)
Create a single high-impact number widget for SOC wallboards.

```cql
#event_simpleName="UserLogonFailed2"
| count(as=TotalFailedLogons)
```

* **Best Widget**: Single Value (Number)
* **Configuration**: Set widget visualization to **Single Value** with label `"Failed Logons (24h)"`.

```
┌─────────────────────────────────┐
│       FAILED LOGONS (24H)       │
│                                 │
│              1,482              │
│                                 │
│  ▲ +14% vs previous window      │
└─────────────────────────────────┘
```

---

### 1.6 Simple Categorical Breakdown (Pie / Donut Chart)
Visualize endpoint operating system distribution across active sensors.

```cql
#event_simpleName="ProcessRollup2"
| groupBy(event_platform)
```

* **Best Widget**: Donut / Pie Chart
* **Output Table**:

| event_platform | _count |
| :--- | :--- |
| `Win` | 84,200 |
| `Mac` | 14,350 |
| `Lin` | 4,210 |

---

## 3. Tier 2: Medium — Grouping, Time Bucketing & Multi-Axis Graphs

### 2.1 Multi-Key Grouping & Joint Frequencies
Analyze frequency distributions across two combined entities (e.g., Host + Process).

```cql
#event_simpleName="ProcessRollup2"
| groupBy([ComputerName, FileName], function=count(as=Executions))
| sort(Executions, order=desc)
```

* **Best Widget**: Grouped Bar Chart or Pivot Table
* **Hunting Rationale**: Immediately spots which specific machines run anomalous binaries.

---

### 2.2 Multi-Column Compound Sorting
Sort by host name alphabetically, and then sort by event timestamp descending within each host.

```cql
#event_simpleName="ProcessRollup2"
| sort([ComputerName, @timestamp], order=[asc, desc])
| table([ComputerName, @timestamp, UserName, FileName])
```

* **Best Widget**: Table with multi-column sorting indicators.

---

### 2.3 Time Bucketing for Bar / Area Charts (`bucket()`)
Discretize continuous time events into uniform time bins for histogram and column chart views.

```cql
#event_simpleName="NetworkConnectIP4"
| bucket(span=1h)
| count(as=ConnectionsPerHour)
```

* **Best Widget**: Column Chart or Area Chart
* **Time Span Units**: `1m` (minute), `5m`, `15m`, `1h` (hour), `1d` (day).

```
Connections
 50k ┼                 ╭─╮
 40k ┼       ╭─╮       │ │
 30k ┼   ╭─╮ │ │   ╭─╮ │ │ ╭─╮
 20k ┼   │ │ │ │   │ │ │ │ │ │
 10k ┼ ──┴─┴─┴─┴───┴─┴─┴─┴─┴─┴──
      08:00 10:00 12:00 14:00 16:00
```

---

### 2.4 Native Timecharts (`timechart()`)
The `timechart()` function automatically handles dynamic time-bucket resolution based on the user's selected search timeframe.

```cql
#event_simpleName="ProcessRollup2"
| timechart(span=15m)
```

* **Best Widget**: Line Chart
* **Feature**: Smooth continuous line plotting with automated zero-fill for empty buckets.

---

### 2.5 Top-N / Long-Tail Slicing with Sorting
Generate Top-10 leaderboards or Long-Tail anomaly lists.

#### Top 10 Talking Endpoints (High Volume)
```cql
#event_simpleName="NetworkConnectIP4"
| groupBy(ComputerName, function=count(as=NetEvents))
| sort(NetEvents, order=desc)
| head(10)
```
* **Best Widget**: Horizontal Bar Chart

#### Long-Tail (Least Frequent) Binaries (Threat Hunting)
```cql
#event_simpleName="ProcessRollup2"
| groupBy(FileName, function=count(as=ExecutionCount))
| ExecutionCount <= 3
| sort(ExecutionCount, order=asc)
| head(20)
```
* **Best Widget**: Table
* **Hunting Context**: Targets rare executables launched fewer than 3 times across the entire fleet.

---

### 2.6 Deduplication & Cardinality Extraction (`selectDistinct`)
Calculate how many unique users are active on each endpoint.

```cql
#event_simpleName="UserLogon"
| groupBy(ComputerName, function=selectDistinct(UserName) as UniqueUsers)
| UserCount := length(UniqueUsers)
| sort(UserCount, order=desc)
| table([ComputerName, UserCount, UniqueUsers])
```

* **Best Widget**: Table with drilldown links.

---

### 2.7 Multi-User Target Hunt with User & Machine Breakdown Counts

When threat hunting across an analyst team, department, or suspect accounts, you often start with a multi-user prefix filter:

```cql
#event_simpleName="ProcessRollup2" and (user.name=~/^bhupender/i or user.name=~/^nayan/i or user.name=~/^monika/i or user.name=~/^afreed/i or user.name=~/^deepak/i or user.name=~/^tanuj/i or user.name=~/^ashwin/i or user.name=~/^anushka/i or user.name=~/^avneet/i or user.name=~/^jatin/i)
| table([@timestamp, ComputerName, UserName, host.os.platform])
```

> [!TIP]
> **PCRE Alternation Optimization (10x Faster Scan)**:  
> Instead of chaining 10 separate `or` statements, consolidate the prefixes into a single non-capturing group `(?:...)`:
> ```cql
> #event_simpleName="ProcessRollup2" AND user.name=/^(?:bhupender|nayan|monika|afreed|deepak|tanuj|ashwin|anushka|avneet|jatin)/i
> | table([@timestamp, ComputerName, UserName, host.os.platform])
> ```

---

#### Solution A: User-Centric Summary Table (Count of Events + Machine Count + Host List)
To see the **count of events per user, how many unique machines they accessed, and the exact machine list** alongside the table:

```cql
#event_simpleName="ProcessRollup2" 
AND user.name=/^(?:bhupender|nayan|monika|afreed|deepak|tanuj|ashwin|anushka|avneet|jatin)/i
| groupBy(UserName, function=[count(as=UserEventCount),
    selectDistinct(ComputerName) as MachineList,
    selectDistinct(host.os.platform) as OperatingSystems
  ])
| MachineCount := length(MachineList)
| table([UserName, UserEventCount, MachineCount, MachineList, OperatingSystems])
| sort(UserEventCount, order=desc)
```

* **Best Widget**: Table / Bar Chart
* **Output Preview**:

| UserName | UserEventCount | MachineCount | MachineList | OperatingSystems |
| :--- | :--- | :--- | :--- | :--- |
| `bhupender` | 1,420 | 3 | `[MACN-BHBHA-SB, WIN-BHBHA-01, LIN-SRV-02]` | `[macos, windows, linux]` |
| `deepak` | 890 | 2 | `[WIN-DPK-01, WIN-DPK-02]` | `[windows]` |
| `monika` | 640 | 1 | `[MAC-MNK-01]` | `[macos]` |

---

#### Solution B1: Which User Logged In From Which Computer, and How Many Times (`UserLogon`)

> [!IMPORTANT]
> **Authentication Sessions (`UserLogon`) vs Process Executions (`ProcessRollup2`)**:  
> In CrowdStrike Falcon telemetry, `#event_simpleName="ProcessRollup2"` records **process creation** (every time an executable or script runs). A single user logging in once in the morning can generate hundreds of `ProcessRollup2` events during their shift.  
> To see **actual user logons** (which user logged into which computer, the logon mechanism, and how many times they authenticated), you must query **`#event_simpleName="UserLogon"`**.

```cql
// Track User Logins: User, Computer, Logon Mechanism, and Total Login Count
#event_simpleName="UserLogon" 
AND UserName=/^(?:admin|service|operator|analyst|user)/i
| case {
    LogonType=2          | LogonTypeName := "Interactive (Console/Direct)" ;
    LogonType=3          | LogonTypeName := "Network (SMB/RPC Share)" ;
    LogonType=7          | LogonTypeName := "Screen Unlock" ;
    LogonType=9          | LogonTypeName := "NewCredentials (PtH / RunAs)" ;
    LogonType=10         | LogonTypeName := "Remote Desktop (RDP)" ;
    LogonType=11         | LogonTypeName := "Cached Interactive" ;
    *                    | LogonTypeName := format("Type-%s", field=[LogonType]) ;
  }
| groupBy([UserName, ComputerName, LogonTypeName, host.os.platform], function=count(as=LoginCount))
| sort([UserName, LoginCount], order=[asc, desc])
| table([UserName, ComputerName, LogonTypeName, host.os.platform, LoginCount])
```

* **Best Widget**: Table or Grouped Bar Chart
* **Output Preview**:

| UserName | ComputerName | LogonTypeName | host.os.platform | LoginCount |
| :--- | :--- | :--- | :--- | :--- |
| `bhupender` | `MACN-BHBHA-SB` | `Interactive (Console/Direct)` | `macos` | 14 |
| `bhupender` | `MACN-BHBHA-SB` | `Screen Unlock` | `macos` | 42 |
| `bhupender` | `WIN-BHBHA-01` | `Remote Desktop (RDP)` | `windows` | 6 |
| `deepak` | `WIN-DPK-01` | `Interactive (Console/Direct)` | `windows` | 18 |
| `monika` | `MAC-MNK-01` | `Interactive (Console/Direct)` | `macos` | 12 |
| `nayan` | `MAC-NYN-01` | `Interactive (Console/Direct)` | `macos` | 15 |

---

#### Solution B2: Process Execution Frequency Matrix per User and Computer (`ProcessRollup2`)
If your objective is to measure **application/process execution workload** generated by each user across endpoints:

```cql
#event_simpleName="ProcessRollup2" 
AND UserName=/^(?:admin|service|operator|analyst|user)/i
| groupBy([ComputerName, UserName, host.os.platform], function=count(as=ProcessCount))
| sort([host.os.platform, ProcessCount], order=[desc, desc])
| table([UserName, ComputerName, host.os.platform, ProcessCount])
```

* **Best Widget**: Pivot Table or Stacked Bar Chart
* **Output Preview**:

| UserName | ComputerName | host.os.platform | ProcessCount |
| :--- | :--- | :--- | :--- |
| `bhupender` | `MACN-BHBHA-SB` | `macos` | 1,120 |
| `nayan` | `MAC-NYN-01` | `macos` | 510 |
| `bhupender` | `WIN-BHBHA-01` | `windows` | 210 |
| `deepak` | `WIN-DPK-01` | `windows` | 740 |

---

#### Solution B3: Correlated Telemetry Pivot (Logins vs Executions Side-by-Side)
Compare actual logons against process activity in a single cross-tabulation table using multi-event inclusion:

```cql
(#event_simpleName="UserLogon" OR #event_simpleName="ProcessRollup2")
AND UserName=/^(?:admin|service|operator|analyst|user)/i
| case {
    #event_simpleName="UserLogon" | EventType := "Logons" ;
    #event_simpleName="ProcessRollup2" | EventType := "ProcessExecutions" ;
    *                    | EventType := #event_simpleName ;
  }
| groupBy([UserName, ComputerName, EventType], function=count(as=Total))
| pivot(UserName, splitBy=EventType, value=Total)
| sort(UserName, order=asc)
```

* **Best Widget**: Pivot Table (Shows columns: `UserName`, `ComputerName`, `Logons`, `ProcessExecutions`)

---

#### Solution C: Side-by-Side SOC Dashboard Construction (Summary Counts + Detail Table)
In Falcon Advanced Event Search / LogScale dashboards, best practice is to place two complementary widgets side-by-side using the same scoped dataset:

```
┌──────────────────────────────────────────────┬──────────────────────────────────────────────┐
│  WIDGET 1: Executions by User (Bar Chart)    │  WIDGET 2: Executions by Machine (Bar Chart) │
│                                              │                                              │
│  bhupender  ████████████████████  1,420      │  MACN-BHBHA-SB  ███████████████████ 1,120    │
│  deepak     ████████████          890        │  WIN-DPK-01     ████████████        740      │
│  monika     █████████             640        │  MAC-NYN-01     ████████            510      │
└──────────────────────────────────────────────┴──────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│  WIDGET 3: Live Forensic Detail Table                                                       │
│                                                                                             │
│  @timestamp           ComputerName    UserName    host.os.platform    CommandLine           │
│  2026-09-23 14:10:02  MACN-BHBHA-SB   bhupender   macos               zsh -c ...            │
│  2026-09-23 14:09:44  WIN-DPK-01      deepak      windows             powershell.exe -ep... │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Tier 3: High — Multi-Metric Stats, Heatmaps & GeoIP Visualizations

### 3.1 Multi-Metric Aggregation Functions (`min`, `max`, `avg`, `sum`, `collect`, `count`)
Summarize network connection payload sizes, preserve forensic sample values, or calculate operational timelines in a single pass using the bracketed `function=[ ... ]` array syntax.

```cql
#event_simpleName="FileCreateForce"
| SizeBytes := Size
| groupBy(TargetFileName, function=[
    count(as=TotalFiles),
    count(aid, distinct=true, as=ImpactedHosts),
    min(@timestamp, as=FirstSeenEpoch),
    max(@timestamp, as=LastSeenEpoch),
    avg(SizeBytes, as=AvgSize),
    max(SizeBytes, as=MaxSize),
    sum(SizeBytes, as=TotalBytesWritten),
    collect([ComputerName, UserName], limit=20)
  ])
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeenEpoch, timezone="Asia/Kolkata")
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeenEpoch, timezone="Asia/Kolkata")
| drop([FirstSeenEpoch, LastSeenEpoch])
| sort(TotalBytesWritten, order=desc)
| head(15)
```

* **Key Parameters**:
  - `function=[...]`: Executes all statistical metrics simultaneously in memory over grouped buckets.
  - `count(aid, distinct=true)`: Measures true entity cardinality (distinct endpoints) rather than raw event volume.
  - `min(@timestamp)` & `max(@timestamp)`: Anchors incident start and finish timestamps for dwell time calculation.
  - `collect([fields], limit=N)`: Retains discrete samples without exploding row cardinality.
* **Best Widget**: Comprehensive Summary Table

---

### 3.2 2D Matrix Heatmaps (Day of Week vs. Hour of Day)
Expose abnormal activity occurring during weekends or outside regular working hours.

```cql
#event_simpleName="UserLogon"
| DayOfWeek := formatTime("%A", field=@timestamp)
| HourOfDay := formatTime("%H", field=@timestamp)
| groupBy([DayOfWeek, HourOfDay], function=count(as=Logons))
```

* **Best Widget**: Heatmap Matrix
* **Axes**: X-Axis = `HourOfDay` (00–23), Y-Axis = `DayOfWeek` (Monday–Sunday), Value = `Logons`.

```
Day / Hour    00 02 04 06 08 10 12 14 16 18 20 22
Monday        ░░ ░░ ░░ ▒▒ ██ ██ ██ ██ ██ ▒▒ ░░ ░░
Tuesday       ░░ ░░ ░░ ▒▒ ██ ██ ██ ██ ██ ▒▒ ░░ ░░
Wednesday     ░░ ░░ ░░ ▒▒ ██ ██ ██ ██ ██ ▒▒ ░░ ░░
Thursday      ░░ ░░ ░░ ▒▒ ██ ██ ██ ██ ██ ▒▒ ░░ ░░
Friday        ░░ ░░ ░░ ▒▒ ██ ██ ██ ██ ██ ▒▒ ░░ ░░
Saturday      ░░ ░░ ░░ ░░ ░░ ░░ ▒▒ ░░ ░░ ░░ ░░ ░░
Sunday        ░░ ░░ ░░ ░░ ░░ ░░ ░░ ░░ ░░ ░░ ░░ ░░
```

---

### 3.3 Geographic World Map Visualization (`ipLocation()`)
Geolocate outbound network traffic and map threat actors geographically.

```cql
#event_simpleName="NetworkConnectIP4"
| !test(RemoteAddressIP4=/^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)/)
| ipLocation(RemoteAddressIP4)
| groupBy([country, lat, lon], function=count(as=InboundOutboundCount))
```

* **Best Widget**: World Map / Geographic Map
* **Configuration**: Set Latitude to `lat`, Longitude to `lon`, and Magnitude to `InboundOutboundCount`.

---

### 3.4 Stacked Multi-Series Timecharts
Compare trends across multiple categories over time on a single axis.

```cql
#event_simpleName="ProcessRollup2"
| timechart(
    field=FileName, 
    limit=5, 
    span=1h, 
    function=count()
  )
```

* **Best Widget**: Stacked Bar Chart or Stacked Area Chart
* **Behavior**: Automatically picks the Top 5 most active binaries and aggregates the rest into an `other` bucket.

---

### 3.5 Human-Readable Time Formatting (`formatTime()`)
Convert raw epoch or ISO timestamps into localized SOC shift formats.

```cql
#event_simpleName="UserLogon"
| ShiftTime := formatTime("%Y-%m-%d %H:%M:%S UTC", field=@timestamp)
| table([ShiftTime, ComputerName, UserName, LogonType])
| head(50)
```

| ShiftTime | ComputerName | UserName | LogonType |
| :--- | :--- | :--- | :--- |
| `2026-09-23 13:45:12 UTC` | `MACN-BHBHA-SB` | `bhupender` | `2` |

---

### 3.6 Dynamic Byte/Size Unit Conversion for Charts
Convert raw bytes into KB, MB, and GB to create clean, readable charts.

```cql
#event_simpleName="FileCreateForce"
| SizeMB := Size / (1024 * 1024) | round(SizeMB)
| groupBy(TargetFileName, function=sum(SizeMB, as=TotalMB))
| sort(TotalMB, order=desc)
| head(10)
```

* **Best Widget**: Bar Chart

---

## 5. Tier 4: Advanced — Statistical Outliers, Ratios, Sankey & Correlated Dashboards

### 4.1 Statistical Outlier Detection with Percentiles (`percentile()`, `stdDev()`)
Identify commands that deviate significantly from standard length or frequency distributions (3-Sigma / Standard Deviation analysis).

```cql
#event_simpleName="ProcessRollup2"
| CmdLength := length(CommandLine)
| groupBy(FileName, function=[
    avg(CmdLength, as=MeanLen), 
    stdDev(CmdLength, as=StdDevLen), 
    percentile(CmdLength, percentiles=[50, 95, 99], as=Pct)
  ])
| Threshold := MeanLen + (StdDevLen * 3)
| CmdLength > Threshold
| table([@timestamp, ComputerName, UserName, FileName, CmdLength, Threshold, CommandLine])
```

* **Best Widget**: Scatter Plot / Outlier Bubble Table
* **Threat Hunting Rationale**: Flags commands whose argument length is 3 standard deviations above the baseline for that specific binary (e.g., heavily obfuscated scripts or base64 injected commands).

---

### 4.2 Authentication Success vs. Failure Ratio (Gauge / Dual-Line)
Calculate authentication failure percentages in real time to spot brute-force and credential stuffing attacks.

```cql
(#event_simpleName="UserLogon" OR #event_simpleName="UserLogonFailed2")
| bucket(span=15m)
| case {
    #event_simpleName="UserLogon"        | SuccessCount := 1, FailureCount := 0 ;
    #event_simpleName="UserLogonFailed2" | SuccessCount := 0, FailureCount := 1 ;
    *                                   | SuccessCount := 0, FailureCount := 0 ;
  }
| groupBy(_bucket, function=[
    sum(SuccessCount, as=TotalSuccess), 
    sum(FailureCount, as=TotalFailed)
  ])
| FailureRatePct := (TotalFailed / (TotalSuccess + TotalFailed)) * 100
| round(FailureRatePct)
| table([_bucket, TotalSuccess, TotalFailed, FailureRatePct])
```

* **Best Widget**: Dual-Axis Line Chart + Gauge Widget (for average failure rate)
* **Visual Output**: Left Axis = Raw event counts, Right Axis = Failure Percentage line.

---

### 4.3 Sankey Flow Preparation: Process Execution Hierarchy
Prepare hierarchical data structures to render multi-tier process execution trees in a Sankey diagram widget.

```cql
#event_simpleName="ProcessRollup2"
| GrandParentBaseFileName=* AND ParentBaseFileName=* AND FileName=*
| Source := ParentBaseFileName
| Target := FileName
| groupBy([Source, Target], function=count(as=Weight))
| sort(Weight, order=desc)
| head(25)
| table([Source, Target, Weight])
```

* **Best Widget**: Sankey Diagram
* **Visual Rendering**:

```
[ explorer.exe ] ──( 4,120 )──► [ cmd.exe ] ──( 3,850 )──► [ powershell.exe ]
                                         └──(   270 )──► [ whoami.exe ]
[ winword.exe  ] ──(    14 )──► [ powershell.exe ] ──► [ certutil.exe ]
```

---

### 4.4 Sliding Window Aggregation & Burst Detection
Detect short-lived, high-frequency bursts that bypass standard hourly thresholds (e.g., port scans, rapid password spraying).

```cql
#event_simpleName="UserLogonFailed2"
| bucket(span=1m)
| groupBy([ComputerName, UserName, _bucket], function=count(as=FailureCount))
| FailureCount > 10
| AlertTime := formatTime("%H:%M:%S", field=_bucket)
| table([AlertTime, ComputerName, UserName, FailureCount])
| sort(FailureCount, order=desc)
```

* **Best Widget**: Alert Counter & High-Priority Notification List

---

### 4.5 Master SOC Threat Hunting Visual Dashboard Query
A composite dashboard query providing an end-to-end incident summary in a single analytical stage.

```cql
#event_module="sensor" (#event_simpleName="ProcessRollup2" OR #event_simpleName="NetworkConnectIP4" OR #event_simpleName="UserLogonFailed2")
| case {
    #event_simpleName="ProcessRollup2" | EventType := "Process Execution" ;
    #event_simpleName="NetworkConnectIP4" | EventType := "Network Socket" ;
    #event_simpleName="UserLogonFailed2" | EventType := "Auth Failure" ;
    *                    | EventType := "Other" ;
  }
| timechart(field=EventType, span=1h, function=count())
```

* **Best Widget**: Stacked Area Chart (24-Hour SOC Overview)
* **Dashboard Positioning**: Top row banner widget showing aggregate activity split by critical event vectors.

---

## 6. Quick Syntax Cheatsheet for Visual Commands

| Visual Operation | CQL Function Syntax | Notes |
| :--- | :--- | :--- |
| **Select Columns** | `\| table([Field1, Field2 as Alias])` | Limits memory and organizes table view |
| **Drop Columns** | `\| drop([@rawstring, @id])` | Removes heavy unparsed fields |
| **Sort Descending** | `\| sort(FieldName, order=desc)` | Highest numbers or newest events first |
| **Sort Ascending** | `\| sort(FieldName, order=asc)` | Lowest numbers or oldest events first |
| **Compound Sort** | `\| sort([Field1, Field2], order=[asc, desc])` | Multi-key ordering |
| **Limit Rows** | `\| head(50)` / `\| tail(20)` | Limits output payload |
| **Deduplicate** | `\| selectDistinct([Field1, Field2])` | Removes exact duplicate tuples |
| **Time Bucketing** | `\| bucket(span=10m)` | Groups rows into time slices (`_bucket`) |
| **Continuous Timechart** | `\| timechart(field=Category, span=1h)` | Automatic time-series line/area plots |
| **Basic Count** | `\| groupBy(Field, function=count())` | Counts events per key |
| **Multi-Metric Group** | `\| groupBy(Field, function=[count(), avg(X), max(Y)])` | Computes multiple statistics simultaneously |
| **Percentiles** | `\| stats(percentile(X, percentiles=[50,90,99]))` | Statistical anomaly baselining |
| **Time Formatting** | `\| Formatted := formatTime("%Y-%m-%d %H:%M", field=@timestamp)` | Localized human-readable timestamps |
| **Ternary Mapping** | `\| Status := test(Metric > 100) ? "ALERT" : "OK"` | Inline conditional tagging |

---
*Created as part of the CrowdStrike Falcon Advanced Event Search & Detection Engineering series.*


---

## 11. Visualizing Unified Investigation Dossiers & Lateral Flows

When conducting triage using the three consolidated investigation dossiers (**Track Machine Activity**, **Track User Activity**, and **Track Communication**), visualizing the results helps analysts immediately pinpoint anomalous spikes, unusual login hours, or lateral pivot points.

### 11.1 Machine Activity Distribution (Sankey / Category Breakdown)
Group events on a investigated machine by activity category over time to spot execution bursts or abnormal socket activity:

```cql
#repo="base_sensor" ComputerName=/^WORKSTATION-01$/i
| (
    #event_simpleName="ProcessRollup2"
    OR #event_simpleName="UserLogon"
    OR #event_simpleName="UserLogonFailed2"
    OR #event_simpleName="NetworkConnectIP4"
    OR #event_simpleName="DnsRequest"
    OR #event_simpleName="FileCreateForce"
  )
| case {
    #event_simpleName="ProcessRollup2"        | ActivityCategory := "Process Execution" ;
    #event_simpleName="UserLogon"             | ActivityCategory := "Logon Success" ;
    #event_simpleName="UserLogonFailed2"      | ActivityCategory := "Logon Failed" ;
    #event_simpleName="NetworkConnectIP4"     | ActivityCategory := "Network Outbound" ;
    #event_simpleName="DnsRequest"            | ActivityCategory := "DNS Query" ;
    #event_simpleName="FileCreateForce"       | ActivityCategory := "File Modification" ;
    *                                         | ActivityCategory := "Other" ;
  }
| timechart(field=ActivityCategory, span=1h, function=count())
```

### 11.2 User Multi-Host Activity Heatmap
Visualize which machines a user accesses and what operations are conducted per machine:

```cql
#repo="base_sensor" UserName=/^john\.doe$/i
| (
    #event_simpleName="UserLogon"
    OR #event_simpleName="ProcessRollup2"
    OR #event_simpleName="NetworkConnectIP4"
  )
| case {
    #event_simpleName="UserLogon"         | OpType := "Logons" ;
    #event_simpleName="ProcessRollup2"     | OpType := "Commands" ;
    #event_simpleName="NetworkConnectIP4" | OpType := "NetworkTraffic" ;
    *                                     | OpType := "Other" ;
  }
| groupBy([ComputerName, OpType], function=count(as=Volume))
| pivot(ComputerName, splitBy=OpType, value=Volume)
| sort(ComputerName, order=asc)
```

### 11.3 Communication Link Matrix (Source <-> Destination Traffic)
Summarize bidirectional port and protocol volume between two communicating endpoints:

```cql
#repo="base_sensor"
| (
    (#event_simpleName="NetworkConnectIP4" 
      AND (LocalAddressIP4="10.0.0.15" OR ComputerName=/^SRC-WORKSTATION$/i)
      AND RemoteAddressIP4="10.0.0.25")
    OR (#event_simpleName="NetworkReceiveAcceptIP4"
      AND (LocalAddressIP4="10.0.0.25" OR ComputerName=/^DEST-SERVER$/i)
      AND RemoteAddressIP4="10.0.0.15")
  )
| case {
    #event_simpleName="NetworkConnectIP4"     | FlowDirection := "Outbound (Source -> Dest)", TargetPort := RemotePort ;
    #event_simpleName="NetworkReceiveAcceptIP4"| FlowDirection := "Inbound (Dest <- Source)", TargetPort := LocalPort ;
    *                                         | FlowDirection := "Other", TargetPort := 0 ;
  }
| groupBy([FlowDirection, TargetPort], function=[count(as=FlowCount), collect(ContextImageFileName, limit=3, as=ActiveBinaries)])
| sort(FlowCount, order=desc)
| table([FlowDirection, TargetPort, FlowCount, ActiveBinaries])
```


---

## 12. Query Hub Visualizations: Correlating Process, DNS & Network Graphs

The **CrowdStrike Advanced Query Hub** commands introduce advanced correlation constructs (`selfJoinFilter`, `splitString`, `concatArray`, `base64Decode`, `join(mode=left)`, and `ipLocation`). You can visualize these correlated multi-event outputs using standard Falcon dashboard widgets:

- **Browser Process to DNS Resolution Graph (Playbooks 4 & 5)**:
  Using `selfJoinFilter(field=[aid, falconPID])`, feed the grouped `[aid, falconPID]` outputs directly into a directed Sankey diagram or multi-value table:
  ```cql
  | groupBy([fileName, DomainName], function=count(as=Resolutions))
  | sort(Resolutions, order=desc, limit=20)
  | table([fileName, DomainName, Resolutions])
  ```

- **GeoIP Authentication Spread & Ingress Density (Playbooks 2 & 8)**:
  Using `ipLocation(aip)`, pipe the resulting coordinates directly into the Map Widget or geographic heat table:
  ```cql
  | groupBy([aip.country, aip.city, aip.lat, aip.lon], function=count(as=LogonDensity))
  ```

- **Public DoH Resolver & Evasion Traffic Breakdown (Playbook 6)**:
  Visualize covert DNS-over-HTTPS resolution volume via a Donut or Bar Chart comparing client processes against DoH endpoints:
  ```cql
  | groupBy([DomainName, ContextBaseFileName], function=count(as=QueryVolume))
  | sort(QueryVolume, order=desc)
  ```

- **Enterprise Generative AI & LLM Consumption Trends (Playbooks 10 & 11)**:
  Track shadow AI adoption across the enterprise using a Top-10 Horizontal Bar Chart or Treemap grouped by AI service provider:
  ```cql
  | groupBy([DomainName], function=count(as=AiQueries))
  | sort(AiQueries, order=desc, limit=15)
  ```

- **PowerShell Obfuscation & Malicious Cradle Prevalence (Playbooks 9 & 12)**:
  Plot `uniqueEndpointCount` vs `executionCount` on a Scatter Plot to quickly isolate widespread administrative automation from targeted one-off encoded cradles:
  ```cql
  | table([executionCount, uniqueEndpointCount, DecodedString, CommandLine])
  | sort(executionCount, order=desc)
  ```

- **Account Brute-Force & Password Spray Sankey (Playbooks 14 & 29)**:
  Feed `TotalFailedLogins`, `UserName`, and `LastLoggedOnHost` into a Sankey flow diagram to visualize attacker credential spraying distribution and isolate verified breaches (`TotalSuccessfulLogins > 0`):
  ```cql
  | table([UserName, LastLoggedOnHost, TotalFailedLogins, TotalSuccessfulLogins])
  | sort(TotalSuccessfulLogins, order=desc)
  ```

- **Distributed Password Spray Host Spread (Playbooks 27 & 28)**:
  Display high-volume multi-endpoint spray attempts using a Bubble Chart plotting `uniqueEP` vs `uniqueFailedLogons` per `UserName`:
  ```cql
  | table([UserName, uniqueEP, uniqueFailedLogons])
  | sort(uniqueEP, order=desc)
  ```

- **Removable Media Data Transfer Volume (Playbook 15)**:
  Track total megabytes written to external USB drives across endpoints using a Top-10 Bar Chart:
  ```cql
  | groupBy([ComputerName], function=sum(FileSizeMB, as=TotalMB))
  | sort(TotalMB, order=desc, limit=10)
  ```

- **Public Inbound RDP Accept Distribution (Playbook 17)**:
  Visualize external brute-force source IP addresses targeting port 3389 using an Area Chart or World Heatmap:
  ```cql
  | groupBy([RemoteAddressIP4], function=count(as=ConnectionAttempts))
  | sort(ConnectionAttempts, order=desc, limit=20)
  ```

- **Installed Browser Extension Prevalence (Playbook 18)**:
  Identify anomalous or rare browser extensions by plotting endpoint install counts in a Pareto Chart:
  ```cql
  | table([BrowserExtensionName, TotalEndpoints, BrowserName, "Chrome Store Link"])
  | sort(TotalEndpoints, order=asc, limit=50)
  ```

- **Exchange Online BEC Inbox Rule Risk Distribution (Playbook 19)**:
  Plot rule risk classifications in a Stacked Bar or Donut Chart to isolate high-risk external mail forwarding and silent deletion rules:
  ```cql
  | groupBy([RiskLevel], function=count(as=RuleCount))
  | sort(RuleCount, order=desc)
  ```

- **Active Directory Audit Event Breakdown (Playbook 21)**:
  Track account lifecycle anomalies, lockout frequency, and password resets over time using a Time-Chart Area graph:
  ```cql
  | timeChart(span=1h, function=count(), by=ActiveDirectoryAuditActionType)
  ```

- **Real Time Response (RTR) Session Activity Timeline (Playbooks 22, 24, 25 & 26)**:
  Plot responder RTR session starts across endpoints over time to audit incident response access:
  ```cql
  | timeChart(span=1d, function=count(), by=UserName)
  ```

- **Operating System Platform Distribution (Playbook 23)**:
  Render a Donut or Pie Chart displaying endpoint platform share across Windows, Mac, and Linux:
  ```cql
  #event_simpleName = SensorHeartbeat
  | groupBy(aid, event_platform)
  | groupBy([event_platform])
  ```

- **High-Velocity SMB File Copy Bursts (Playbook 30)**:
  Monitor rapid lateral file movement bursts via a Bar Chart plotting `file_copies` and `time_diff_min` grouped by `user.name`:
  ```cql
  | table([user.name, source.address, file_copies, time_diff_min, start_time_fmt, end_time_fmt])
  | sort(file_copies, order=desc)
  ```

- **360 Destination IP & Geolocation Heatmap (Playbook 31)**:
  Pipe remote IP connections with GeoIP coordinates into a World Map Widget or Geographic Density Table:
  ```cql
  | groupBy([RemoteAddressIP4.country, RemoteAddressIP4.city, RemoteAddressIP4.org, RemoteAddressIP4], function=count(as=Connections))
  | sort(Connections, order=desc)
  ```

- **360 Destination Domain Request Frequency (Playbook 32)**:
  Plot DNS lookups per domain and requesting binary across endpoints using a Multi-Metric Bar Chart:
  ```cql
  | groupBy([DomainName, ContextBaseFileName], function=count(as=QueryCount))
  | sort(QueryCount, order=desc, limit=25)
  ```

- **Master 360 Domain / IP / URI Flow Sankey (Playbook 33)**:
  Visualize process-to-domain-to-IP egress flows using a multi-stage Sankey Diagram linking initiating binary, resolved domain, and destination IP:
  ```cql
  | groupBy([ContextBaseFileName, DomainName, RemoteAddressIP4], function=count(as=FlowVolume))
  | sort(FlowVolume, order=desc, limit=30)
  ```

- **Top 25 Offensive Hacking Tools Breakdown Matrix (Playbook 34)**:
  Track adversary tool usage and targeted systems via a Treemap or Stacked Bar Chart categorized by `DetectedTool` and `TargetDestination`:
  ```cql
  | groupBy([DetectedTool, TargetDestination], function=count(as=ExecutionVolume))
  | sort(ExecutionVolume, order=desc, limit=25)
  ```

