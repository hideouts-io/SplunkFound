# SplunkFound

### macOS forensic research into unexplained Splunk deployment, logging, and encryption artifacts

![Platform](https://img.shields.io/badge/platform-macOS-000000?logo=apple&logoColor=white)
![Research](https://img.shields.io/badge/type-security%20research-8250df)
![Analysis](https://img.shields.io/badge/analysis-digital%20forensics-0969da)
![Status](https://img.shields.io/badge/status-investigation-f0ad4e)

> **Scope:** SplunkFound documents Splunk-related artifacts discovered on a macOS computer that may indicate previous or current participation in a Splunk deployment, logging, forwarding, monitoring, or management environment. The repository distinguishes **observed evidence** from **interpretation**. The artifacts are unusual and worth investigating, but their presence alone does not prove that the computer was actively monitored, remotely controlled, or compromised.

---

## Table of Contents

- [Overview](#overview)
- [Executive Summary](#executive-summary)
- [Why This Repository Exists](#why-this-repository-exists)
- [Observed Evidence](#observed-evidence)
- [iOS Evidence: T-Mobile Digits and Splunk MINT](#ios-evidence-t-mobile-digits-and-splunk-mint)
- [Evidence vs. Interpretation](#evidence-vs-interpretation)
- [What Splunk Could Be Used For](#what-splunk-could-be-used-for)
- [Deployment Infrastructure](#deployment-infrastructure)
- [Encryption Material](#encryption-material)
- [Possible Architectures](#possible-architectures)
- [Investigation Questions](#investigation-questions)
- [macOS Investigation Workflow](#macos-investigation-workflow)
- [Processes and Services](#processes-and-services)
- [Files and Configuration](#files-and-configuration)
- [Network Evidence](#network-evidence)
- [Unified Logging](#unified-logging)
- [Evidence Handling](#evidence-handling)
- [Interpretation Boundaries](#interpretation-boundaries)
- [Responsible Research](#responsible-research)
- [Repository Structure](#repository-structure)
- [Conclusion](#conclusion)

---

## Overview

**SplunkFound** is a forensic research repository documenting unexpected Splunk-related material discovered on a macOS computer.

The original artifact contains two notable fields:

```text
Deploy
<64-character hexadecimal value>

Enc
<Base64-encoded-looking value>
```

The original values are intentionally not reproduced in this README or the public evidence file. Instead, the public repository retains SHA-256 fingerprints of the exact stored values so they can be compared with privately preserved evidence without exposing the originals.

The labels justify additional investigation because Splunk products can be used for:

- centralized log collection;
- endpoint telemetry;
- system and application monitoring;
- security analytics;
- event forwarding;
- infrastructure monitoring;
- configuration deployment;
- management of Splunk forwarders;
- alerting;
- incident investigation;
- SIEM workflows;
- operational intelligence.

However:

> **Finding a Splunk-related artifact is not the same thing as proving active surveillance.**

The purpose of this repository is to determine what the artifacts actually represent.

---

## Executive Summary

A macOS system under investigation contained an artifact identifying itself with Splunk-related terminology and containing:

- a value labeled **`Deploy`**;
- a 64-character hexadecimal value associated with that label;
- a value labeled **`Enc`**;
- Base64-encoded-looking data associated with `Enc`.

The original values have been removed from the public evidence file and replaced with SHA-256 fingerprints.

These artifacts raise several possibilities.

### Plausible explanations

1. **Splunk Universal Forwarder configuration**
2. **Splunk Enterprise client configuration**
3. **Deployment-server enrollment material**
4. **Locally stored application configuration**
5. **Configuration-management remnants**
6. **Authentication or encrypted configuration material**
7. **An artifact left behind by previously installed software**
8. **A third-party product using Splunk as a backend**
9. **A security or IT-management product forwarding telemetry to Splunk**
10. **Unrelated data whose labels merely resemble Splunk terminology**

At this stage, the repository does **not** claim that any single explanation has been proven.

---

## Why This Repository Exists

The initial question was simple:

> **Why does this Mac contain Splunk-related deployment and encryption material?**

That question expands into several forensic questions:

```text
Was Splunk installed?
        |
        v
Was a Splunk forwarder installed?
        |
        v
Was the Mac configured as a deployment client?
        |
        v
Was data being forwarded?
        |
        v
Where was it forwarded?
        |
        v
What data sources were configured?
        |
        v
Who or what installed the configuration?
```

SplunkFound attempts to answer those questions using reproducible evidence instead of assumptions.

---

## Observed Evidence

### Artifact 1 — Deploy

An observed value is labeled:

```text
Deploy
```

followed by a hexadecimal string.

The public evidence file preserves the following fingerprint of the exact original stored value:

```text
SHA-256: c633a6d32492c9b5e0d5017d7f80eea3c99cb3e6f6cfe9dfd346f4da7f8b993b
```

Its original format was a 64-character hexadecimal string. That format is consistent with many possible identifiers or cryptographic values, including:

- hashes;
- fingerprints;
- identifiers;
- derived values;
- deployment-related identifiers;
- integrity values;
- authentication-related material.

**The format alone is insufficient to identify its purpose.**

### Artifact 2 — Enc

A second observed value is labeled:

```text
Enc
```

and appears to be Base64-encoded binary data.

The public evidence file preserves the following fingerprint of the exact original stored value:

```text
SHA-256: 502556a21f087acff65d77143db43e23f06ae5bee358009c58a0f3d0d86324b2
```

The original stored representation was 44 characters long and Base64-looking.

The label may suggest:

```text
Enc -> encryption
Enc -> encrypted
Enc -> encoded
Enc -> encryption material
Enc -> application-specific configuration
```

but this remains an interpretation until the generating software and configuration format are identified.

---

## iOS Evidence: T-Mobile Digits and Splunk MINT

This repository also preserves a separate, redacted iOS application diagnostic finding. It is distinct from the macOS `Deploy` and `Enc` artifact: it identifies the application-side telemetry component and its configured collector, but it does not identify the meaning or origin of the `Deploy` or `Enc` values.

### Preserved evidence

The private source was a 90,861-byte `NotificationLog.txt` diagnostic log (SHA-256 `9fcb2a2d9f1682af75665b1a26aab17cf4e392ac975087c27e900ca072dcb3c5`). The public repository contains only a [redacted extract](iOS/NotificationLog.redacted.txt).

The log identifies `UccViperProto` and `NotificaitonExtension`, records a T-Mobile Digits 2.0 user agent, and repeatedly names `SplunkManager.swift`. It shows `setupMint()` configuring a URL of the form:

```text
https://splk-hec.t-mobile.com:8088/services/collector/mint
```

The token is redacted. The original also contained private message content, phone numbers, personal names, device and app-group identifiers, account/session values, client identifiers, and authenticated request data; none of those are published.

The log further records `logPNSinSplunk()` constructing notification-event data and `processPendingLogs() > processPendingLogs 0`. This establishes that the application initialized a Mint/HEC telemetry path and invoked code intended to build notification telemetry. It does **not** record an HTTP POST to that collector, an HEC response, indexer acknowledgement, packet capture, or a server-side event receipt. The retained `0` count is not proof that no upload ever occurred; it only records the observed pending-log state at those moments.

### What Splunk MINT means here

Splunk MINT was Splunk's mobile-app monitoring product and SDK family. Its historical documentation describes mobile-app projects, app keys, and iOS SDK support, and states that the commercial MINT products reached end of life in 2021. The 2022 diagnostic should therefore be read as evidence that this application retained or used a **Mint-formatted telemetry integration**, not as evidence that a current MINT commercial service was necessarily active. [Splunk MINT Add-on documentation](https://docs.splunk.com/Documentation/MintAddon/3.0.1/UserGuide/AbouttheSplunkMINTAddon)

The endpoint in the log is especially specific: current Splunk documentation defines `services/collector/mint` as an HTTP Event Collector (HEC) endpoint for posting Mint-formatted data. HEC uses a token-based model and normally uses HTTPS port 8088. This aligns with the observed URL and the redacted `QOE token`; it does not identify the token's authorization scope, prove that the endpoint accepted data, or establish the operator of the destination beyond the hostname's `t-mobile.com` suffix. [HEC endpoint reference](https://help.splunk.com/en/splunk-cloud-platform/get-data-in/get-started-with-getting-data-in/10.3.2512/get-data-with-http-event-collector/http-event-collector-rest-api-endpoints)

In practical terms, the log supports the following bounded interpretation:

```text
T-Mobile Digits notification extension
        |
        +-- SplunkManager.swift / setupMint()
        |
        +-- configured Mint-formatted HEC collector
        |
        +-- builds notification-event telemetry
        |
        +-- successful transmission: not demonstrated by this log
```

`SplunkManager.swift` is an application source-file label, not evidence of an Apple iOS system daemon, an installed Splunk Universal Forwarder, device management, remote control, or compromise. The evidence is consistent with carrier application telemetry/quality-of-experience instrumentation.

### Security and publication boundary

An HEC token is a credential-like value. Publishing the raw log would unnecessarily expose it and unrelated private communications and session material. The source is retained privately by its custodian; the public extract preserves only the minimum context needed to reproduce the analysis. An authorized administrator for the endpoint should treat the disclosed historical token as potentially exposed and rotate or disable it if it remains usable.

---

## Evidence vs. Interpretation

A major goal of this project is avoiding the mistake of turning an interesting artifact into a conclusion.

| Classification | Finding |
|---|---|
| **Observed** | A file associated with Splunk terminology was discovered on macOS. |
| **Observed** | The artifact contains a `Deploy` field. |
| **Observed** | `Deploy` was followed by a hexadecimal value. |
| **Observed** | The artifact contains an `Enc` field. |
| **Observed** | `Enc` was followed by Base64-looking data. |
| **Observed** | The original values are now represented publicly only by SHA-256 fingerprints. |
| **Observed** | A redacted iOS application log names `SplunkManager.swift`, `setupMint()`, and a Mint-formatted HEC collector URL. |
| **Observed** | The iOS log records notification-event construction but no HEC request result or server receipt. |
| **Documented Splunk capability** | Splunk supports centralized deployment and management of deployment clients. |
| **Documented Splunk capability** | HEC accepts Mint-formatted data at `services/collector/mint`. |
| **Documented Splunk capability** | Splunk can collect and forward machine-generated data. |
| **Documented Splunk capability** | Splunk uses cryptographic material to protect some stored credentials and configuration secrets. |
| **Plausible** | The Mac may previously have participated in a Splunk-managed environment. |
| **Plausible** | Splunk software or another product may have collected logs from the system. |
| **Unverified** | The discovered `Deploy` value is specifically a Splunk deployment credential. |
| **Unverified** | The discovered `Enc` value is specifically a Splunk encryption key. |
| **Unverified** | Splunk was actively monitoring the computer when the artifact was discovered. |
| **Unverified** | The iOS application successfully uploaded the observed notification data to the collector. |
| **Unverified** | The artifacts indicate malicious surveillance or compromise. |

This distinction is critical.

---

## What Splunk Could Be Used For

Splunk is much broader than simply reading logs.

A Splunk environment can potentially include:

```text
                    macOS Endpoint
                          |
                 +--------+--------+
                 |                 |
                 v                 v
            System Logs       Application Logs
                 |                 |
                 +--------+--------+
                          |
                          v
                  Splunk Forwarder
                          |
                          v
                Network / TLS Transport
                          |
          +---------------+---------------+
          |                               |
          v                               v
       Indexer                       Splunk Cloud
          |
          v
      Search Head
          |
    +-----+------+-------+
    |            |       |
    v            v       v
Searches       Alerts   Dashboards
    |
    v
Security / Operations Analysis
```

Depending on configuration, Splunk can be used for:

- macOS logs;
- application logs;
- authentication events;
- process events;
- network-related events;
- security-tool telemetry;
- audit events;
- application metrics;
- cloud telemetry;
- infrastructure monitoring.

The important question is therefore not simply:

> "Was Splunk present?"

but:

> **"What inputs, forwarders, applications, and destinations were configured?"**

---

## Deployment Infrastructure

Splunk supports centralized deployment management.

A simplified architecture may look like:

```text
                         Deployment Server
                                |
                       configuration / apps
                                |
              +-----------------+-----------------+
              |                 |                 |
              v                 v                 v
         Mac Client         Linux Client      Windows Client
              |                 |                 |
              v                 v                 v
          Forwarder         Forwarder         Forwarder
              |                 |                 |
              +-----------------+-----------------+
                                |
                                v
                             Indexer
```

A machine enrolled as a deployment client can receive centrally managed Splunk configuration.

This is one reason the label:

```text
Deploy
```

is especially interesting.

It does **not**, by itself, prove enrollment.

It does provide a useful investigative lead.

---

## Encryption Material

Splunk Enterprise uses encryption mechanisms to protect some authentication material stored inside configuration files.

One particularly important component in Splunk installations is commonly referred to as:

```text
splunk.secret
```

That key can participate in protecting various configuration secrets.

Examples can include credentials associated with:

- TLS;
- LDAP;
- data forwarding;
- application credentials;
- communication between Splunk components.

The `Enc` value discovered in this repository has **not yet been proven to be `splunk.secret` or material derived from it**.

That distinction should remain explicit.

### Security Note

Cryptographic values should be treated as potentially sensitive until proven otherwise.

Do not publish an active:

- `splunk.secret`;
- authentication token;
- API token;
- deployment credential;
- private key;
- password;
- session token;
- shared secret.

For public research, use a SHA-256 fingerprint or `REDACTED` rather than the original value whenever possible.

---

## Possible Architectures

### Scenario A — Universal Forwarder

```text
Mac
 |
 v
Splunk Universal Forwarder
 |
 | selected logs / events
 v
Splunk Indexer
```

This would be consistent with centralized log forwarding.

### Scenario B — Managed Forwarder

```text
                Splunk Deployment Server
                         |
                         | apps/configuration
                         v
                       Mac
                         |
                  Universal Forwarder
                         |
                         v
                       Indexer
```

This could explain both deployment-related and encrypted configuration artifacts.

### Scenario C — Third-Party Security Product

Another possibility is:

```text
Mac
 |
 v
EDR / IT / Security Agent
 |
 v
Vendor Backend
 |
 v
Splunk
```

In that situation, Splunk may never have been directly administered on the Mac.

A third-party application could instead have used Splunk somewhere farther downstream.

### Scenario D — Historical Artifact

The files may simply be remnants of an older installation:

```text
Past Splunk Installation
          |
        Removed
          |
          v
Residual configuration remains
```

Residual artifacts are common in forensic analysis.

A file's existence does not necessarily establish current execution.

---

## Investigation Questions

The main questions SplunkFound seeks to answer are:

- Was Splunk software installed on the Mac?
- Is Splunk currently installed?
- Was Splunk previously installed?
- Was the Universal Forwarder present?
- Was `splunkd` ever executed?
- Are Splunk LaunchDaemons present?
- Are Splunk package receipts present?
- Does `/Applications/Splunk*` exist?
- Does `/opt/splunk` exist?
- Does `/opt/splunkforwarder` exist?
- Are Splunk configuration files present?
- Is `deploymentclient.conf` present?
- Is `outputs.conf` present?
- Is `inputs.conf` present?
- Is `server.conf` present?
- Is `splunk.secret` present?
- Are remote indexers configured?
- Is a deployment server configured?
- What sources were configured for collection?
- When were the files created?
- When were they modified?
- What process created them?
- Were they associated with an MDM or enterprise-management system?
- Are there network connections to Splunk infrastructure?
- Are related entries present in macOS Unified Logging?

---

## macOS Investigation Workflow

The following commands are intended for analysis of a system you own or are authorized to examine.

### Check running processes

```bash
ps aux | grep -i '[s]plunk'
```

Also inspect:

```bash
pgrep -alf splunk
```

Possible process names may include:

```text
splunkd
splunk
```

---

## Processes and Services

Check macOS launch services:

```bash
sudo launchctl print system | grep -i splunk
```

Inspect common service directories:

```bash
sudo find /Library/LaunchDaemons \
  /Library/LaunchAgents \
  ~/Library/LaunchAgents \
  -iname '*splunk*' \
  -print 2>/dev/null
```

Check loaded processes:

```bash
ps -axo pid,ppid,user,start,time,command | grep -i '[s]plunk'
```

---

## Files and Configuration

Check common Splunk installation locations:

```bash
sudo find \
  /Applications \
  /Library \
  /opt \
  /usr/local \
  -iname '*splunk*' \
  -print 2>/dev/null
```

Common locations worth examining include:

```text
/Applications/Splunk
/opt/splunk
/opt/splunkforwarder
```

Search specifically for configuration files:

```bash
sudo find /opt /Applications /Library \
  \( \
    -name deploymentclient.conf -o \
    -name outputs.conf -o \
    -name inputs.conf -o \
    -name server.conf -o \
    -name authentication.conf -o \
    -name splunk.secret \
  \) \
  -print 2>/dev/null
```

The configuration context can be much more informative than an isolated identifier.

For example:

```text
deploymentclient.conf
        |
        +--> possible deployment server

outputs.conf
        |
        +--> possible forwarding destination

inputs.conf
        |
        +--> possible collected data

server.conf
        |
        +--> server/security configuration
```

### Package Installation Evidence

Check package receipts:

```bash
pkgutil --pkgs | grep -i splunk
```

Search installation history:

```bash
grep -i splunk /var/log/install.log 2>/dev/null
```

On modern macOS, Unified Logging may provide additional evidence.

---

## Network Evidence

If Splunk is currently running, inspect its connections:

```bash
sudo lsof -nP -i | grep -i splunk
```

Inspect the process first:

```bash
ps aux | grep -i '[s]plunk'
```

Then examine a confirmed PID:

```bash
sudo lsof -nP -p <PID>
```

The objective is to identify:

```text
process
   |
   v
destination
   |
   v
port
   |
   v
hostname
   |
   v
certificate / network context
```

A remote connection alone is not proof of logging.

It must be correlated with:

- the process;
- configuration;
- timestamps;
- DNS;
- executable provenance;
- destination ownership.

---

## Unified Logging

Search macOS Unified Logging:

```bash
log show \
  --style compact \
  --last 30d \
  --predicate 'eventMessage CONTAINS[c] "splunk"'
```

Search process names:

```bash
log show \
  --style compact \
  --last 30d \
  --predicate 'process CONTAINS[c] "splunk"'
```

For a larger historical investigation:

```bash
log show \
  --style syslog \
  --info \
  --debug \
  --predicate 'eventMessage CONTAINS[c] "splunk"'
```

Results should be preserved with timestamps.

---

## Evidence Handling

For a suspicious artifact:

```bash
stat -x <file>
```

Extended attributes:

```bash
xattr -l <file>
```

Access control information:

```bash
ls -leO@ <file>
```

Cryptographic fingerprint:

```bash
shasum -a 256 <file>
```

File type:

```bash
file <file>
```

These can help establish provenance without modifying the evidence.

### Timeline Analysis

An ideal investigation builds a timeline:

```text
Installation
     |
     v
Configuration created
     |
     v
Deploy artifact created
     |
     v
Enc artifact created
     |
     v
Splunk process execution
     |
     v
Network connection
     |
     v
Log forwarding
```

If these events correlate closely, confidence increases.

If they do not, alternative explanations become more likely.

### Evidence Record

For every artifact, ideally record:

```text
Path:
File size:
Owner:
Group:
Permissions:
Creation time:
Modification time:
Extended attributes:
SHA-256:
Associated process:
Associated package:
Associated network activity:
Source device:
Collection date:
```

A useful evidence record might look like:

```text
Artifact
   |
   +-- Original file
   |
   +-- SHA-256
   |
   +-- Metadata
   |
   +-- Screenshot
   |
   +-- Relevant logs
   |
   +-- Interpretation notes
```

Preserve the original whenever possible.

Perform analysis on a copy.

---

## Interpretation Boundaries

SplunkFound deliberately separates facts from hypotheses.

### Finding Splunk files does NOT automatically prove:

- unauthorized monitoring;
- malware;
- compromise;
- employee surveillance;
- remote control;
- data exfiltration;
- continuous log collection;
- malicious administration.

Likewise, the absence of an active Splunk process does not prove that Splunk was never installed.

Historical investigation requires multiple independent sources of evidence.

### Confidence Model

Findings should be classified using explicit confidence levels.

#### Confirmed

Directly demonstrated by evidence.

Example:

```text
A file named deploymentclient.conf exists.
```

#### Documented Capability

Something Splunk officially supports.

Example:

```text
Splunk deployment servers can distribute applications
and configuration to deployment clients.
```

#### Technically Plausible

Consistent with known behavior but not yet demonstrated.

Example:

```text
This Mac may have been a managed Splunk deployment client.
```

#### Speculative

A possibility without enough supporting evidence.

Example:

```text
The artifact might be associated with historical monitoring.
```

#### Unsupported

No evidence currently supports the claim.

Example:

```text
The computer was definitely being secretly monitored.
```

This model prevents an interesting artifact from becoming an unsupported conclusion.

---

## What Would Strengthen the Case?

Evidence of the following would materially strengthen attribution:

```text
splunkd executable
       +
deploymentclient.conf
       +
outputs.conf
       +
inputs.conf
       +
Splunk LaunchDaemon
       +
package receipt
       +
Unified Log execution events
       +
network connections to configured destinations
```

If several independent artifacts converge on the same timeline and configuration, the probability of an actual Splunk deployment rises substantially.

### What Would We Want to Find Next?

Priority evidence:

1. `deploymentclient.conf`
2. `outputs.conf`
3. `inputs.conf`
4. `server.conf`
5. `splunk.secret`
6. Splunk package receipts
7. LaunchDaemon configuration
8. `splunkd` execution history
9. Unified Logging references
10. outbound Splunk-related network activity
11. installation timestamps
12. code-signing information
13. configuration provenance
14. MDM profiles
15. third-party agents configured to forward to Splunk

The most important question is attribution.

```text
WHO / WHAT CREATED THE ARTIFACT?
```

---

## Security and Key Handling

Any value suspected of being cryptographic material should be considered sensitive.

Public repositories should avoid publishing usable secrets.

Instead, preserve:

```text
SHA-256(original_secret)
```

and document:

```text
Original value: REDACTED
Length: <length>
Encoding: suspected Base64 / hex / binary
Source path: <path>
SHA-256: <fingerprint>
```

This provides reproducible evidence without unnecessarily exposing credentials.

If a discovered value belongs to an active environment, it should be treated as potentially compromised and rotated by the authorized administrator.

---

## Responsible Research

SplunkFound is intended for:

- defensive security research;
- digital forensics;
- incident response;
- system administration;
- software provenance research;
- authorized endpoint investigation.

The project is **not** intended to obtain unauthorized access to Splunk infrastructure or recover credentials belonging to third parties.

Only analyze systems and services you own or have explicit authorization to investigate.

---

## Repository Structure

Current research begins with macOS:

```text
SplunkFound/
├── README.md
├── iOS/
│   └── NotificationLog.redacted.txt
└── MacOS/
    └── Splunk
```

As the investigation grows, a possible structure is:

```text
SplunkFound/
├── README.md
├── MacOS/
│   ├── artifacts/
│   ├── configuration/
│   ├── logs/
│   └── metadata/
├── evidence/
│   ├── hashes/
│   ├── screenshots/
│   └── timelines/
├── docs/
│   ├── architecture.md
│   └── findings.md
└── scripts/
    └── collect_splunk_artifacts.sh
```

Sensitive values should be redacted before committing evidence publicly.

---

## Conclusion

SplunkFound began with a small but unusual artifact:

```text
Deploy
<hex value>

Enc
<encoded value>
```

Those two fields do not prove surveillance.

They do justify investigation.

Splunk is capable of centralized logging, data forwarding, infrastructure monitoring, security analytics, and managed deployment. Therefore, deployment-related and encryption-related artifacts found unexpectedly on a Mac deserve careful examination.

The objective of this project is to move from:

```text
"I found something unusual."
```

to:

```text
"What created it?"
"What did it configure?"
"What process used it?"
"Where did data go?"
"When did it happen?"
"What evidence proves that?"
```

That distinction is what turns speculation into digital forensics.

---

## Current Finding

**Status:** Investigation ongoing.

**Observed:** Splunk-related artifact containing `Deploy` and `Enc` fields.

**Public evidence:** Original values redacted; SHA-256 fingerprints retained.

**Possible significance:** Deployment, configuration, logging, forwarding, or protected configuration material.

**Not yet established:** Exact Splunk component, origin, active monitoring status, or purpose.

> **Evidence first. Attribution second. Conclusions last.**
