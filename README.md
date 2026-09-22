SCOPEX

External Attack Surface Intelligence Platform

SCOPEX is a reconnaissance and attack-surface intelligence platform designed to build a structured, continuously updated view of an organization's authorized external infrastructure.

Instead of producing raw scanner output, SCOPEX correlates domains, subdomains, IP addresses, ports, services, technologies, certificates, websites, and security findings into an analyst-friendly interface.

The goal is simple:

Discover what is exposed, understand what is running, identify changes, and present the evidence clearly.

 Authorized Use Only

SCOPEX is intended for authorized security assessments, internal security monitoring, CTF/lab environments, and assets you own or have explicit permission to assess.

Active scanning can generate traffic and may affect systems or trigger security controls. Always define and verify an explicit scope before running active modules.

SCOPEX is not intended for indiscriminate scanning of third-party infrastructure.

Why SCOPEX?

Security tools often provide excellent individual capabilities:

DNS enumeration

subdomain discovery

port scanning

HTTP probing

TLS inspection

technology fingerprinting

vulnerability intelligence

The problem is that analysts frequently have to run several tools independently and manually correlate the results.

SCOPEX aims to provide one normalized workflow:

                    TARGET
                       │
                       ▼
              ┌─────────────────┐
              │ Scope Validation │
              └────────┬────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Passive       Active       Metadata
        Recon         Recon       Sources
          │            │            │
          └────────────┼────────────┘
                       ▼
                Asset Correlation
                       │
                       ▼
               Service / Tech
                 Fingerprinting
                       │
                       ▼
              Security Intelligence
                       │
                       ▼
              Historical Tracking
                       │
              ┌────────┴────────┐
              ▼                 ▼
             CLI            Dashboard

Core Features

 External Asset Discovery

Discover and normalize assets associated with an authorized organization:

Domains

Subdomains

IP addresses

DNS records

Autonomous Systems

Network ranges

TLS certificate relationships

Web applications

Internet-facing services

Example:

example.com
├── www.example.com
├── api.example.com
├── portal.example.com
├── vpn.example.com
├── dev.example.com
└── staging.example.com

 DNS Intelligence

Collect and correlate DNS information such as:

A
AAAA
CNAME
MX
NS
TXT
SOA

The system should preserve the relationship between:

Domain
   ↓
DNS record
   ↓
IP
   ↓
Host

This allows multiple data sources to converge on the same underlying asset.

🛰️ Service Discovery

For authorized targets, SCOPEX can identify exposed network services.

Example:

api.example.com

22/tcp    SSH
80/tcp    HTTP
443/tcp   HTTPS
8080/tcp  HTTP-ALT

The raw scanner result is normalized into the SCOPEX asset model.

🧩 Service & Version Fingerprinting

Identify technologies and, where reliable evidence exists, versions.

Example:

Host:
api.example.com

Service:
HTTPS

Server:
nginx

Application:
FastAPI

Runtime:
Python

Detected Version:
1.x

Evidence:
HTTP response + TLS + service fingerprint

SCOPEX should distinguish between:

confirmed fingerprints

probable fingerprints

inferred technologies

unknown values

It should never present an uncertain fingerprint as confirmed fact.

🌍 Website Intelligence

For HTTP/HTTPS services, collect useful metadata:

URL
HTTP status
Page title
Redirect chain
Server header
Content type
Technology indicators
Security headers
TLS information

Example:

https://api.example.com

HTTP Status       200
Server            nginx
Application       FastAPI
TLS               1.3
HSTS              ✓
CSP               ✗
X-Frame-Options   ✗

🔐 TLS Analysis

Analyze HTTPS/TLS configuration and certificate metadata.

Potential observations include:

Certificate validity

Expiration date

Issuer

Subject

SANs

TLS versions

Certificate/hostname mismatches

Expiring certificates

Weak configuration indicators

Example:

TLS STATUS

Certificate       VALID
Issuer             Let's Encrypt
Expires            2027-04-12
TLS 1.2            ✓
TLS 1.3            ✓
Hostname Match     ✓

🛡️ HTTP Security Analysis

SCOPEX can inspect security-relevant HTTP response headers.

Example:

SECURITY HEADERS

Strict-Transport-Security     ✓
Content-Security-Policy       ✗
X-Content-Type-Options        ✓
X-Frame-Options               ✗
Referrer-Policy               ✓

Findings should include evidence rather than relying on an unexplained numerical score.

Vulnerability Intelligence

SCOPEX can correlate discovered software and versions with vulnerability intelligence.

Example:

Software:
ExampleServer 4.2

Advisory:
CVE-XXXX-XXXX

Affected Version:
Potentially affected

Evidence:
Version fingerprint

Confidence:
MEDIUM

Exploitability:
NOT VERIFIED

Important design principle

A detected version should not automatically become a confirmed vulnerability.

For example:

Detected Version
       ↓
Potentially Affected?
       ↓
Evidence Validation
       ↓
Confidence
       ↓
Analyst Finding

This avoids turning imperfect fingerprinting into false-positive security alerts.

Asset Relationship Model

SCOPEX maintains relationships between discovered objects.

Example:

example.com
    │
    ├── subdomain
    │       │
    │       ▼
    │   api.example.com
    │       │
    │       ▼
    │   203.0.113.10
    │       │
    │       ├── 22/tcp
    │       ├── 80/tcp
    │       └── 443/tcp
    │               │
    │               ▼
    │             nginx
    │               │
    │               ▼
    │             FastAPI

This relationship model becomes the foundation for future attack-path analysis.

Historical Monitoring

SCOPEX is designed to operate continuously, not only as a one-time scanner.

Example:

22 Sep 2026
47 hosts
138 services

23 Sep 2026
49 hosts
144 services

CHANGE DETECTED

+ api2.example.com
+ 203.0.113.55
+ TCP/8443 on dev.example.com

The system should retain historical observations so analysts can answer:

When was this asset first observed?

When was it last seen?

When did a port open?

When did a technology change?

When did a certificate change?

When did a new subdomain appear?

Did a previously exposed service disappear?

Dashboard

The dashboard should prioritize clarity over visual noise.

Example:

┌──────────────────────────────────────────────────────┐
│ SCOPEX — EXTERNAL ATTACK SURFACE                    │
├──────────────────────────────────────────────────────┤
│ Target: example.com                                  │
│ Last Scan: 22 Sep 2026                               │
├──────────────────────────────────────────────────────┤
│                                                      │
│   DOMAINS       HOSTS       SERVICES       WEBSITES │
│      8            47           138             31   │
│                                                      │
├──────────────────────────────────────────────────────┤
│ EXPOSURE                                             │
│                                                      │
│ Internet-facing hosts                         47    │
│ Open services                                138    │
│ Web applications                              31    │
│ Potentially vulnerable services                 7    │
│ Certificates expiring soon                      2    │
│                                                      │
├──────────────────────────────────────────────────────┤
│ TOP FINDINGS                                         │
│                                                      │
│ ⚠ Publicly exposed database                         │
│ ⚠ Legacy software detected                           │
│ ⚠ Development environment exposed                    │
│ ⚠ Missing security headers                           │
└──────────────────────────────────────────────────────┘

CLI

The CLI should be a first-class interface rather than a debugging interface.

Scan

scopex scan example.com

Discover assets

scopex assets example.com

Example:

HOSTNAME               IP              PORTS        WEB
────────────────────────────────────────────────────────
api.example.com        203.0.113.10    22,443       ✓
vpn.example.com        203.0.113.11    443          ✓
dev.example.com        203.0.113.12    80,443,8080  ✓
mail.example.com       203.0.113.13    25,443,587   ✓

Inspect an asset

scopex inspect dev.example.com

Example:

╭──────────── ASSET ────────────╮
│ dev.example.com               │
├───────────────────────────────┤
│ IP       203.0.113.12         │
│ HTTP     200                  │
│ Server   nginx                │
│ Framework React               │
│ TLS      1.3                  │
╰───────────────────────────────╯

OPEN SERVICES

22    SSH
80    HTTP
443   HTTPS
8080  HTTP-ALT

FINDINGS

[MED] Development service exposed
[LOW] Missing HSTS

Compare scans

scopex diff example.com --from yesterday --to today

Export

scopex export example.com --format json
scopex export example.com --format csv
scopex export example.com --format html

Continuous monitoring

scopex monitor example.com

Proposed Architecture

                         ┌──────────────┐
                         │     CLI      │
                         └──────┬───────┘
                                │
                         ┌──────▼───────┐
                         │  API / Core  │
                         └──────┬───────┘
                                │
                    ┌───────────▼───────────┐
                    │     Orchestrator      │
                    └───────────┬───────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
          ▼                     ▼                     ▼
   Passive Recon          Active Recon          Intelligence
          │                     │                     │
      DNS / CT /             Ports / HTTP /       CVE / TLS /
      RDAP / ASN             TLS / Service        Headers / Tech
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                ▼
                       ┌─────────────────┐
                       │ Normalization   │
                       └────────┬────────┘
                                ▼
                       ┌─────────────────┐
                       │ Asset Database  │
                       └────────┬────────┘
                                │
                  ┌─────────────┼─────────────┐
                  ▼             ▼             ▼
               History       Graph          Findings
                  │             │             │
                  └─────────────┼─────────────┘
                                ▼
                       ┌─────────────────┐
                       │ Dashboard / API │
                       └─────────────────┘

Proposed Technology Stack

Backend

Python

FastAPI

Pydantic

asyncio

CLI

Typer

Rich

Reconnaissance

Nmap

DNS tooling

HTTP probing

TLS inspection

Certificate transparency sources

RDAP/ASN data

Storage

Initial:

PostgreSQL

Future graph layer:

Neo4j

Frontend

React

Tailwind CSS

REST API

Deployment

Docker

Docker Compose

Data Model

A simplified model:

Organization
    │
    ├── Domain
    │      │
    │      └── Subdomain
    │             │
    │             └── Host
    │                   │
    │                   ├── IP
    │                   ├── Port
    │                   ├── Service
    │                   ├── Technology
    │                   ├── Certificate
    │                   └── Finding
    │
    └── Network

Every observation should ideally contain:

asset_id
source
timestamp
value
confidence
evidence

This makes the system auditable and allows historical comparison.

Confidence & Evidence

SCOPEX should treat reconnaissance as an evidence problem.

Instead of:

nginx 1.24

prefer:

Technology: nginx
Version: 1.24.x

Confidence: HIGH

Evidence:
- HTTP Server header
- Service fingerprint
- Response characteristics

Observed:
2026-09-22

For uncertain data:

Technology: Apache

Confidence: LOW

Evidence:
HTML fingerprint only

This distinction is fundamental to producing trustworthy security intelligence.

Development Roadmap

Phase 1 — Recon Core

Project structure

Scope validation

DNS enumeration

Subdomain discovery

IP resolution

Basic asset database

JSON output

Phase 2 — Active Discovery

Port scanning integration

Service detection

HTTP probing

TLS inspection

Redirect tracking

Technology fingerprinting

Phase 3 — Intelligence

Security header analysis

CVE correlation

Certificate analysis

Confidence scoring

Evidence storage

Finding normalization

Phase 4 — CLI

Rich terminal interface

Scan command

Asset command

Inspect command

Finding command

Diff command

Export command

Phase 5 — Dashboard

Asset inventory

Service inventory

Technology inventory

Findings

Asset details

Search/filtering

Scan history

Phase 6 — Continuous Monitoring

Scheduled scans

Asset change detection

New-service detection

New-domain detection

Certificate change detection

Technology change detection

Alerts

Phase 7 — Graph Intelligence

Neo4j integration

Asset relationships

Infrastructure graph

Attack-path modeling

Relationship visualization

Phase 8 — Analyst Automation

Investigation summaries

Evidence-based AI analysis

Automated security reports

Natural-language asset queries

Analyst workflow integration

Example End-to-End Workflow

scopex scan example.com

SCOPEX:

[1/7] Validating scope............. ✓
[2/7] Discovering domains.......... ✓ 8 found
[3/7] Resolving infrastructure..... ✓ 47 hosts
[4/7] Enumerating services......... ✓ 138 services
[5/7] Fingerprinting technology.... ✓ 74 technologies
[6/7] Analyzing security........... ✓ 17 findings
[7/7] Updating asset history....... ✓

Scan complete.

Assets       47
Services    138
Websites     31
Findings     17

New assets     3
Changed assets 5

Report:
./reports/example.com/2026-09-22/

Example JSON Output

{
  "target": "example.com",
  "scan_time": "2026-09-22T15:30:00Z",
  "assets": [
    {
      "hostname": "api.example.com",
      "ip": "203.0.113.10",
      "services": [
        {
          "port": 443,
          "protocol": "https",
          "service": "https"
        }
      ],
      "technologies": [
        {
          "name": "nginx",
          "confidence": "high"
        },
        {
          "name": "FastAPI",
          "confidence": "medium"
        }
      ]
    }
  ]
}

Design Principles

1. Evidence over assumptions

Every important finding should have supporting evidence.

2. Confidence matters

Not every fingerprint is equally reliable.

3. Passive before active

Start with passive intelligence whenever possible. Active scanning should operate only within explicit authorization and scope.

4. Normalize everything

Different scanners and intelligence sources should produce a consistent internal data model.

5. History is intelligence

A single scan shows a snapshot.

Multiple scans show change.

6. Explain findings

Don't simply report:

PORT 3306 OPEN

Explain:

MySQL service detected on an internet-facing host.

Evidence:
TCP/3306 responded to authorized scan.

Observed:
2026-09-22

7. Don't confuse detection with exploitation

SCOPEX is primarily an external attack-surface intelligence and reconnaissance platform. A detected service or possible vulnerability should not be treated as proof of exploitability.

Future Vision

The long-term goal is to evolve SCOPEX from a scanner into an external security intelligence platform.

                ORGANIZATION
                     │
                     ▼
              ASSET DISCOVERY
                     │
                     ▼
             ASSET INVENTORY
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
     SERVICES     SOFTWARE       CLOUD
        │            │            │
        └────────────┼────────────┘
                     ▼
              SECURITY INTEL
                     │
                     ▼
              RELATIONSHIP GRAPH
                     │
                     ▼
              ATTACK PATHS
                     │
                     ▼
             CONTINUOUS MONITORING

The eventual question SCOPEX should answer is not merely:

"What ports are open?"

but:

"What does this organization expose to the internet, what is running there, how has it changed, what security evidence do we have, and what relationships between those assets matter?"

Project Status

 Early-stage / Architecture phase

The project is currently being designed with a modular architecture so individual reconnaissance and intelligence components can be developed, tested, replaced, and extended independently.

License

To be decided.

Disclaimer

SCOPEX is a security research and defensive security project. Use it only against systems and infrastructure for which you have explicit authorization.
