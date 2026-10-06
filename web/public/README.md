# SPECTRA // Enterprise Visualizer Frontend (`web/public`)

## Overview

The `web/public` directory contains the responsive, single-page application (SPA) client for the **SPECTRA Enterprise CBOM Visualizer & Post-Quantum Assurance** platform.

Designed around a high-trust, audit-grade visual aesthetic (deep slate backgrounds, emerald accents, and zero high-saturation neon clutter), the dashboard translates complex cryptographic telemetry and mathematical risk calculations into actionable executive and technical views.

---

## Architecture & Asset Breakdown

```
web/public/
├── index.html     # SPA structure, layout grids, modal drawers, and theme boots
├── app.js         # Reactive state manager, Chart.js telemetry, Mosca calculator
└── style.css      # Custom styling, print formats, and accessibility enhancements
```

```mermaid
flowchart TD
    subgraph UI Layout (index.html)
        Header[Executive Header\nTheme Toggle & Status]
        Hero[KPI Metric Ribbons\nTotal Assets, Quantum Risk, Mosca Breaches]
        Tabs[Navigation Tabs]
        View1[Dashboard Overview & Charts]
        View2[Cryptographic Inventory Table]
        View3[Mosca Risk Assessment Engine]
        Drawer[Component Detail Slideout Drawer]
    end

    subgraph State Management (app.js)
        State[(State Object\nCBOM, Components, Filters, Mosca Settings)]
        Fetcher[API Service / File Drag & Drop]
        FilterEngine[Multi-criteria Filter & Search]
        MoscaCalc[Interactive Mosca Risk Recalculator]
        ChartManager[Chart.js Controllers]
    end

    Fetcher -->|Ingests CBOM| State
    State -->|Updates| Hero
    State -->|Triggers| ChartManager
    State -->|Feeds| FilterEngine
    FilterEngine -->|Renders| View2
    View2 -->|Select Row| Drawer
    MoscaCalc -->|Dynamic Recalc| View3
```

---

## Core Capabilities

### 1. Executive Telemetry & KPI Cards
- **Cryptographic Inventory Counter**: Tracks total detected keys, certificates, ciphers, and library calls across all 4 audit domains (Network, Source Code, Binaries/Artifacts, Infrastructure).
- **Quantum Vulnerability Status**: Instantly tags components vulnerable to Shor's algorithm (e.g. RSA, ECC, ECDH, DSA, Diffie-Hellman).
- **NIST FIPS PQC Readiness**: Displays post-quantum readiness percentages based on NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) compliance.
- **Mosca Inequality Breaches**: Real-time counter of cryptographic assets where migration timeline exceeds quantum compromise horizon ($X + Y > Z$).

---

### 2. Interactive Mosca Theorem Engine

Users can manipulate dynamic sliders to test different post-quantum planning scenarios across their infrastructure:

$$\text{Mosca Condition: } X + Y > Z \implies \text{Critical Risk}$$

- **Shelf-life parameter ($X$)**: Number of years the encrypted sensitive data must remain private.
- **Migration parameter ($Y$)**: Number of years required to re-engineer systems to post-quantum standards.
- **Collapse timeline ($Z$)**: Number of years until a Cryptanalytically Relevant Quantum Computer (CRQC) emerges.

Adjusting sliders instantly recalculates urgency scores, updates badge indicators, and highlights high-risk assets in the CBOM table without page reload.

---

### 3. Comprehensive CBOM Table & Filtering
- **Multi-domain Filtering**: Slice data by domain (`source`, `artifacts`, `network`, `infrastructure`).
- **Quantum Filter**: Filter for Shor-vulnerable, PQC-safe, or legacy deprecated ciphers.
- **Keyword Search**: Instant client-side search across component names, algorithm labels, file paths, and key lengths.
- **Deep-dive Slideout Drawer**: Selecting any asset slides out detailed metadata including:
  - Algorithm family, mode of operation, and padding scheme.
  - Key length and elliptic curve identifiers.
  - Source file path or endpoint IP/port.
  - NIST SP 800-131A / CNSA 2.0 migration guidance.

---

### 4. Zero-Dependency Standalone Mode
The visualizer includes native drag-and-drop JSON file parsing:
- Users can drag any valid `cbom.json` file onto the dashboard to inspect external audit reports immediately, even when disconnected from the backend API.
- Full export capabilities: Download sanitized JSON reports or filtered audit summaries directly from the interface.
