# SPECTRA // Web Visualizer Subsystem (`web/`)

## Overview

The `web` directory houses the local HTTP visualization backend and static application assets for SPECTRA. It provides security engineers, auditors, and executive decision-makers with an interactive, zero-dependency dashboard for exploring **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** documents, tracking **Mosca Theorem** risk timelines, and planning Post-Quantum Cryptography (PQC) migrations.

---

## Architecture

The server is built with pure Node.js standard libraries (`http`, `fs`, `path`, `url`), eliminating `node_modules` overhead and external security dependencies.

```mermaid
flowchart LR
    subgraph SPECTRA Backend / CLI
        Engine[SPECTRA Engine] -->|Generates| CBOM[cbom.json]
    end

    subgraph Web Server (server.js :3000)
        Router[HTTP Request Router]
        CBOMStore[(In-Memory / File CBOM Cache)]
        StaticServe[Static File Handler]
    end

    subgraph Web UI (public/)
        SPA[Single-Page Dashboard\nindex.html + app.js]
    end

    CBOM -->|Auto-loaded by| CBOMStore
    Router -->|GET /api/cbom| CBOMStore
    Router -->|POST /api/cbom| CBOMStore
    Router -->|GET /api/status| CBOMStore
    Router -->|GET /*| StaticServe
    StaticServe -->|Serves CSS/JS/HTML| SPA
    SPA -->|Fetch CBOM & Metrics| Router
```

---

## Directory Structure

```
web/
├── server.js          # Standalone Node.js HTTP server & REST API
├── public/            # Client-side single-page application (SPA)
│   ├── index.html     # Semantic dashboard markup & layouts
│   ├── app.js         # Reactive UI state, Chart.js integrations & filters
│   └── style.css      # Executive design system & dark/light theme tokens
└── README.md          # Visualizer server documentation (this file)
```

---

## Getting Started

### Prerequisites
- Node.js version 14.x or higher (no `npm install` required).

### Launching the Visualizer

From the repository root or the `web/` directory:

```bash
# Default launch (listens on port 3000, searches standard cbom.json locations)
node web/server.js

# Custom port
PORT=8080 node web/server.js

# Specify exact CBOM path via environment variable
CBOM_PATH=/path/to/custom-cbom.json node web/server.js
```

Upon startup, open your browser at:
```
http://localhost:3000
```

---

## REST API Specification

The built-in HTTP server exposes three core endpoints:

### 1. `GET /api/cbom`
Returns the active CycloneDX 1.6 CBOM document as JSON.

- **Status 200 OK**: JSON payload of the CBOM document.
- **Status 404 Not Found**: Emitted if no CBOM file is found at the active candidate paths.
- **Candidate Discovery Order**:
  1. `activeCbomPath` (configured path or last uploaded file).
  2. `./cbom.json` in current working directory.
  3. `C:/Users/Arnesh/Desktop/cbom.json`.
  4. `../cbom.json` relative to `server.js`.

### 2. `POST /api/cbom`
Allows external tools, CI/CD runners, or the SPECTRA CLI to stream a fresh CBOM directly into server memory without restarting the process.

- **Request Body**: Valid CycloneDX 1.6 JSON.
- **Response**:
  ```json
  {
    "status": "ok",
    "components": 142,
    "message": "CBOM ingested successfully"
  }
  ```

### 3. `GET /api/status`
Health check and telemetry metadata endpoint.

- **Response**:
  ```json
  {
    "status": "online",
    "activeCbomPath": "C:/Users/.../cbom.json",
    "exists": true,
    "componentsCount": 142,
    "vulnerabilitiesCount": 38,
    "dependenciesCount": 210,
    "fileSizeKb": "184.2",
    "lastModified": "2026-10-06T12:00:00.000Z",
    "serverTime": "2026-10-06T12:05:00.000Z"
  }
  ```

---

## Static Asset Delivery

The server transparently serves all frontend assets located in [`public/`](./public/README.md) with appropriate MIME types, cache control, and UTF-8 charset encodings for HTML, CSS, JavaScript, and SVG icons.
