# TinyFiles — AT‑1 Compression

  **Verified‑lossless, structure‑aware compression.** TinyFiles shrinks structured data
  (CSV, JSON, logs, genomics, and more) and *proves* it can rebuild the original
  **byte‑for‑byte** — with a built‑in guarantee that the compressed file is **never larger**
  than its baseline compressor. Many archives stay **queryable in place**, so you can run
  SQL over a compressed file without unpacking it.

  🌐 **Website:** https://tinyfiles.io
  🧪 **Try it in your browser:** https://tinyfiles.io/try
  📥 **Downloads:** see [Download](#download) below

  ---

  ## Why TinyFiles is different

  - **Verified lossless.** Every compression is checked by decompressing and comparing to
    the original. If it doesn't match exactly, it doesn't ship. No silent corruption.
  - **Non‑inferiority guarantee.** AT‑1 races a trusted baseline compressor and keeps the
    winner — so the output is *never bigger* than what the baseline would have produced.
  - **Structure‑aware.** Instead of treating everything as opaque bytes, AT‑1 understands
    the shape of your data (columns, records, log lines, genotype matrices) and compresses
    along that structure.
  - **Queryable in place.** Compatible archives carry a self‑describing container you can
    run filters and SQL against directly — including over the network, fetching only the
    bytes a query needs.
  - **Self‑contained.** A single‑file "living database" export bundles the archive *and* an
    in‑browser query engine in one HTML file.

  ## Download

  Desktop app for Windows, macOS, and Linux:

  | Platform | Installer |
  |----------|-----------|
  | Windows  | `TinyFiles-Setup.exe` / `.msi` |
  | macOS (Apple Silicon) | `TinyFiles-macOS-arm64.dmg` |
  | macOS (Intel) | `TinyFiles-macOS-x64.dmg` |
  | Linux    | `.AppImage` / `.deb` |

  > Download links are published on the [website download page](https://tinyfiles.io/download).

  ## How it works (in brief)

  1. **Detect** the structure of the input (or let auto‑selection profile it).
  2. **Encode** along that structure with the codec best suited to it.
  3. **Verify** by decoding and comparing to the original, byte‑for‑byte.
  4. **Gate** against a baseline compressor and keep whichever is smaller.
  5. **(Optional) Stay queryable** — write a self‑describing container that supports
     predicate pushdown and SQL without full decompression.

  ## Supported data

  Tabular/CSV · JSON & JSON documents · application & system logs · geospatial (OSM) ·
  genomics (VCF) · columnar exports · PDF/Word bundles (full‑text searchable) — and a
  general fallback that still honors the verified‑lossless + non‑inferiority guarantees.

  ## Status

  **Patent pending** (U.S. provisional patent application, filed 2026).
  TinyFiles is under active development. Interfaces and file formats may evolve;
  the verified‑lossless guarantee will not.

  ## Contact

  Questions, partnerships, or early access: **hello@tinyfiles.io**

  ---

  © 2026 TinyFiles. All rights reserved. See the website for terms.
