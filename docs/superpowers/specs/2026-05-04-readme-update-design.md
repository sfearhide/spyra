# README Update: MITM & UI Exerciser

## Overview
A brief update to the existing `README.md` to mention the newly added MITM proxy and UI Exerciser capabilities, without overcrowding the documentation with an exhaustive list of CLI parameters.

## Changes Required

1. **Prerequisites Section**
   - Add a bullet point for `mitmproxy` (specifically `mitmdump`), noting it is optionally required for HTTPS capture.

2. **Usage Section**
   - Add a sentence or two explaining that the tool now supports:
     - Automated UI testing (Monkey profile) during capture.
     - MITM HTTPS capture via mitmdump.
   - Mention that these features are enabled by default but configurable via CLI flags (e.g., `--mitm`, `--exerciser`).

3. **Command Line Examples**
   - Provide a slightly updated `bash` block showing how to invoke the tool with the new capabilities in mind (e.g., demonstrating that flags exist, like `python3 main.py sample.apk --label malware`).

## Out of Scope
- Exhaustive documentation of all new CLI arguments (e.g., `--mitm-port`, `--label-source`, `--duration`).
- Detailed documentation of the internal architecture of `MITMController` or `UIExerciser`.
