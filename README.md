# SPYRA

This tool automates the analysis of Android applications (APKs) by detecting used frameworks and generating custom Frida hooks to intercept API calls and network activity. It is designed to assist in malware analysis by providing visibility into application behavior, including native layer interactions.

## Prerequisites

- **Python 3.9+**
- **Latest version of UV**: Required for dependency management.
- **Node.js & npm**: Required for compiling Frida scripts.
- **Apktool**: Required for decompiling APKs.
- **Android Device/Emulator**: Must be running `frida-server`.

## Installation

1. Clone the repository.
2. Install Python dependencies:
   ```bash
   uv sync
   ```
3. Ensure `apktool` and `npm` are in your system PATH.

## Usage

Connect your Android device with `frida-server` running, then execute:

```bash
python3 main.py <path_to_apk>
```

Example:
```bash
python3 main.py sample.apk
```

The tool will:
1. Check dependencies and device connection.
2. Decompile the APK to analyze its structure.
3. Detect frameworks and generate appropriate hooks.
4. Compile the hooks into a single JavaScript file.
5. Spawn the application and begin monitoring.

## Output

Results are displayed in the console and saved to the `output/` directory:

- **Console**: real-time logging of network requests, file operations, crypto usage, and native calls.
- **JSON Reports**:
  - `output/<package>/<package>_api_sequence.json`: chronological sequence of API calls.
  - `output/<package>/<package>_network_sequence.json`: detailed log of network activity.
