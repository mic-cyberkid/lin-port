# Linux C2 Implant Port

This project is a complete, production-ready, pure Linux C2 implant. It maintains full protocol compatibility with the original Python Flask/SocketIO server while implementing Linux-native features for persistence, reconnaissance, and evasion.

## Core Capabilities

- **Stealthy Beaconing**: HTTPS communication via OpenSSL BIO (avoiding libcurl signatures) with AES-256-GCM encryption.
- **PTY-based Shell**: Full interactive shell using pseudo-terminals (`forkpty`) for a native experience.
- **In-Memory Execution**: ELF files can be received via C2 and executed directly from memory using `memfd_create`.
- **SOCKS5 Proxy**: Built-in functional SOCKS5 proxy for pivoting and lateral movement.
- **Credential Theft**:
  - **Chromium/Firefox**: Decrypts passwords and cookies natively using `libsecret` and OpenSSL.
  - **System Harvest**: Dumps `/etc/shadow` (if root), harvests sensitive environment variables, and searches for cloud/SSH/Docker secrets.
- **Lateral Movement**:
  - SSH key harvesting (`~/.ssh/`).
  - Target identification from `known_hosts` and `/etc/hosts`.
  - SSH Agent detection for hijacking.
- **Multimedia Capture**:
  - **Screenshots**: X11 capture encoded to **JPEG** via `libjpeg` for minimal exfiltration footprint.
  - **Webcam**: V4L2 photo capture.
  - **Audio**: Stealthy recording via **PulseAudio Simple API** (no shell-outs).
- **WiFi Scanning**: Stealthy discovery via **Wireless Extensions (ioctl)**.
- **Persistence**:
  - `systemd` user-level services.
  - `cron` @reboot tasks.
  - Desktop Autostart entries.
- **Advanced Evasion**:
  - Early anti-analysis checks (ptrace, TracerPid, uptime).
  - Process name randomization and `argv` scrubbing.
  - Environmental jitter based on machine-id and hostname.
  - Compile-time XOR string obfuscation.

## Build Instructions

### Dependencies

Ensure the following development headers are installed:
- `libssl-dev`
- `libx11-dev`
- `libsqlite3-dev`
- `libjpeg-dev`
- `libpulse-dev`
- `libsecret-1-dev`

### Compilation

Use CMake to build the project:

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

The resulting `implant` binary will be located in the `build/` directory.

## Technical Notes

- **Stealth**: The implant renames itself to a common system daemon (e.g., `systemd`, `dbus-daemon`) immediately upon execution and scrubs its command-line arguments. It avoids spawning external shells wherever possible by using native C/C++ APIs.
- **Compatibility**: Tested on Ubuntu 22.04 and 24.04. The binary is optimized for minimal dynamic linking dependencies while ensuring compatibility across modern Linux distributions.
- **Protocol**: Exact match for the original Windows implant protocol, including chunked MJPEG streaming and AES-GCM beacon format.
