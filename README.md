# Linux C2 Implant Port

This project is a complete, production-ready Linux port of the Windows C2 implant. It maintains full protocol compatibility with the original Python Flask/SocketIO server while implementing Linux-native features for persistence, reconnaissance, and evasion.

## Core Capabilities

- **Stealthy Beaconing**: HTTPS communication via OpenSSL BIO (avoiding libcurl signatures) with AES-256-GCM encryption.
- **PTY-based Shell**: Full interactive shell using pseudo-terminals (`forkpty`) for a native experience.
- **In-Memory Execution**: ELF files can be received via C2 and executed directly from memory using `memfd_create` and `execveat` (via `/proc/self/fd/`).
- **Persistence**:
  - `systemd` user-level services (`~/.config/systemd/user/`)
  - `cron` @reboot tasks
- **Credential Theft**: Search and extraction for Chromium and Firefox passwords/cookies on Linux.
- **Multimedia Capture**:
  - X11 Screenshot capture (optimized for BMP exfiltration).
  - V4L2 Webcam photo capture.
  - Microphone recording via `arecord`.
- **Reconnaissance**: Deep system info collection (uname, sysinfo, /proc), software enumeration (dpkg/rpm), and network discovery (ARP).
- **Advanced Evasion**:
  - Early anti-analysis checks (ptrace, TracerPid, uptime).
  - Process name randomization and argv scrubbing.
  - Environmental jitter based on machine-id and hostname.
  - Compile-time XOR string obfuscation.

## Build Instructions

### Dependencies

Ensure the following development headers are installed:
- `libssl-dev`
- `libx11-dev`
- `libsqlite3-dev`

### Compilation

Use CMake to build the project:

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

The resulting `implant` binary will be located in the `build/` directory.

## Implementation Notes

- **Screenshot Format**: Due to environment constraints during the porting phase, screenshots are captured in BMP format. A future upgrade to `libjpeg-turbo` is recommended for better compression.
- **Audio**: Audio recording relies on the standard `arecord` utility, ensuring broad compatibility across distributions.
- **Static vs Dynamic**: The build targets standard system libraries (libc, libssl, libX11) to maintain a small binary size (~2.5 MB) while avoiding common static linking pitfalls.
- **Stealth**: The implant renames itself to a common system daemon (e.g., `systemd`, `dbus-daemon`) immediately upon execution and scrubs its command-line arguments.
