# Windows Test Bench (dockurr/windows)

Automated test bench for building, debugging, and E2E verification of the `OutlineProxy` Windows client (`bins/outline-windows`) and network core `outline-client.exe`, running under KVM virtualization and Docker on a home UGREEN DXP4800 Plus NAS (`198.18.1.105`).

---

## Architecture

- **Host**: NAS UGREEN `.105` (`198.18.1.105`, access: `ssh sysadm@198.18.1.105`).
- **Virtual Machine**: `dockurr/windows` container with hardware KVM acceleration (`/dev/kvm`).
  - OS: Windows 10 x64 Enterprise / Pro.
  - Resources: 2 CPUs, 4 GB RAM, 40 GB virtual disk (`/volume2/windows/storage/data.img`).
  - Web VNC: `http://198.18.1.105:8006` (in-browser view and interaction).
  - RDP: `198.18.1.105:3389` (Microsoft Remote Desktop).
- **Proxy Bridge**: `http-proxy-102` container (`gogost/gost`):
  - Port `:8118` on NAS `.105`.
  - Forwards HTTP/HTTPS traffic through Node 102 (`socks5://198.18.1.102:1080`).
  - Provides stable internet egress for downloading updates and packages.
- **Shared Directory**:
  - Host NAS path: `/volume1/docker/windows/shared`.
  - Guest Windows path: `\\host.lan\Data\`.
  - Installed application path: `C:\OutlineProxy\` (`OutlineProxy.exe`, `outline-client.exe`, `wintun.dll`).

---

## Management

All scripts can be run either locally from a macOS workstation (via SSH) or directly on the NAS under `/volume1/docker/windows/`:

### 1. Check Status
```bash
./ops/windows-bench/status.sh
```
Displays container status for `windows` and `http-proxy-102`, network ports (`8118`, `8006`, `3389`), virtual disk size, and runner loop activity.

### 2. Start Test Bench
```bash
./ops/windows-bench/start.sh
```
Starts both containers (booting an existing VM takes ~15–20 seconds) and waits for network readiness.
The PowerShell automation loop (`runner_loop.ps1`) is configured to auto-start on Windows boot via `Startup/runner_loop.cmd`.

### 3. Stop Test Bench (Resource Saving)
```bash
./ops/windows-bench/stop.sh
```
Performs a graceful ACPI shutdown of the Windows VM and stops the proxy bridge. Virtual disk `data.img` and installed files remain preserved.

---

## Automation and Testing

### Executing PowerShell Commands in Guest VM
The `exec.sh` helper submits commands via the shared queue and returns stdout:
```bash
# Check running Outline processes
./ops/windows-bench/exec.sh "Get-Process OutlineProxy"

# Check binary file hashes
./ops/windows-bench/exec.sh "Get-FileHash C:\OutlineProxy\OutlineProxy.exe"

# Execute external .ps1 script
./ops/windows-bench/exec.sh -f path/to/script.ps1
```

### Capturing Guest VM Screenshot
```bash
./ops/windows-bench/screenshot.sh output.png
```
Takes a screenshot of the guest primary display and downloads it locally to `output.png`.
