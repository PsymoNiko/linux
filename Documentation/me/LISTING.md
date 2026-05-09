
# Isolated Server Protection Guide
### Covering CVE‑2026‑31431 (Copy Fail) and Beyond

This document provides a layered, practical checklist for securing isolated servers – bare‑metal, virtual machines, or cloud instances – with a focus on Docker, GPU, Python, and OS‑level hardening. It extends the original CVE‑2026‑31431 fix guide to a defence‑in‑depth approach.

---

## 1. Vulnerability Detection & Verification

Run these commands first to assess whether your system is affected by **Copy Fail** and other weaknesses that could allow container escape or local privilege escalation.

| Target | Command / Check | Notes |
|-------|-----------------|-------|
| Kernel configuration (algif_aead) | `grep -E '^CONFIG_CRYPTO_USER_API_AEAD=' /boot/config-$(uname -r)` | `=m` → module (can be blacklisted / removed). `=y` → built‑in (harder to disable, use kernel cmdline). |
| Module loaded? | `lsmod \| grep algif_aead` | Silence = module not loaded (good). Output = vulnerable. |
| Running kernel version | `uname -r` | Compare with fixed versions: 6.19.12+, 6.18.22+, 6.12.85+, 6.6.98+, 6.1.170+, 7.0+. |
| Docker Engine version | `docker version` | Must be **≥ 29.4.2** for patched default seccomp profile. |
| NVIDIA Container Toolkit | `nvidia-ctk --version` | Must be **> 1.17.3** (fixed in 1.17.8+) due to CVE-2025-23359. |
| Python AF_ALG reachability | `python3 -c "import socket; s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)"` 2>/dev/null | Successful socket creation → vulnerable. |

---

## 2. Host Operating System Hardening

The OS is the trust anchor. A compromised host gives an attacker control over all containers, GPU workloads, and Python environments.

### 2.1 CVE‑2026‑31431 – Permanent Fix

Update the kernel to a patched version.

```bash
# Debian / Ubuntu
sudo apt update && sudo apt upgrade

# RHEL / AlmaLinux / Rocky / Fedora
sudo dnf update kernel

# Amazon Linux 2 / 2023
sudo yum update kernel

# SUSE / openSUSE
sudo zypper patch

# Arch Linux
sudo pacman -Syu
```

⚠️ Reboot to load the new kernel.

2.2 CVE‑2026‑31431 – Module Mitigation (if kernel update not possible)

```bash
# Prevent algif_aead from loading at boot
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf

# Unload it immediately (only works if compiled as a module)
sudo rmmod algif_aead 2>/dev/null

# Refresh initramfs so the blacklist sticks
sudo update-initramfs -u
```

For kernels with CONFIG_CRYPTO_USER_API_AEAD=y (built‑in), add initcall_blacklist=algif_aead_init to the kernel command line (GRUB_CMDLINE_LINUX in /etc/default/grub).

2.3 General Kernel Hardening

Add these entries to /etc/sysctl.conf (or a .conf file in /etc/sysctl.d/) and apply with sudo sysctl -p:

```ini
# Restrict kernel pointer exposure
kernel.kptr_restrict = 2
# Restrict access to kernel logs
kernel.dmesg_restrict = 1
# Disable unprivileged BPF (often used in exploits)
kernel.unprivileged_bpf_disabled = 1
# Randomise memory space aggressively
kernel.randomize_va_space = 2
```

2.4 SSH Hardening

Edit /etc/ssh/sshd_config:

```ini
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
```

Then restart the service: sudo systemctl restart sshd.

2.5 Mandatory Access Control

· SELinux (RHEL, Fedora, etc.):
  ```bash
  sudo setenforce 1
  # Make it persistent in /etc/selinux/config: SELINUX=enforcing
  ```
· AppArmor (Ubuntu, Debian):
  ```bash
  sudo aa-status
  # Ensure profiles are loaded and in enforce mode
  ```

2.6 Host Firewall

Default‑deny inbound traffic, allow only necessary services.

UFW example:

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw enable
```

For iptables/nftables, ensure INPUT chain ends with a drop policy.

---

3. Docker & Container Security

Copy Fail can be used as a container‑escape. A multi‑layered approach inside Docker is essential.

3.1 Update Docker Engine

Docker ≥ 29.4.2 ships a default seccomp profile that denies the AF_ALG socket family (value 38). Without this, even a host with algif_aead removed might still be vulnerable if a container runs with a permissive profile.

```bash
# Check version
docker version

# Update (example for Debian/Ubuntu)
sudo apt update && sudo apt install docker-ce docker-ce-cli containerd.io
```

3.2 Custom Seccomp Profile for Older Docker

If you cannot update, create a custom seccomp JSON profile that explicitly denies socket with family == 38.

Minimal custom profile (deny-af_alg.json):

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "args": [
        {
          "index": 0,
          "value": 38,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

Apply it when running containers:
docker run --security-opt seccomp=/path/to/deny-af_alg.json ...

3.3 Rootless Docker

Run the entire Docker daemon in rootless mode. This adds an extra user‑namespace boundary, making the host root unreachable even from a container breakout.

```bash
# Setup (one‑time)
dockerd-rootless-setuptool.sh install
```

3.4 Drop Capabilities & Privileges

· Never use --privileged.
· Drop all capabilities and add back only those that are absolutely necessary:

```bash
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...
```

· Consider --security-opt=no-new-privileges to prevent setuid binaries from gaining extra capabilities.

3.5 Read‑Only Root Filesystem

```bash
docker run --read-only ...
```

Mount any writable directories (/tmp, /var/run, etc.) explicitly as tmpfs or volumes.

3.6 Resource Limits

Always set hard memory and CPU limits to prevent denial‑of‑service attacks from within a container:

```bash
docker run --memory="512m" --cpus="1.0" ...
```

3.7 Image Security

· Use minimal base images (distroless, Alpine with careful dependencies).
· Scan images with docker scan, Trivy, or Grype before deployment.
· Pin image digests, not just tags: image@sha256:....

3.8 Docker Bench Security

Run the CIS Docker Benchmark assessment regularly:

```bash
docker run --rm --net host --pid host --userns host \
  --cap-add audit_control \
  -v /var/lib/docker:/var/lib/docker \
  -v /etc/docker:/etc/docker \
  docker/docker-bench-security
```

---

4. GPU & NVIDIA Container Security

GPU‑accelerated containers often require privileged access to the NVIDIA driver stack. This broad attack surface must be tightly restricted.

4.1 Update NVIDIA Container Toolkit

Update to v1.17.8+ (or GPU Operator v25.3.1+) to fix CVE‑2025‑23359, which allowed mounting host directories through specially crafted CDI specifiers.

```bash
# Check current version
nvidia-ctk --version

# Update via package manager (example for Debian/Ubuntu)
sudo apt update && sudo apt install nvidia-container-toolkit
```

4.2 GPU Isolation Techniques

· MIG (Multi‑Instance GPU) – For A100, A30, H100: partition a physical GPU into isolated slices. Each container gets its own MIG instance, providing hardware‑enforced memory and compute isolation.
· Time‑slicing – For non‑MIG GPUs, configure time‑slicing in Kubernetes (NVIDIA device plugin) to share a GPU, adding a scheduling‑layer isolation.
· vNode / microVM – Use Kata Containers or Firecracker‑based runtimes for GPU workloads. This gives each container its own lightweight VM, making kernel exploits irrelevant.

4.3 Avoid Untrusted GPU Container Images

The NVIDIAScape attack chain started with a malicious container image. Always:

· Use only trusted registries.
· Scan images for vulnerabilities.
· Avoid images that mount sensitive host paths (like /var/run/docker.sock or /proc).

4.4 Limit Device Exposure

When running GPU containers, expose only the required device files and libraries. The NVIDIA Container Toolkit’s --gpus flag is safer than manually mounting /dev/nvidia* because it uses a controlled set of device nodes and libraries.

---

5. Python Environment Security

Python is a common vector for exploits like Copy Fail. Secure the runtime and its sandboxes.

5.1 AF_ALG Blocker (Runtime)

The detection snippet above can be turned into a pre‑flight check that aborts execution if AF_ALG is reachable:

```python
import socket, sys
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.close()
    print("AF_ALG reachable – system is vulnerable. Aborting.", file=sys.stderr)
    sys.exit(1)
except (OSError, PermissionError):
    pass   # Good, socket creation failed
```

5.2 RestrictedPython / AST Sandbox

If executing untrusted code, transform it with RestrictedPython and validate the AST. This removes dangerous constructs (__import__, exec, attribute access on certain objects, etc.).

5.3 Containerized Sandbox

Never run untrusted Python code directly on the host. Use a container with the custom seccomp profile from Section 3.2, plus:

· --read-only
· --tmpfs /tmp
· --network none (if network isn’t needed)
· --security-opt=no-new-privileges

5.4 Bubblewrap (bwrap) Sandbox

For a lightweight sandbox without Docker:

```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --tmpfs /tmp \
  --unshare-net \
  --cap-drop ALL \
  python3 /path/to/script.py
```

5.5 Dependency Security

· Use pip-audit or safety to scan for known vulnerabilities in your requirements.
· Pin versions and use hashes (pip install --require-hashes).
· Avoid pulling code from unverified PyPI packages.

---

6. Implementation Notes & Best Practices

1. Layered defence is mandatory – Combine host mitigation, Docker seccomp, and application‑level checks. A single layer can be bypassed.
2. Test in a staging environment – Kernel updates, seccomp profiles, and NCCL changes can break applications. Validate before production rollout.
3. Automate monitoring – Use tools like Prometheus + Node Exporter, or a simple cron job that checks lsmod for algif_aead and alerts if it reappears.
4. Patch aggressively – The 2026 Linux kernel landscape (Copy Fail, Stack Clash, DirtyFrag) demands a patching cycle of days, not weeks.
5. Hardend defaults – When provisioning new servers or containers, use Infrastructure‑as‑Code (Terraform, Ansible) that bakes in these security controls from the start.

---

7. References

· Microsoft Security Blog – Copy Fail
· CISA KEV Catalog
· Theori Xint Disclosure – 732 bytes to root
· NVIDIA Container Toolkit Security Advisory
· CIS Docker Benchmark

---

Last updated: 2026‑05‑09

