# DIRTY FRAG Detection with Wazuh 4.14.4 - CVE-2026-43284 / CVE-2026-43500

> **Detection engineering for the Dirty Frag kernel LPE · Wazuh 4.14.4 · auditd · Ubuntu / RHEL / SUSE / AlmaLinux / Fedora**

![rules](https://img.shields.io/badge/wazuh_rules-8-brightgreen)
![sca](https://img.shields.io/badge/SCA_checks-6-blue)
![status](https://img.shields.io/badge/status-production--validated-success)
![mitre](https://img.shields.io/badge/MITRE-T1068-red)
![cve](https://img.shields.io/badge/CVE-2026--43284-critical)
![cve2](https://img.shields.io/badge/CVE-2026--43500-critical)

---

## What is Dirty Frag?

Dirty Frag is a **Linux kernel local privilege escalation** that chains two independent page-cache write primitives discovered and published by **Hyunwoo Kim (@v4bel)**. It belongs to the same vulnerability class as Dirty Pipe and Copy Fail — but it bypasses the Copy Fail mitigation entirely.

A **single C binary** achieves root on all major Linux distributions with a one-line build-and-run command.

**The on-disk file remains unchanged**, making traditional FIM completely blind — just like Copy Fail.

> **Dirty Frag was motivated by Copy Fail research.** The xfrm-ESP variant shares the same cryptographic sink (`authencesn` seqno_lo write), but is triggered via the kernel's IPsec input path rather than through the AF_ALG user-space interface. Even on systems where the published Copy Fail mitigation (algif_aead blacklist) is applied, **your Linux is still vulnerable to Dirty Frag**.

---

## Official References

| Resource | Link |
|---|---|
| Canonical PoC - dirtyfrag (V4bel) | https://github.com/V4bel/dirtyfrag |
| Technical Write-up | https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md |
| oss-security Disclosure (2026-05-07) | https://www.openwall.com/lists/oss-security/2026/05/07/8 |
| CloudLinux Mitigation Advisory | https://blog.cloudlinux.com/dirty-frag-mitigation-and-kernel-update |
| Kernel Fix ESP - f4c50a4034e6 | https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cac2661c53f3 |
| AlmaLinux Advisory | https://almalinux.org/blog/2026-05-07-dirty-frag/ |
| MITRE ATT&CK T1068 | https://attack.mitre.org/techniques/T1068/ |
| Related - Copy Fail (CVE-2026-31431) | https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4 |

---

## The Page-Cache Write Bug Class

Dirty Frag, Copy Fail, and Dirty Pipe all exploit the same fundamental pattern:

```
1. splice() plants a page cache page reference into a kernel buffer
   (no copy - zero-copy path)

2. An in-kernel crypto or processing function performs in-place
   operations on that buffer, writing back into the page cache

3. The page cache modification persists in RAM
   On-disk file = UNCHANGED
   FIM result   = BLIND
```

| Vulnerability | Trigger mechanism | In-place operation | Bytes written |
|---|---|---|---|
| Dirty Pipe (CVE-2022-0847) | pipe_write() | overwrite pipe_buffer | arbitrary |
| Copy Fail (CVE-2026-31431) | AF_ALG socket + splice | authencesn_decrypt seqno_lo | 4 bytes |
| **Dirty Frag ESP (CVE-2026-43284)** | **xfrm ESP input + splice** | **authencesn_decrypt seqno_lo** | **4 bytes** |
| **Dirty Frag RxRPC (CVE-2026-43500)** | **RxRPC verify + splice** | **pcbc(fcrypt) in-place decrypt** | **8 bytes** |

> The ESP variant shares the exact same sink as Copy Fail (`scatterwalk_map_and_copy` writing `seqno_lo` into the dst SGL). However, the path to reach that sink is completely different — and completely unaffected by the algif_aead blacklist.

---

## Two Vulnerability Variants

### Variant 1 - xfrm-ESP Page-Cache Write (CVE-2026-43284)

**Requires:** `unshare(CLONE_NEWUSER|CLONE_NEWNET)` to gain `CAP_NET_ADMIN` inside a namespace.

**Modules needed:** `esp4.ko` (present on most distributions by default)

**Root cause:** `esp_input()` in `net/ipv4/esp4.c` skips `skb_cow_data()` for non-linear skbs without a frag list, allowing attacker-pinned page cache pages to remain in the scatterlist destination for in-place AEAD decryption.

**Primitive:** Arbitrary **4-byte controlled STORE** at any file offset. The 4 bytes written = `seq_hi` from `XFRMA_REPLAY_ESN_VAL` (attacker-controlled via XFRM SA registration).

**Target:** `/usr/bin/su` - 48 x 4-byte stores replace 192 bytes of page cache with a root-shell ELF. PAM is bypassed entirely.

**Mitigation impact:** Blacklisting `esp4/esp6` **BREAKS IPsec tunnels** (strongSwan, Libreswan). Do not apply on IPsec hosts.

---

### Variant 2 - RxRPC Page-Cache Write (CVE-2026-43500)

**Requires:** NO namespace privilege. Works without `unshare()`.

**Modules needed:** `rxrpc.ko` (Ubuntu default; absent on RHEL/CentOS/SUSE by default)

**Root cause:** `rxkad_verify_packet_1()` performs in-place `pcbc(fcrypt)` decryption on the first 8 bytes of the skb rxrpc payload, which the attacker has planted via splice.

**Primitive:** **8-byte brute-forced STORE**. The 8 bytes = `fcrypt_decrypt(C, K)` where K is the session key planted by `add_key("rxrpc", ...)`. The exploit brute-forces K in userspace (~18M/s, ~1s total).

**Target:** `/etc/passwd` line 1 - 3 x 8-byte stores replace `root:x:0:0` with `root::0:0:GGGGGG:`, emptying the password field. `pam_unix.so nullok` accepts the empty passwd without prompt.

**Mitigation impact:** Blacklisting `rxrpc` is **safe** on all non-AFS systems (web servers, cloud VMs, containers).

---

## Exploit Chain (Chaining Logic)

The public PoC chains both variants to achieve universal coverage:

```
Step 1: Try ESP variant (child process):
  unshare(CLONE_NEWUSER|CLONE_NEWNET)
  -> register 48 XFRM SAs (one per 4-byte chunk of shellcode)
  -> for each chunk:
       vmsplice(ESP_header, 24B)
       splice(/usr/bin/su, page_cache, i*4 offset)
       splice(pipe -> udp_socket)
       -> esp_input() in-place authencesn_decrypt -> 4-byte STORE
  -> check if first byte of shellcode landed at /usr/bin/su offset 0

Step 2: If ESP succeeded:
  execve("/usr/bin/su") -> root shell

Step 3: If ESP failed (AppArmor blocks CLONE_NEWUSER):
  Fall back to RxRPC variant:
  add_key("rxrpc", K_A/K_B/K_C) -> socket(AF_RXRPC)
  -> vmsplice(RxRPC wire header) + splice(/etc/passwd)
  -> rxkad_verify_packet_1() in-place fcrypt -> 8-byte STORE x3
  -> /etc/passwd root line: "root::0:0:GGGGGG:..."
  execve("/usr/bin/su -") -> PAM nullok -> root shell
```

---

## Affected Distributions

The PoC achieves root on all tested distributions:

| Distribution | Kernel | Status |
|---|---|---|
| Ubuntu 24.04.4 | 6.17.0-23-generic | ROOT CONFIRMED |
| RHEL 10.1 | 6.12.0-124.49.1.el10_1.x86_64 | ROOT CONFIRMED |
| AlmaLinux 10 | 6.12.0-124.52.3.el10_1.x86_64 | ROOT CONFIRMED |
| CentOS Stream 10 | 6.12.0-224.el10.x86_64 | ROOT CONFIRMED |
| openSUSE Tumbleweed | 7.0.2-1-default | ROOT CONFIRMED |
| Fedora 44 | 6.19.14-300.fc44.x86_64 | ROOT CONFIRMED |

**xfrm-ESP (CVE-2026-43284):** All Linux kernels from commit `cac2661c53f3` (2017-01-17) to mainline are in scope.

**RxRPC (CVE-2026-43500):** All Linux kernels from commit `2dc334f1a63a` (2023-06) to mainline are in scope. No patch exists in any tree yet.

---

## Repository Structure

```
DIRTY-FRAG-Detection-with-Wazuh-4.14.4/
│
├── rules/
│   └── local_rules.xml              # 8 Wazuh detection rules (200000-200008)
│
├── auditd/
│   └── cve-2026-43284.rules         # auditd syscall sensor rules (7 signals)
│
├── sca/
│   └── cve_2026_43284.yml           # SCA policy - 6 checks, kernel-version independent
│
└── docs/
    └── (screenshots, technical notes)
```

---

## Detection Architecture

Two independent layers - neither depends on kernel version.

### Layer 1 - Behavioral Detection (auditd + Wazuh)

The `uid!=0` filter covers users beyond interactive accounts: service accounts, containers, web shells without login sessions.

**Auditd sensor rules** (`auditd/cve-2026-43284.rules`):
```
-a always,exit -F arch=b64 -S vmsplice -F uid!=0 -k dirty_frag_vmsplice
-a always,exit -F arch=b32 -S vmsplice -F uid!=0 -k dirty_frag_vmsplice
-a always,exit -F arch=b64 -S splice   -F uid!=0 -k dirty_frag_splice
-a always,exit -F arch=b32 -S splice   -F uid!=0 -k dirty_frag_splice
-a always,exit -F arch=b64 -S unshare  -F a0&0x10000000=0x10000000 -F uid!=0 -k dirty_frag_ns_escape
-a always,exit -F arch=b64 -S add_key  -F uid!=0 -k dirty_frag_add_key
-a always,exit -F arch=b64 -S socket   -F a0=0x23 -F uid!=0 -k dirty_frag_rxrpc_socket
-w /usr/bin/kmod -p x -k dirty_frag_modload
-w /usr/bin/su   -p x -k dirty_frag_execve_su
```

### Layer 2 - SCA Policy (`sca/cve_2026_43284.yml`)

Automated configuration checks every 12 hours. No kernel version required.

### Rule Architecture

| Rule | Parent | Signal | Depth | Level |
|---|---|---|---|---|
| 80700 | decoded_as=auditd | auditd anchor (Wazuh built-in) | 0 | 0 |
| **200000** | 80700 | vmsplice() by non-root - pipe header plant | **1** | **10** |
| **200001** | 80700 | splice() by non-root - page cache plant | **1** | **10** |
| **200007** | 200001 + if_matched=200000 | EXPLOIT CHAIN - vmsplice+splice same pid/120s | 2 | **15** |
| **200002** | 80700 | unshare(CLONE_NEWUSER) by non-root | **1** | **12** |
| **200003** | 80700 | add_key() by non-root - RxRPC key plant | **1** | **8** |
| **200004** | 80700 | socket(AF_RXRPC) by non-root | **1** | **10** |
| **200008** | 200001 + if_matched=200004 | RXRPC CHAIN - AF_RXRPC+splice same pid/120s | 2 | **15** |
| **200005** | 80700 | kmod/modprobe execution | **1** | **12** |
| **200006** | 80700 | /usr/bin/su execution | **1** | **6** |

> **Detection note:** Unlike Copy Fail (Python stdlib PoC), the Dirty Frag public PoC is compiled C. Rules 200000-200008 are all anchored at depth 1 under 80700 (not under 92600) and cover all languages equally — C, Go, Rust, recompiled variants, web shells.

> **Key differentiator:** `vmsplice()` (rule 200000) is unique to Dirty Frag and absent from Copy Fail. The vmsplice + splice chain from the same PID (rule 200007) provides a high-fidelity signal with very low false-positive rate.

---

## Deployment

### Step 1 - Install auditd

```bash
# Ubuntu / Debian / Kali
apt install auditd audispd-plugins -y
systemctl enable --now auditd
```

```bash
# RHEL / AlmaLinux / CentOS
yum install audit -y
systemctl enable --now auditd
```

```bash
# SUSE
zypper install audit -y
systemctl enable --now auditd
```

### Step 2 - Deploy auditd sensor rules

```bash
cp auditd/cve-2026-43284.rules /etc/audit/rules.d/
augenrules --load
auditctl -l | grep dirty_frag
```

Expected output:
```
-a always,exit -F arch=b64 -S vmsplice -F uid!=0 -F key=dirty_frag_vmsplice
-a always,exit -F arch=b32 -S vmsplice -F uid!=0 -F key=dirty_frag_vmsplice
-a always,exit -F arch=b64 -S splice   -F uid!=0 -F key=dirty_frag_splice
...
```

### Step 3 - Deploy Wazuh detection rules

```bash
# Option A - standalone file
cp rules/local_rules.xml /var/ossec/etc/rules/dirty-frag-rules.xml

# Option B - append to existing local_rules.xml
cat rules/local_rules.xml >> /var/ossec/etc/rules/local_rules.xml
```

```bash
# Validate - must exit 0 with zero warnings
/var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5
systemctl restart wazuh-manager
```

### Step 4 - Deploy SCA policy

```bash
cp sca/cve_2026_43284.yml /var/ossec/etc/shared/default/
```

Add to `ossec.conf` inside the `<sca>` block:

```xml
<policies>
  <policy>/var/ossec/etc/shared/default/cve_2026_43284.yml</policy>
</policies>
```

### Step 5 - Configure ossec.conf localfile

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

---

## Validation (Quick Test - No Exploit)

```bash
# Create test user
useradd -m testuser 2>/dev/null || true

# SIGNAL 1 - vmsplice (requires root to run dd-like test, or use test binary)
# Generate the signal with a pipe test
su - testuser -c "python3 -c \"
import os, ctypes, struct
libc = ctypes.CDLL('libc.so.6', use_errno=True)
pr, pw = os.pipe()
buf = (ctypes.c_char * 8)(b'AAAAAAAA')
iov = struct.pack('PP', ctypes.addressof(buf), 8)
iov_arr = ctypes.create_string_buffer(iov)
libc.vmsplice(pw, ctypes.addressof(iov_arr), 1, 0)
print('vmsplice signal generated')
os.close(pr); os.close(pw)
\""

# SIGNAL 2 - splice
su - testuser -c "python3 -c \"
import os
fd = os.open('/usr/bin/su', os.O_RDONLY)
pr, pw = os.pipe()
os.splice(fd, pw, 8)
print('splice signal generated')
os.close(fd); os.close(pr); os.close(pw)
\""

# SIGNAL 4 - add_key
su - testuser -c "python3 -c \"
import ctypes
libc = ctypes.CDLL('libc.so.6', use_errno=True)
# Attempt rxrpc key - will fail but generates the audit event
libc.syscall(248, b'user', b'test_dirty_frag', b'data', 4, -4) # KEY_SPEC_PROCESS_KEYRING
print('add_key signal generated')
\""

# Verify Wazuh captured events
grep -E "200000|200001|200003" /var/ossec/logs/alerts/alerts.log | tail -10
```

---

## Remediation

### ⚠️ CRITICAL - Read Before Applying ESP Mitigation

> **Blacklisting `esp4`/`esp6` BREAKS IPsec tunnels** (strongSwan, Libreswan, Openswan). Do NOT apply the esp4/esp6 blacklist on hosts that terminate or transit IPsec VPN connections. Apply only the `rxrpc` blacklist on IPsec hosts.

### Immediate Mitigation

**For all hosts (safe - rxrpc is not used outside AFS):**
```bash
rmmod rxrpc 2>/dev/null || true
echo 'install rxrpc /bin/false' >> /etc/modprobe.d/dirtyfrag.conf
```

**For non-IPsec hosts only (breaks IPsec tunnels):**
```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf; \
  rmmod esp4 esp6 rxrpc 2>/dev/null; \
  echo 3 > /proc/sys/vm/drop_caches"
```

> The `echo 3 > /proc/sys/vm/drop_caches` clears any page cache that may have been contaminated by exploitation attempts prior to mitigation.

### Permanent Fix

**CVE-2026-43284 (ESP variant):**
Apply kernel commit `f4c50a4034e6` (mainline). It adds `SKBFL_SHARED_FRAG` flag to splice-originated frags and checks it in `esp_input`/`esp6_input` to force the `skb_cow_data()` path, preventing attacker-pinned pages from entering the dst SGL.

```bash
# Ubuntu / Debian
apt update && apt upgrade linux-generic

# RHEL / AlmaLinux (testing repo during rollout)
dnf update 'kernel*'

# SUSE
zypper update kernel-default
```

**CVE-2026-43500 (RxRPC variant):**
No patch exists in any tree yet (as of 2026-05-08). The only mitigation is `rxrpc` blacklist.

### Restore After Patching

```bash
# Remove mitigation once patched kernel is in place
rm /etc/modprobe.d/dirtyfrag.conf
```

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-04-29 | RxRPC vulnerability reported to security@kernel.org; patch submitted to netdev |
| 2026-04-30 | ESP vulnerability reported to security@kernel.org; patch submitted to netdev |
| 2026-04-30 (+9h) | Kuan-Ting Chen independently submits ESP report with reproducer |
| 2026-05-04 | Kuan-Ting Chen submits shared-frag approach patch to netdev |
| 2026-05-07 | ESP patch merged into netdev tree (f4c50a4034e6) |
| 2026-05-07 | Both vulnerabilities submitted to linux-distros@vs.openwall.org (5-day embargo) |
| **2026-05-07** | **Embargo broken by unrelated third party publishing the exploit publicly** |
| **2026-05-07** | **Full Dirty Frag disclosure with exploit published by Hyunwoo Kim** |
| 2026-05-08 | CVE-2026-43284 assigned (ESP); CVE-2026-43500 reserved (RxRPC, no patch) |

---

## Comparison with Related Vulnerabilities

| | Dirty Pipe (2022) | Copy Fail (2026-31431) | Dirty Frag ESP (2026-43284) | Dirty Frag RxRPC (2026-43500) |
|---|---|---|---|---|
| Race condition | No | No | No | No |
| Bug class | pipe_buffer overwrite | AF_ALG + splice | xfrm-ESP + splice | RxRPC + splice |
| Namespace needed | No | No | Yes (CLONE_NEWUSER) | **No** |
| Privilege needed | None | None | CLONE_NEWUSER | **None** |
| Bypasses Copy Fail mitigation | N/A | N/A | **Yes** | **Yes** |
| Module dependency | None | algif_aead | esp4/esp6 | rxrpc |
| FIM detection | No | No | No | No |
| PoC language | C | Python stdlib | C | C |
| Affected since | 2022 | 2017 | 2017 | 2023 |

---

## SCA Policy Summary

| Check | Title | Risk |
|---|---|---|
| 43284001 | esp4 not loaded in memory | CRITICAL |
| 43284002 | esp6 not loaded in memory | CRITICAL |
| 43284003 | rxrpc not loaded in memory | HIGH |
| 43284004 | esp4/esp6/rxrpc disabled via modprobe.d | HIGH |
| 43284005 | auditd active and running | HIGH |
| 43284006 | CVE-2026-43284 sensor rules deployed | HIGH |

---

## Related Work

- [COPY-FAIL Detection with Wazuh 4.14.4](https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4) - Detection engineering for CVE-2026-31431 (the predecessor vulnerability that motivated Dirty Frag research)
- [Unified-Sysmon-Configs](https://github.com/mym0us3r/Unified-Sysmon-Configs) - Wazuh detection ruleset for Windows endpoint (Sysmon Native + Legacy)

---

## Author

**Kislley Rodrigues (m0us3r)**
Wazuh Ambassador | Detection Engineering | Blue Team

---

## Acknowledgments

- **Hyunwoo Kim (@v4bel)** for discovering, researching, and publishing Dirty Frag with full technical detail and a working exploit
- **Kuan-Ting Chen** for the shared-frag approach kernel patch (f4c50a4034e6)
- **Wazuh Team** for the open SIEM/XDR platform and Ambassador Program
- **CloudLinux / KernelCare** for the rapid mitigation advisory

---

*Detection rules, auditd sensor configuration and SCA policy produced as part of the Wazuh Ambassador Program. Validated on Wazuh 4.14.4.*
