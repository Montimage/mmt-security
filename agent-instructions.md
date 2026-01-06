# MMT-Security: AI Agent Installation Instructions

This document provides comprehensive instructions for an AI agent to perform a complete, from-scratch installation and setup of the MMT-Security project. The installation follows a **three-phase execution model** with explicit user approval gates between phases.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Three-Phase Execution Model](#three-phase-execution-model)
3. [Phase 1: Research](#phase-1-research)
4. [Phase 2: Plan](#phase-2-plan)
5. [Phase 3: Execute](#phase-3-execute)
6. [Dependency Reference](#dependency-reference)
7. [Platform-Specific Instructions](#platform-specific-instructions)
8. [Verification Commands](#verification-commands)
9. [Rollback Strategies](#rollback-strategies)
10. [Troubleshooting Guide](#troubleshooting-guide)

---

## Project Overview

**MMT-Security** is a C-based network intrusion detection system developed by Montimage. It analyzes network traffic against 95+ security rules to detect abnormalities, attacks, and protocol violations.

### Key Components

| Component | Description |
|-----------|-------------|
| `compile_rule` | Encodes XML rules into shared libraries (.so) |
| `rule_info` | Displays information about compiled rules |
| `mmt_sec_standalone` | Analyzes real-time traffic or PCAP files |
| `mmt_sec_server` | Analyzes metadata from mmt-probe |
| `libmmt_security2` | Core library (static .a and shared .so) |

### Version Information

- **Current Version**: 1.2.19
- **Build System**: GNU Make
- **Primary Platform**: Linux (Debian/Ubuntu), partial macOS support
- **Default Installation Path**: `/opt/mmt/security`

---

## Three-Phase Execution Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     PHASE 1: RESEARCH                           │
│  Gather information, detect environment, identify requirements  │
│                                                                 │
│  Output: research.md                                            │
│  Gate: USER APPROVAL REQUIRED                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      PHASE 2: PLAN                              │
│  Create detailed task list with success criteria                │
│                                                                 │
│  Output: plan.md, human_tasks.md                                │
│  Gate: USER APPROVAL REQUIRED                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     PHASE 3: EXECUTE                            │
│  Execute tasks with verification, stop on any failure           │
│                                                                 │
│  Output: Installation complete or error report                  │
└─────────────────────────────────────────────────────────────────┘
```

**CRITICAL**: Do not proceed to the next phase until the user explicitly approves.

---

## Phase 1: Research

### Objective
Collect all necessary information about the installation environment and requirements.

### Task 1.1: Detect Operating System

```bash
# Detection command
uname -s

# Expected values:
# - "Linux" -> Proceed with Linux instructions
# - "Darwin" -> Proceed with macOS instructions (limited support)
```

**Success Criterion**: OS type identified
**Verification**: Command returns "Linux" or "Darwin"

### Task 1.2: Detect OS Distribution (Linux only)

```bash
# Detection command
cat /etc/os-release | grep -E "^ID=" | cut -d= -f2 | tr -d '"'

# Expected values:
# - "ubuntu", "debian" -> Use apt-get
# - "fedora", "rhel", "centos" -> Use dnf/yum
```

**Success Criterion**: Package manager identified
**Verification**: Distribution name retrieved

### Task 1.3: Check System Architecture

```bash
# Detection command
uname -m

# Expected: x86_64 (primary supported architecture)
```

**Success Criterion**: Architecture is x86_64
**Verification**: Command returns "x86_64"

### Task 1.4: Check Required Tools

```bash
# Check for gcc
gcc --version 2>/dev/null && echo "gcc: FOUND" || echo "gcc: MISSING"

# Check for make
make --version 2>/dev/null && echo "make: FOUND" || echo "make: MISSING"

# Check for git
git --version 2>/dev/null && echo "git: FOUND" || echo "git: MISSING"

# Check for wget or curl
wget --version 2>/dev/null && echo "wget: FOUND" || echo "wget: MISSING"
curl --version 2>/dev/null && echo "curl: FOUND" || echo "curl: MISSING"
```

**Success Criterion**: gcc, make, git, and (wget or curl) are available
**Verification**: All required tools report FOUND

### Task 1.5: Check Existing MMT Installation

```bash
# Check for existing MMT-DPI installation
ls -la /opt/mmt/dpi 2>/dev/null && echo "MMT-DPI: FOUND at /opt/mmt/dpi" || echo "MMT-DPI: NOT FOUND"

# Check for existing MMT-Security installation
ls -la /opt/mmt/security 2>/dev/null && echo "MMT-Security: FOUND at /opt/mmt/security" || echo "MMT-Security: NOT FOUND"

# Check for custom MMT_BASE environment variable
echo "MMT_BASE=${MMT_BASE:-not set}"
```

**Success Criterion**: Existing installation status determined
**Verification**: Paths checked and reported

### Task 1.6: Check Required Libraries

```bash
# Debian/Ubuntu
dpkg -l | grep -E "libxml2-dev|libpcap-dev|libconfuse-dev" 2>/dev/null

# Alternative: Check pkg-config
pkg-config --exists libxml-2.0 && echo "libxml2: FOUND" || echo "libxml2: MISSING"
pkg-config --exists libpcap && echo "libpcap: FOUND" || echo "libpcap: MISSING"

# Check header files directly
ls /usr/include/libxml2/libxml/parser.h 2>/dev/null && echo "libxml2-dev: FOUND" || echo "libxml2-dev: MISSING"
ls /usr/include/pcap/pcap.h 2>/dev/null && echo "libpcap-dev: FOUND" || echo "libpcap-dev: MISSING"
ls /usr/include/confuse.h 2>/dev/null && echo "libconfuse-dev: FOUND" || echo "libconfuse-dev: MISSING"
```

**Success Criterion**: Library status determined
**Verification**: Each library reports FOUND or MISSING

### Task 1.7: Check Available Disk Space

```bash
# Check space in /opt (for installation)
df -h /opt 2>/dev/null || df -h /

# Check space in current directory (for build)
df -h .

# Minimum requirements:
# - Build directory: ~500MB
# - Installation: ~100MB
```

**Success Criterion**: At least 1GB available in both locations
**Verification**: df reports sufficient space

### Task 1.8: Check User Permissions

```bash
# Check if running as root
[ "$(id -u)" -eq 0 ] && echo "Running as root" || echo "Running as non-root user"

# Check sudo availability
sudo -n true 2>/dev/null && echo "sudo: AVAILABLE without password" || echo "sudo: MAY REQUIRE PASSWORD"

# Check write access to /opt
[ -w /opt ] && echo "/opt: WRITABLE" || echo "/opt: NOT WRITABLE (need sudo)"
```

**Success Criterion**: Permission status determined
**Verification**: User can either write to /opt or has sudo access

### Task 1.9: Identify Configuration Preferences

**Questions to ask the user:**

1. **Installation Directory**: Use default `/opt/mmt/security` or custom path?
2. **Redis Support**: Enable Redis output module? (requires hiredis)
3. **Debug Build**: Build with debug symbols? (DEBUG=1)
4. **Runtime Rule Updates**: Enable add/remove rules at runtime? (default: yes)

### Research Output Template: research.md

```markdown
# MMT-Security Installation Research

## Environment Summary

| Item | Value |
|------|-------|
| Operating System | [Linux/Darwin] |
| Distribution | [ubuntu/debian/fedora/etc.] |
| Architecture | [x86_64/arm64] |
| Kernel Version | [output of uname -r] |

## Tool Availability

| Tool | Status | Version |
|------|--------|---------|
| gcc | [FOUND/MISSING] | [version] |
| make | [FOUND/MISSING] | [version] |
| git | [FOUND/MISSING] | [version] |
| wget | [FOUND/MISSING] | [version] |
| curl | [FOUND/MISSING] | [version] |

## Library Status

| Library | Status | Action Required |
|---------|--------|-----------------|
| libxml2-dev | [FOUND/MISSING] | [Install/None] |
| libpcap-dev | [FOUND/MISSING] | [Install/None] |
| libconfuse-dev | [FOUND/MISSING] | [Install/None] |
| hiredis | [FOUND/MISSING/OPTIONAL] | [Install if Redis wanted] |

## Existing Installations

| Component | Status | Path |
|-----------|--------|------|
| MMT-DPI | [FOUND/NOT FOUND] | [path or N/A] |
| MMT-Security | [FOUND/NOT FOUND] | [path or N/A] |

## Disk Space

| Location | Available | Required | Status |
|----------|-----------|----------|--------|
| Build Directory | [X GB] | 500 MB | [OK/INSUFFICIENT] |
| Install Directory | [X GB] | 100 MB | [OK/INSUFFICIENT] |

## Permissions

| Permission | Status |
|------------|--------|
| Root access | [YES/NO] |
| Sudo available | [YES/NO] |
| /opt writable | [YES/NO] |

## Ambiguities and Questions

1. [List any unclear items requiring user input]
2. [List optional features requiring user decision]

## Recommendations

1. [Recommended installation approach]
2. [Any warnings or considerations]
```

### User Verification Prompt

```
=== PHASE 1 COMPLETE: RESEARCH ===

I have completed the research phase and documented my findings in research.md.

Key Findings:
- Operating System: [OS]
- Missing Dependencies: [list or "None"]
- Existing Installation: [Yes/No]
- Estimated Installation Time: [X minutes]

Please review research.md for detailed findings.

Questions requiring your input:
1. [Question 1]
2. [Question 2]

Do you approve proceeding to Phase 2 (Planning)?
[YES/NO]
```

**STOP AND WAIT FOR USER APPROVAL BEFORE PROCEEDING TO PHASE 2**

---

## Phase 2: Plan

### Objective
Create a comprehensive, detailed plan for installation and setup based on approved research findings.

### Task 2.1: Generate Task Sequence

Based on research findings, generate a numbered task list. The following is the **complete task template** - skip tasks that are not needed based on research.

### Complete Task Sequence Template

#### Section A: System Preparation

**Task A.1: Install Build Tools** (if missing)
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential git wget

# Fedora/RHEL
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git wget
```
- **Success Criterion**: gcc, make, git available
- **Verification**: `gcc --version && make --version && git --version`
- **Rollback**: `sudo apt-get remove build-essential` (rarely needed)
- **Risk Level**: LOW

**Task A.2: Install Required Libraries**
```bash
# Debian/Ubuntu
sudo apt-get install -y libxml2-dev libpcap-dev libconfuse-dev

# Fedora/RHEL
sudo dnf install -y libxml2-devel libpcap-devel libconfuse-devel
```
- **Success Criterion**: All library headers available
- **Verification**:
  ```bash
  ls /usr/include/libxml2/libxml/parser.h && \
  ls /usr/include/pcap/pcap.h && \
  ls /usr/include/confuse.h && \
  echo "SUCCESS"
  ```
- **Rollback**: `sudo apt-get remove libxml2-dev libpcap-dev libconfuse-dev`
- **Risk Level**: LOW

**Task A.3: Install hiredis** (OPTIONAL - only if Redis support requested)
```bash
# Option 1: From package manager (if available)
sudo apt-get install -y libhiredis-dev

# Option 2: From source
git clone https://github.com/redis/hiredis.git /tmp/hiredis
cd /tmp/hiredis
make
sudo make install
sudo ldconfig
cd -
rm -rf /tmp/hiredis
```
- **Success Criterion**: hiredis library installed
- **Verification**: `ls /usr/local/lib/libhiredis.* || ls /usr/lib/*/libhiredis.*`
- **Rollback**: `sudo rm -f /usr/local/lib/libhiredis.* /usr/local/include/hiredis/`
- **Risk Level**: LOW
- **Permission Gate**: YES - requires user approval for optional component

#### Section B: MMT-DPI Installation

**Task B.1: Download MMT-DPI Package**
```bash
# Detect architecture
ARCH=$(uname -m)
OS=$(uname -s)

# Download URL
MMT_DPI_VERSION="1.7.7"
MMT_DPI_HASH="bb5a717"
DPI_URL="https://github.com/Montimage/mmt-dpi/releases/download/v${MMT_DPI_VERSION}/mmt-dpi_${MMT_DPI_VERSION}_${MMT_DPI_HASH}_${OS}_${ARCH}.deb"

# Download
wget -O /tmp/mmt-dpi.deb "${DPI_URL}"
```
- **Success Criterion**: DEB file downloaded
- **Verification**: `ls -la /tmp/mmt-dpi.deb && file /tmp/mmt-dpi.deb | grep -q "Debian"`
- **Rollback**: `rm -f /tmp/mmt-dpi.deb`
- **Risk Level**: LOW

**Task B.2: Install MMT-DPI Package**
```bash
sudo dpkg -i /tmp/mmt-dpi.deb
sudo ldconfig
```
- **Success Criterion**: MMT-DPI installed at /opt/mmt/dpi
- **Verification**:
  ```bash
  ls /opt/mmt/dpi/lib/libmmt_core.so && \
  ls /opt/mmt/dpi/include/mmt_core.h && \
  echo "SUCCESS"
  ```
- **Rollback**: `sudo dpkg -r mmt-dpi`
- **Risk Level**: MEDIUM
- **Permission Gate**: YES - system package installation

#### Section C: MMT-Security Build

**Task C.1: Clone/Update Repository** (if not already present)
```bash
# If starting fresh
git clone https://github.com/Montimage/mmt-security.git
cd mmt-security

# If updating existing
cd mmt-security
git fetch origin
git checkout main
git pull origin main
```
- **Success Criterion**: Repository available and up-to-date
- **Verification**: `ls Makefile && git log -1 --format="%H"`
- **Rollback**: `rm -rf mmt-security`
- **Risk Level**: LOW

**Task C.2: Clean Previous Build** (if applicable)
```bash
make clean-all
```
- **Success Criterion**: Build artifacts removed
- **Verification**: `[ ! -f mmt_sec_standalone ] && echo "CLEAN"`
- **Rollback**: N/A
- **Risk Level**: LOW

**Task C.3: Generate DPI Header**
```bash
# Set library path for mmt-dpi
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH

# Build generates the header automatically
make gen_dpi
```
- **Success Criterion**: DPI header generated
- **Verification**: `ls src/dpi/mmt_dpi.h && echo "SUCCESS"`
- **Rollback**: `rm -f src/dpi/mmt_dpi.h`
- **Risk Level**: LOW

**Task C.4: Compile MMT-Security**
```bash
# Set library path
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH

# Standard build
make

# OR Debug build (if requested)
make DEBUG=1

# OR with Redis support
make REDIS=1

# OR combined
make DEBUG=1 REDIS=1
```
- **Success Criterion**: All binaries compiled
- **Verification**:
  ```bash
  ls compile_rule && \
  ls rule_info && \
  ls mmt_sec_standalone && \
  ls mmt_sec_server && \
  ls libmmt_security2.so && \
  ls libmmt_security2.a && \
  echo "SUCCESS"
  ```
- **Rollback**: `make clean`
- **Risk Level**: LOW

**Task C.5: Compile Sample Rules**
```bash
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
make sample_rules
```
- **Success Criterion**: Rule .so files generated
- **Verification**: `ls rules/*.so | wc -l` (should be > 50)
- **Rollback**: `make clean-rules`
- **Risk Level**: LOW

#### Section D: Testing

**Task D.1: Run Test Suite**
```bash
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
make check
```
- **Success Criterion**: All tests pass
- **Verification**: Output contains "All test passed!"
- **Rollback**: N/A (tests are non-destructive)
- **Risk Level**: LOW
- **Permission Gate**: NO

**Task D.2: Verify Standalone Tool**
```bash
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
./mmt_sec_standalone -h
./mmt_sec_standalone -l | head -20
```
- **Success Criterion**: Help and rule list displayed
- **Verification**: Output shows available options and rules
- **Rollback**: N/A
- **Risk Level**: LOW

#### Section E: Installation

**Task E.1: Install to System** (if requested)
```bash
sudo make install INSTALL_DIR=/opt/mmt/security
```
- **Success Criterion**: Files installed to /opt/mmt/security
- **Verification**:
  ```bash
  ls /opt/mmt/security/bin/mmt_security && \
  ls /opt/mmt/security/lib/libmmt_security2.so && \
  ls /opt/mmt/security/rules/*.so && \
  echo "SUCCESS"
  ```
- **Rollback**: `sudo make uninstall`
- **Risk Level**: HIGH
- **Permission Gate**: YES - system installation

**Task E.2: Update Library Cache**
```bash
sudo ldconfig
```
- **Success Criterion**: Library cache updated
- **Verification**: `ldconfig -p | grep mmt_security`
- **Rollback**: N/A
- **Risk Level**: LOW

**Task E.3: Verify Installation**
```bash
/opt/mmt/security/bin/mmt_security -h
/opt/mmt/security/bin/mmt_security -l | head -10
```
- **Success Criterion**: Installed binary works
- **Verification**: Output shows help and rules
- **Rollback**: N/A
- **Risk Level**: LOW

#### Section F: Create Debian Package (OPTIONAL)

**Task F.1: Build DEB Package**
```bash
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
make deb
```
- **Success Criterion**: .deb file created
- **Verification**: `ls mmt-security_*.deb`
- **Rollback**: `rm -f mmt-security_*.deb`
- **Risk Level**: LOW
- **Permission Gate**: NO

### Plan Output Template: plan.md

```markdown
# MMT-Security Installation Plan

## Installation Configuration

| Setting | Value |
|---------|-------|
| Installation Path | [/opt/mmt/security or custom] |
| Build Type | [Standard/Debug] |
| Redis Support | [Yes/No] |
| Runtime Rule Updates | [Yes/No] |

## Task Sequence

### Section A: System Preparation
[Include only tasks needed based on research]

### Section B: MMT-DPI Installation
[Include if MMT-DPI not already installed]

### Section C: MMT-Security Build
[Always include]

### Section D: Testing
[Always include]

### Section E: Installation
[Include if system installation requested]

### Section F: Package Creation
[Include if DEB package requested]

## Permission Gates

The following tasks require explicit user permission:

1. Task A.3: Install hiredis (optional)
2. Task B.2: Install MMT-DPI package
3. Task E.1: System installation

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Existing installation overwrite | Check and backup first |
| Build failure | Clean and retry |
| Test failure | Review specific test output |

## Estimated Execution Time

| Section | Estimated Time |
|---------|----------------|
| System Preparation | 2-5 minutes |
| MMT-DPI Installation | 1-2 minutes |
| Build | 2-5 minutes |
| Testing | 1-3 minutes |
| Installation | 1 minute |
| **Total** | **7-16 minutes** |
```

### Human Tasks Template: human_tasks.md

```markdown
# Manual Tasks for MMT-Security Setup

This document lists tasks that require manual user intervention.

## Pre-Installation

### 1. Network Configuration (if live capture needed)
- Ensure network interface is available for capture
- Grant capture permissions if running as non-root:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip /opt/mmt/security/bin/mmt_security
  ```

### 2. Redis Server Setup (if Redis output enabled)
- Install Redis server: `sudo apt-get install redis-server`
- Start Redis: `sudo systemctl start redis`
- Verify: `redis-cli ping` (should return PONG)

## Post-Installation

### 3. Environment Configuration
Add to `~/.bashrc` or `~/.profile`:
```bash
export PATH=/opt/mmt/security/bin:$PATH
export LD_LIBRARY_PATH=/opt/mmt/security/lib:/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
```

### 4. Rule Customization
- Review rules in `/opt/mmt/security/rules/`
- Create custom rules using XML format (see doc/rule.md)
- Compile custom rules: `compile_rule output.so input.xml`

### 5. Configuration File
Copy and customize configuration:
```bash
cp /opt/mmt/security/mmt-security.conf ~/mmt-security.conf
# Edit as needed
```

## Verification Checklist

- [ ] `mmt_security -h` displays help
- [ ] `mmt_security -l` lists available rules
- [ ] Test with sample PCAP: `mmt_security -t check/pcap/1.ssh_brute.pcap`
- [ ] (If Redis) Verify output: `redis-cli keys "mmt:*"`
```

### User Verification Prompt

```
=== PHASE 2 COMPLETE: PLAN ===

I have created the installation plan in plan.md.

Summary:
- Total Tasks: [N]
- Permission Gates: [N]
- High-Risk Operations: [list]
- Estimated Time: [X] minutes

Required Manual Inputs:
[List any required inputs]

Please review:
1. plan.md - Detailed task sequence
2. human_tasks.md - Manual tasks after installation

Do you approve proceeding to Phase 3 (Execution)?
[YES/NO]
```

**STOP AND WAIT FOR USER APPROVAL BEFORE PROCEEDING TO PHASE 3**

---

## Phase 3: Execute

### Objective
Execute all planned tasks with verification and error handling.

### Pre-Execution Checklist

Before starting execution, verify:

```bash
# 1. Confirm we're in the right directory
pwd  # Should be mmt-security directory

# 2. Confirm user has approved the plan
echo "User approval confirmed: [YES/NO]"

# 3. Confirm all manual inputs are available
echo "All manual inputs received: [YES/NO]"
```

### Execution Protocol

For EACH task in the plan:

```
╔══════════════════════════════════════════════════════════════════╗
║ TASK [N]: [Task Name]                                            ║
╠══════════════════════════════════════════════════════════════════╣
║ Success Criterion: [criterion]                                   ║
║ Risk Level: [LOW/MEDIUM/HIGH]                                    ║
║ Permission Required: [YES/NO]                                    ║
╚══════════════════════════════════════════════════════════════════╝

[If HIGH risk or Permission Required]
>>> PERMISSION REQUEST: Approve execution of this task? [YES/NO]

[Execute task commands]
$ [command 1]
$ [command 2]

[Run verification]
$ [verification command]

[Report result]
>>> RESULT: [SUCCESS/FAILURE]
>>> [If FAILURE: Error details and options]
```

### Error Handling Protocol

If a task verification fails:

```
╔══════════════════════════════════════════════════════════════════╗
║ ⚠ TASK FAILURE DETECTED                                          ║
╠══════════════════════════════════════════════════════════════════╣
║ Task: [Task Name]                                                ║
║ Expected: [expected result]                                      ║
║ Actual: [actual result]                                          ║
║ Error Output:                                                    ║
║ [error details]                                                  ║
╚══════════════════════════════════════════════════════════════════╝

Options:
1. RETRY - Attempt the task again
2. RETRY WITH MODIFICATION - Adjust command and retry
3. SKIP - Skip this task (may affect later tasks)
4. ABORT - Stop installation entirely
5. ROLLBACK - Undo this task and previous tasks

Please select an option: [1/2/3/4/5]
```

**NEVER proceed past a failed task without user decision.**

### Completion Report Template

```
╔══════════════════════════════════════════════════════════════════╗
║               MMT-SECURITY INSTALLATION COMPLETE                  ║
╚══════════════════════════════════════════════════════════════════╝

## Summary

| Metric | Value |
|--------|-------|
| Total Tasks | [N] |
| Completed | [N] |
| Skipped | [N] |
| Failed | [N] |

## Completed Tasks

1. ✓ [Task name]
2. ✓ [Task name]
...

## Skipped Tasks (if any)

1. ⊘ [Task name] - Reason: [reason]
...

## Failed Tasks (if any)

1. ✗ [Task name] - Error: [error]
...

## Installation Paths

| Component | Path |
|-----------|------|
| Binaries | /opt/mmt/security/bin/ |
| Libraries | /opt/mmt/security/lib/ |
| Rules | /opt/mmt/security/rules/ |
| Headers | /opt/mmt/security/include/ |

## Quick Start

# Analyze a PCAP file
mmt_security -t /path/to/file.pcap

# Monitor live traffic (requires root or capabilities)
sudo mmt_security -i eth0

# List available rules
mmt_security -l

## Next Steps

1. Review human_tasks.md for remaining manual configuration
2. Customize rules in /opt/mmt/security/rules/
3. Read documentation in doc/

## Verification Commands

# Test installation
mmt_security -t check/pcap/1.ssh_brute.pcap -f /tmp/

# Check output
cat /tmp/mmt-security*.csv
```

---

## Dependency Reference

### Required Dependencies

| Dependency | Purpose | Installation (Debian) | Installation (Fedora) |
|------------|---------|----------------------|----------------------|
| gcc | C compiler | `apt install build-essential` | `dnf groupinstall "Development Tools"` |
| make | Build tool | `apt install build-essential` | `dnf groupinstall "Development Tools"` |
| git | Version control | `apt install git` | `dnf install git` |
| libxml2-dev | XML parsing | `apt install libxml2-dev` | `dnf install libxml2-devel` |
| libpcap-dev | Packet capture | `apt install libpcap-dev` | `dnf install libpcap-devel` |
| libconfuse-dev | Config parsing | `apt install libconfuse-dev` | `dnf install libconfuse-devel` |
| MMT-DPI | Packet inspection | Download from GitHub releases | Download from GitHub releases |

### Optional Dependencies

| Dependency | Purpose | Installation |
|------------|---------|--------------|
| hiredis | Redis output | `apt install libhiredis-dev` or build from source |
| valgrind | Memory testing | `apt install valgrind` |

### MMT-DPI Download URLs

```bash
# Linux x86_64
https://github.com/Montimage/mmt-dpi/releases/download/v1.7.7/mmt-dpi_1.7.7_bb5a717_Linux_x86_64.deb

# Check latest releases at:
https://github.com/Montimage/mmt-dpi/releases
```

---

## Platform-Specific Instructions

### Linux (Debian/Ubuntu)

```bash
# Full dependency installation
sudo apt-get update
sudo apt-get install -y build-essential git wget \
    libxml2-dev libpcap-dev libconfuse-dev

# Download and install MMT-DPI
wget -O /tmp/mmt-dpi.deb https://github.com/Montimage/mmt-dpi/releases/download/v1.7.7/mmt-dpi_1.7.7_bb5a717_Linux_x86_64.deb
sudo dpkg -i /tmp/mmt-dpi.deb
sudo ldconfig

# Build MMT-Security
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
make clean-all
make
make sample_rules
make check

# Install
sudo make install
```

### Linux (Fedora/RHEL/CentOS)

```bash
# Full dependency installation
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git wget libxml2-devel libpcap-devel libconfuse-devel

# MMT-DPI (convert DEB to RPM or build from source)
# Option 1: Use alien to convert
sudo dnf install alien
wget -O /tmp/mmt-dpi.deb https://github.com/Montimage/mmt-dpi/releases/download/v1.7.7/mmt-dpi_1.7.7_bb5a717_Linux_x86_64.deb
sudo alien -r /tmp/mmt-dpi.deb
sudo rpm -i mmt-dpi*.rpm

# Build MMT-Security
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
make clean-all
make
make sample_rules
make check

# Create RPM package
make rpm

# Install
sudo rpm -i mmt-security*.rpm
```

### macOS (Limited Support)

```bash
# Install Homebrew dependencies
brew install libxml2 libpcap confuse

# Note: MMT-DPI may need to be built from source for macOS
# Clone and build MMT-DPI first
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi
make
sudo make install

# Build MMT-Security
export MMT_DPI_DIR=/usr/local/opt/mmt-dpi  # Adjust path as needed
export LD_LIBRARY_PATH=$MMT_DPI_DIR/lib:$LD_LIBRARY_PATH
make clean-all
make
make sample_rules

# Note: Some tests may fail on macOS due to platform differences
```

---

## Verification Commands

### Post-Build Verification

```bash
# Verify all binaries were built
ls -la compile_rule rule_info mmt_sec_standalone mmt_sec_server

# Verify libraries were built
ls -la libmmt_security2.so libmmt_security2.a

# Verify rules were compiled
ls rules/*.so | wc -l  # Should be > 50

# Check binary functionality
./mmt_sec_standalone -h
./rule_info | head -20
```

### Post-Installation Verification

```bash
# Verify installation paths
ls -la /opt/mmt/security/bin/
ls -la /opt/mmt/security/lib/
ls -la /opt/mmt/security/rules/

# Verify library is loadable
ldconfig -p | grep mmt_security

# Test with sample data
/opt/mmt/security/bin/mmt_security -t check/pcap/1.ssh_brute.pcap -f /tmp/
cat /tmp/mmt-security*.csv
```

### Rule Verification

```bash
# List all available rules
./mmt_sec_standalone -l

# Get info on specific rule
./rule_info rules/1.ssh.so

# Test specific rule
./mmt_sec_standalone -t check/pcap/1.ssh_brute.pcap -f /tmp/
```

---

## Rollback Strategies

### Uninstall MMT-Security (System Installation)

```bash
# If installed via make install
sudo make uninstall

# If installed via DEB package
sudo dpkg -r mmt-security

# If installed via RPM
sudo rpm -e mmt-security

# Manual cleanup
sudo rm -rf /opt/mmt/security
sudo rm -f /etc/ld.so.conf.d/mmt-security.conf
sudo ldconfig
```

### Uninstall MMT-DPI

```bash
# If installed via DEB
sudo dpkg -r mmt-dpi

# If installed via RPM
sudo rpm -e mmt-dpi

# Manual cleanup
sudo rm -rf /opt/mmt/dpi
sudo ldconfig
```

### Clean Build Directory

```bash
# Remove all build artifacts
make clean-all

# Remove only compiled objects (keep DPI header)
make clean

# Remove only rule .so files
make clean-rules
```

### Revert to Previous State

```bash
# If using git, reset to previous state
git status
git checkout -- .
git clean -fd

# If build directory was backed up
rm -rf mmt-security
mv mmt-security.backup mmt-security
```

---

## Troubleshooting Guide

### Common Issues

#### Issue: "libmmt_core.so not found"

```bash
# Symptom
./mmt_sec_standalone: error while loading shared libraries: libmmt_core.so: cannot open shared object file

# Solution
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
# Or add permanently to /etc/ld.so.conf.d/mmt-dpi.conf
echo "/opt/mmt/dpi/lib" | sudo tee /etc/ld.so.conf.d/mmt-dpi.conf
sudo ldconfig
```

#### Issue: "mmt_dpi.h not found"

```bash
# Symptom
fatal error: mmt_dpi.h: No such file or directory

# Solution
make gen_dpi  # Regenerate the DPI header
# Or ensure MMT-DPI is installed
ls /opt/mmt/dpi/include/
```

#### Issue: "Permission denied" during installation

```bash
# Symptom
mkdir: cannot create directory '/opt/mmt': Permission denied

# Solution
sudo make install
# Or use custom directory
make install INSTALL_DIR=$HOME/mmt-security
```

#### Issue: Test failures

```bash
# Get verbose output
make check VERBOSE=1

# Check specific test log
cat /tmp/<test_name>.log

# Compare expected vs actual output
diff /tmp/mmt-security-expect.csv /tmp/mmt-security-result.csv
```

#### Issue: Missing header files

```bash
# Symptom
confuse.h: No such file or directory
# OR
libxml/parser.h: No such file or directory

# Solution (Debian/Ubuntu)
sudo apt-get install libconfuse-dev libxml2-dev

# Solution (Fedora)
sudo dnf install libconfuse-devel libxml2-devel
```

#### Issue: hiredis not found (when building with REDIS=1)

```bash
# Symptom
cannot find -lhiredis

# Solution: Build from source
git clone https://github.com/redis/hiredis.git
cd hiredis
make
sudo make install
sudo ldconfig
```

---

## Quick Reference: Essential Commands

```bash
# === SETUP ===
# Install dependencies (Debian)
sudo apt-get install -y build-essential git wget libxml2-dev libpcap-dev libconfuse-dev

# Install MMT-DPI
wget -O /tmp/mmt-dpi.deb https://github.com/Montimage/mmt-dpi/releases/download/v1.7.7/mmt-dpi_1.7.7_bb5a717_Linux_x86_64.deb
sudo dpkg -i /tmp/mmt-dpi.deb

# === BUILD ===
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
make clean-all
make
make sample_rules

# === TEST ===
make check

# === INSTALL ===
sudo make install

# === USE ===
mmt_security -t file.pcap          # Analyze PCAP
mmt_security -i eth0               # Live capture
mmt_security -l                    # List rules
mmt_security -h                    # Help

# === CLEANUP ===
make clean                         # Clean build
sudo make uninstall               # Remove installation
```

---

## Document Version

- **Version**: 1.0
- **Last Updated**: January 2026
- **Target Project Version**: MMT-Security 1.2.19
- **MMT-DPI Version**: 1.7.7
