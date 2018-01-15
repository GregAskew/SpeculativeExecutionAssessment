# SpeculativeExecutionAssessment
Assesses a system for the "speculative execution" vulnerabilities described in:
 CVE-2017-5715 (branch target injection)
 CVE-2017-5753 (bounds check bypass)
 CVE-2017-5754 (rogue data cache load)

WARNING: Ensure that "Prefer 32-bit" is not checked in the build options.
Requires elevated permissions
Mitigiation requires:
 1. Set the registry value indicating the antivirus/security product is compatible with the Windows update
 2. Install the Windows operating system update (part of the January 2018 Security Monthly Quality Rollup)
 3. Enable the registry settings
 4. Update the hardware/firmware
 5. On virtual platforms, the hypervisor must be updated (or for Hyper-V, it may be reconfigured)
