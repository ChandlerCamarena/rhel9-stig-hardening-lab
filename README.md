# RHEL 9 DISA STIG Hardening Lab

Hardening a Red Hat Enterprise Linux 9.8 virtual machine to the DISA STIG profile with OpenSCAP and Ansible: baseline scan, generated Ansible remediation reviewed before it was applied, rescans, and a documented account of every rule that still fails.

## Goal

1. Build RHEL 9 with separate filesystems for /boot, /boot/efi, /, /home, /tmp, /var, /var/tmp, /var/log and /var/log/audit.
2. Measure an unhardened baseline against the STIG profile.
3. Generate Ansible remediation from the baseline results, review it for risky changes, and apply it.
4. Rescan, compare, and explain every remaining failure.

## Results

| Result | Baseline | After remediation pass 1 | Final |
|---|---|---|---|
| pass | 179 | 430 | 434 |
| fail | 261 | 13 | 9 |
| notapplicable | 27 | 24 | 24 |
| notchecked | 10 | 10 | 10 |
| error | 0 | 0 | 0 |
| XCCDF score (default model) | 47.79 | 95.45 | 97.04 |

477 rules are selected by the profile in every scan. Of the 261 baseline failures, 252 were fixed by the first pass. Four rules failed after pass 1 that had not failed at baseline (see Findings). The final 9 failures are explained below.

The score is the XCCDF default scoring model (weighted, group hierarchical). It is a trend metric, not a compliance percentage. The simple baseline pass rate was 179 / 440 = 40.7%.

## Environment

**Host**
- Arch Linux, QEMU 11.1.2, libvirt 12.8.0, virt-install
- VM disk on a dedicated btrfs subvolume with copy-on-write disabled (`chattr +C`), excluded from snapper snapshots

**Guest**
- Red Hat Enterprise Linux 9.8 (Plow), kernel 5.14.0-687.61.1.el9_8.x86_64
- Red Hat Developer Subscription for Individuals, installed from the boot ISO with the Red Hat CDN as the package source, updated 2026-10-31
- 4 vCPUs (host-passthrough), 4 GiB RAM, 40 GiB virtio qcow2 disk, UEFI (OVMF)
- Software selection: Server, no GUI
- FIPS mode enabled at install time (installer entry with `fips=1`)

**Tooling**
- openscap-scanner 1.3.14
- scap-security-guide 0.1.82, profile `xccdf_org.ssgproject.content_profile_stig`, which the content states is aligned to DISA STIG for RHEL 9 V2R9
- ansible-core 2.14.18 (RHEL AppStream)
- ansible.posix 1.5.4 and community.general 9.5.13 (Ansible Galaxy, pinned to versions compatible with ansible-core 2.14)

## Partition layout

| Mount point | Size | Type | Mount options after remediation |
|---|---|---|---|
| /boot/efi | 600 MiB | EFI System Partition (vfat) | nosuid |
| /boot | 1 GiB | standard partition, xfs | nosuid, nodev |
| swap | 2 GiB | LVM | |
| / | 12 GiB | LVM, xfs | defaults |
| /home | 2 GiB | LVM, xfs | nosuid, nodev, noexec |
| /tmp | 2 GiB | LVM, xfs | nosuid, nodev, noexec |
| /var | 8 GiB | LVM, xfs | nodev |
| /var/tmp | 2 GiB | LVM, xfs | nosuid, nodev, noexec |
| /var/log | 4 GiB | LVM, xfs | nosuid, nodev, noexec |
| /var/log/audit | 4 GiB | LVM, xfs | nosuid, nodev, noexec |
| /dev/shm | tmpfs | | nosuid, nodev, noexec |

Volume group `rhel_rhel9-stig` was sized "as large as possible", leaving 2.41 GiB of unallocated extents so a filling filesystem can be grown online with `lvextend -r`.

**Why separate filesystems**
- **Exhaustion isolation.** A full /tmp or a log flood cannot fill / and stop the system. auditd space thresholds are only meaningful when /var/log/audit has its own capacity.
- **Per-filesystem mount options.** nodev, nosuid and noexec apply to a whole filesystem, so /tmp cannot be noexec while it is a directory on /.
- **Hard link containment.** Hard links cannot cross filesystems, so a setuid binary cannot be hard linked into world-writable /tmp.

**What the options do**
- `nodev`: device nodes on the filesystem are not interpreted.
- `nosuid`: setuid and setgid bits are ignored.
- `noexec`: direct `execve()` fails. This is defense in depth, not a boundary: `sh /tmp/x.sh` or invoking the dynamic loader directly still runs code.

Mount options were deliberately left at installer defaults so the baseline would record them as failures and the remediation would fix them. `mounts-before.txt` and `mounts-after.txt` show the change.

## Method

1. Installed RHEL 9.8 with the layout above, FIPS at install, no security profile in the installer.
2. Updated, installed openscap-scanner and scap-security-guide, and took a shut-off libvirt snapshot (`clean-base`). Snapshot revert was tested on this UEFI VM before relying on it.
3. Baseline scan with HTML report, XCCDF results and ARF.
4. Generated an Ansible playbook from the baseline results with `oscap xccdf generate fix`. Because it is generated from results, it contains fixes only for the 261 rules that failed. It contained no FIPS mode switching tasks because the FIPS mode rules already passed.
5. Reviewed the 49,736-line playbook by risk category before running it: crypto policy, sshd, faillock, sudo, session timeouts, banners, package removal, fapolicyd, usbguard, and audit immutability and panic settings.
6. Took a `pre-remediation` snapshot.
7. Applied the playbook locally as an unprivileged user with `--become`, skipping the three fapolicyd rules (STIG IDs RHEL-09-433010, 433015, 433016). Tag selection was verified with `--list-tasks` before running.
8. Validated the new sshd configuration with `sshd -t`, reloaded sshd, and confirmed a new SSH login with the DoD banner while existing sessions stayed open.
9. Applied the fapolicyd rules last, in separate runs.
10. Rebooted and verified SSH login, sudo, mounts, audit state, FIPS state and failed units.
11. Rescanned, generated a second playbook from the post-remediation results for rules that had become applicable, applied two manual fixes, and ran a final scan.

## Ansible runs

| Run | Scope | ok | changed | failed |
|---|---|---|---|---|
| 1 | All failed rules except fapolicyd | 2933 | 483 | 0 |
| 2 | fapolicyd install, enable, default deny | 7 | 2 | 1 |
| 3 | fapolicyd default deny only, fapolicyd stopped | 6 | 2 | 0 |
| Pass 2 | usbguard audit backend, postfix relay | 7 | 2 | 0 |

## Findings

**1. fapolicyd blocked Ansible mid-run.** Run 2 installed and started fapolicyd, then the next task failed with `Operation not permitted`. The audit log shows `python3.9` (the `ansible-playbook` process) denied a read-only `openat` of its own generated module file in `~/.ansible/tmp`, with `resp=deny`, `fan_info=11` and `obj_trust=no`. Rule 11 of the active ruleset is `deny_audit perm=any all : ftype=%languages`, which denies untrusted interpreted-language files. The risk was identified during playbook review, which is why fapolicyd was sequenced last. The remaining rule was applied with fapolicyd stopped, and its final task restarted the service. Evidence: `fapolicyd-ansible-denial.txt`, `ansible-run2.log`, `ansible-run3.log`.

**2. Remediation changed which rules apply.** `configure_usbguard_auditbackend` and `postfix_prevent_unrestricted_relay` were `notapplicable` at baseline because usbguard and postfix were not installed. Pass 1 installed both packages, which made the rules applicable and failing. Their fixes could not be in the pass 1 playbook because it was generated from baseline failures. A second playbook generated from the post-remediation results fixed both. Results-based remediation is iterative.

**3. One remediation broke another rule's check.** `harden_sshd_macs_openssh_conf_crypto_policy` and `harden_sshd_macs_opensshserver_conf_crypto_policy` passed at baseline under the `FIPS` crypto policy. Pass 1 set the policy to `FIPS:STIG`, which regenerated the OpenSSH backend files. The resulting MAC list (`hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256`) no longer satisfies these checks. The backend files are generated, so editing them by hand would be overwritten by the next `update-crypto-policies` run. This is left open (see Remaining failures).

**4. Tag verification caught a missed rule.** The first exclusion of fapolicyd skipped two STIG IDs. Listing the selected tasks with `--list-tasks` showed a third fapolicyd rule (RHEL-09-433016, deny-all final rule and enforcing mode) still selected. Ansible silently ignores unknown tags, so a typo in a tag would also have gone unnoticed without this check.

**5. No Ansible fix for one rule.** `use_pam_wheel_for_su` failed at baseline and after pass 1. The generated playbook contains no task for it. It was fixed manually by uncommenting `auth required pam_wheel.so use_uid` in `/etc/pam.d/su`.

**6. sshd configuration written but not active.** Pass 1 wrote sshd settings to `/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf` but the running daemon had not reloaded, so the banner did not appear on a new login. The configuration was validated with `sshd -t` before `systemctl reload sshd`. The `00-` prefix matters because sshd uses the first value it reads for each keyword. Evidence: `sshd-effective-after.txt`.

**7. Scan results contain secrets.** Before publishing, the artifacts were searched for password hash formats. The ARF files embed OVAL system characteristics, the raw items the scanner collected, and the HTML reports display them: full `/etc/shadow` lines with the root and user password hashes, and the GRUB2 PBKDF2 password hash from `/boot/grub2/user.cfg`. The ARF and results XML files were withheld, and the hashes in the HTML reports were redacted and then verified absent by searching for the known salts. SCAP results should be handled as sensitive data, not shared as routine reports.

## Remaining failures

| Rule | Bucket | Reasoning |
|---|---|---|
| `harden_sshd_macs_openssh_conf_crypto_policy` | Needs manual action | Regression from the `FIPS:STIG` subpolicy (Finding 3). The fix is a custom crypto-policy module or an upstream content correction, not editing generated files. |
| `harden_sshd_macs_opensshserver_conf_crypto_policy` | Needs manual action | Same cause, server backend file. |
| `accounts_authorized_local_users` | Needs manual action | Compares local accounts to a site-defined list. Resolved properly by declaring the authorized accounts in a tailoring file. |
| `grub2_admin_username` | Needs manual action | Renaming the GRUB superuser means editing GRUB generator scripts. SSG provides no automated fix. |
| `selinux_context_elevation_for_sudo` | Needs manual action | Requires designing SELinux confined user mappings for administrators in sudoers. Site architecture, not a setting. |
| `chronyd_server_directive` | Needs manual action | RHEL ships a `pool` line. The STIG requires `server` lines pointing at an authoritative time source, which is site specific. |
| `network_configure_name_resolution` | Lab limitation | Requires at least two DNS servers. The libvirt NAT network provides one. |
| `sssd_enable_certmap` | Lab limitation | Maps CAC/PIV certificates to accounts. No PKI or smart cards in the lab. |
| `sysctl_user_max_user_namespaces_no_remediation` | Deliberately left alone | SSG ships no remediation on purpose. Disabling user namespaces breaks rootless containers, Flatpak and browser sandboxes. |

Two baseline failures were closed manually: `use_pam_wheel_for_su` (Finding 5) and `grub2_password` (`grub2-setpassword`).

**Not checked (10).** These require human verification and do not affect the exit code: `crypto_policy_not_overridden`, `encrypt_partitions`, `security_patches_up_to_date` (requires the remote CVE feed, not fetched in this lab), `account_temp_expire_date`, `accounts_user_home_paths_only`, `configured_firewalld_default_deny`, `libreswan_approved_tunnels`, `ssh_keys_passphrase_protected`, `sssd_has_trust_anchor`, `auditd_audispd_configure_sufficiently_large_partition`. The disks are not encrypted. Encryption at rest requires a reinstall and is a lab limitation.

## Usability impacts

- **Account lockout.** pam_faillock is enabled through authselect (`custom/hardening` profile with `with-faillock`). Three failed attempts within 900 seconds (`deny = 3`, `fail_interval = 900`) lock the account, and `unlock_time = 0` keeps it locked until an administrator runs `faillock --user <name> --reset`. Sudo password typos count toward the lockout.
- **Sudo re-authentication.** `Defaults timestamp_timeout=0`: sudo no longer caches credentials and every `sudo` prompts for a password.
- **Idle sessions.** Bash `TMOUT=600` is exported read only, so an idle shell exits after 10 minutes, and systemd-logind `StopIdleSessionSec = 600` ends idle sessions. sshd `ClientAliveInterval` and `ClientAliveCountMax` only drop unresponsive connections, not idle users.
- **noexec /home.** Nothing in a home directory can be executed directly.
- **fapolicyd.** Untrusted interpreted-language files are denied. Ansible cannot manage this host while fapolicyd is enforcing unless fapolicyd is stopped for the run or a trust exception is added for Ansible's temporary directory. Shell scripts are still allowed by rule 12 of the default ruleset.
- **Audit.** Rules are immutable until reboot (`enabled 2`) and the kernel panics on critical audit failure (`failure 2`). 76 audit rules are loaded.
- **Banners.** The DoD notice and consent banner is shown on SSH login.
- **SSH key exchange.** Under FIPS, sshd offers only NIST ECDH (P-256, P-384, P-521) and finite-field DH groups 14, 16 and 18. X25519 and the post-quantum hybrid key exchanges are unavailable, so current OpenSSH clients warn about a non post-quantum key exchange.
- **kdump.** Masked. The `crashkernel=` memory reservation remains on the kernel command line, so memory is still reserved for a crash kernel that will not run.
- **Packages removed.** tuned and iprutils were removed. Removing tuned drops the virtual-guest performance profile.
- **Kernel command line.** Added `init_on_free=1 page_poison=1 pti=on vsyscall=none audit=1 audit_backlog_limit=8192`.
- **su.** Restricted to members of wheel. `su -c id` still works for an administrator in wheel.

## FIPS state

```
/proc/sys/crypto/fips_enabled   1
fips-mode-setup --check         FIPS mode is enabled.
update-crypto-policies --show   FIPS:STIG   (FIPS before remediation)
/proc/cmdline                   contains fips=1
```

FIPS mode was enabled by booting the installer with `fips=1`. Red Hat documents `fips-mode-setup` as deprecated for switching an installed RHEL 9 system into FIPS mode, so the generated playbook contained no FIPS mode tasks.

FIPS mode is a runtime configuration: crypto libraries run self-tests and refuse non-approved algorithms. FIPS 140-3 validation is a CMVP certificate for specific module versions. The validation status of the installed module versions was not checked against CMVP certificates in this lab.

## Reproduction

Host VM creation:

```
virt-install --name rhel9-stig --osinfo rhel9.8 --memory 4096 --vcpus 4 \
  --cpu host-passthrough --boot uefi \
  --disk path=/var/lib/libvirt/images/rhel9-stig.qcow2,size=40,format=qcow2,bus=virtio \
  --cdrom /var/lib/libvirt/boot/rhel-9.8-x86_64-boot.iso \
  --network network=default,model=virtio --graphics spice --noautoconsole
```

Install with the FIPS mode installer entry and the partition layout above, register to Red Hat in the installer, then:

```
sudo dnf -y update
sudo dnf -y install openscap-scanner scap-security-guide ansible-core
ansible-galaxy collection install 'ansible.posix:==1.5.4' 'community.general:>=8.0.0,<10.0.0'
```

Baseline scan:

```
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \
  --results baseline-results.xml --results-arf baseline-arf.xml --report baseline-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Generate remediation from results:

```
oscap xccdf generate fix --fix-type ansible \
  --result-id xccdf_org.open-scap_testresult_xccdf_org.ssgproject.content_profile_stig \
  --output stig-remediation.yml baseline-results.xml
```

Apply, fapolicyd last:

```
FAPO=DISA-STIG-RHEL-09-433010,DISA-STIG-RHEL-09-433015,DISA-STIG-RHEL-09-433016
ansible-playbook -i localhost, -c local --list-tasks --skip-tags $FAPO stig-remediation.yml | grep -i fapolicyd
ansible-playbook -i localhost, -c local --become --ask-become-pass --skip-tags $FAPO stig-remediation.yml
sudo sshd -t && sudo systemctl reload sshd
ansible-playbook -i localhost, -c local --become --ask-become-pass \
  --tags DISA-STIG-RHEL-09-433010,DISA-STIG-RHEL-09-433015 stig-remediation.yml
sudo systemctl stop fapolicyd
ansible-playbook -i localhost, -c local --become --ask-become-pass \
  --tags DISA-STIG-RHEL-09-433016 stig-remediation.yml
sudo reboot
```

The second command must print nothing. Running 433015 starts fapolicyd, so in this lab run 2 combined all three IDs and failed after the service started; separating them as shown avoids that.

Rescan, second pass for newly applicable rules, manual fixes, final scan:

```
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \
  --results after-results.xml --results-arf after-arf.xml --report after-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
oscap xccdf generate fix --fix-type ansible \
  --result-id xccdf_org.open-scap_testresult_xccdf_org.ssgproject.content_profile_stig \
  --output stig-remediation-pass2.yml after-results.xml
sudo systemctl stop fapolicyd
ansible-playbook -i localhost, -c local --become --ask-become-pass \
  --tags configure_usbguard_auditbackend,postfix_prevent_unrestricted_relay stig-remediation-pass2.yml
sudo systemctl start fapolicyd
sudo systemctl restart usbguard
sudo sed -i 's/^#\(auth[[:space:]]\+required[[:space:]]\+pam_wheel\.so use_uid\)/\1/' /etc/pam.d/su
sudo grub2-setpassword
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \
  --results final-results.xml --results-arf final-arf.xml --report final-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

## Artifacts

All in `artifacts/`. The XCCDF results and ARF XML files are not published, and password and boot loader hashes in the HTML reports are replaced with `REDACTED` (see Finding 7).

| File | Contents |
|---|---|
| `versions.txt` | Scanner, content, Ansible and collection versions |
| `ds-info.txt`, `stig-profile-info.txt` | Data stream profiles and STIG profile description (V2R9) |
| `mounts-before.txt`, `mounts-after.txt` | Mount options before and after |
| `sample-rules-before.txt`, `sample-rules-after.txt` | Live state of /dev/shm, audit, faillock, kdump, IPv6 redirects, FIPS, kernel command line, failed units |
| `sshd-kex-fips.txt`, `sshd-effective-after.txt` | Effective sshd key exchange and hardened settings |
| `baseline-report.html`, `baseline-scan.log` | Baseline scan |
| `baseline-counts.txt`, `baseline-fails.txt` | Baseline counts and the 261 failed rules |
| `stig-remediation.yml` | Generated pass 1 playbook |
| `ansible-run1.log`, `ansible-run2.log`, `ansible-run3.log` | Pass 1 run logs |
| `fapolicyd-ansible-denial.txt` | Audit records of fapolicyd denying Ansible |
| `after-report.html`, `after-scan.log` | Scan after pass 1 |
| `after-fails.txt`, `after-notchecked.txt` | Failures and notchecked rules after pass 1 |
| `fixed.ids`, `still-failing.ids`, `new-failures.ids` | Rule level comparison, baseline to pass 1 |
| `stig-remediation-pass2.yml`, `ansible-pass2.log` | Second pass playbook and log |
| `final-report.html`, `final-scan.log`, `final-fails.txt` | Final scan |
| `before-after.txt`, `before-after-final.txt` | Count tables |
| `usability-verify.txt` | faillock, sudo, TMOUT and logind values, removed packages |
