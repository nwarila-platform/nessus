# Tech debt register

## TD-001 — CLOSED 2026-09-30 — the runner can read the Nessus deployment objects

- **Recorded and closed:** 2026-09-30.
- **Original issue:** the playbook reads four objects under `<account-id>-ansible/applications/nessus/`,
  and live `nwarila-platform_nessus_runner_s3` granted none of them.
- **Closure evidence:**
  - The desired document, carrying the `ReadOnlyTheNessusDeploymentObjects` statement, was
    published as the policy's default version v2.
  - The live export of v2, tokenized, is byte-identical to
    `dependencies/aws/policies/nwarila-platform_nessus_runner_s3.json`.
  - `iam simulate-principal-policy` for the runner allowed `s3:GetObject` on each of the four
    objects and on the installer, and denied an undeclared key under the same prefix.
  - `divergence.not_yet_applied` is empty.

## TD-002 — OPEN — the scanner has no route to anything worth scanning

- **Recorded:** 2026-09-30.
- **Issue:** the bed proves a registered scanner serving validated HTTPS. It does not prove a
  scan. The host joins no directory, opens no tunnel onto the private network, and its egress is
  HTTPS alone. The reference repository reaches its targets through the framework's
  `remote_client` and a target it builds beside itself; this repository has neither yet.
- **Exit criteria:** a scan target is built beside the scanner, the scanner reaches it, and the
  pipeline proves a completed scan of it through the API.

## TD-003 — CLOSED 2026-09-30 — `/opt/nessus` is its own data volume

- **Recorded and closed:** 2026-09-30.
- **Original issue:** plugins, scan results and the imported certificate lived under `/opt/nessus`
  on the root filesystem of an ephemeral OS disk, so nothing survived an OS replacement.
- **Closure evidence:**
  - Run 36773018135 converged green onto a standalone `Function=NESSUS` volume mounted at
    `/opt/nessus` by `linux_disk_manager`, and its second converge reported `changed=0`.
  - Run 36779428440 gave a new instance a volume restored from a snapshot of that run's. The disk
    was adopted unformatted and the package reinstalled. The settings, certificate and account were found
    intact: none rewritten, re-imported or re-created.
  - The lab rehearsal showed the same when the volume moved between machines with different
    hostnames and machine-ids.
- **What remains is licensing, not the volume.** An `os_swap` run cannot yet pass end to end,
  because the replacement machine must register again and an Essentials code registers once
  (TD-007).

## TD-004 — OPEN — software self-updates are switched off but proven only by their effect

- **Recorded:** 2026-09-30. **Updated:** 2026-10-01.
- **Issue:** `nessuscli fix --set` accepts any name, so storing `disable_core_updates=yes` does not
  prove Nessus honours it. That was measured on 2026-09-30: an unknown name is stored as readily
  as a real one.
- **Progress (2026-10-01):** both switches are now known to be real. The product's own catalogue
  lists `disable_core_updates` ("Disable software updates on this managed scanner") and
  `auto_update_ui` ("Automatically download and apply Nessus updates"), and the role refuses any
  name the catalogue lacks. The first describes a *managed* scanner, so the role now sets both:
  `disable_core_updates: yes` and `auto_update_ui: no`.
- **Mitigation in place:** every converge asserts that the installed RPM version equals the pin,
  and the idempotency gate fails on any change. A core self-update surfaces as a failed run, not
  as silent drift.
- **Exit criteria:** a held bed that has passed a feed update with a newer core available still
  reports the pinned version.

## TD-005 — OPEN — the reference inventory still names platform-python for RHEL

- **Recorded:** 2026-09-30.
- **Issue:** this repository's inventory differs from the reference inventory in two keys that a
  STIG-hardened RHEL host needs: the Python 3.12 interpreter and pipelining. Both are ignored by
  Windows connections. See `ansible/inventory/README.md`.
- **Exit criteria:** the reference inventory carries both, and this repository's copy is
  byte-identical to it outside the "This Repository" region again.

## TD-006 — OPEN — no PowerShell gate, because there is no PowerShell

- **Recorded:** 2026-09-30.
- **Issue:** the reference repository carries `.github/workflows/powershell.yml`, a thin caller for
  the organization's pester-matrix. At the reference pin (#34) that matrix refuses an empty
  discovery by design ("an empty matrix passing would hide a broken path"), and this repository
  has no `<Name>.ps1` + `<Name>.pester.ps1` pair: every run of the copied caller failed on
  2026-09-30 for that reason alone. Carrying a workflow that can only fail, or a placeholder script
  to feed it, would be worse than carrying none.
- **Exit criteria:** the first script pair lands under `scripts/` together with the reference
  `powershell.yml`, byte-identical to the reference, and its matrix passes.

## TD-007 — OPEN — a Nessus Essentials code registers one scanner, once, and registrations are machine-bound

- **Recorded:** 2026-09-30.
- **Issue:** the licence is Nessus Essentials: 5 IPs, one account. Its activation code registers
  exactly one scanner; a second registration of the same code was refused with HTTP 400 (runs
  36763608707 and 36779428440). Tenable also binds a registration to the machine: an adopted
  scanner on a new instance reports itself unregistered (run 36779428440). So every new
  machine — every run, and every OS-drive replacement — needs a fresh code, and a run without
  one goes red at registration, by name.
- **Decision (2026-09-30):** keep the ephemeral lifecycle; the owner supplies a fresh code per
  registering run. No copy of the registration's own records avoids that: run 36779428440
  carried every one of them onto a new instance, which still reported unregistered. For the same
  reason the snapshot-based `preserve_data` flag was withdrawn the same day. It carried the data
  between runs, but not the registration it was wanted for. Since 2026-10-05 the deploy runs only
  when dispatched, and the code is typed into its `activation_code` input, masked in the logs and
  never stored: a push or a schedule has no code to give, and every scheduled run before then
  failed.
- **Exit criteria:** a licence whose code re-registers on a new host (Professional or Expert), so
  that ordinary runs and OS-drive replacements stop consuming codes, and an `os_swap` run passes
  end to end.

## TD-008 — OPEN — the sign-in banner waits on the organization's text

- **Recorded:** 2026-10-01.
- **Issue:** a system-use notice before sign-in is a common STIG control (AC-8), and Nessus shows
  one through `login_banner`. The text is the organization's to write: the DoD Notice and Consent
  Banner applies only to DoD systems, and `acas_classification` only to systems that carry a
  classification marking. Both stay empty until that text is chosen.
- **Exit criteria:** the playbook sets `login_banner` to the approved text, and a deploy shows it on
  the sign-in page.

## TD-009 — ACCEPTED — the host firewall is nftables, not firewalld

- **Recorded:** 2026-10-01.
- **Decision:** the owner chose nftables directly as the host firewall: "mask firewalld, make the
  role itself not care". The playbook masks firewalld and writes `/etc/sysconfig/nftables.conf`.
  That ruleset is the host's whole filter:
  - policy drop on input and forward;
  - established traffic and loopback accepted, with spoofed loopback dropped;
  - ICMP accepted;
  - SSH and, while the scanner is present, its listener accepted, with new connections
    rate-limited.
  The role no longer manages any firewall.
- **Effect on the RHEL 8 STIG:** firewalld stays installed but masked. RHEL-08-040100 (a firewall
  installed) is still met. Its companion check that firewalld is *active* reports open, and
  RHEL-08-040150 (firewalld's nftables backend) no longer applies, because nftables is used
  directly. These are deviations by decision. The nftables ruleset is the mitigation, and its
  rate limits carry RHEL-08-040150's intent.
- **Exit criteria:** none while the decision stands. Revisit if the fleet's STIG evidence must
  show firewalld active.

## TD-010 — OPEN — check mode covers the role, not the playbook or the S3 fetch

- **Recorded:** 2026-10-01.
- **Issue:** the role supports `--check` on its present and absent paths. Reads run for real;
  steps that need the product installed are skipped whenever the pinned version is not installed,
  and steps that depend on an earlier change in the same run are skipped under `--check`. Setting
  drift, the service's enable and start, and an install that is due (as its fetch) are reported as
  changed. Not covered:
  - The playbook's own tasks and the framework roles it composes are not check-mode-proven.
  - The two S3 fetches keep pdq-deploy-inventory's form (no `check_mode: false`), so under
    `--check` nothing is downloaded, and the framework loader creates no temporary directory to
    stage into. The steps that read a fetched or staged file are skipped -- the bundle's decode,
    the certificate reads and the HTTPS steps that trust the CA decoded from it -- so certificate
    and administrator-password drift are not reported. That `s3_object` reports a skipped get as
    changed is read from amazon.aws 11.4.0's source ("GET operation skipped - running in check
    mode"), never run: the lab replaces the fetch, and the deploy never runs `--check`.
  - The signing-key trust, a missing administrator account and a lost registration are read, but
    their writes are skipped and only settings have a "would write" report; reporting them the
    same way is possible later work. The install-root relabel is skipped outright.
  - END proves what PROCESS did, so a check run skips it.
- **Exit criteria:** a held bed converged with `--check` from the real controller shows the fetch
  path skipping cleanly, and the playbook's own check-mode behaviour is decided.

## TD-011 — CLOSED 2026-10-01 — the settled-registration read is removed

- **Recorded:** 2026-10-01. **Closed:** 2026-10-01.
- **Original issue:** `PROCESS | Read Whether The Settled Scanner Is Registered`
  (`nessuscli fetch --check`) ran when the readiness wait settled on 'register', to decide the one
  restart that clears a stale setup state.
- **Closure evidence:**
  - The read and the restart's clause on it are removed. Control flow ran the read only on a
    scanner whose registration had just been confirmed: the scanner was already registered
    (`nessuscli fetch --check` answered 0), or `PROCESS | Require The Registration To Succeed`
    passed, in a block with no rescue.
  - Parity, when the read was removed: where it answered 0, the restart ran exactly as before. On
    a registered scanner where it would have answered non-zero, the restart then ran where, with
    the read, the readiness require would have failed for certain. A scanner that is genuinely
    unregistered still failed loudly: at the sign-in once its API closed, else at END's registration
    proof.
  - The stale-'register' restart never ran in a deploy: the three AWS deploys that reached it
    (36765880901, 36773018135, 36837460712) settled on 'ready'. It ran once in a lab run, on a stale
    state made by hand (an account added to a running scanner), which it cleared. It was then
    removed too: the service is restarted after the account is created, before registration and the
    readiness wait, so no start that wait depends on lacks the account.

## TD-012 — OPEN — the fapolicyd trust refresh may be redundant

- **Recorded:** 2026-10-01.
- **Issue:** `PROCESS | Refresh The fapolicyd Trust Database After The Install` runs
  `fapolicyd-cli --update` after every install while fapolicyd is active, and
  `BEGIN | Read Whether fapolicyd Is Running` exists for it. On EL8, fapolicyd requires
  `rpm-plugin-fapolicyd`, which rpm's default macros enable and which gives fapolicyd each new
  file's digest during the transaction itself, so the refresh probably adds nothing. It is kept
  because removing it can be proven only on the STIG image with fapolicyd enforcing.
- **Exit criteria:** an AWS deploy on the STIG AMI that records
  `rpm -q fapolicyd rpm-plugin-fapolicyd`, freshly installs with both tasks removed and fapolicyd
  active, passes END, and reports changed=0 on its second converge.

## TD-013 — OPEN — the Essentials licence imposes usage telemetry and the in-app guides

- **Recorded:** 2026-10-05.
- **Issue:** the role hardened `send_telemetry` to `no` and `disable_guides` to `yes`, and the
  merge deploy of #26 (run 37063488799) failed its idempotency gate because the second converge
  found both changed back. A lab bisection on Nessus 10.12.4 isolated the cause:
  - registration alone (`nessuscli fetch --register-only`, no download) rewrites exactly those two
    values to `yes` and `no`;
  - written back, they revert at the next start, and on a running scanner at a backend reload
    whose trigger was not isolated (within three minutes in the lab);
  - the backend log shows the Essentials licence payload re-applied at each.

  The two settings are therefore left to Nessus (`~`): usage telemetry is sent and the in-app
  guides are shown, as the licence requires. The reads are recorded in the pull request that
  opened this entry.
- **Exit criteria:** a licence under which a lab scanner keeps `send_telemetry: no` and
  `disable_guides: yes` through a restart and a backend reload; then both are declared again and
  marked `Hardened:`.
