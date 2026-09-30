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
  - Run 36779428440 seeded a new instance's volume from that run's snapshot. The disk was adopted
    unformatted and the package reinstalled. The settings, certificate and account were found
    intact: none rewritten, re-imported or re-created.
  - The lab rehearsal showed the same when the volume moved between machines with different
    hostnames and machine-ids.
- **What remains is licensing, not the volume.** An `os_swap` run cannot yet pass end to end,
  because the replacement machine must register again and an Essentials code registers once
  (TD-007).

## TD-004 — OPEN — `disable_core_updates` is declared but proven only by its effect

- **Recorded:** 2026-09-30.
- **Issue:** `nessuscli fix --set` accepts any name, so storing `disable_core_updates=yes` does not
  prove Nessus honours it. That was measured on 2026-09-30: an unknown name is stored as readily
  as a real one.
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
  36763608707 and 36779428440). Tenable also binds a registration to the machine: a preserved
  scanner on a new instance reports itself unregistered (run 36779428440). So every new
  machine — every run, and every OS-drive replacement — needs a fresh code, and a run without
  one goes red at registration, by name.
- **Decision (2026-09-30):** keep the ephemeral lifecycle; the owner supplies a fresh code per
  registering run. Everything else carries between runs on the preserved data disk, which every
  run adopts when one exists. No backup of the registration's own records can carry it: run
  36779428440 restored all of them onto a new instance, which still reported unregistered.
- **Exit criteria:** a licence whose code re-registers on a new host (Professional or Expert), so
  that ordinary runs and OS-drive replacements stop consuming codes, and an `os_swap` run passes
  end to end.
