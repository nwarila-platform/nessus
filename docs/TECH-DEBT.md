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

## TD-003 — OPEN — `/opt/nessus` shares the root filesystem

- **Recorded:** 2026-09-30.
- **Issue:** plugins, scan results and the imported certificate live under `/opt/nessus` on the
  root filesystem of an ephemeral OS disk. The role measures free space before registration, but
  nothing survives an OS replacement.
- **Exit criteria:** `/opt/nessus` is a standalone data volume placed by `linux_disk_manager`,
  `refresh = true` in `terraform/aws.tfvars`, and an `os_swap` proof reconverges onto it with the
  registration and scan history intact.

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
