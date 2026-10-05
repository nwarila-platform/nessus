# `nessus_scanner` role

Installs Tenable Nessus at a pinned version on a STIG-hardened RHEL 8 host and brings it up as a
registered scanner serving HTTPS with a certificate the deployment owns. In one converge it trusts
Tenable's RPM signing key, refused unless its fingerprint is the pinned one, and installs the
pinned RPM; starts the service and converges **every** Nessus setting to its declaration; imports
the declared certificate when what Nessus serves differs; creates the one administrator account
from the command line **before** registration, because the web tier reads whether setup is
complete when the service starts; registers the scanner with its activation code and fetches the
plugins; waits until Nessus reports ready **over HTTPS validated against the declared CA and
hostname**; proves the account by signing in to the API, converging its password if it moved;
and verifies the result against the machine: the installed version, the service, the
registration, and the fingerprint of the certificate the listener actually serves. Every step
reads before it writes, so a converged host reports no change.

The controller fetches the RPM and the PKCS#12 certificate bundle from S3 with its own AWS
credentials, verifies each against its pinned SHA-256, and hands the guest a copy; the role gives
the guest no cloud credentials. The guest requires the signature of the pinned vendor key before
`dnf` installs the RPM. It decodes the bundle with the system's FIPS-validated OpenSSL, and the key,
certificate and CA are checked as a set. The playbook resolves the activation code and both
passwords on the controller, and the role never logs them.

## Data volume

The role treats its install root, `/opt/nessus`, as the unit of the scanner's data: binaries,
plugins, settings, certificates, accounts and scan results. In the composed play it is its own
volume, mounted there by `linux_disk_manager` before this role runs, so the OS disk can be
replaced underneath it.

The role follows the fleet's rule for application data (PDQ, WSUS, Wazuh): **if the volume already
holds a scanner, adopt it; otherwise install one.** It decides before any package transaction,
from the installation's identity: `var/nessus/uuid` and `var/nessus/master.key`.

| The volume holds | The role |
| --- | --- |
| No identity | Installs a fresh scanner onto it |
| An identity this OS has never run (the OS was replaced) | **Adopts** it: reinstalls the package over the tree, then requires the identity to have come through byte for byte |
| The identity of the scanner this OS already runs | Converges it in place |

An adopted scanner keeps its settings, certificate and account, and the role writes none of them.
It registers again, because Tenable binds a registration to the machine. On 2026-09-30 an
adopted scanner reported itself unregistered on a new AWS instance.

An OS-swap rehearsal on RHEL 8.10 on 2026-09-30 moved the volume to a machine with a different
hostname and machine-id. The installation UUID, the account and its password, the settings and
the served certificate all carried over. The only changes were the package, the signing key and
the service, which live on the OS disk.

`restorecon` labels the install root on every converge and changes only what policy disagrees
with, because a filesystem made for it starts unlabelled.

## Composition and prerequisites

The role is overlaid into a version-pinned checkout of `nwarila-platform/ansible-framework` at run
time; it is not run directly from this repository. `tasks/main.yml` is the fleet's shared role
loader: it merges `defaults/main.yml`, the OS overlay in `vars/` and the caller's `nessus_scanner`
map, runs `tasks/validate.yml`, creates the guest temporary directory the role stages into, and
runs `<state>_redhat.yml`.

The shipped `ansible/playbooks/nessus-aws.yml` prepares the host with the framework's
`credential_resolver`, `host_readiness` and `os_bootstrap`, which installs the Python 3.12 the
inventory names because RHEL 8's own Python is below ansible-core's floor. `linux_disk_manager`
then mounts the scanner's data volume at `/opt/nessus` (except under `state=absent`), and
`nessus_scanner` runs in a play of its own. The host firewall is not the role's: that play's tasks
run after the role, mask firewalld and load a default-drop nftables ruleset that admits SSH and,
while the scanner is present, its listener (TD-009 in `docs/TECH-DEBT.md`).

The target is RHEL 8 from the CIS RHEL 8 STIG image, whose constraints shape the role (below). The
controller's Ansible environment needs the `amazon.aws` collection with supported
`boto3`/`botocore` for the S3 fetch.

## What the caller supplies

Required deployment-specific inputs carry an account id or change with every site, so the
playbook states them where a reader can see them: the installer (bucket, three-part version,
digest), the activation code, the administrator account (username and password), and the HTTPS
bundle (bucket, object key, digest and password). The installer's object key defaults to the
application repository's `<Publisher>/<Application>/<version>/<file>` layout, with the token
`<version>` replaced by `installer.version` at fetch. The listener defaults to port 8834; the
caller may change it, and any setting by name (below). Nothing under this role names an account,
bucket or secret.

`tasks/validate.yml` enforces these inputs on the controller before the role changes anything on
the guest, and a failure names the input and never prints a secret. `installer.version` is
required for every state; the artifact sources and secrets only for `present`.
[`meta/main.yml`](meta/main.yml) describes each input.

## Configuration

Universally safe values live in [`defaults/main.yml`](defaults/main.yml): the product's identity
and paths, the vendor signing key and its pinned fingerprint, the listener, the bounds on every
wait, the free space registration needs (10 GiB), and every setting.

Every setting Nessus has is declared, so every one is configured through CI/CD. For 10.12.4 that is
160: the 157 in the product's own catalogue (`nessuscli fix --show`) and the 5 it stores at install
without cataloguing, less two that are not settings of their own -- `timeout.<PLUGIN_ID>`, a
per-plugin template, and `xmlrpc_listen_port`, which `listener.port` sets (measured 2026-10-01).
They are grouped by the product's own categories, each at the product's own value unless a comment
says otherwise. To change one, set it by name in the playbook, and the next deploy converges it:

```yaml
nessus_scanner:
  settings:
    xmlrpc_idle_session_timeout: '15'
    login_banner: 'Authorized use only.'
```

On every converge the role:

- reads the catalogue and the store once, rather than once per setting;
- refuses a declared name this Nessus does not have, because `fix --set` would store a typo
  silently;
- writes only the settings whose value differs, treating `yes`/`no` and `true`/`false` as equal
  because Nessus reports booleans both ways;
- names any setting Nessus has that the declaration lacks, which is how a version bump shows up.

`~` leaves a setting to Nessus. Six are left that way by default: five that Nessus computes from
the hardware (`engine.max`, `engine.min`, `global.max_hosts`, `global.max_portscanners`,
`global.max_simult_tcp_sessions`), and `plugin_detail_locale_current`, which is state Nessus
rewrites itself. Per-plugin timeouts are declared as `timeout.<plugin id>`. Values must be quoted,
because an unquoted `yes` is a YAML boolean. The listener port has one source, `listener.port`, so
naming `xmlrpc_listen_port` in `settings` is refused.

### Hardening

There is no DISA STIG for Nessus itself, so the defaults apply the common application controls
that map onto its settings: the Application Security and Development (ASD) STIG, NIST SP 800-52r2
for TLS, and FIPS 140. Each hardened value is marked `Hardened:` in `defaults/main.yml`, and each
was proven in the lab on 2026-10-01 (RHEL 8, Nessus 10.12.4) without breaking the role or sign-in.

| Setting | Value | Control | Measured in the lab |
| --- | --- | --- | --- |
| `ssl_mode` | `tls_1_3` | NIST SP 800-52r2 | TLS 1.2 refused with a protocol-version alert; TLS 1.3 negotiates `TLS_AES_256_GCM_SHA384` and validates against the declared CA |
| `fips_mode` | `enforcing` | SC-13 | Nessus runs and its database stays readable |
| `strict_certificate_validation` | `yes` | SC-23 | Linking to a manager then needs that manager's CA trusted |
| `xmlrpc_idle_session_timeout` | `10` | ASD STIG APSC-DV-000080 | Admin sessions end after 10 idle minutes |
| `user_max_login_attempt` | `3` | AC-7 | The fourth sign-in after three failures is refused as locked; `nessuscli chpasswd`, the role's own recovery, unlocks it |
| `min_password_len`, `xmlrpc_min_password_len` | `15` | ASD STIG APSC-DV-001680 | Shorter passwords refused, from the command line too |
| `passwd_complexity` | `yes` | IA-5(1) | Nessus requires 3 of 4 character classes; the role's validation requires all 4 of the declared password |
| `passwd_notifications` | `yes` | AC-9 | Last successful and failed sign-ins shown |
| `max_sessions_per_user` | `3` | AC-10 | A fourth concurrent session is refused; the role holds one and signs out |
| `report_crashes`, `send_telemetry` | `no` | CM-7 | Nothing goes to Tenable but feed traffic |
| `disable_guides` | `yes` | CM-7 | In-app messaging off (it needs telemetry anyway) |
| `hide_activation_code` | `yes` | IA-5 | The licence secret is not shown in the interface |
| `log_details` | `yes` | AU-3 | Scan logs name the user and the scan |
| `qdb_mem_usage` | `high` | Performance | Tenable's setting for a dedicated server |

Two more are deliberate: `auto_update: yes` keeps plugins current, and `disable_core_updates: yes`
with `auto_update_ui: no` stops the software replacing itself. The installed version stays the
pinned RPM, which fapolicyd trusts by its digest.

Left at the product's value on purpose, because the hardened value breaks common use:

- `niap_mode: enforcing` pins TLS 1.2 (`ssl_mode: niap`), which conflicts with TLS 1.3 only.
- `audit_file_signature_check: yes` refuses unsigned custom audit files, a common compliance
  workflow.
- `force_pubkey_auth: yes` disables password sign-in, which the role and the interface use.
- `listen_address: 127.0.0.1` would close the listener to Security Center and linked scanners.
- `login_banner` and `acas_classification` need the organization's own text and marking (TD-008).

## HTTPS

The certificate is ONE password-protected PKCS#12 bundle: the server key, the server certificate
and the single CA that signed it.
[`scripts/mint-nessus-https.sh`](../../../scripts/mint-nessus-https.sh) mints exactly that shape.
It creates a private root CA, signs a server certificate that names the host, `localhost` and
`127.0.0.1`, and destroys the CA key.

The role never trusts the certificate on its word:

- the bundle's SHA-256 is pinned and checked on the controller, which hands the guest a copy;
- it is decoded on the guest by `/usr/bin/openssl`, the FIPS-validated module, so a bundle this
  host's crypto policy would refuse fails by name rather than half-installing;
- `nessuscli import-certs` itself refuses a key that does not open the certificate, a CA that
  did not sign it, or an expired certificate; before import the role also requires exactly one CA,
  a certificate in date for another day, and both this host's name and `localhost`;
- the readiness wait trusts **only** the declared CA and connects to `https://localhost:<port>`,
  so it cannot pass against Nessus's self-generated certificate, another CA or a name mismatch;
- finally the leaf certificate the listener serves in a live handshake must carry the declared
  fingerprint.

The plaintext key exists only between decoding and import: it is removed once the import is done,
and if PROCESS fails before then, with the loader's temporary directory when the role ends.

### Why the bundle is AES-256 and not the PKCS#12 default of older tools

RHEL 8 in FIPS mode refuses RC2, 3DES and SHA-1 MACs, the algorithms many tools still use for
PKCS#12. The mint script writes PBES2/PBKDF2 with AES-256-CBC and a SHA-256 MAC. On 2026-09-30,
RHEL 8's OpenSSL 1.1.1k decoded that form with FIPS mode forced on. A bundle exported by another
tool fails at `PROCESS | Require The Bundle To Decode`, and the message names the cause.

## STIG constraints

| Constraint | How the role meets it |
| --- | --- |
| `localpkg_gpgcheck` | Tenable's key is trusted by pinned fingerprint before `dnf` installs the RPM |
| fapolicyd denies untrusted scripts | No task stages a module as a file (no `async`); the inventory pipelines. After an install the trust database is refreshed |
| `noexec` on `/tmp`, `/var/tmp`, `/home` | Nothing staged in the loader's temporary directory is executed |
| FIPS mode | System OpenSSL decodes the bundle; RSA-3072 and SHA-256 throughout |
| Host firewall | Not the role's: the playbook's nftables ruleset is the host's filter, so the role works the same behind any firewall |

## State

- `present` (default) — install, configure, register and prove the scanner as described above.
- `absent` — stop and disable the service, remove the package, remove everything under the
  install root and withdraw the vendor signing key, then prove that neither the package nor any
  entry under the install root remains. The install root itself stays, because it is the data
  volume's mount point and the disk role's. The registration is not released with Tenable. A
  second run reports no change.
- `clean` — remove only the superseded certificate material each import leaves behind: the
  timestamped `servercert.pem.<epoch>` and `serverkey.pem.<epoch>` copies (measured 2026-09-30),
  which include superseded private keys. The product, its data and its configuration are
  untouched.

`present` and `absent` support `--check`. Reads run for real, and END, which proves what PROCESS
did, is skipped. Reported as changed: setting drift, the service's enable and start, and an install
that is due (as its fetch). Read but not reported, because the write is skipped and only settings
have a "would write" report: the signing-key trust, a missing administrator account and a lost
registration. Not read: certificate drift and administrator-password drift, because the bundle's
decode, the certificate reads and the HTTPS steps that trust its CA need a file only a real run
fetches or stages. Skipped outright: the install-root relabel. Whenever the pinned version is not
installed, the steps that need it are skipped. TD-010 records these limits; the S3 fetch path under
`--check` is unproven, because the lab replaces the fetch.

## Design invariants

- **One administrator account.** Nessus Professional and Essentials hold exactly one account, so
  `administrator` is *the* account. The product refuses a second, and a converge that meets that
  refusal fails naming it. Every account write is judged by its exit status, and a refusal fails
  naming the product's last line.
- **The pinned version is authoritative both ways.** The package is installed whenever the
  installed version differs from `installer.version`, older or newer, so `dnf` runs with
  `allow_downgrade`, and END fails if the installed version is not the pin.
- **Only the pinned vendor key's signature.** `dnf` accepts a package signed by any key the host
  trusts (measured 2026-10-01 with a distribution-signed RPM), so before installing, the role
  requires `rpm --checksig` to report a good signature by the pinned key's ID.
- **The identity survives every package transaction.** Whenever a package transaction runs over
  an existing identity (an adopted volume, or a version change in place), `var/nessus/uuid` and
  `var/nessus/master.key` are read before and after it and must come through byte for byte, or the
  converge fails naming the file.
- **Cleanup is tidiness, not recovery, except for the key material.** The controller's staging
  directory holds the certificate bundle, so it is removed in PROCESS's `always`, whether PROCESS
  succeeds or fails, before any pending restart is applied; a run from a workstation is not
  ephemeral. The loader removes its guest temporary directory, and with it any decoded key,
  whatever the outcome. The rest of PROCESS's `always` applies a restart a change already notified,
  so a failed converge does not leave Nessus running its old configuration. END's `always` signs
  out; an unrescued PROCESS failure skips END.

## Verification

```bash
export PATH="$PATH:/root/.local/bin"
yamllint -c .yamllint.yml ansible
# ansible-lint runs inside the pinned framework tree scripts/compose-and-run.sh composes, so
# refresh the role's overlay there first.
rsync -a --delete ansible/applications/nessus_scanner/ \
  .compose/ansible-framework/applications/nessus_scanner/
(cd .compose/ansible-framework && ansible-lint applications/nessus_scanner)
```
