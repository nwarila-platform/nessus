# `nessus_scanner` role

Installs Tenable Nessus at a pinned version on a STIG-hardened RHEL 8 host and brings it up as a
registered scanner serving HTTPS with a certificate the deployment owns. In one converge it:

1. trusts Tenable's RPM signing key, refused unless its fingerprint is the pinned one;
2. installs the pinned RPM from a copy verified against its SHA-256 **and** the vendor signature,
   on the guest, immediately before `dnf` installs it;
3. starts the service and converges **every** Nessus setting to its declaration (below);
4. admits the listener in every active firewalld zone;
5. decodes the declared PKCS#12 bundle with the system's FIPS-validated OpenSSL, checks the key,
   certificate and CA as a set, and imports them into Nessus when what it serves differs;
6. creates the one administrator account from the command line, **before** registration, because
   the web tier reads whether setup is complete when the service starts;
7. registers the scanner with its activation code and fetches the plugins;
8. waits until Nessus reports ready, **over HTTPS validated against the declared CA and hostname**,
   restarting once if a registered scanner settles on a stale `register` state (measured
   2026-09-30);
9. proves the account by signing in to the API, converging its password if it moved;
10. verifies the result against the machine: the installed version, the service, the
    registration, and the fingerprint of the certificate the listener actually serves.

Every step reads before it writes, so a converged host reports no change.

## Data volume

The role treats its install root, `/opt/nessus`, as the unit of the scanner's data: binaries,
plugins, settings, certificates, accounts and scan results. In the composed play it is its own
volume, mounted there by `linux_disk_manager` before this role runs, so the OS disk can be
replaced underneath it.

The role follows the fleet's rule for application data (PDQ, WSUS, Wazuh): **if the volume already
holds a scanner, adopt it; otherwise install one.** It decides before any package transaction,
from the installation's identity: `var/nessus/uuid` and `var/nessus/master.key`.

| The volume holds | The role |
|---|---|
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
with, because a filesystem made for it starts unlabelled. `state=absent` empties the install root
rather than removing it, because the mount point is the disk role's.

## Settings

Every setting Nessus has is declared, so every one is configured through CI/CD. For 10.12.4 that
is 160 settings: the 157 in the product's own catalogue (`nessuscli fix --show`) and 5 it stores at
install without cataloguing. They live in `defaults/main.yml`, grouped by the product's own
categories, each at the product's own value unless a comment says otherwise. To change one, set it
by name in the playbook, and the next deploy converges it:

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
- reads back each setting it wrote and requires it to hold its declared value;
- names any setting Nessus has that the declaration lacks, which is how a version bump shows up.

`~` leaves a setting to Nessus. Six are left that way by default: five that Nessus computes from
the hardware (`engine.max`, `engine.min`, `global.max_hosts`, `global.max_portscanners`,
`global.max_simult_tcp_sessions`), and `plugin_detail_locale_current`, which is state Nessus
rewrites itself. Per-plugin timeouts are declared as `timeout.<plugin id>`. Values must be quoted,
because an unquoted `yes` is a YAML boolean.

Four values are deliberate rather than the product's:
- `ssl_mode: tls_1_2`, the TLS floor;
- `auto_update: yes`, so plugins stay current;
- `disable_core_updates: yes` and `auto_update_ui: no`, so the software never replaces itself. The
  installed version stays the pinned RPM, which fapolicyd trusts by its digest.

## HTTPS

The certificate is ONE password-protected PKCS#12 bundle: the server key, the server certificate
and the single CA that signed it. [`scripts/mint-nessus-https.sh`](../../../scripts/mint-nessus-https.sh)
mints exactly that shape. It creates a private root CA, signs a server certificate that names the
host, `localhost` and `127.0.0.1`, and destroys the CA key.

The role never trusts the certificate on its word:

- the bundle's SHA-256 is pinned, and checked on the controller and again on the guest;
- it is decoded on the guest by `/usr/bin/openssl`, the FIPS-validated module, so a bundle this
  host's crypto policy would refuse fails by name rather than half-installing;
- before import the key must open the certificate, the CA must verify it, it must be in date for
  another day, and it must name both this host and `localhost`;
- the readiness wait trusts **only** the declared CA and connects to `https://localhost:<port>`,
  so it cannot pass against Nessus's self-generated certificate, another CA or a name mismatch;
- finally the leaf certificate the listener serves in a live handshake must carry the declared
  fingerprint.

The plaintext key exists only between decoding and import and is removed in an `always` block;
the loader removes its whole temporary directory when the role ends as well.

### Why the bundle is AES-256 and not the PKCS#12 default of older tools

RHEL 8 in FIPS mode refuses RC2, 3DES and SHA-1 MACs, the algorithms many tools still use for
PKCS#12. The mint script writes PBES2/PBKDF2 with AES-256-CBC and a SHA-256 MAC. On 2026-09-30,
RHEL 8's OpenSSL 1.1.1k decoded that form with FIPS mode forced on. A bundle exported by another
tool fails at `PROCESS | Decode The Bundle`, and the message names the cause.

## STIG constraints

| Constraint | How the role meets it |
|---|---|
| `localpkg_gpgcheck` | Tenable's key is trusted by pinned fingerprint before `dnf` installs the RPM |
| fapolicyd denies untrusted scripts | No task stages a module as a file (no `async`); the inventory pipelines. After an install the trust database is refreshed and the vendor's FIPS-module step is re-run if it was denied mid-transaction |
| `noexec` on `/tmp`, `/var/tmp`, `/home` | Nothing staged in the loader's temporary directory is executed |
| FIPS mode | System OpenSSL decodes the bundle; RSA-3072 and SHA-256 throughout |
| firewalld | The listener is admitted per active zone and proven in the running configuration |

## Inputs

See [`meta/main.yml`](meta/main.yml) for the required inputs and
[`defaults/main.yml`](defaults/main.yml) for everything with a safe default. Nothing under this
role names an account, bucket or secret; the playbook supplies them.

| State | Does |
|---|---|
| `present` | Everything above |
| `absent` | Stops and removes the service, the package, the whole install root, the firewall rule and the signing key; proves none remains |
| `clean` | Removes the superseded certificate material each import leaves behind |

## Licence model

Nessus Professional and Essentials hold exactly one account, so `administrator` is *the* account.
A converge that finds a different one refuses rather than guessing which is meant. Every account
write is judged by what the product prints as well as by its exit status.
