#!/usr/bin/env bash
# =========================================================================================== #
# File: 'scripts/mint-nessus-https.sh'
# --- [ Description ] ----------------------------------------------------------------------- #
#
# Mints the certificate the Nessus listener serves: a private root CA, which signs itself, and a
# server certificate that CA signs. The server key, the server certificate and the CA go into ONE
# password-protected PKCS#12 bundle, which is the only certificate material the deployment
# consumes.
#
# The CA's private key is destroyed once it has signed. Renewal mints a new CA and a new server
# certificate together, so there is no signing key anywhere to protect between renewals. The
# price is that every client re-imports the new CA certificate after a renewal.
#
# FIPS: the target runs RHEL 8 in FIPS mode, where OpenSSL refuses the legacy PKCS#12 algorithms
# (RC2, 3DES and a SHA-1 MAC). The bundle is written with PBES2/PBKDF2 and AES-256-CBC, protected
# by a SHA-256 MAC. RHEL 8's FIPS-mode OpenSSL decodes exactly this form (measured 2026-09-30,
# OpenSSL 1.1.1k with OPENSSL_FORCE_FIPS_MODE=1). RSA-3072 and SHA-256 are approved there too.
#
# The certificate always names localhost and 127.0.0.1 besides the host. The role proves HTTPS
# on the scanner itself by validating the chain AND the hostname against https://localhost, and
# an operator reaches a held bed through an SSH tunnel to the same name.
#
# --- [ How To Call It ] -------------------------------------------------------------------- #
#   scripts/mint-nessus-https.sh <output-dir> [extra-dns-name ...]
#   NESSUS_HOSTNAME=tcnaw-nessus01 is the default subject; override it for another host.
#
# Writes, into a NEW directory with mode 0700, created only once everything has been minted:
#   nessus-https.p12                  the bundle             -> s3://<account-id>-ansible/applications/nessus/
#   nessus-https-p12-password.txt     its password           -> s3://<account-id>-ansible/applications/nessus/
#   nessus-ca.pem                     the public CA certificate for clients to trust (not uploaded)
# Then prints the bundle's SHA-256, which ansible/playbooks/nessus-aws.yml and
# dependencies/aws/artifacts.yml both pin; dependencies/MANIFEST.sha256 is regenerated after.
#
# =========================================================================================== #
set -euo pipefail

die() { printf 'mint-nessus-https: %s\n' "$1" >&2; exit 1; }

[ "$#" -ge 1 ] || die "usage: $0 <output-dir> [extra-dns-name ...]"
OUT_DIR="$1"
shift
HOST_NAME="${NESSUS_HOSTNAME:-tcnaw-nessus01}"
[[ "${HOST_NAME}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]] \
    || die "NESSUS_HOSTNAME '${HOST_NAME}' is not a DNS name"
# Refuse to overwrite: a second mint over the first would silently orphan the bundle already
# uploaded and pinned.
[ ! -e "${OUT_DIR}" ] || die "refusing to overwrite existing path: ${OUT_DIR}"
command -v openssl >/dev/null || die "openssl is required"

umask 077
WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf -- "${WORK_DIR}"; }
trap cleanup EXIT

# OpenSSL writes progress and errors to stderr alike: held back, and shown only on a failure.
ossl() {
    local step="$1"
    shift
    openssl "$@" 2>"${WORK_DIR}/openssl.err" \
        || die "${step} failed: $(<"${WORK_DIR}/openssl.err")"
}

san="DNS:${HOST_NAME},DNS:localhost,IP:127.0.0.1"
for extra in "$@"; do
    [[ "${extra}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]] \
        || die "extra name '${extra}' is not a DNS name"
    san="${san},DNS:${extra}"
done

# --- 1. The private root CA ---------------------------------------------------------------- #
ossl 'minting the root CA' req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
    -keyout "${WORK_DIR}/ca.key" -out "${WORK_DIR}/ca.pem" \
    -subj "/O=nwarila-platform/CN=Nessus HTTPS Root CA ${HOST_NAME}" \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'

# --- 2. The server certificate, signed by that CA ------------------------------------------ #
ossl 'requesting the server certificate' req -newkey rsa:3072 -sha256 -nodes \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.csr" \
    -subj "/O=nwarila-platform/CN=${HOST_NAME}"
printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    "subjectAltName=${san}" > "${WORK_DIR}/server.ext"
# 397 days: inside the 398-day maximum that publicly trusted certificates are held to.
ossl 'signing the server certificate' x509 -req -sha256 -days 397 -in "${WORK_DIR}/server.csr" \
    -CA "${WORK_DIR}/ca.pem" -CAkey "${WORK_DIR}/ca.key" -CAcreateserial \
    -extfile "${WORK_DIR}/server.ext" -out "${WORK_DIR}/server.pem"
openssl verify -CAfile "${WORK_DIR}/ca.pem" "${WORK_DIR}/server.pem" >/dev/null \
    || die "the server certificate does not verify against the CA it was just signed by"

# --- 3. The password-protected bundle ------------------------------------------------------ #
# One line with no newline: the role hands it to OpenSSL on stdin, which reads the first line.
openssl rand -base64 36 | tr -d '\n' > "${WORK_DIR}/nessus-https-p12-password.txt"
ossl 'writing the PKCS#12 bundle' pkcs12 -export -name 'nessus-https' \
    -inkey "${WORK_DIR}/server.key" -in "${WORK_DIR}/server.pem" -certfile "${WORK_DIR}/ca.pem" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 -iter 100000 \
    -passout "file:${WORK_DIR}/nessus-https-p12-password.txt" \
    -out "${WORK_DIR}/nessus-https.p12"

# --- 4. Publish the three files ------------------------------------------------------------ #
# Only now, so a failed mint leaves nothing behind that refuses the re-run.
mkdir -p -- "${OUT_DIR}"
cp -- "${WORK_DIR}/nessus-https.p12" "${WORK_DIR}/nessus-https-p12-password.txt" "${OUT_DIR}/"
cp -- "${WORK_DIR}/ca.pem" "${OUT_DIR}/nessus-ca.pem"
chmod 0644 "${OUT_DIR}/nessus-ca.pem"

# --- 5. Report what the deployment pins ---------------------------------------------------- #
digest="$(sha256sum "${OUT_DIR}/nessus-https.p12" | cut -d' ' -f1)"
printf 'mint-nessus-https: wrote %s\n' "${OUT_DIR}"
printf '  subject alternative names: %s\n' "${san}"
printf '  server certificate sha256 fingerprint: %s\n' \
    "$(openssl x509 -in "${WORK_DIR}/server.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
printf '  nessus-https.p12 sha256: %s\n' "${digest}"
printf '  pin it in ansible/playbooks/nessus-aws.yml and dependencies/aws/artifacts.yml, then\n'
printf '  regenerate dependencies/MANIFEST.sha256 (the command is in dependencies/README.md)\n'
