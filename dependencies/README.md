# Dependency declarations

This tree is this repository's declared dependency contract for the organization estates.
`dependencies/aws/` is desired state matching the proven fleet baseline and, as last exported on
2026-09-30, live AWS. That equality is a point-in-time claim re-established by a live round-trip,
not a guarantee that live state cannot later drift. The owner reviews this tree before any AWS apply.

The layout is the one `nwarila-platform/secure-wazuh` introduced; see "Copy this pattern" below.

## Layout

`aws/policies/` contains one desired customer-managed IAM document per object. Policy metadata
lives in `aws/manifest.json`. There is no `aws/proposed/` tree: desired changes are made in the
real policy files and recorded in the manifest's `divergence` block until they are applied.

`aws/roles/` pairs each desired trust document with a role sidecar. The sidecar carries session
duration, customer and AWS-managed attachments, the trust filename, path, nullable description
and ownership.

`aws/manifest.json` keeps the exported date and the authoritative role-to-policy attachments for
the closed export set: three roles, zero profiles, and fifteen customer-managed policies. Its
`policies` and `divergence` objects are declared local extensions to the golden manifest schema.

`aws/artifacts.yml` declares the exactly consumed S3 objects: the installer and the HTTPS bundle,
with their SHA-256 pins, and the three secrets, deliberately without digests. IAM policy documents
separately declare authorization, and the validator proves the two agree.

There is no `ad/` directory because this repository's verified Active Directory footprint is
empty: the scanner joins no directory.

## Changes from the fleet baseline

**`nwarila-platform_nessus_runner_ebs` v3 (published 2026-09-30):** the `preserve_data` grants.
- `ec2:DescribeSnapshots`.
- `ec2:CreateSnapshot`, but only from this repository's own volumes, and only into snapshots
  requested with `Preserve=true`, `ManagedBy=aws-deploy` and this repository's identity tags.
- Tag-on-create for those snapshots.
- `ec2:DeleteSnapshot`, but only for snapshots carrying those same tags.
- `ec2:CreateVolume` from a snapshot, but only from one carrying those same tags (v3).

EC2 authorizes the source snapshot of `CreateVolume` as a resource of its own, and request-tag
conditions do not apply to it. So the baseline `CreateTaggedVolume` grant cannot cover seeding;
AWS Deploy run 36778799276 was refused on exactly that. IAM policy simulation of v3 allowed each
intended case, including creating a volume from this repository's preserved snapshot. It denied
the near-misses:
- snapshotting another repository's volume;
- creating an untagged snapshot;
- deleting a snapshot without the preservation tags;
- creating a volume from another repository's snapshot or from an untagged one.

**`nwarila-platform_nessus_runner_s3`** carries one statement the other repositories' runners do not:
`ReadOnlyTheNessusDeploymentObjects`. It grants `s3:GetObject` on exactly the four objects under
`<account-id>-ansible/applications/nessus/` that the playbook reads: the activation code, the
administrator password, the HTTPS bundle and its password. It was published from the tracked
document as the policy's v2 on 2026-09-30. The re-export was byte-identical to this tree, and IAM
policy simulation allowed each of the four objects and denied a fifth key under the same prefix.

## External dependencies

This repository's host launches with the shared instance profile `nwarila-ec2-apprepo-profile`.
That profile is registry-owned and declared by whichever repository owns the shared estate.
`terraform/aws.tfvars` selects it, and the runner holds `iam:PassRole` and `iam:GetInstanceProfile`
on it.

The installer object lives in the shared application repository bucket, under its
`<Publisher>/<Application>/<version>/` layout. The runner already reads that bucket by exact path.

## Registry shim

`registry-values.yml` is the sacrificial local resolver. Delete that one file when the
organization registry exists; declarations retain their URIs. It contains only values genuinely
referenced by machine declarations, in both directions, each with evidence a reader can open in
this repository. Canonical AWS documents are already portable through the token vocabulary. They
therefore keep native AWS ARNs and names and have no resolver entries.

## Integrity

Every file below `dependencies/`, except `MANIFEST.sha256`, is covered by the manifest.
The SHA-256 of `MANIFEST.sha256` is the bundle digest naming the entire declaration set.
Regenerate it from the repository root with exactly:

~~~bash
(cd dependencies && LC_ALL=C find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z \
  | xargs -0 sha256sum > MANIFEST.sha256)
~~~

Verify it with exactly:

~~~bash
(cd dependencies && sha256sum -c MANIFEST.sha256)
~~~

The credential-free validator, `scripts/check-dependencies.py`, also checks:
- schemas, metadata, attachments and object closure;
- tokens, literals, canonical JSON and symlinks;
- divergence references;
- that the playbook's installer and certificate pins equal the declared artifacts;
- that the runner's S3 policy authorizes every declared object, and nothing else under this
  repository's prefix.

The live baseline uses `<account-id>`, `<owner-id>`, `<repository-id>` and `<region>`.

## Known gaps

- Live `runner_s3` grants `s3:GetObject` on the domain-join secret and the VPN profile. No code
  path in this repository consumes either, because the scanner joins no directory and opens no
  tunnel. These grants are safe to remove, but they stay in the fleet baseline pending a
  separately reviewed, fleet-wide hardening change.
- Live `runner_s3` grants `s3:GetObject` on all of `<account-id>-apprepo/*`. This repository
  consumes one object there. Per-object grants remain the fleet's stated intent.
- `runner_ssm` grants `SendCommand` with the PowerShell document, a Windows-fleet grant this Linux
  host never uses. It remains in the fleet baseline.
- The apprepo role, the profile, and `nwarila-apprepo-read` are excluded because reach is
  transitive through `PassRole`, not a configured dependency.

## Copy this pattern

The next consumer should:
- declare only the objects it owns;
- keep policy metadata and authoritative attachments in one manifest;
- preserve role sidecars where they carry real data;
- record external shared estate without redeclaring it;
- close every URI, attachment, token, literal, checksum and divergence reference in its validator.
