# terraform/ — data only

This directory carries **no `.tf` files and never will**. The AWS resources are declared by the
pinned `nwarila-platform/aws-terraform-framework`; this repository contributes only the variable
input that shapes them.

- `aws.tfvars` is the system declaration the framework consumes verbatim. It pins the availability
  zone, subnet, instance type, AMI (CIS RHEL 8 STIG), key pair, instance profile, disk layout,
  network interface and egress. The OS instance is not swap-eligible (`refresh = false`) until
  `/opt/nessus` gets a persistent data volume of its own.
- The framework SHA is pinned in `.github/terraform-framework-pin`.

`.github/workflows/aws-deploy.yml` checks the framework out at that pin, runs Terraform from
inside it, and passes this file with `-var-file`. The deployment identity (`environment`,
`repository`, `repository_id`, `commit_sha`, `run_id`) is supplied separately with `-var`, after
the file. Terraform resolves repeated assignments in order, so the tags that satisfy the deploy
role's create-time IAM conditions cannot be overridden from here.

Reachability is **direct SSH over a launch-time public IPv4**. The shared subnet's
MapPublicIpOnLaunch assigns the address (no Elastic IP, no NAT). At runtime the framework attaches
the only ingress: one security group scoped to the runner's validated public IPv4 and, when
configured, the operator's. An operator reaches a held scanner's HTTPS listener through an SSH
tunnel (`ssh -L 8834:localhost:8834`), and the certificate names `localhost` for exactly that.
SSM (via the instance profile's `AmazonSSMManagedInstanceCore`) is the administrator's backup
connection, not the primary path.
