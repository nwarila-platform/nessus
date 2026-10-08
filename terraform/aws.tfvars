# =========================================================================================== #
# File: 'terraform/aws.tfvars'
# --- [ Description ] ----------------------------------------------------------------------- #
#
# Variable input for the pinned aws-terraform-framework (SHA in .github/terraform-framework-pin).
# Plain tfvars — the workflow passes this file to terraform verbatim. This repository declares
# NO .tf files of its own: resources live in the pinned framework, configuration in the pinned
# ansible-framework plus this repository's roles.
#
# REACHABILITY — DIRECT SSH OVER A PUBLIC IPv4. The workflow discovers the runner's public IPv4
# and passes it as the framework's runtime-only runner_ip variable. When an operator hostname is
# configured it resolves that too and passes debug_ip, so a person can reach a held host and its
# Nessus listener through an SSH tunnel. The framework attaches one security group carrying both
# to every interface. The instance receives a public IPv4 at launch; no Elastic IP is involved.
# The account has no NAT and no VPC endpoints.
#
# The dependency worth knowing: MapPublicIpOnLaunch is an attribute of a shared subnet no
# repository owns. Direct SSH requires the instance's launch-time public address as well as the
# runner-scoped security group.
#
# readiness_gate is FALSE by design: credential_resolver owns the bounded-round connection wait.
# The host is Linux; SSH lands on the image's ec2-user with the account key pair, and the
# framework's redhat_rocky_8 bootstrap installs the Python every later module runs under.
#
# =========================================================================================== #

# environment and the deployment identity (repository, repository_id, commit_sha, run_id) are
# deliberately NOT in this file: the workflow passes them as -var flags placed AFTER this file on
# the command line. Terraform resolves repeated command-line assignments in the order given, so it
# is that ordering, not the kind of flag, that keeps this file from renaming the deployment.

all_systems = [
  {
    region   = "us_east_1"
    hostname = "tcnaw-nessus01"
    # The availability-zone spec lock, and a subnet in this account's only VPC.
    availability_zone = "us-east-1c"
    subnet_id         = "subnet-03a855e712be7b399"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # The org EC2 baseline: SSM through AmazonSSMManagedInstanceCore, the administrator's backup
    # connection, and the baseline's read of two Windows OpenSSH cabs this host never uses. The
    # controller fetches every artifact and hands the guest a verified copy, so the guest needs
    # no read of the application repository. The runner role only reads and passes the profile.
    iam_instance_profile = "nwarila-ec2-profile"
    aws_kms_alias        = "aws/ebs"
    # CIS Red Hat Enterprise Linux 8 Benchmark - STIG - v10 (owner 679593333241). FIPS mode,
    # fapolicyd, SELinux enforcing, and noexec /tmp and /home are all in force on it (/var/tmp is
    # not; read on a v10 host 2026-10-06); the nessus_scanner role is written against each. It
    # ships firewalld, which the playbook masks for nftables (TD-009). The publisher deprecates
    # each version about three months after release, and the framework's lookup then no longer
    # finds it ("Your query returned no results" at data.aws_ami.us_east_1_verified), so the pin
    # moves to the newest version.
    ami = "ami-099eb08281f527485"
    # OS-DRIVE REPLACEMENT (immutable-OS pattern). refresh=true makes this host's OS instance
    # swap-eligible: bumping the framework's refresh_serial variable (0 -> 1 -> ...) replaces the
    # OS instance in place while the standalone data volume below detaches and re-attaches to the
    # replacement, so /opt/nessus -- plugins, settings, certificates, users, scan data -- survives
    # an OS rebuild and the scanner resumes on it. It is a no-op until refresh_serial actually
    # changes, so the ephemeral apply -> converge -> destroy path is unaffected.
    refresh = true
    # Nessus compiles its full plugin set on first start; Tenable's floor is 4 GiB of memory with
    # 8 GiB recommended, and the compile is the long pole of a converge. t3.large is 2 vCPUs and
    # 8 GiB.
    instance_type = "t3.large"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = null

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    tags = {
      Function = "nessus"
      Backup   = false
    }

    # The image's root is 15 GiB. The scanner's data lives on its own volume below, so the
    # replaceable OS disk only needs room for the OS, the bootstrap's Python and its updates;
    # padding it further is pure cost.
    root_block_device = {
      delete_on_termination = true
      iops                  = null
      tags                  = {}
      throughput            = null
      volume_type           = "gp3"
      volume_size           = "20"
    }

    # The CIS RHEL 8 AMI ships TWO devices: /dev/sda1 (root, handled by root_block_device, which
    # the framework forces encrypted) and a 40 GiB /dev/sdf the image defines and Terraform would
    # otherwise never see. Restating it here re-renders the mapping with encrypted = true, which
    # is the only declarative way to encrypt a device the AMI ships unencrypted. No collision
    # with ebs_block_devices: the framework assigns those suffixes starting at 'd'.
    ami_block_device_overrides = [
      {
        delete_on_termination = true
        device_name           = "/dev/sdf"
        iops                  = "3000"
        throughput            = "125"
        volume_size           = "40"
        volume_type           = "gp3"
      }
    ]

    # ONE raw data disk for the scanner's whole install root. The deploy layer owns the hardware;
    # the composed play's linux_disk_manager partitions, formats and mounts it at /opt/nessus, and
    # adopts it unformatted when it arrives already labelled -- which is what an OS replacement
    # hands it. The Function tag is the identity the disk role resolves the volume by, because a
    # volume id only exists after apply; it must be unique and must match the play. It is a
    # STANDALONE volume whose lifecycle is independent of the OS instance, so an OS replacement
    # (refresh above) detaches and re-attaches the SAME volume instead of recreating it, and the
    # scanner role adopts what it holds. `terraform destroy` deletes it with the ephemeral bed:
    # in the pinned framework skip_destroy governs only the ATTACHMENT (whether destroy detaches
    # it), not whether the volume itself survives.
    #
    # Sized for the compiled plugin set, which is the bulk of it, plus scan results; the role
    # refuses to register with less than its minimum free. device_index 0 renders /dev/sdd,
    # clear of the image's own /dev/sdf override above.
    ebs_block_devices = [
      {
        resource_key = "nessusdata"
        device_index = 0
        iops         = null
        snapshot_id  = null
        skip_destroy = false
        tags         = { Function = "NESSUS" }
        throughput   = null
        volume_type  = "gp3"
        volume_size  = "60"
      }
    ]

    network_interfaces = [
      {
        description     = "tcnaw-nessus01 CI firewall"
        interface_type  = null
        private_ip      = null
        security_groups = []
        ingress         = []
        # HTTPS is the only way out the scanner needs: the RHEL update service, Tenable's
        # registration and plugin feed. The VPC resolver and time service are link-local and
        # never pass through a security group. A scan of the private network needs its own
        # route and egress; nothing here claims one.
        egress = [
          {
            description                  = "HTTPS out"
            ip_protocol                  = "tcp"
            from_port                    = 443
            to_port                      = 443
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  }
]

all_databases      = []
all_load_balancers = []
