# Proxmox IaC Skeleton

This directory is intentionally a skeleton. It documents the resource model for the Proxmox reference-network research project and should not be applied to a live Proxmox cluster yet.

## Toolchain

| Tool | Version | Notes |
|---|---:|---|
| OpenTofu | 1.10.0 | Use instead of HashiCorp Terraform to keep the project open-source-only. |
| Provider | `bpg/proxmox` 0.100.0 | Selected over Telmate because Telmate current release is an RC line. |
| Proxmox VE | 8.4 | Target hypervisor. |
| Proxmox Backup Server | 3.4 | Target backup platform. |

## Expected Future Commands

```bash
tofu init
tofu validate
tofu plan -out ngn-sip-reference.tfplan
```

Do not run `tofu apply` until provider resources are tested against the target Proxmox VE 8.4 cluster.

## Secret Handling

Use `change-me-local-only` placeholders in committed files. Real Proxmox API tokens, SSH private keys, OIDC client secrets, Vault tokens, and CA private material belong in Vault, never in this repo.

## Next Implementation Pass

| Task | Output |
|---|---|
| Validate `bpg/proxmox` resource syntax against PVE 8.4 | first executable `main.tf` |
| Import Debian 12, Ubuntu 24.04 LTS, AlmaLinux 9.5 Cloud-Init images | image resources or documented manual import |
| Generate VM resources from `local.vm_profiles` | VM inventory and IPAM outputs |
| Export Ansible inventory | generated `inventory.yml` |
| Add PBS snapshot jobs | deterministic attack rollback |

