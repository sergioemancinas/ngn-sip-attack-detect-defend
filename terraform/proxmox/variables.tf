variable "proxmox_endpoint" {
  description = "Proxmox VE API endpoint, for example https://pve-01.example.internal:8006/api2/json."
  type        = string
  default     = "https://change-me-local-only:8006/api2/json"
}

variable "proxmox_api_token" {
  description = "Proxmox API token from Vault. Do not commit real values."
  type        = string
  sensitive   = true
  default     = "change-me-local-only"
}

variable "proxmox_insecure_tls" {
  description = "Temporary bootstrap flag only. Set false after Step-CA trust is installed."
  type        = bool
  default     = true
}

variable "target_node" {
  description = "Default Proxmox node for early single-node tests."
  type        = string
  default     = "pve-01"
}

variable "ssh_public_key" {
  description = "Cloud-Init SSH public key. Replace from Vault or operator key management."
  type        = string
  default     = "ssh-ed25519 change-me-local-only ngn-sip-reference"
}

variable "cloud_init_user" {
  description = "Default non-root Cloud-Init user for Ansible."
  type        = string
  default     = "ngnadmin"
}

