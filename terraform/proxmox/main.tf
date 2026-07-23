terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.100.0"
    }
  }
}

provider "proxmox" {
  endpoint  = var.proxmox_endpoint
  api_token = var.proxmox_api_token
  insecure  = var.proxmox_insecure_tls
}

locals {
  project_name = "ngn-sip-reference-network"

  vlan_map = {
    mgmt          = { id = 0, cidr = "10.10.0.0/24", gateway = "10.10.0.1" }
    sip_edge      = { id = 10, cidr = "10.10.10.0/24", gateway = "10.10.10.1" }
    sip_internal  = { id = 20, cidr = "10.10.20.0/24", gateway = "10.10.20.1" }
    siem          = { id = 30, cidr = "10.10.30.0/24", gateway = "10.10.30.1" }
    soar          = { id = 40, cidr = "10.10.40.0/24", gateway = "10.10.40.1" }
    observability = { id = 50, cidr = "10.10.50.0/24", gateway = "10.10.50.1" }
    attack        = { id = 99, cidr = "10.10.99.0/24", gateway = "10.10.99.1" }
  }

  cloud_images = {
    debian_12    = "debian-12-genericcloud-amd64"
    ubuntu_2404  = "ubuntu-24.04-server-cloudimg-amd64"
    almalinux_95 = "AlmaLinux-9.5-GenericCloud"
    opnsense_261 = "OPNsense-26.1-dvd-amd64"
  }

  vm_profiles = {
    fw-opnsense-01     = { image = "opnsense_261", vcpu = 4, ram_mb = 4096, disk_gb = 32, vlans = ["wan", "mgmt", "sip_edge", "sip_internal", "siem", "soar", "observability", "attack"] }
    sec-vault-01       = { image = "debian_12", vcpu = 2, ram_mb = 4096, disk_gb = 32, vlans = ["mgmt"] }
    sec-stepca-01      = { image = "debian_12", vcpu = 2, ram_mb = 2048, disk_gb = 32, vlans = ["mgmt"] }
    id-keycloak-01     = { image = "ubuntu_2404", vcpu = 4, ram_mb = 8192, disk_gb = 64, vlans = ["mgmt"] }
    sip-kamailio-01    = { image = "debian_12", vcpu = 4, ram_mb = 4096, disk_gb = 32, vlans = ["mgmt", "sip_edge"] }
    sip-rtpengine-01   = { image = "debian_12", vcpu = 4, ram_mb = 4096, disk_gb = 32, vlans = ["mgmt", "sip_edge"] }
    pbx-asterisk-01    = { image = "debian_12", vcpu = 4, ram_mb = 4096, disk_gb = 64, vlans = ["mgmt", "sip_internal"] }
    db-postgres-01     = { image = "debian_12", vcpu = 4, ram_mb = 8192, disk_gb = 128, vlans = ["mgmt", "sip_internal"] }
    wazuh-manager-01   = { image = "ubuntu_2404", vcpu = 4, ram_mb = 8192, disk_gb = 128, vlans = ["mgmt", "siem"] }
    wazuh-indexer-01   = { image = "ubuntu_2404", vcpu = 8, ram_mb = 16384, disk_gb = 256, vlans = ["mgmt", "siem"] }
    wazuh-dashboard-01 = { image = "ubuntu_2404", vcpu = 2, ram_mb = 4096, disk_gb = 64, vlans = ["mgmt", "siem"] }
    shuffle-01         = { image = "ubuntu_2404", vcpu = 4, ram_mb = 8192, disk_gb = 128, vlans = ["mgmt", "soar"] }
    obs-clickhouse-01  = { image = "ubuntu_2404", vcpu = 8, ram_mb = 16384, disk_gb = 512, vlans = ["mgmt", "observability"] }
    obs-vector-01      = { image = "debian_12", vcpu = 2, ram_mb = 4096, disk_gb = 64, vlans = ["mgmt", "observability"] }
    obs-grafana-01     = { image = "ubuntu_2404", vcpu = 2, ram_mb = 4096, disk_gb = 64, vlans = ["mgmt", "observability"] }
    obs-prometheus-01  = { image = "ubuntu_2404", vcpu = 4, ram_mb = 8192, disk_gb = 256, vlans = ["mgmt", "observability"] }
    obs-homer-01       = { image = "debian_12", vcpu = 4, ram_mb = 8192, disk_gb = 128, vlans = ["mgmt", "observability"] }
    atk-sippts-01      = { image = "debian_12", vcpu = 2, ram_mb = 4096, disk_gb = 64, vlans = ["mgmt", "attack"] }
    atk-sipvicious-01  = { image = "debian_12", vcpu = 2, ram_mb = 4096, disk_gb = 64, vlans = ["mgmt", "attack"] }
    atk-honeypot-01    = { image = "almalinux_95", vcpu = 2, ram_mb = 4096, disk_gb = 64, vlans = ["mgmt", "attack"] }
    k3s-cp-01          = { image = "ubuntu_2404", vcpu = 4, ram_mb = 8192, disk_gb = 80, vlans = ["mgmt", "observability"] }
    k3s-worker-01      = { image = "ubuntu_2404", vcpu = 4, ram_mb = 8192, disk_gb = 80, vlans = ["mgmt", "observability"] }
    k3s-worker-02      = { image = "ubuntu_2404", vcpu = 4, ram_mb = 8192, disk_gb = 80, vlans = ["mgmt", "observability"] }
  }
}

# Skeleton only.
# Next implementation pass should add tested bpg/proxmox resources for:
# - Proxmox pools and SDN/VNet objects, if provider support matches Proxmox VE 8.4.
# - Cloud-Init image imports from the catalog above.
# - VM resources generated from local.vm_profiles.
# - PBS backup jobs and snapshot-before-attack helpers.

