output "project_name" {
  description = "Reference network project name."
  value       = local.project_name
}

output "vlan_map" {
  description = "VLAN definitions planned for Proxmox SDN and OPNsense."
  value       = local.vlan_map
}

output "cloud_images" {
  description = "Pinned Cloud-Init image catalog names."
  value       = local.cloud_images
}

output "vm_profiles" {
  description = "VM profile map for the next implementation pass and Ansible inventory generation."
  value       = local.vm_profiles
}

