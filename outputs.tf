output "target_resource_group_name" {
  description = "Name of the simulated CSP target resource group to scan."
  value       = azurerm_resource_group.target.name
}

output "engine_resource_group_name" {
  description = "Name of the 3PAO assessment engine resource group."
  value       = azurerm_resource_group.engine.name
}

output "subscription_id" {
  description = "Azure subscription ID in use."
  value       = data.azurerm_client_config.current.subscription_id
}

output "compliant_storage_account_name" {
  description = "Name of the compliant storage account."
  value       = azurerm_storage_account.compliant.name
}

output "vulnerable_storage_account_name" {
  description = "Name of the intentionally non-compliant storage account."
  value       = azurerm_storage_account.vulnerable.name
}

output "nsg_app_id" {
  description = "Resource ID of nsg-app (contains the intentional Allow-HTTP-Global finding)."
  value       = azurerm_network_security_group.app.id
}

output "vnet_core_id" {
  description = "Resource ID of vnet-core."
  value       = azurerm_virtual_network.core.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics Workspace used for KSI-MLA checks."
  value       = azurerm_log_analytics_workspace.audit.name
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics Workspace."
  value       = azurerm_log_analytics_workspace.audit.id
}

output "log_analytics_workspace_customer_id" {
  description = "Workspace (customer) ID of the Log Analytics Workspace."
  value       = azurerm_log_analytics_workspace.audit.workspace_id
}

output "ksi_scanner_identity_client_id" {
  description = "Client ID of the id-ksi-scanner user-assigned managed identity."
  value       = azurerm_user_assigned_identity.ksi_scanner.client_id
}

output "ksi_scanner_identity_principal_id" {
  description = "Principal (object) ID of the id-ksi-scanner user-assigned managed identity."
  value       = azurerm_user_assigned_identity.ksi_scanner.principal_id
}

output "ksi_scanner_identity_id" {
  description = "Full resource ID of the id-ksi-scanner user-assigned managed identity."
  value       = azurerm_user_assigned_identity.ksi_scanner.id
}

output "engine_key_vault_name" {
  description = "Name of the Key Vault holding scanner credentials/metadata."
  value       = azurerm_key_vault.engine.name
}

output "engine_key_vault_uri" {
  description = "URI of the Key Vault holding scanner credentials/metadata."
  value       = azurerm_key_vault.engine.vault_uri
}
