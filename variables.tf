variable "subscription_id" {
  description = "Azure subscription ID to deploy the lab into. Leave null to use the subscription set via `az account set`."
  type        = string
  default     = null
}

variable "location" {
  description = "Azure region for all lab resources."
  type        = string
  default     = "eastus"
}

variable "target_resource_group_name" {
  description = "Name of the resource group representing the simulated CSP target environment being audited."
  type        = string
  default     = "rg-fedramp-target"
}

variable "engine_resource_group_name" {
  description = "Name of the resource group hosting the 3PAO / KSI scanner assessment infrastructure."
  type        = string
  default     = "rg-fedramp-engine"
}

variable "vnet_address_space" {
  description = "Address space for vnet-core."
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnet_app_prefix" {
  description = "Address prefix for Subnet-App."
  type        = string
  default     = "10.0.1.0/24"
}

variable "subnet_db_prefix" {
  description = "Address prefix for Subnet-Db."
  type        = string
  default     = "10.0.2.0/24"
}

variable "compliant_storage_account_name" {
  description = "Globally unique name for the compliant storage account (lowercase, no dashes, 3-24 chars)."
  type        = string
  default     = "stgcompliant"
}

variable "vulnerable_storage_account_name" {
  description = "Globally unique name for the intentionally non-compliant storage account (lowercase, no dashes, 3-24 chars)."
  type        = string
  default     = "stgvulnerable"
}

variable "log_analytics_workspace_name" {
  description = "Name of the Log Analytics Workspace used for KSI-MLA audit log routing."
  type        = string
  default     = "law-fedramp-20x-audit"
}

variable "key_vault_name" {
  description = "Name of the Key Vault holding scanner credentials and environment metadata (must be globally unique)."
  type        = string
  default     = "kv-fedramp-20x-eng"
}

variable "tags" {
  description = "Common tags applied to all resources."
  type        = map(string)
  default = {
    project     = "fedramp-20x-automation-lab"
    environment = "lab"
    managed_by  = "terraform"
    framework   = "FedRAMP-20x"
  }
}
