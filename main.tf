data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 5
  special = false
  upper   = false
  numeric = true
}

# ---------------------------------------------------------------------------
# RESOURCE GROUP 1: rg-fedramp-target (the simulated CSP environment)
# ---------------------------------------------------------------------------

resource "azurerm_resource_group" "target" {
  name     = var.target_resource_group_name
  location = var.location
  tags     = var.tags
}

# --- Networking --------------------------------------------------------

resource "azurerm_virtual_network" "core" {
  name                = "vnet-core"
  resource_group_name = azurerm_resource_group.target.name
  location            = azurerm_resource_group.target.location
  address_space       = var.vnet_address_space
  tags                = var.tags
}

resource "azurerm_subnet" "app" {
  name                 = "Subnet-App"
  resource_group_name  = azurerm_resource_group.target.name
  virtual_network_name = azurerm_virtual_network.core.name
  address_prefixes     = [var.subnet_app_prefix]
}

resource "azurerm_subnet" "db" {
  name                 = "Subnet-Db"
  resource_group_name  = azurerm_resource_group.target.name
  virtual_network_name = azurerm_virtual_network.core.name
  address_prefixes     = [var.subnet_db_prefix]
}

# --- Network Security Group (intentionally non-compliant) --------------

resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = azurerm_resource_group.target.location
  resource_group_name = azurerm_resource_group.target.name
  tags                = var.tags

  # NON-COMPLIANT BY DESIGN: exposes HTTP (port 80) to the entire internet.
  # This rule exists so the KSI-CNA scanner has a real finding to detect
  # (drift / open ingress on an unencrypted port). Do not "fix" this in
  # code - it is the negative test fixture for the validation engine.
  security_rule {
    name                       = "Allow-HTTP-Global"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
  }

  # A compliant baseline rule included for contrast - restricted to the
  # virtual network only, so the scanner should NOT flag this one.
  security_rule {
    name                       = "Allow-HTTPS-VNet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

# --- Storage: Compliant -------------------------------------------------

resource "azurerm_storage_account" "compliant" {
  name                = "${var.compliant_storage_account_name}${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.target.name
  location            = azurerm_resource_group.target.location

  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  min_tls_version                  = "TLS1_2"
  enable_https_traffic_only        = true
  public_network_access_enabled    = false
  allow_nested_items_to_be_public  = false
  shared_access_key_enabled        = true

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  tags = merge(var.tags, { compliance_state = "compliant" })
}

# --- Storage: Intentionally Non-Compliant -------------------------------

resource "azurerm_storage_account" "vulnerable" {
  name                = "${var.vulnerable_storage_account_name}${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.target.name
  location            = azurerm_resource_group.target.location

  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  # NON-COMPLIANT BY DESIGN: allows plaintext HTTP and legacy TLS 1.0.
  # This is the negative test fixture for the KSI-SC control checks.
  min_tls_version                 = "TLS1_0"
  enable_https_traffic_only       = false
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = true

  network_rules {
    default_action = "Allow"
    bypass         = ["AzureServices"]
  }

  tags = merge(var.tags, { compliance_state = "non-compliant" })
}

# --- Managed Identity for the KSI Scanner -------------------------------

resource "azurerm_user_assigned_identity" "ksi_scanner" {
  name                = "id-ksi-scanner"
  resource_group_name = azurerm_resource_group.target.name
  location            = azurerm_resource_group.target.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "ksi_scanner_reader" {
  scope                = azurerm_resource_group.target.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.ksi_scanner.principal_id
}

# --- Log Analytics Workspace & Diagnostic Settings (KSI-MLA) -----------

resource "azurerm_log_analytics_workspace" "audit" {
  name                = var.log_analytics_workspace_name
  resource_group_name = azurerm_resource_group.target.name
  location            = azurerm_resource_group.target.location
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "storage_compliant" {
  name                       = "diag-stgcompliant-to-law"
  target_resource_id         = "${azurerm_storage_account.compliant.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.audit.id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "nsg_app" {
  name                       = "diag-nsg-app-to-law"
  target_resource_id         = azurerm_network_security_group.app.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.audit.id

  enabled_log {
    category = "NetworkSecurityGroupEvent"
  }
  enabled_log {
    category = "NetworkSecurityGroupRuleCounter"
  }
}

# NOTE: azurerm_storage_account.vulnerable intentionally has NO diagnostic
# setting wired up, as a second negative fixture for the KSI-MLA control
# (missing audit logging on a data-plane resource).

# ---------------------------------------------------------------------------
# RESOURCE GROUP 2: rg-fedramp-engine (the 3PAO assessment infrastructure)
# ---------------------------------------------------------------------------

resource "azurerm_resource_group" "engine" {
  name     = var.engine_resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_key_vault" "engine" {
  name                       = "${var.key_vault_name}${random_string.suffix.result}"
  resource_group_name        = azurerm_resource_group.engine.name
  location                   = azurerm_resource_group.engine.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  enable_rbac_authorization     = true
  public_network_access_enabled = true

  tags = var.tags
}

resource "azurerm_role_assignment" "engine_kv_current_user" {
  scope                = azurerm_key_vault.engine.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "engine_kv_scanner_identity" {
  scope                = azurerm_key_vault.engine.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.ksi_scanner.principal_id
}

# Scanner credentials / environment metadata stored as secrets for the
# validation engine to reference (e.g. from a CI/CD pipeline).
resource "azurerm_key_vault_secret" "scanner_client_id" {
  name         = "ksi-scanner-client-id"
  value        = azurerm_user_assigned_identity.ksi_scanner.client_id
  key_vault_id = azurerm_key_vault.engine.id

  depends_on = [azurerm_role_assignment.engine_kv_current_user]
}

resource "azurerm_key_vault_secret" "target_subscription_id" {
  name         = "target-subscription-id"
  value        = data.azurerm_client_config.current.subscription_id
  key_vault_id = azurerm_key_vault.engine.id

  depends_on = [azurerm_role_assignment.engine_kv_current_user]
}

resource "azurerm_key_vault_secret" "target_resource_group" {
  name         = "target-resource-group-name"
  value        = azurerm_resource_group.target.name
  key_vault_id = azurerm_key_vault.engine.id

  depends_on = [azurerm_role_assignment.engine_kv_current_user]
}

resource "azurerm_key_vault_secret" "target_law_workspace_id" {
  name         = "target-law-workspace-id"
  value        = azurerm_log_analytics_workspace.audit.workspace_id
  key_vault_id = azurerm_key_vault.engine.id

  depends_on = [azurerm_role_assignment.engine_kv_current_user]
}
