terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Uncomment and configure this block if you want remote state
  # backend "azurerm" {
  #   resource_group_name  = "rg-tfstate"
  #   storage_account_name = "sttfstatefedramp20x"
  #   container_name       = "tfstate"
  #   key                  = "fedramp-20x-lab.tfstate"
  # }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }

  # Authentication is resolved via `az login` (Azure CLI) by default.
  # Override with ARM_SUBSCRIPTION_ID / ARM_TENANT_ID env vars, or a
  # service principal (ARM_CLIENT_ID / ARM_CLIENT_SECRET) for CI/CD.
  subscription_id = var.subscription_id
}

provider "random" {}
