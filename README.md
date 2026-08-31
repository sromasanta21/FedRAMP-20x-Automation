# Azure FedRAMP 20x KSI Automation Lab

A self-contained lab that provisions a simulated Cloud Service Provider (CSP)
target environment in Azure, then runs an automated Python validation engine
that evaluates it against a subset of **FedRAMP 20x Key Security Indicators
(KSIs)** and emits an OSCAL-shaped evidence package.

```
fedramp-20x-lab/
├── terraform/
│   ├── providers.tf     # azurerm ~> 3.90 provider configuration
│   ├── variables.tf     # input variables (region, names, tags)
│   ├── main.tf           # rg-fedramp-target + rg-fedramp-engine resources
│   └── outputs.tf        # resource names/IDs consumed by the Python engine
├── engine/
│   ├── ksi_validator.py  # KSI-SC / KSI-CNA / KSI-MLA validation engine
│   └── requirements.txt  # Python dependencies
└── README.md
```

## Architecture Summary

| Resource Group        | Purpose                                            | Key Resources |
|------------------------|-----------------------------------------------------|----------------|
| `rg-fedramp-target`    | Simulated CSP environment under audit               | `vnet-core` (10.0.0.0/16), `Subnet-App` (10.0.1.0/24), `Subnet-Db` (10.0.2.0/24), `nsg-app` (intentional `Allow-HTTP-Global` finding), `stgcompliant<suffix>`, `stgvulnerable<suffix>`, `id-ksi-scanner` (Reader on RG), `law-fedramp-20x-audit` |
| `rg-fedramp-engine`    | 3PAO / assessment infrastructure                    | Key Vault storing scanner credentials & environment metadata |

Two negative test fixtures are deployed **on purpose** so the scanner has
real findings to detect:

1. `nsg-app` → `Allow-HTTP-Global` rule opens TCP/80 to `0.0.0.0/0`.
2. `stgvulnerable<suffix>` → HTTPS-only disabled, TLS 1.0 permitted, public
   network access enabled, and **no** diagnostic setting wired to the
   Log Analytics Workspace.

---

## 1. Prerequisites

| Tool          | Minimum Version | Install |
|---------------|------------------|---------|
| Azure CLI     | 2.60+            | https://learn.microsoft.com/cli/azure/install-azure-cli |
| Terraform     | 1.5+             | https://developer.hashicorp.com/terraform/install |
| Python        | 3.10+            | https://www.python.org/downloads/ |

You also need:

- An Azure subscription with **Contributor** (or higher) rights to create
  resource groups, networking, storage, identities, role assignments, and
  Key Vaults.
- Sufficient rights to assign roles (`Microsoft.Authorization/roleAssignments/write`)
  at the resource group scope, since Terraform creates the `Reader` role
  assignment for `id-ksi-scanner` and the Key Vault RBAC assignments.

Authenticate once before running Terraform or the Python engine:

```bash
az login
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"
export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
```

---

## 2. Deploy the Infrastructure (Terraform)

```bash
cd terraform

terraform init

terraform plan \
  -var="subscription_id=${AZURE_SUBSCRIPTION_ID}" \
  -out=tfplan

terraform apply tfplan
```

Optional: override any variable (see `variables.tf` for the full list), e.g.
a different region or globally-unique Key Vault name:

```bash
terraform apply \
  -var="subscription_id=${AZURE_SUBSCRIPTION_ID}" \
  -var="location=eastus2" \
  -var="key_vault_name=kv-fr20x-eng-myorg"
```

When it completes, capture the outputs the Python engine needs:

```bash
terraform output -json > ../engine/terraform_outputs.json
terraform output target_resource_group_name
terraform output log_analytics_workspace_name
terraform output ksi_scanner_identity_client_id
```

> **Note:** `stgcompliant` and `stgvulnerable` are suffixed with a random
> 5-character string by Terraform (via `random_string.suffix`) to satisfy
> Azure's global storage account name uniqueness requirement. Use
> `terraform output compliant_storage_account_name` /
> `vulnerable_storage_account_name` to get the exact deployed names.

---

## 3. Set Up the Python Validation Engine

```bash
cd ../engine

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install azure-identity azure-mgmt-storage azure-mgmt-network \
            azure-mgmt-monitor azure-mgmt-resource rich

# or simply:
pip install -r requirements.txt
```

The engine authenticates via `DefaultAzureCredential`, so as long as you
already ran `az login` (Section 1) it will pick that up automatically with
no extra configuration. No credentials are hard-coded anywhere in the code.

---

## 4. Run the Validation Engine

```bash
python ksi_validator.py \
  --resource-group rg-fedramp-target \
  --workspace-name law-fedramp-20x-audit \
  --subscription-id "${AZURE_SUBSCRIPTION_ID}" \
  --output assessment_results.json
```

This will:

1. Verify connectivity/authorization against `rg-fedramp-target`.
2. Run all three KSI checkers (`KSI-SC`, `KSI-CNA`, `KSI-MLA`) against every
   in-scope resource.
3. Print a color-coded findings table and compliance summary to the console.
4. Print full detail (description + remediation) for every non-compliant
   finding.
5. Write the full OSCAL-shaped Assessment Results document to
   `assessment_results.json` **and** echo it to stdout (useful for piping
   into `jq` or a CI/CD artifact step).

### Expected non-compliant findings

Running against the lab as deployed, you should see these `FAIL` rows:

| KSI ID       | Resource                 | Reason |
|--------------|---------------------------|--------|
| `KSI-SC-01`  | `stgvulnerable<suffix>`   | HTTPS-only traffic is disabled. |
| `KSI-SC-02`  | `stgvulnerable<suffix>`   | Minimum TLS version is `TLS1_0`, below the 1.2 baseline. |
| `KSI-SC-03`  | `stgvulnerable<suffix>`   | Public network access is enabled. |
| `KSI-CNA-01` | `nsg-app`                 | `Allow-HTTP-Global` permits `0.0.0.0/0` inbound on TCP/80. |
| `KSI-MLA-01` | `stgvulnerable<suffix>` (blob service) | No diagnostic setting routes logs to `law-fedramp-20x-audit`. |

`stgcompliant<suffix>` and the `Allow-HTTPS-VNet` rule on `nsg-app` should
report `PASS` across the board, demonstrating the scanner correctly
distinguishes compliant from non-compliant configuration rather than
flagging everything.

### Running as the managed identity (`id-ksi-scanner`)

If you deploy the engine on Azure compute (VM, Container App, Automation
Runbook, DevOps agent, etc.) and attach the `id-ksi-scanner` user-assigned
managed identity, run:

```bash
python ksi_validator.py \
  --resource-group rg-fedramp-target \
  --workspace-name law-fedramp-20x-audit \
  --subscription-id "${AZURE_SUBSCRIPTION_ID}" \
  --managed-identity-client-id "$(terraform -chdir=../terraform output -raw ksi_scanner_identity_client_id)"
```

`DefaultAzureCredential` will use `ManagedIdentityCredential` pinned to that
client ID instead of falling back to the Azure CLI credential, with no code
changes required.

### Inspecting the OSCAL evidence package

```bash
cat assessment_results.json | jq '.["assessment-results"].results[0].props'
cat assessment_results.json | jq '.["assessment-results"].results[0].findings[] | select(.target.status.state=="not-satisfied")'
```

---

## 5. Cleanup

Destroy the lab to avoid ongoing Azure charges:

```bash
cd terraform
terraform destroy \
  -var="subscription_id=${AZURE_SUBSCRIPTION_ID}"
```

Confirm with `yes` when prompted. This removes both `rg-fedramp-target` and
`rg-fedramp-engine` and all resources inside them, including the Key Vault
(soft-deleted for 7 days per `soft_delete_retention_days`, then purged
automatically by the `purge_soft_delete_on_destroy = true` provider setting).

---

## Security Notes

- The `Allow-HTTP-Global` NSG rule and `stgvulnerable` storage account are
  **intentional negative fixtures** for this lab. Do not reuse this
  Terraform configuration as-is against a production subscription.
- The `id-ksi-scanner` identity is scoped to `Reader` only at the
  `rg-fedramp-target` resource group — sufficient for read-only compliance
  scanning, following least-privilege principles.
- Key Vault access uses Azure RBAC (`enable_rbac_authorization = true`)
  rather than legacy access policies, and secrets are only readable by the
  deploying principal and the scanner identity.
