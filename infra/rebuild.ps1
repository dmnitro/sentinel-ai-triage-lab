# infra/rebuild.ps1 - rebuild the lab core in about an hour (for an interview demo).
# UNTESTED against a live subscription when written (2026-10-11): run it line by line the first time.
# Covers: resource group, workspace, Sentinel, VM with auto-shutdown. Connectors, DCR, Entra logs,
# Defender plans and analytics rules are re-done from the guide (phases 2c-4), about 20 minutes.
$rg = "rg-soclab"; $loc = "uksouth"; $law = "law-soclab"; $vm = "victim-01"
az group create -n $rg -l $loc
az monitor log-analytics workspace create -g $rg -n $law -l $loc --retention-time 30
az extension add --name sentinel --upgrade
az sentinel onboarding-state create -g $rg --workspace-name $law --name default
$myip = (Invoke-RestMethod "https://api.ipify.org")
az vm create -g $rg -n $vm --image Win2022Datacenter --size Standard_B2s `
  --admin-username labadmin --admin-password (Read-Host "VM admin password") `
  --public-ip-sku Standard --nsg-rule NONE
az network nsg rule create -g $rg --nsg-name "${vm}NSG" -n allow-rdp-myip --priority 1000 `
  --source-address-prefixes "$myip/32" --destination-port-ranges 3389 --access Allow --protocol Tcp
az vm auto-shutdown -g $rg -n $vm --time 2200   # UTC: 23:00 UK summer time