function Create-WindowsDataScienceVM
{
[CmdletBinding(SupportsShouldProcess=$true)]
param 
(
[Parameter(Mandatory=$false, Position=0, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Enables Simple Mode - As little as possible is asked and everything is created with random names")]  
[switch]$Simple,
[Parameter(mandatory=$false, Position=0, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Resource Group Name")]        
[ValidatePattern("^[a-zA-Z0-9_-]{1,64}$")] ## 1-64 characters Alphanumeric, underscore and dash
[string]$resourcegroupname,
[Parameter(mandatory=$false, Position=0, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Location for VM - Run (Get-AzureRmLocation).Location for values")]
[ValidateScript({(Get-AzureRmLocation).Location -contains $_})]
[string]$location,
[pscredential]$credential,
[Parameter(mandatory=$false, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Machine Name")]
[ValidatePattern("^[a-zA-Z0-9_-]{0,15}$")] ## 1-15 characters Alphanumeric, underscore and dash
[ValidateScript({if($resourcegroupname){(Get-AzureRmVM -ResourceGroupName $resourcegroupname).Name -notcontains $_} else {$true}})]
[string]$virtualmachinename,
[Parameter(mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Machine Size - Run (Get-AzureRmVmSize -Location DataCentre).Name for values")]
[ValidatePattern("^[a-zA-Z0-9_-]{0,15}$")] ## 1-15 characters Alphanumeric, underscore and dash
[ValidateScript({if($location){(Get-AzureRmVMSize -Location $location).Name -contains $_}else {$true}})]
[string]$virtualmachinesize,
[Parameter(mandatory=$false, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Storage Account Name must be unique across Azure")]
[ValidatePattern("^[a-z0-9]{3,24}$")] ## 3-24 Alphanumeric, underscore and dash
[ValidateScript({(Test-AzureName -Storage -Name $_) -ne $true})]
[string]$storageaccountname,
[Parameter(mandatory=$false, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Network Name - must be unique in Resource Group")]
[ValidatePattern("^[a-zA-Z0-9 _-]{2,64}$")] ## 2-64 characters Alphanumeric, underscore, space and dash
[ValidateScript({if($resourcegroupname){(Get-AzureRmVirtualNetwork -ResourceGroupName $resourcegroupname).Name -notcontains $_}else {$true}})]
[string]$virtualNetworkName,
[Parameter(mandatory=$false, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Network Interface Name - must be unique in Resource Group")]
[ValidatePattern("^[a-zA-Z0-9 _-]{1,80}$")] ## 1-80 characters Alphanumeric, underscore, space and dash
[ValidateScript({if($resourcegroupname){(Get-AzureRmNetworkInterface -ResourceGroupName $resourcegroupname).Name -notcontains $_}else {$true}})]
[string]$networkInterfaceName,
[Parameter(mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Network Security Group Name - must be unique in Resource Group")]
[ValidatePattern("^[a-zA-Z0-9 _-]{1,80}$")] ## 1-80 characters Alphanumeric, underscore, space and dash
[ValidateScript({if($resourcegroupname){(Get-AzureRmNetworkSecurityGroup -ResourceGroupName $resourcegroupname).Name -notcontains $_}else {$true}})]
[string]$networkSecurityGroupName,
[Parameter(mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Storage Account Type - 'Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS'")]
[ValidateSet('Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS')]
[string]$storageAccountType,
[Parameter(mandatory=$false, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Diagnostic Storage Account Name must be unique across Azure")]
[ValidatePattern("^[a-z0-9]{3,24}$")] ## 3-24 Alphanumeric, underscore and dash
[ValidateScript({(Test-AzureName -Storage -Name $_) -ne $true})]
[string]$diagnosticstorageaccountname,
[Parameter(mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Diagnostic Storage Account Type - 'Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS'")]
[ValidateSet('Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS')]
[string]$diagnosticsStorageAccountType,
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$false, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Address Prefix - normally leave to default")]
[string]$addressPrefix = "10.0.0.0/24", ## I'm not working out the regex for this, sorry :-)
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Subnet Name - normally leave to default")]
                   [ValidatePattern("^[a-zA-Z0-9 _-]{2,80}$")] ## 2-80 characters Alphanumeric, underscore, space and dash

[string]$subnetName ='default',
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Subnet Prefix - normally leave to default")]
[string]$subnetPrefix = "10.0.0.0/24", ## nor this
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Public IP Address Name - unique accross Resource Group")]
                   [ValidatePattern("^[a-zA-Z0-9 _-]{2,80}$")] ## 2-80 characters Alphanumeric, underscore, space and dash
[ValidateScript({if($resourcegroupname){(Get-AzureRmPublicIpAddress -ResourceGroupName $resourcegroupname).ResourceGroupName -notcontains $_}else {$true}})]
[string]$publicIpAddressName,
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Template Json file path")]
[string]$TemplateJsonFilePath,
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Parameter Json file path")]
[string]$ParameterJsonFilePath
)

if ($simple)
{
$rand = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
$resourcegroupname = 'DS-' + $rand
$docs = [Environment]::GetFolderPath("mydocuments")
$ParameterJsonFilePath = "$docs\newparameter.json"
$TemplateJsonFilePath = "$docs\newtemplate.json"
$cred = Get-Credential -Message 'Enter Local Admin Credentials for the VM - Password must have 3 of the following 1 Upper case, 1 lower case, I special character and 1 number'
$location = 'ukwest'
$virtualMachineName = 'DSVM' + $rand
$virtualMachineSize = 'Standard_DS1_v2'
$adminUsername = $adminusername
$storageAccountName = 'dsstorage' + $rand.ToLower()
$virtualNetworkName = 'dsnet' + $rand.ToLower()
$networkInterfaceName = 'dsinter' + $rand.ToLower()
$networkSecurityGroupName = 'dssecgrp' + $rand.ToLower()
$storageAccountType = 'Standard_LRS' 
$diagnosticsStorageAccountName = 'diagds' + $rand.ToLower()
$diagnosticsStorageAccountType = 'Standard_LRS'
$diagnosticsStorageAccountId = "Microsoft.Storage/storageAccounts/$diagnosticsStorageAccountName"
$publicIpAddressName = 'dspubip' + $rand
$publicIpAddressType = 'Dynamic'
}
Function Set-ParameterJson
{
    [CmdletBinding(SupportsShouldProcess=$true)]
param 
(
[Parameter(Mandatory=$true, Position=0, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Resource Group Name")]        
[ValidatePattern("^[a-zA-Z0-9_-]{1,64}$")] ## 1-64 characters Alphanumeric, underscore and dash
[string]$resourcegroupname,
[Parameter(Mandatory=$true, Position=0, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Location for VM - Run (Get-AzureRmLocation).Location for values")]
[ValidateScript({(Get-AzureRmLocation).Location -contains $_})]
[string]$location,
[pscredential]$credential,
[Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Machine Name")]
[ValidatePattern("^[a-zA-Z0-9_-]{0,15}$")] ## 1-15 characters Alphanumeric, underscore and dash
[ValidateScript({(Get-AzureRmVM -ResourceGroupName $resourcegroupname).Name -notcontains $_})]
[string]$virtualmachinename,
[Parameter(Mandatory=$true,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Machine Size - Run (Get-AzureRmVmSize -Location DataCentre).Name for values")]
[ValidatePattern("^[a-zA-Z0-9_-]{0,15}$")] ## 1-15 characters Alphanumeric, underscore and dash
[ValidateScript({(Get-AzureRmVMSize -Location $location).Name -contains $_})]
[string]$virtualmachinesize,
[Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Storage Account Name must be unique across Azure")]
[ValidatePattern("^[a-z0-9]{3,24}$")] ## 3-24 Alphanumeric, underscore and dash
[ValidateScript({(Test-AzureName -Storage -Name $storageaccountname) -ne $true})]
[string]$storageaccountname,
[Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Network Name - must be unique in Resource Group")]
[ValidatePattern("^[a-zA-Z0-9 _-]{2,64}$")] ## 2-64 characters Alphanumeric, underscore, space and dash
[ValidateScript({(Get-AzureRmVirtualNetwork -ResourceGroupName $resourcegroupname).Name -notcontains $_})]
[string]$virtualNetworkName,
[Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Virtual Network Interface Name - must be unique in Resource Group")]
[ValidatePattern("^[a-zA-Z0-9 _-]{1,80}$")] ## 1-80 characters Alphanumeric, underscore, space and dash
[ValidateScript({(Get-AzureRmNetworkInterface -ResourceGroupName $resourcegroupname).Name -notcontains $_})]
[string]$networkInterfaceName,
[Parameter(Mandatory=$true,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Network Security Group Name - must be unique in Resource Group")]
[ValidatePattern("^[a-zA-Z0-9 _-]{1,80}$")] ## 1-80 characters Alphanumeric, underscore, space and dash
[ValidateScript({(Get-AzureRmNetworkSecurityGroup -ResourceGroupName $resourcegroupname).Name -notcontains $_})]
[string]$networkSecurityGroupName,
[Parameter(Mandatory=$true,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Storage Account Type - 'Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS'")]
[ValidateSet('Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS')]
[string]$storageAccountType,
[Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Diagnostic Storage Account Name must be unique across Azure")]
[ValidatePattern("^[a-z0-9]{3,24}$")] ## 3-24 Alphanumeric, underscore and dash
[ValidateScript({(Test-AzureName -Storage -Name $_) -ne $true})]
[string]$diagnosticstorageaccountname,
[Parameter(Mandatory=$true,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Diagnostic Storage Account Type - 'Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS'")]
[ValidateSet('Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS','Premium_LRS')]
[string]$diagnosticsStorageAccountType,
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$false, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Address Prefix - normally leave to default")]
[string]$addressPrefix = "10.0.0.0/24", ## I'm not working out the regex for this, sorry :-)
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Subnet Name - normally leave to default")]
                   [ValidatePattern("^[a-zA-Z0-9 _-]{2,80}$")] ## 2-80 characters Alphanumeric, underscore, space and dash

[string]$subnetName ='default',
[Parameter(Mandatory=$false,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Subnet Prefix - normally leave to default")]
[string]$subnetPrefix = "10.0.0.0/24", ## nor this
[Parameter(Mandatory=$true,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Public IP Address Name - unique accross Resource Group")]
                   [ValidatePattern("^[a-zA-Z0-9 _-]{2,80}$")] ## 2-80 characters Alphanumeric, underscore, space and dash
                   [ValidateScript({(Get-AzureRmPublicIpAddress -ResourceGroupName $resourcegroupname).ResourceGroupName -notcontains $_})]
[string]$publicIpAddressName,
[Parameter(Mandatory=$true,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Template Json file path")]
[string]$TemplateJsonFilePath,
[Parameter(Mandatory=$true,  
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Parameter Json file path")]
[string]$ParameterJsonFilePath
)

    $ParameterJson = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SQLDBAWithABeard/DataScienceVM/master/parameters.json').Content | ConvertFrom-Json 
    $adminusername =$credential.UserName
    $adminuserpassword = $credential.GetNetworkCredential().SecurePassword
    
    $ParameterJson.parameters.location.value = $location
    $ParameterJson.parameters.virtualMachineName.value = $virtualmachinename
    $ParameterJson.parameters.virtualMachineSize.value = $virtualmachinesize
    $ParameterJson.parameters.adminUsername.value = $adminusername
    $ParameterJson.parameters.adminPassword.value = $adminuserpassword
    $ParameterJson.parameters.storageAccountName.value = $storageaccountname
    $ParameterJson.parameters.virtualNetworkName.value = $virtualNetworkName
    $ParameterJson.parameters.networkInterfaceName.value = $networkInterfaceName
    $ParameterJson.parameters.networkSecurityGroupName.value = $networkSecurityGroupName
    $ParameterJson.parameters.storageAccountType.value = $storageAccountType 
    $ParameterJson.parameters.diagnosticsStorageAccountName.value = $diagnosticsStorageAccountName
    $ParameterJson.parameters.diagnosticsStorageAccountType.value = $diagnosticsStorageAccountType
    $ParameterJson.parameters.diagnosticsStorageAccountId.value = "Microsoft.Storage/storageAccounts/$diagnosticsStorageAccountName"
    $ParameterJson.parameters.addressPrefix.value = $addressPrefix 
    $ParameterJson.parameters.subnetName.value = $subnetName
    $ParameterJson.parameters.subnetPrefix.value = $subnetPrefix
    $ParameterJson.parameters.publicIpAddressName.value = $publicIpAddressName
    $ParameterJson.parameters.publicIpAddressType.value = 'Dynamic'
  
    
    If ($Pscmdlet.ShouldProcess($ParameterJsonFilePath, "Creating Parameter File"))
    {
        $ParameterJson | ConvertTo-Json | Set-Content -Path $ParameterJsonFilePath
    }
    If ($Pscmdlet.ShouldProcess("https://raw.githubusercontent.com/SQLDBAWithABeard/DataScienceVM/master/template.json", "Saving Template json file to $TemplateJsonFilePath"))
    {
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SQLDBAWithABeard/DataScienceVM/master/template.json' -OutFile $TemplateJsonFilePath
    }

    (Get-Content $TemplateJsonFilePath).Replace("parameters('resourcegroupname')","'$resourcegroupname'")|Out-File $TemplateJsonFilePath
}

# Register RPs
$resourceProviders = @("microsoft.compute","microsoft.storage","microsoft.network");
if($resourceProviders.length) {
    foreach($resourceProvider in $resourceProviders) {
        $null = Register-AzureRmResourceProvider -ProviderNamespace $resourceProvider;
    }
}

#Create or check for existing resource group
$resourceGroup = Get-AzureRmResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue
if(!$resourceGroup)
{
   try
   {
        If ($Pscmdlet.ShouldProcess($resourceGroupName, "Creating Resource group $resourcegroupname in $location"))
        {
            New-AzureRmResourceGroup -Name $resourceGroupName -Location $Location -erroraction stop
        }
    }
    catch
    {
        Write-warning -message "Something Went wrong- Run `$Error[0] | fl -force to get more information"
    }
}

Set-ParameterJson -resourcegroupname $resourcegroupname -location $location -virtualmachinename $virtualmachinename `
-virtualmachinesize $virtualmachinesize -storageaccountname $storageaccountname -virtualNetworkName $virtualNetworkName `
-networkInterfaceName $networkInterfaceName -networkSecurityGroupName $networkSecurityGroupName `
-storageAccountType $storageAccountType -diagnosticstorageaccountname $diagnosticsStorageAccountName `
-diagnosticsStorageAccountType $diagnosticsStorageAccountType -publicIpAddressName $publicIpAddressName `
-TemplateJsonFilePath $TemplateJsonFilePath -ParameterJsonFilePath $ParameterJsonFilePath -credential $cred

# Start the deployment

if((Test-Path $ParameterJsonFilePath) -and (Test-Path $TemplateJsonFilePath )) 
{
    try
    {
        If ($Pscmdlet.ShouldProcess($resourceGroupName, "Deploying using $TemplateJsonFilePath and $ParameterJsonFilePath"))
        {
            New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $TemplateJsonFilePath -TemplateParameterFile $ParameterJsonFilePath -Verbose -erroraction stop;
        }
    }
    catch
    {
        Write-warning -message "Something Went wrong- Run `$Error[0] | fl -force to get more information"
    } 
}
 else 
 {
    Write-Warning -Message "Something went wrong the files were not available"
 }

 }