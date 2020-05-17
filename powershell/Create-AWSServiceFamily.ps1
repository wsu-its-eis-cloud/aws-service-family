param(
    [Alias("se")]
    [string] $sessionName = "awsDefaultSession",

    [Alias("s")]
    [string] $serviceFamily = "",

    [Alias("st")]
    [string] $serviceFamilyTagName = "service-family",

    [Alias("c")]
    [string] $cidrBlock  = "10.1.1.0/24",

    [Alias("t")]
    [string] $instanceTenancy   = "default",

    [Alias("n")]
    [string[]] $networks  = @("10.1.1.0/25", "10.1.1.128/25"),

    [Alias("z")]
    [string[]] $zones  = @("us-west-2a", "us-west-2b"),

    [Alias("m")]
    [string] $managementMode  = "automatic",

    [Alias("mt")]
    [string] $managementModeTagName  = "management-mode",

    [Alias("e")]
    [string] $environment  = "production",

    [Alias("et")]
    [string] $environmentTagName  = "environment",

    [Alias("elb")]
    [bool] $loadBalancer = $false,

    [Alias("app")]
    [string] $serviceType = "",

    [Alias("ecr")]
    [bool] $containerRegistry = $false,

    [Alias("ecs")]
    [bool] $containerCluster = $false,

    [Alias("tr")]
    [switch] $transcribe = $true,

    [Alias("h")]
    [switch] $help = $false
)

if ($help) {
    Write-Output ("`t Provisions the basic building blocks of a service family.")
    Write-Output ("`t Prerequisites: Powershell, aws-api-session-management, included setup.ps1")
    Write-Output ("`t ")
    Write-Output ("`t Parameters:")
    Write-Output ("`t ")
    Write-Output ("`t sessionName")
    Write-Output ("`t     The name of the global variable that stores the MFA validated AWS session.")
    Write-Output ("`t     Default: {0}" -f $sessionName)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -sessionName {1}" -f $MyInvocation.MyCommand.Name, $sessionName)
    Write-Output ("`t     Example: .\{0}.ps1 -s {1}" -f $MyInvocation.MyCommand.Name, $sessionName)

    Write-Output ("`t ")
    Write-Output ("`t serviceFamily")
    Write-Output ("`t     The name of the service family.")
    Write-Output ("`t     Default: {0}" -f $serviceFamily)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -serviceFamily {1}" -f $MyInvocation.MyCommand.Name, $serviceFamily)
    Write-Output ("`t     Example: .\{0}.ps1 -s {1}" -f $MyInvocation.MyCommand.Name, $serviceFamily)
	
    Write-Output ("`t ")
    Write-Output ("`t serviceFamilyTagName")
    Write-Output ("`t     The name of the tag that stores the service family name")
    Write-Output ("`t     Default: {0}" -f $serviceFamilyTagName)
    Write-Output ("`t     Alias: st")
    Write-Output ("`t     Example: .\{0}.ps1 -serviceFamilyTagName {1}" -f $MyInvocation.MyCommand.Name, $serviceFamilyTagName)
    Write-Output ("`t     Example: .\{0}.ps1 -st {1}" -f $MyInvocation.MyCommand.Name, $serviceFamilyTagName)

    Write-Output ("`t ")
    Write-Output ("`t cidrBlock")
    Write-Output ("`t     The CIDR block to use for this VPC")
    Write-Output ("`t     Default: {0}" -f $cidrBlock)
    Write-Output ("`t     Alias: c")
    Write-Output ("`t     Example: .\{0}.ps1 -cidrBlock {1}" -f $MyInvocation.MyCommand.Name, $cidrBlock)
    Write-Output ("`t     Example: .\{0}.ps1 -c {1}" -f $MyInvocation.MyCommand.Name, $cidrBlock)

    Write-Output ("`t ")
    Write-Output ("`t instanceTenancy")
    Write-Output ("`t     The default tenancy for this VPC, i.e. dedicated hosting versus shared hosting.")
    Write-Output ("`t     Default: {0}" -f $instanceTenancy)
    Write-Output ("`t     Alias: t")
    Write-Output ("`t     Example: .\{0}.ps1 -instanceTenancy {1}" -f $MyInvocation.MyCommand.Name, $instanceTenancy)
    Write-Output ("`t     Example: .\{0}.ps1 -t {1}" -f $MyInvocation.MyCommand.Name, $instanceTenancy)

    Write-Output ("`t ")
    Write-Output ("`t networks")
    Write-Output ("`t     Array of networks to define in the VPC CIDR block.  Must positionally match the zones parameter.")
    Write-Output ("`t     Default: {0}" -f $networks)
    Write-Output ("`t     Alias: n")
    Write-Output ("`t     Example: .\{0}.ps1 -networks {1}" -f $MyInvocation.MyCommand.Name, $networks)
    Write-Output ("`t     Example: .\{0}.ps1 -n {1}" -f $MyInvocation.MyCommand.Name, $networks)

    Write-Output ("`t ")
    Write-Output ("`t zones")
    Write-Output ("`t     The zones to to place the subnets in; corresponds positionally to the subnetworks parameter")
    Write-Output ("`t     Default: {0}" -f $zones)
    Write-Output ("`t     Alias: z")
    Write-Output ("`t     Example: .\{0}.ps1 -zones {1}" -f $MyInvocation.MyCommand.Name, $zones)
    Write-Output ("`t     Example: .\{0}.ps1 -z {1}" -f $MyInvocation.MyCommand.Name, $zones)

    Write-Output ("`t ")
    Write-Output ("`t environment")
    Write-Output ("`t     The environment of the service, e.g., production or staging.")
    Write-Output ("`t     Default: {0}" -f $environment)
    Write-Output ("`t     Alias: e")
    Write-Output ("`t     Example: .\{0}.ps1 -environment {1}" -f $MyInvocation.MyCommand.Name, $environment)
    Write-Output ("`t     Example: .\{0}.ps1 -e {1}" -f $MyInvocation.MyCommand.Name, $environment)

    Write-Output ("`t ")
    Write-Output ("`t environmentTagName")
    Write-Output ("`t     The name of the tag that stores the environment")
    Write-Output ("`t     Default: {0}" -f $environmentTagName)
    Write-Output ("`t     Alias: et")
    Write-Output ("`t     Example: .\{0}.ps1 -environmentTagName {1}" -f $MyInvocation.MyCommand.Name, $environmentTagName)
    Write-Output ("`t     Example: .\{0}.ps1 -et {1}" -f $MyInvocation.MyCommand.Name, $environmentTagName)

    Write-Output ("`t ")
    Write-Output ("`t loadBalancer")
    Write-Output ("`t     Indicates whether to provision a load balancer for the environment.")
    Write-Output ("`t     Default: {0}" -f $loadBalancer)
    Write-Output ("`t     Alias: elb")
    Write-Output ("`t     Example: .\{0}.ps1 -loadBalancer {1}" -f $MyInvocation.MyCommand.Name, $loadBalancer)
    Write-Output ("`t     Example: .\{0}.ps1 -elb {1}" -f $MyInvocation.MyCommand.Name, $loadBalancer)

    Write-Output ("`t ")
    Write-Output ("`t application")
    Write-Output ("`t     Indicates the type of application used by the service to tailor the environment.")
    Write-Output ("`t     Default: {0}" -f $application)
    Write-Output ("`t     Alias: app")
    Write-Output ("`t     Example: .\{0}.ps1 -application {1}" -f $MyInvocation.MyCommand.Name, $application)
    Write-Output ("`t     Example: .\{0}.ps1 -app {1}" -f $MyInvocation.MyCommand.Name, $application)

    Write-Output ("`t ")
    Write-Output ("`t containerRepository")
    Write-Output ("`t     Indicates whether to provision a container repository for the environment.")
    Write-Output ("`t     Default: {0}" -f $containerRegistry)
    Write-Output ("`t     Alias: ecr")
    Write-Output ("`t     Example: .\{0}.ps1 -containerRepository {1}" -f $MyInvocation.MyCommand.Name, $containerRegistry)
    Write-Output ("`t     Example: .\{0}.ps1 -ecr {1}" -f $MyInvocation.MyCommand.Name, $containerRegistry)

    Write-Output ("`t ")
    Write-Output ("`t containerCluster")
    Write-Output ("`t     Indicates whether to provision a container repository for the environment.")
    Write-Output ("`t     Default: {0}" -f $containerRegistry)
    Write-Output ("`t     Alias: ecr")
    Write-Output ("`t     Example: .\{0}.ps1 -containerRepository {1}" -f $MyInvocation.MyCommand.Name, $containerCluster)
    Write-Output ("`t     Example: .\{0}.ps1 -ecs {1}" -f $MyInvocation.MyCommand.Name, $containerCluster)

    Write-Output ("`t ")
    Write-Output ("`t managementMode")
    Write-Output ("`t     The management mode of the service, i.e. automatic or manual")
    Write-Output ("`t     Default: {0}" -f $managementMode)
    Write-Output ("`t     Alias: m")
    Write-Output ("`t     Example: .\{0}.ps1 -managementMode {1}" -f $MyInvocation.MyCommand.Name, $managementMode)
    Write-Output ("`t     Example: .\{0}.ps1 -m {1}" -f $MyInvocation.MyCommand.Name, $managementMode)

    Write-Output ("`t ")
    Write-Output ("`t managementModeTagName")
    Write-Output ("`t     The name of the tag that stores the management mode tag name")
    Write-Output ("`t     Default: {0}" -f $managementModeTagName)
    Write-Output ("`t     Alias: mt")
    Write-Output ("`t     Example: .\{0}.ps1 -managementModeTagName {1}" -f $MyInvocation.MyCommand.Name, $managementModeTagName)
    Write-Output ("`t     Example: .\{0}.ps1 -mt {1}" -f $MyInvocation.MyCommand.Name, $managementModeTagName)

    Write-Output ("`t ")
    Write-Output ("`t loadBalancer")
    Write-Output ("`t     Indicates whether to build a generic load balancer for the service environment")
    Write-Output ("`t     Default: {0}" -f $loadBalancer)
    Write-Output ("`t     Alias: elb")
    Write-Output ("`t     Example: .\{0}.ps1 -loadBalancer {1}" -f $MyInvocation.MyCommand.Name, $loadBalancer)
    Write-Output ("`t     Example: .\{0}.ps1 -elb {1}" -f $MyInvocation.MyCommand.Name, $loadBalancer)

    Write-Output ("`t ")
    Write-Output ("`t containerRegistry")
    Write-Output ("`t     Indicates whether to build a generic container repository for the service environment")
    Write-Output ("`t     Default: {0}" -f $containerRegistry)
    Write-Output ("`t     Alias: ecr")
    Write-Output ("`t     Example: .\{0}.ps1 -loadBalancer {1}" -f $MyInvocation.MyCommand.Name, $containerRegistry)
    Write-Output ("`t     Example: .\{0}.ps1 -elb {1}" -f $MyInvocation.MyCommand.Name, $containerRegistry)

    Write-Output ("`t ")
    Write-Output ("`t containerCluster")
    Write-Output ("`t     Indicates whether to build a generic container cluster for the service environment, with ASG, LC, capacity plan")
    Write-Output ("`t     Default: {0}" -f $containerCluster)
    Write-Output ("`t     Alias: ecs")
    Write-Output ("`t     Example: .\{0}.ps1 -loadBalancer {1}" -f $MyInvocation.MyCommand.Name, $containerCluster)
    Write-Output ("`t     Example: .\{0}.ps1 -elb {1}" -f $MyInvocation.MyCommand.Name, $containerCluster)

    Write-Output ("`t ")
    Write-Output ("`t serviceType")
    Write-Output ("`t     Configures service based on matching rules in IpPermissions and other csv's.")
    Write-Output ("`t     Default: {0}" -f $serviceType)
    Write-Output ("`t     Alias: app")
    Write-Output ("`t     Example: .\{0}.ps1 -serviceType {1}" -f $MyInvocation.MyCommand.Name, $serviceType)
    Write-Output ("`t     Example: .\{0}.ps1 -app {1}" -f $MyInvocation.MyCommand.Name, $serviceType)

    Write-Output ("`t ")
    Write-Output ("`t transcribe")
    Write-Output ("`t     If set, creates a transcript of the script.")
    Write-Output ("`t     Default: {0}" -f $transcribe)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\{0}.ps1 -transcribe {1}" -f $MyInvocation.MyCommand.Name, $transcribe)
    Write-Output ("`t     Example: .\{0}.ps1 -tr {1}" -f $MyInvocation.MyCommand.Name, $transcribe)

    return $false
}

# navigate to library root
cd $PSScriptRoot

# load necessary modules
.\import-required-modules.ps1


if($networks.Length -ne $zones.Length) {
    Write-Output "`t The number of subnetworks must match the number of zones"
    return $false
}

# Check if we are transcribing
if($transcribe) {
    $transcriptName = ("{0}-{1}.transcript" -f $MyInvocation.MyCommand.Name, [DateTimeOffset]::Now.ToUnixTimeSeconds())
    Start-Transcript -Path $transcriptName
}

# Prompt for name if not specified
if ($serviceFamily -eq "") {
	$serviceFamily = Read-Host "Enter the name of the service family"
}
$serviceFamily = $serviceFamily.ToLower()

# Prompt for environment if not valid value
if ($environment -ne "production" -and $environment -ne "staging") {
	$environment = Read-Host "Enter a valid environment [production or staging]"
}
$environment = $environment.ToLower()

# Retrieve specified AWS STS session
$globalSession = $null
$expression = ("`$globalSession = `$global:{0}" -f $sessionName)
Invoke-Expression -Command $expression

# If the session is null, return false
if($globalSession -eq $null) {
    Write-Output ("`t Failed to retrieve specified AWS session.")
    if($transcribe) {
        Stop-Transcript
    }

    return $false
}

# Creating session hashtable for parameter splatting
$session = @{
    'AccessKey'    = $globalSession.AccessKeyId;
    'SecretKey'    = $globalSession.SecretAccessKey;
    'SessionToken' = $globalSession.SessionToken;
}

$serviceFamily
$serviceFamilyTagName
$cidrBlock
$instanceTenancy
$networks
$zones
$managementMode

# Checking for existing VPC with service family
Write-Output ""
Write-Output "`t Searching for conflicting service family VPCs."
Write-Output "`t Building tag filters and retrieving tags..."

$filters = @()
$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "resource-type"
$filter.Values.Add("vpc")
$filters += $filter

$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "tag:service-family"
$filter.Values.Add($serviceFamily)
$filters += $filter
$vpcTags = Get-EC2Tag -Filter $filters @session

if($vpcTags -ne $null) {
    Write-Output "`t Service already exists - aborting!"
    Stop-Transcript
    return $false
}

# Prepare tags for to apply to resources as they are created
Write-Output "`t Building environment tags..."
$hash = @{Key="Name"; Value=$serviceFamily}
$nameTag = [PSCustomObject]$hash
$nameTag

$hash = @{Key=$serviceFamilyTagName; Value=$serviceFamily}
$serviceTag = [PSCustomObject]$hash
$serviceTag

$hash = @{Key=$managementModeTagName; Value=$managementMode}
$managementTag = [PSCustomObject]$hash
$managementTag

$hash = @{Key=$environmentTagName; Value=$environment}
$environmentTag = [PSCustomObject]$hash
$environmentTag

# Creating the virtual private cloud
Write-Output ""
Write-Output "`t Begin building and configuring the virtual private cloud."
Write-Output "`t Creating VPC..."

$vpc = New-EC2VPC -CidrBlock $cidrBlock -InstanceTenancy $instanceTenancy @session
$vpc

do{
    Write-Output ("`t Checking VPC {0} state..." -f $vpc.VpcId)
    $vpc = Get-EC2Vpc -VpcId $vpc.VpcId @session
    Start-Sleep -Seconds 5
} while($vpc.State -ne "available")

Write-Output "`t Enabling VPC DNS hostnames..."
Edit-EC2VpcAttribute -VpcId $vpc.VpcId -EnableDnsHostname $true @session

Write-Output "`t Tagging VPC..."
New-EC2Tag -Resource $vpc.VpcId -Tag $nameTag @session
New-EC2Tag -Resource $vpc.VpcId -Tag $serviceTag @session
New-EC2Tag -Resource $vpc.VpcId -Tag $managementTag @session
New-EC2Tag -Resource $vpc.VpcId -Tag $environmentTag @session

Write-Output "`t Building subnets..."
$subnets = @()
for($i=0;$i -lt $networks.Length;$i++) {
    $subnet = New-EC2Subnet -VpcId $vpc.VpcId -CidrBlock $networks[$i] -AvailabilityZone $zones[$i] @session
    $subnet
    do{
        Write-Output ("`t Checking subnet {0} state..." -f $subnet.CidrBlock)
        $subnet = Get-EC2Subnet -SubnetId $subnet.SubnetId @session
        $subnet
        Start-Sleep -Seconds 5
    } while($subnet.State -ne "available")

    Write-Output "`t Tagging subnet..."
    New-EC2Tag -Resource $subnet.SubnetId -Tag $nameTag @session
    New-EC2Tag -Resource $subnet.SubnetId -Tag $serviceTag @session
    New-EC2Tag -Resource $subnet.SubnetId -Tag $managementTag @session
    New-EC2Tag -Resource $subnet.SubnetId -Tag $environmentTag @session
    $subnets += $subnet
}

# For use in subsequent steps
$subnetList = ($subnets | Select-Object -Expand SubnetId)

# Creating the internet gateway
Write-Output ""
Write-Output "`t Begin building and configuring the internet gateway."
Write-Output "`t Creating internet gateway..."
$igw = New-EC2InternetGateway @session
$igw

Write-Output "`t Tagging internet gateway..."
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $nameTag @session
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $serviceTag @session
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $managementTag @session
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $environmentTag @session

Write-Output "`t Attaching internet gateway to VPC..."
Add-EC2InternetGateway -VpcId $vpc.VpcId -InternetGatewayId $igw.InternetGatewayId @session

do{
    Write-Output "`t Verifying IGW-VPC attachment..."
    do{
        Write-Output "`t Checking IGW-VPC attachment..."
        $igw = Get-EC2InternetGateway -InternetGatewayId $igw.InternetGatewayId @session
        $igw
        Start-Sleep -Seconds 5
    } while($igw.Attachments.Count -ne 1)

    Write-Output "`t Checking IGW-VPC attachment status..."
    $igw = Get-EC2InternetGateway -InternetGatewayId $igw.InternetGatewayId @session
    $igw
    Start-Sleep -Seconds 5
} while($igw.Attachments[0].VpcId -ne $vpc.VpcId -and $igw.Attachments[0].State -ne "available")

Write-Output "`t Internet gateway built, configured, and attached to VPC."
Write-Output ""

Write-Output "`t Retrieving route tables..."
$routeTables = Get-EC2RouteTable @session
$routeTables
foreach($routeTable in $routeTables) {
    if($routeTable.VpcId -eq $vpc.VpcId) {
        Write-Output "`t Tagging route tables..."
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $nameTag @session
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $serviceTag @session
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $managementTag @session
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $environmentTag @session

        Write-Output "`t Registering subnets to route table..."
        foreach($subnet in $subnets) {
            Register-EC2RouteTable -RouteTableId $routeTable.RouteTableId -SubnetId $subnet.SubnetId @session
        }

        Write-Output "`t Creating default IGW route..."
        New-EC2Route -RouteTableId $routeTable.RouteTableId -DestinationCidrBlock "0.0.0.0/0" -GatewayId $igw.InternetGatewayId @session
    }
}
Write-Output "`t VPC built, configured, and tagged."
Write-Output ""

# Revoke default rules from default security group of service VPC (CIS/PCI/AWS best practice)
Write-Output "`t Remove rules from default security group..."
Write-Output ""
$filters = @()
$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "vpc-id"
$filter.Values.Add($vpc.VpcId)
$filters = $filters + $filter

$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "group-name"
$filter.Values.Add("default")
$filters = $filters + $filter

$defaultSg = Get-EC2SecurityGroup -Filter $filters @session
Revoke-EC2SecurityGroupIngress -GroupId $defaultSg.GroupId -IpPermission $defaultSg.IpPermissions @session
Revoke-EC2SecurityGroupEgress -GroupId $defaultSg.GroupId -IpPermission $defaultSg.IpPermissionsEgress @session

# Creating a non-default security group for the service
Write-Output ""
Write-Output "`t Begin building and configuring security groups."
Write-Output "`t Creating service family security group..."
$serviceSgId = New-EC2SecurityGroup -GroupName $serviceFamily -Description $serviceFamily -VpcId $vpc.VpcId @session
$serviceSgId
Start-Sleep 5

# Retrieve newly created service family security group
$filters = @()
$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "vpc-id"
$filter.Values.Add($vpc.VpcId)
$filters = $filters + $filter

$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "group-name"
$filter.Values.Add($serviceFamily)
$filters = $filters + $filter
$serviceSg = Get-EC2SecurityGroup -Filter $filters @session

# Remove default egress rules from service family sg, except when building a container cluster which must register with global ECS service broker
if($containerCluster -eq $false) {
    Write-Output "`t Revoking default egress rules..."
    Revoke-EC2SecurityGroupEgress -GroupId $serviceSgId -IpPermission $serviceSg.IpPermissionsEgress @session
}

# Check if application name is specified
if($serviceType -ne "") {
    [Amazon.EC2.Model.IpPermission[]] $ipPermissionsIngress = @()
    [Amazon.EC2.Model.IpPermission[]] $ipPermissionsEgress = @()

    Import-Csv ApplicationsDefaultSgRules_IpPermissions.csv | ForEach-Object {
        $rule = $_
    
        if($serviceType -eq $rule.ServiceType) {
            $ipPermission = New-Object -TypeName Amazon.EC2.Model.IpPermission
            [Amazon.EC2.Model.IpRange[]] $ipRanges = @()

            if($rule.Ipv4Ranges -ne "") {
                foreach($range in $rule.Ipv4Ranges.Split(",")) {
                    $ipRange = New-Object -TypeName Amazon.EC2.Model.IpRange
                    $ipRange.CidrIp = $range
                    $ipRanges = $ipRanges + $ipRange
                }
                $ipPermission.Ipv4Ranges = $ipRanges
            } elseif ($rule.Ipv6Ranges -ne "") {
                foreach($range in $rule.Ipv6Ranges.Split(",")) {
                    $ipRange = New-Object -TypeName Amazon.EC2.Model.IpRange
                    $ipRange.CidrIp = $range
                    $ipRanges = $ipRanges + $ipRange
                }
                $ipPermission.Ipv6Ranges = $ipRanges
            } else {
                Write-Output ("`t`t Rule {0} {1} contains no IP ranges." -f $rule.Application, $rule.RuleName)
                continue
            }

            $ipPermission.FromPort = $rule.FromPort
            $ipPermission.IpProtocol = $rule.IpProtocol
            $ipPermission.ToPort = $rule.ToPort
            $ipPermission

            if($rule.Directionality -eq "Ingress") {
                $ipPermissionsIngress = $ipPermissionsIngress + $ipPermission
            } else {
                $ipPermissionsEgress = $ipPermissionsEgress + $ipPermission
            }
        }
    }

    if($ipPermissionsIngress.Count -gt 0) {
        Write-Output "`t Applying application ingress rules..."
        Grant-EC2SecurityGroupIngress -GroupId $serviceSgId -IpPermission $ipPermissionsIngress @session
    }

    if($ipPermissionsEgress.Count -gt 0) {
        Write-Output "`t Applying application egress rules..."
        Grant-EC2SecurityGroupEgress -GroupId $serviceSgId -IpPermission $ipPermissionsEgress @session
    }
}

Write-Output "`t Tagging security group..."
New-EC2Tag -Resource $serviceSgId -Tag $nameTag @session
New-EC2Tag -Resource $serviceSgId -Tag $serviceTag @session
New-EC2Tag -Resource $serviceSgId -Tag $managementTag @session
New-EC2Tag -Resource $serviceSgId -Tag $environmentTag @session

Write-Output "`t Security group created, configured, and tagged."
Write-Output ""

if($loadBalancer) {
    # Creating the load balancer
    Write-Output ""
    Write-Output "`t Begin creation and configuration of load balancer."
    Write-Output "`t Creating elastic load balancer..."
    $elb = New-ELB2LoadBalancer -IpAddressType ipv4 -Name $serviceFamily -Scheme internet-facing -SecurityGroup $serviceSgId -Subnet $subnetList -Tag $nameTag,$serviceTag -Type application @session
    $elb

    do{
        Write-Output "`t Checking ELB state..."
        $elb = Get-ELB2LoadBalancer -LoadBalancerArn $elb.LoadBalancerArn @session
        Start-Sleep -Seconds 5
    } while($elb.State.Code -ne "active")

    Write-Output "`t Tagging ELB..."
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $nameTag @session
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $serviceTag @session
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $managementTag @session
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $environmentTag @session

    if($containerCluster -and $serviceType -eq "web") {
        Write-Output "`t Creating web group target..."
        $elbTargetGroupParams = @{ 
            'Name'                       = $serviceFamily;
            'HealthCheckEnabled'         = $true;
            'HealthCheckIntervalSecond'  = 10;
            'HealthCheckTimeoutSecond'   = 5;
            'HealthyThresholdCount'      = 2;
            'Port'                       = 80;
            'Protocol'                   = 'HTTP';
            'TargetType'                 = 'instance';
            'UnhealthyThresholdCount'    = 2;
            'VpcId'                      = $vpc.VpcId;
        }

        $elbTargetGroup = New-ELB2TargetGroup @elbTargetGroupParams @session

        Write-Output "`t Tagging ELB target group..."
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $nameTag @session
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $serviceTag @session
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $managementTag @session
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $environmentTag @session

        Write-Output "`t Creating http listener..."
        $listenerTargetGroupTuple = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.TargetGroupTuple
        $listenerTargetGroupTuple.TargetGroupArn = $elbTargetGroup.TargetGroupArn
        $listenerTargetGroupTuple.Weight = 1
        
        $listenerTargetGroupStickiness = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.TargetGroupStickinessConfig
        $listenerTargetGroupStickiness.DurationSeconds = 300
        $listenerTargetGroupStickiness.Enabled = $false

        $listenerForwardAction = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.ForwardActionConfig
        $listenerForwardAction.TargetGroups = $listenerTargetGroupTuple
        $listenerForwardAction.TargetGroupStickinessConfig = $listenerTargetGroupStickiness

        $listenerAction = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.Action
        $listenerAction.ForwardConfig = $listenerForwardAction
        $listenerAction.Order = 1
        $listenerAction.TargetGroupArn = $elbTargetGroup.TargetGroupArn
        $listenerAction.Type = "Forward"

        $elbHttpListener = @{
            'LoadBalancerArn'            = $elb.LoadBalancerArn;
            'DefaultAction'              = $listenerAction;
            'Port'                       = 80;
            'Protocol'                   = 'HTTP';
        }

        $elbListener = New-ELB2Listener @elbHttpListener @session
        $elbListener
    }

    Write-Output "`t ELB created, tagged and active."
    Write-Output ""
}

if($containerCluster) {
    # Creating EC2 Key Pair
    Write-Output ""
    Write-Output "`t Begin creation and configuration of EC2 SSH Key Pair."
    Write-Output "`t Checking for conflicting key..."

    $ec2Key = $null
    try {
        $ec2Key = Get-EC2KeyPair -KeyName $serviceFamily @session
    } catch {
        $ec2Key = $null
    }

    if($ec2Key -eq $null) {
        if (Test-Path("{0}-ec2Key.fingerprint" -f $serviceFamily)) {
            rm ("{0}cd-ec2Key.fingerprint" -f $serviceFamily)
        }

        if (Test-Path("{0}-ec2Key.pem" -f $serviceFamily)) {
            rm ("{0}-ec2Key.pem" -f $serviceFamily)
        }

        $ec2Key = New-EC2KeyPair -KeyName $serviceFamily @session
        $ec2Key.KeyFingerprint | Out-File -FilePath ("{0}-ec2Key.fingerprint" -f $serviceFamily)
        $ec2Key.KeyMaterial | Out-File -FilePath ("{0}-ec2Key.pem" -f $serviceFamily)
        Write-Output "`t EC2 Key created."
    } else {
        Write-Output "`t EC2 key already exists or failed to be created."
    }

    Write-Output "`t EC2 Key stage complete, "
    Write-Output ""

    $blockDeviceMap = New-Object -TypeName Amazon.AutoScaling.Model.BlockDeviceMapping
    $blockDeviceMap.DeviceName = '/dev/xvdcz'

    $blockDeviceMap.Ebs = New-Object -TypeName Amazon.AutoScaling.Model.Ebs
    $blockDeviceMap.Ebs.VolumeSize = 22;
    $blockDeviceMap.Ebs.VolumeType = 'gp2';
    $blockDeviceMap.Ebs.Encrypted = $true;
    $blockDeviceMap.Ebs.DeleteOnTermination = $true;

    $userData = ('#!/bin/bash
echo ECS_CLUSTER={0} >> /etc/ecs/ecs.config;echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config;' -f $serviceFamily)
    $userData = [System.Text.Encoding]::UTF8.GetBytes($userData)
    $userData = [System.Convert]::ToBase64String($userData)

    #$imageId = (Get-SSMParameter -Name /aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2 -region 'us-west-2').Value
    $imageId = ((Get-SSMParameter -Name /aws/service/ecs/optimized-ami/amazon-linux-2/recommended -region 'us-west-2' @session).Value | ConvertFrom-Json).image_id
    $imageId

    if($imageId -eq $null) {
        Write-Output "`t Failed to retrieve valid AMI image."
        Stop-Transcript
        return $false
    }

    $iamRoleParams = @{ 
        'Path'                       = '/';
        'RoleName'                   = ("{0}-ecs-cluster-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'AssumeRolePolicyDocument'   = '{"Version":"2008-10-17","Statement":[{"Sid":"","Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}';
        'Tag'                        = $nameTag,$serviceTag,$managementTag,$environmentTag;
    }
    $iamRole = New-IAMRole @iamRoleParams @session
    $iamRole

    if($iamRole -eq $null) {
        Write-Output "`t Failed to create role."
        Stop-Transcript
        return $false
    }

    # Attach AmazonEC2ContainerServiceforEC2Role policy
    $iamRolePolicyParams = @{ 
        'RoleName'                   = $iamRole.RoleName;
        'PolicyArn'                  = 'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role';
    }
    $iamRolePolicy = Register-IAMRolePolicy @iamRolePolicyParams @session
    $iamRolePolicy

    # Attach CloudWatchAgentServerPolicy policy
    $iamRolePolicyParams = @{ 
        'RoleName'                   = $iamRole.RoleName;
        'PolicyArn'                  = 'arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy';
    }
    $iamRolePolicy = Register-IAMRolePolicy @iamRolePolicyParams @session
    $iamRolePolicy

    # Attach AmazonSSMManagedInstanceCore policy
    $iamRolePolicyParams = @{ 
        'RoleName'                   = $iamRole.RoleName;
        'PolicyArn'                  = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore';
    }
    $iamRolePolicy = Register-IAMRolePolicy @iamRolePolicyParams @session
    $iamRolePolicy

    # Attach AmazonSSMDirectoryServiceAccess policy
    $iamRolePolicyParams = @{ 
        'RoleName'                   = $iamRole.RoleName;
        'PolicyArn'                  = 'arn:aws:iam::aws:policy/AmazonSSMDirectoryServiceAccess';
    }
    $iamRolePolicy = Register-IAMRolePolicy @iamRolePolicyParams @session
    $iamRolePolicy

    $iamInstanceProfileParams = @{ 
        'InstanceProfileName'        = $iamRole.RoleName;
        'Path'                       = '/';
    }
    $iamInstanceProfile = New-IAMInstanceProfile @iamInstanceProfileParams @session
    $iamInstanceProfile = Add-IAMRoleToInstanceProfile -InstanceProfileName $iamRole.RoleName -RoleName $iamRole.RoleName @session
    $iamInstanceProfile = Get-IAMInstanceProfile -InstanceProfileName $iamRole.RoleName @session
    $iamInstanceProfile

    # Wait for Profile ARN to propogate in AWS backend
    Start-Sleep -Seconds 30

    $asLaunchConfigurationParams = @{ 
        'LaunchConfigurationName'    = ("EC2ContainerService-{0}-EcsInstanceLc-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'InstanceType'               = 't3a.medium';
        'ImageId'                    = $imageId;
        'KeyName'                    = $serviceFamily;
        'AssociatePublicIpAddress'   = $true;
        'BlockDeviceMapping'         = $blockDeviceMap;
        'IamInstanceProfile'         = $iamInstanceProfile.Arn;
        'InstanceMonitoring_Enabled' = $true;
        'SecurityGroup'              = $serviceSgId;
        'UserData'                   = $userData;
    }
    New-ASLaunchConfiguration @asLaunchConfigurationParams @session
    Start-Sleep -Seconds 2
    $asLaunchConfiguration = Get-ASLaunchConfiguration -LaunchConfigurationName $asLaunchConfigurationParams.LaunchConfigurationName @session

    $asAutoScalingGroupParams = @{ 
        'AutoScalingGroupName'             = ("EC2ContainerService-{0}-EcsInstanceAsg-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'LaunchConfigurationName'          = $asLaunchConfiguration.LaunchConfigurationName;
        'MinSize'                          = 1;
        'MaxSize'                          = 2;
        'AvailabilityZone'                 = $zones;
        'DefaultCooldown'                  = 300;
        'DesiredCapacity'                  = 1;
        'NewInstancesProtectedFromScaleIn' = $true;
        'Tag'                              = $nameTag,$serviceTag,$managementTag,$environmentTag;
        'TargetGroupARNs'                  = $elbTargetGroup.TargetGroupArn;
        'VPCZoneIdentifier'                = ($subnetList -join ',');
    }
    New-ASAutoScalingGroup @asAutoScalingGroupParams @session
    Start-Sleep -Seconds 2
    $asAutoScalingGroup = Get-ASAutoScalingGroup -AutoScalingGroupName $asAutoScalingGroupParams.AutoScalingGroupName @session
    $asAutoScalingGroup

    Write-Output "`t Verifying ECS Capacity Provider Created..."
    $ecsCapacityProviderParams = @{ 
        'Name'                                                  = $("EC2ContainerService-{0}-EcsInstanceCp-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'AutoScalingGroupProvider_AutoScalingGroupArn'          = $asAutoScalingGroup.AutoScalingGroupARN;
        'AutoScalingGroupProvider_ManagedTerminationProtection' = "ENABLED";
        'ManagedScaling_MaximumScalingStepSize'                 = 1;
        'ManagedScaling_MinimumScalingStepSize'                 = 1;
        'ManagedScaling_Status'                                 = "DISABLED";
        'ManagedScaling_TargetCapacity'                         = 1;
        'Tag'                                                   = $nameTag,$serviceTag,$managementTag,$environmentTag;
    }
    $ecsCapacityProvider = New-ECSCapacityProvider @ecsCapacityProviderParams @session
    $ecsCapacityProvider

    Write-Output "`t Verifying ECS Capacity Provider Created..."
    do{
        Write-Output "`t Checking ECS Capacity Provider status..."
        $ecsCapacityProvider = Get-ECSCapacityProvider -CapacityProvider $ecsCapacityProvider.CapacityProviderArn @session
        $ecsCapacityProvider
        Start-Sleep -Seconds 2
    } while($ecsCapacityProvider.Status -ne 'ACTIVE')
    Write-Output "`t ECS Capacity Provider verified."

    Write-Output "`t Creating ECS cluster..."
    $clusterStrategyItem = New-Object -TypeName Amazon.ECS.Model.CapacityProviderStrategyItem
    $clusterStrategyItem.Base = 0
    $clusterStrategyItem.CapacityProvider = $ecsCapacityProvider.Name
    $clusterStrategyItem.Weight = 1

    $clusterSetting = New-Object -TypeName Amazon.ECS.Model.ClusterSetting
    $clusterSetting.Name = "containerInsights"
    $clusterSetting.Value = "enabled"

    $clusterName = $serviceFamily
    $clusters = Get-ECSClusterList @session
    if($clusters) {
        foreach($cluster in $clusters) {
            if($cluster.Split("/")[1] -eq $serviceFamily) {
                $clusterName = ("{0}-{1}" -f $clusterName, [DateTimeOffset]::Now.ToUnixTimeSeconds())
                Write-Output "`t`t`t Warning >>>>>>> Duplicate ECS Cluster name detected, adding time string"
            }
        }
    }

    $ecs = New-ECSCluster -ClusterName $clusterName -Tag $nameTag,$serviceTag,$managementTag,$environmentTag -Setting $clusterSetting -CapacityProvider $ecsCapacityProvider.Name -DefaultCapacityProviderStrategy $clusterStrategyItem @session
    Start-Sleep -Seconds 5
    $ecs
    $ecs = Get-ECSClusterDetail -Cluster $ecs.ClusterArn @session

    Write-Output "`t Verifying ECS Capacity Provider Created..."
    do{
        Write-Output "`t Checking ECS Cluster has propagated..."
        $ecs = Get-ECSClusterDetail -Cluster $ecs.Clusters[0].ClusterArn @session
        $ecs
        Start-Sleep -Seconds 5
    } while($ecs.Clusters[0].Status -ne 'ACTIVE')

    do{
        Write-Output "`t Checking ECS Cluster status..."
        $ecs = Get-ECSClusterDetail -Cluster $ecs.Clusters[0].ClusterArn @session
        $ecs
        Start-Sleep -Seconds 5
    } while($ecs.Clusters[0].Status -ne 'ACTIVE')
    Write-Output "`t ECS cluster is active."
}

if($containerRegistry) {
    # Creating the container repository
    Write-Output ""
    Write-Output "`t Begin creation and configuration of elastic container repository."
    
    Write-Output "`t Creating elastic container repository..."
    $containerName = ("{0}/{1}" -f $environment,$serviceFamily)
    $ecr = New-ECRRepository -RepositoryName $containerName -Tag $nameTag,$serviceTag,$managementTag,$environmentTag @session
    $ecr

    do{
        Write-Output "`t Checking ECR state..."
        $ecrExists = $false

        try {
            $ecr = Get-ECRRepository -RepositoryName $containerName @session
            if($ecr -ne $null) {
                $ecrExists = $true
            }
        } catch {
            Write-Output "`t ECR was not found, checking again..."
        }
        
        Start-Sleep -Seconds 5
    } while($ecrExists -ne $true)

    Write-Output "`t ECR created, tagged and active."
    Write-Output ""
}

Write-Output ""
Write-Output "`t Service environment created successfully."

# Begin validation
Write-Output "`t Validating Environment..."
$validationPassed = $false

$vpcValidated = $false
$vpcTest = Get-EC2Vpc -VpcId $vpc.VpcId @session
if($vpcTest.State -eq "available") {
    Write-Output ("`t`t VPC {0} validated" -f $vpc.VpcId)
    $vpcValidated = $true
} else {
    Write-Output ("`t`t VPC {0} FAILED" -f $vpc.VpcId)
}

$subnetsValidated = @()
foreach($subnet in $subnets) {
    $subnetTest = Get-EC2Subnet -SubnetId $subnet.SubnetId @session

    $subnetsValidated += $false
    if($subnetTest.State -eq "available") {
        Write-Output ("`t`t subnet {0} validated" -f $subnet.CidrBlock)
        $subnetsValidated[$subnetsValidated.Count-1] = $true
    } else {
        Write-Output ("`t`t subnet {0} FAILED" -f $subnet.CidrBlock)
    }
}

$igwValidated = $false
$igwTest = Get-EC2InternetGateway -InternetGatewayId $igw.InternetGatewayId @session
if($igwTest.Attachments[0].State -eq "available") {
    Write-Output ("`t`t IGW {0} validated" -f $igw.InternetGatewayId)
    $igwValidated = $true
} else {
    Write-Output ("`t`t IGW {0} FAILED" -f $igw.InternetGatewayId)
}

$serviceSgIdValidated = $false
$serviceSgIdTest = Get-EC2SecurityGroup -GroupId $serviceSgId @session
if($serviceSgIdTest.VpcId -eq $vpc.VpcId) {
    Write-Output ("`t`t SG {0} validated" -f $serviceSgId)
    $serviceSgIdValidated = $true
} else {
    Write-Output ("`t`t SG {0} FAILED" -f $serviceSgId)
}

$ecsValidated = $false
$ec2KeyValidated = $false
if($containerCluster) {
    try {
        $ecsTest = Get-ECSClusterDetail -Cluster $ecs.Clusters[0].ClusterArn @session
        if($ecsTest -ne $null) {
            if($ecsTest.Clusters[0].Status -eq "ACTIVE") {
                $ecsValidated = $true
            }
            
            Write-Output ("`t`t ECS {0} validated" -f $ecsTest.Clusters[0].ClusterArn)
            $ecsValidated = $true
        }
    } catch {
        #
    }

    $ec2KeyValidated = $false
    if ((Test-Path("{0}-ec2Key.fingerprint" -f $serviceFamily)) -and (Test-Path("{0}-ec2Key.pem" -f $serviceFamily))) {
        Write-Output ("`t`t EC2 Key {0} validated" -f $serviceFamily)
        $ec2KeyValidated = $true
    } else {
        Write-Output ("`t`t EC2 Key {0} FAILED" -f $serviceFamily)
    }
} else {
    $ecsValidated = $true
    $ec2KeyValidated = $true
}

$elbValidated = $false
if($loadBalancer) {
    
    $elbTest = Get-ELB2LoadBalancer -LoadBalancerArn $elb.LoadBalancerArn @session
    if($elbTest.State[0].Code -eq "active") {
        Write-Output ("`t`t ELB {0} validated" -f $elb.LoadBalancerName)
        $elbValidated = $true
    } else {
        Write-Output ("`t`t ELB {0} FAILED" -f $elb.LoadBalancerName)
    }
} else {
    $elbValidated = $true
}

if($containerRegistry) {
    $ecrValidated = $false

    try {
        $ecrTest = Get-ECRRepository -RepositoryName $ecr.RepositoryName @session
        if($ecrTest -ne $null) {
            Write-Output ("`t`t ECR {0} validated" -f $ecr.RepositoryName)
            $ecrValidated = $true
        }
    } catch {
        #
    }
} else {
    $ecrValidated = $true
}

if($vpcValidated -and (($subnetsValidated | Unique).Count -eq 1 -and $subnetsValidated[0] -eq $true) -and $igwValidated -and $serviceSgIdValidated -and $ec2KeyValidated -and $ecsValidated -and $elbValidated -and $ecrValidated) {
    $validationPassed = $true
}

$validationPassed
if($validationPassed) {
    Write-Output "`t Environment successfully validated"
} else {
    Write-Output "`t Validation failed, review logs."
}

# Check if we are transcribing
if($transcribe) {
    Stop-Transcript
    Start-Sleep 2
}

# Build account baseline packet
$packetName = ("ServiceProvisionedPacket-{0}-{1}.zip" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds())
Get-ChildItem -Exclude _*,.*,*.md | Compress-Archive -DestinationPath $packetName -Force
rm *.transcript
rm *.pem
rm *.fingerprint

return $validationPassed