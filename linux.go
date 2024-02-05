package main

import (
	"os"
	"context"
	"io/ioutil"
	"log"
	"fmt"
	"time"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

var subscriptionId string

const (
	resourceGroupName = "demo-group"
	vmName = "demo-vm"
	vnetName = "demo-vnet"
	subnetName = "demo-subnet"
	nsgName = "demo-nsg"
	nicName = "demo-nic"
	diskName = "demo-disk"
	IPName = "demo-IP"
	location = "westus"
)

var (
	resourcesClientFactory *armresources.ClientFactory
	computeClientFactory   *armcompute.ClientFactory
	networkClientFactory   *armnetwork.ClientFactory
)

var (
	resourceGroupClient *armresources.ResourceGroupsClient

	virtualNetworksClient   *armnetwork.VirtualNetworksClient
	subnetsClient           *armnetwork.SubnetsClient
	securityGroupsClient    *armnetwork.SecurityGroupsClient
	publicIPAddressesClient *armnetwork.PublicIPAddressesClient
	interfacesClient        *armnetwork.InterfacesClient

	virtualMachinesClient *armcompute.VirtualMachinesClient
	disksClient           *armcompute.DisksClient
)


func main() {
	subscriptionId = os.Getenv("AZURE_SUBSCRIPTION_ID")
	if len(subscriptionId) == 0 {
		log.Fatal("SubscriptionId is not set")
	}

	// Creates VM using helper functions
	create()
	// Wait 5 minute before deleting
	fmt.Println("Start 5 minute timer")
	time.Sleep(5*time.Minute)
	// Delete VM using helper functions
	destroy()
	log.Println("Linux Virtual Machine deleted successfully")
}

func create() {
	conn, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("Can't connect to Azure:%+v", err)
	}
	// Create background context for API calls
	ctx := context.Background()


	// Set up ARM client factories for managing resources
	resourcesClientFactory, err = armresources.NewClientFactory(subscriptionId, conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	networkClientFactory, err = armnetwork.NewClientFactory(subscriptionId, conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	computeClientFactory, err = armcompute.NewClientFactory(subscriptionId, conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	// Initialize clients using factory
	resourceGroupClient = resourcesClientFactory.NewResourceGroupsClient()
	virtualNetworksClient = networkClientFactory.NewVirtualNetworksClient()
	subnetsClient = networkClientFactory.NewSubnetsClient()
	securityGroupsClient = networkClientFactory.NewSecurityGroupsClient()
	publicIPAddressesClient = networkClientFactory.NewPublicIPAddressesClient()
	interfacesClient = networkClientFactory.NewInterfacesClient()
	virtualMachinesClient = computeClientFactory.NewVirtualMachinesClient()
	disksClient = computeClientFactory.NewDisksClient()

	// Create virtual machine using helper functions
	if err := createResourceGroup(ctx); err != nil {
		log.Fatalf("Can't create Resource Group:%+v", err)
	}
	log.Println("Resource Group created successfully")
	if err := createVirtualNetwork(ctx); err != nil {
		log.Fatalf("Can't create Virtual Network:%+v", err)
	}
	log.Println("Virtual network created successfully")

	subnet, err := createSubnets(ctx)
	if err != nil {
		log.Fatalf("cannot create subnet:%+v", err)
	}
	log.Println("Subnet created successfully")
	IP, err := createIP(ctx)
	if err != nil {
		log.Fatalf("cannot create public IP address:%+v", err)
	}
	log.Println("IP created successfully")

	nsg, err := createNetworkSecurityGroup(ctx)
	if err != nil {
		log.Fatalf("cannot create network security group:%+v", err)
	}
	log.Println("nsg created successfully")

	networkInterface, err := createNetworkInterface(ctx, *subnet.ID, *IP.ID, *nsg.ID)
	if err != nil {
		log.Fatalf("cannot create network interface:%+v", err)
	}
	log.Println("Network Interface created successfully")

	networkInterfaceID := networkInterface.ID
	if err := createVirtualMachine(ctx, *networkInterfaceID); err != nil {
		log.Fatalf("Can't create Virtual Machine:%+v", err)
	}
	log.Println("Linux Virtual machine created successfully")

}

func destroy() {
	ctx := context.Background()
	//Delete virtual machine resources using helper functions

	if err := deleteVirtualMachine(ctx); err != nil {
		log.Fatalf("Can't delete Virtual Machine:%+v", err)
	}
	if err := deleteDisk(ctx); err != nil {
		log.Fatalf("Can't delete Disk:%+v", err)
	}
	log.Println("Disk deleted successfully")
	if err := deleteNetworkInterface(ctx); err != nil {
		log.Fatalf("Can't delete Network Interface:%+v", err)
	}
	log.Println("Network Interface deleted successfully")
	if err := deleteNetworkSecurityGroup(ctx); err != nil {
		log.Fatalf("Can't delete nsg:%+v", err)
	}
	log.Println("nsg deleted successfully")
	if err := deleteIP(ctx); err != nil {
		log.Fatalf("Can't delete IP Address:%+v", err)
	}
	log.Println("IP Address deleted successfully")
	if err := deleteSubnets(ctx); err != nil {
		log.Fatalf("Can't delete Subnets:%+v", err)
	}
	log.Println("Subnet deleted successfully")
	if err := deleteVirtualNetwork(ctx); err != nil {
		log.Fatalf("Can't delete Virtual Network:%+v", err)
	}
	if err := deleteResourceGroup(ctx); err != nil {
		log.Fatalf("Can't delete Resource Group:%+v", err)
	}
	log.Println("ResourceGroup deleted successfully")
}


func createResourceGroup(ctx context.Context) error{
	// Create instance of armresources.ResourceGroup
    parameters := armresources.ResourceGroup{
        Location: to.Ptr(location),
        Tags:     map[string]*string{"demo-rs-tag": to.Ptr("demo-tag")},
    }
	// Create Resource Group
    _,err := resourceGroupClient.CreateOrUpdate(ctx, resourceGroupName, parameters, nil)
    if err != nil {
        return err
    }
	return nil
}


func deleteResourceGroup(ctx context.Context) error{
	// Begin deletion
	pollerResponse, err := resourceGroupClient.BeginDelete(ctx, resourceGroupName, nil)
	if err != nil {
		return err
	}
	// Poll until deletion is done to check for errors during deletion
	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

func createVirtualNetwork(ctx context.Context) error {
	// Create instance of Virtual Network
	parameters := armnetwork.VirtualNetwork{
        Location: to.Ptr(location), // Set the location for the virtual network.
        Properties: &armnetwork.VirtualNetworkPropertiesFormat{
            AddressSpace: &armnetwork.AddressSpace{
                AddressPrefixes: []*string{
                    to.Ptr("10.1.0.0/16"), // Set the IPv4 address space for the virtual network.
                },
            },
        },
    }
	// Begin creating Virtual Network and check for errors 
	pollerResponse, err := virtualNetworksClient.BeginCreateOrUpdate(ctx, resourceGroupName, vnetName, parameters, nil)
	if err != nil {
		return err
	}
	// Check for errors until creation of Virtual Network is done
	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

func deleteVirtualNetwork(ctx context.Context) error {
	// Initiate deletion of Virtual network
	pollerResponse, err := virtualNetworksClient.BeginDelete(ctx, resourceGroupName, vnetName, nil)
	if err != nil {
		return err
	}

	// Poll until deletion is finished
	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

func createSubnets(ctx context.Context) (*armnetwork.Subnet, error){
	// Create instance of armnetwork.Subnet
	parameters := armnetwork.Subnet {
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: to.Ptr("10.1.10.0/24"),
		},
	}

	// Initiate creation of subnet
	pollerResponse, err := subnetsClient.BeginCreateOrUpdate(ctx, resourceGroupName, vnetName, subnetName, parameters, nil)
    if err != nil {
        return nil, err
    }

    // Poll until creation of subnet is done.
    res, err := pollerResponse.PollUntilDone(ctx, nil)
    if err != nil {
        return nil, err
    }

	return &res.Subnet, nil
}

func deleteSubnets(ctx context.Context) error {
	// Initiate deletion of Subnet
	pollerResponse, err := subnetsClient.BeginDelete(ctx, resourceGroupName, vnetName, subnetName, nil)
	if err != nil {
		return err
	}
	// Poll until deletion is complete
	_,err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

func createIP(ctx context.Context) (*armnetwork.PublicIPAddress, error) {
	// Create instance of armnetwork.PublicIPAddress
	parameters := armnetwork.PublicIPAddress{
		Location: to.Ptr(location),
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic), 
		},
	}
	// Initiate creation of PublicIPAddress
	pollerResponse, err := publicIPAddressesClient.BeginCreateOrUpdate(ctx, resourceGroupName, IPName, parameters, nil)
	if err != nil {
		return nil, err
	}
	// Poll until creation of PublicIPAddress is complete
	res, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &res.PublicIPAddress, err
}

func deleteIP(ctx context.Context) error {
// Initiate deletion of PublicIPAddress
	pollerResponse, err := publicIPAddressesClient.BeginDelete(ctx, resourceGroupName, IPName, nil)
	if err != nil {
		return err
	}
// Poll until deletion of PublicIPAddress is complete
	_,err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

func createNetworkSecurityGroup(ctx context.Context) (*armnetwork.SecurityGroup, error) {
	// Create instance of armnetwork.SecurityGroup
	parameters := armnetwork.SecurityGroup{
		Location: to.Ptr(location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				{ // Define an inbound security rule for SSH (port 2).
					Name: to.Ptr("demo_inbound_22"),  // Set the name for the inbound rule.
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						SourceAddressPrefix:      to.Ptr("0.0.0.0/0"),  // Allow traffic from any source.
						SourcePortRange:          to.Ptr("*"),         // Allow traffic from any source port.
						DestinationAddressPrefix: to.Ptr("0.0.0.0/0"), // Allow traffic to any destination.
						DestinationPortRange:     to.Ptr("18"),        // Allow traffic to port 18 (SSH).
						Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolTCP), // Set the protocol to TCP.
						Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow), // Allow the traffic.
						Priority:                 to.Ptr[int32](100), // Set the priority for rule evaluation.
						Description:              to.Ptr("sample network security group inbound port 18"), // Set a description for the rule.
						Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound), // Set the direction to inbound.
					},
		
				},
				// Define an outbound security rule for SSH (port 22).
				{
					Name: to.Ptr("demo_outbound_22"), // Set the name for the outbound rule.
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						SourceAddressPrefix:      to.Ptr("0.0.0.0/0"),  // Allow traffic from any source.
						SourcePortRange:          to.Ptr("*"),        // Allow traffic from any source port.
						DestinationAddressPrefix: to.Ptr("0.0.0.0/0"),  // Allow traffic to any destination.
						DestinationPortRange:     to.Ptr("22"),         // Allow traffic to port 2 (SSH).
						Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolTCP),   // Set the protocol to TCP.
						Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),   // Allow the traffic.
						Priority:                 to.Ptr[int32](100),    // Set the priority for rule evaluation.
						Description:              to.Ptr("demo network security group outbound port 22"), // Set a description for the rule.
						Direction:                to.Ptr(armnetwork.SecurityRuleDirectionOutbound),  // Set the direction to outbound. 
					},
				},
			},
		},
	}

	pollerResponse, err := securityGroupsClient.BeginCreateOrUpdate(ctx, resourceGroupName, nsgName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.SecurityGroup, nil
}

func deleteNetworkSecurityGroup(ctx context.Context) error{
// Begin deletion of nsg
	pollerResponse, err := securityGroupsClient.BeginDelete(ctx, resourceGroupName, nsgName, nil)
	if err != nil {
		return err
	}
// Poll until deletion of nsg is complete
	_,err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

func createNetworkInterface(ctx context.Context, subnetID string, IPID string, nsgID string) (*armnetwork.Interface, error){
    // Create an instance of armnetwork.Interface
	parameters := armnetwork.Interface{
		Location: to.Ptr(location),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("ipConfig"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
						Subnet: &armnetwork.Subnet{
							ID: to.Ptr(subnetID),
						},
						PublicIPAddress: &armnetwork.PublicIPAddress{
							ID: to.Ptr(IPID),
						},
					},
				},
			},
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: to.Ptr(nsgID),
			},
		},
	}
// Initiate creation of network interface
	pollerResponse, err := interfacesClient.BeginCreateOrUpdate(ctx, resourceGroupName, nicName, parameters, nil)
	if err != nil {
		return nil, err
	}
// Poll until creation of network interface is complete
	res, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &res.Interface, err
}

func deleteNetworkInterface(ctx context.Context) error {
// Initiate deletion of network interface
	pollerResponse, err := interfacesClient.BeginDelete(ctx, resourceGroupName, nicName, nil)
	if err != nil{
		return err
	}
// Poll until deletion of network interface is complete
	_,err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

func createVirtualMachine(ctx context.Context, networkInterfaceID string) error {
	//require ssh key for authentication on linux
	sshPublicKeyPath := "/Users/vknr/.ssh/id_rsa.pub"
	var sshBytes []byte
	_,err := os.Stat(sshPublicKeyPath)
	if err == nil {
		sshBytes,err = ioutil.ReadFile(sshPublicKeyPath)
		if err != nil {
			return err
		}
	}


	// Define parameters for creating the virtual machine.
	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(location), // Set the location for the virtual machine.

		Identity: &armcompute.VirtualMachineIdentity{
			Type: to.Ptr(armcompute.ResourceIdentityTypeNone),
		},

		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					//Specify the image reference for the virtual machine.
					//require ssh key for authentication on linux
					Offer:     to.Ptr("UbuntuServer"),
					Publisher: to.Ptr("Canonical"),
					SKU:       to.Ptr("18.04-LTS"),
					Version:   to.Ptr("latest"),

				},
				OSDisk: &armcompute.OSDisk{
					Name:         to.Ptr(diskName), // Set the name for the OS disk.
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
					Caching:      to.Ptr(armcompute.CachingTypesReadWrite),
					ManagedDisk: &armcompute.ManagedDiskParameters{
						StorageAccountType: to.Ptr(armcompute.StorageAccountTypesStandardLRS), 
					},
				},
			},
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_F2s")), // Set the VM size.
			},
			OSProfile: &armcompute.OSProfile{
				ComputerName:  to.Ptr("demo-compute"), // Set the computer name.
				AdminUsername: to.Ptr("demo-user"),     // Set the admin username.
				AdminPassword: to.Ptr("Password!23"),    // Set the admin password.
				//require ssh key for authentication on linux
				LinuxConfiguration: &armcompute.LinuxConfiguration{
					DisablePasswordAuthentication: to.Ptr(true),
					SSH: &armcompute.SSHConfiguration{
						PublicKeys: []*armcompute.SSHPublicKey{
							{
								Path:    to.Ptr(fmt.Sprintf("/home/%s/.ssh/authorized_keys", "demo-user")),
								KeyData: to.Ptr(string(sshBytes)),
							},
						},
					},
				},
			},
			NetworkProfile: &armcompute.NetworkProfile{
				// Specify the network interfaces for the virtual machine.
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: to.Ptr(networkInterfaceID),
					},
				},
			},
		},
	}

	// Initiate the creation of the virtual machine.
	pollerResponse, err := virtualMachinesClient.BeginCreateOrUpdate(ctx, resourceGroupName, vmName, parameters, nil)
	if err != nil {
		return err
	}

	// Poll until the virtual machine creation is done.
	_,err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}


func deleteVirtualMachine(ctx context.Context) error {
	// Begin deletion of Virtual Machine
	pollerResponse, err := virtualMachinesClient.BeginDelete(ctx, resourceGroupName, vmName, nil)
	if err != nil {
		return err
	}
	// Poll until deletion of Virtual Machine is done
	_,err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

func deleteDisk(ctx context.Context) error {
	// Begin deletion of Disk
	pollerResponse, err := disksClient.BeginDelete(ctx, resourceGroupName, diskName, nil)
	if err != nil {
		return err
	}
	// Poll until deletion of Disk
	_,err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}
