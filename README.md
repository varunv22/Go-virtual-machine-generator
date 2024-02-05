# Go-virtual-monitor-generator
This is a Golang script to create a windows virtual machine as well as a linux virtual machine.

Steps to run this script
1. Set your azure subscription ID variable so the code runs. You can do this by running **export AZURE_SUBSCRIPTION_ID="xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"**

If running the windows script(windows.go):
1. Run **go run windows.go**
5. Run **az ssh vm -g demo-group -n demo-vm --local-user demo-user** to ssh into your vm

If running the linux script(linux.go):
1. Change the sshPublicKeyPath variable to where your public ssh key is located(usually in the id_rsa.pub file).
2. Next, run **go run linux.go**
3. You can get the IP address necessary to login by running **az network public-ip list -g demo-group**
4. Run **ssh demo-user@IPAddress** to ssh into your vm
