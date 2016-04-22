VM definitions for test servers
================================

Virtual machines defined by [Vagrant](https://www.vagrantup.com) scripts. Virtualbox is used for virtualisation.

Each of the virtual machines is configured to compile openvpn and run a server.

Inside the vm a openvpn server can be launched to run `t_client.sh` tests against it.

Use Cases:
---------------
 
### Start the VM:
  * `vagrant up` from inside the VMs folder (e.g. `centos7`)

### Login to  the VM:
  * `vagrant ssh`

### Synchronize local changes into the VM & rebuild the server
  * (insinde the vm)
  *  `/scripts/sync_codebase.sh`
  *  `/scripts/compile.sh`

### Start the server for  `t_client` tests
  * (outside of the vm) Modify `t_client.rc` ( `REMOTE_IP`, `REMOTE_PORT`, `SERVER_KEY`, `SERVER_CERT`
  * (inside the vm) run `/scripts/sync_codebase.sh` (to sync the changed `t_client.rc`)
  * (inside the vm) run `/scripts/compile.sh`
  * (inside the vm) run `/scripts/start_server.sh`

VM Layout
-----------
 * The original source tree is mounted at /openvpn
 * The source tree used for compilation is copied to `~vagrant/openvpn`
 * Scripts are installed in the /scripts directory
   * `sync_codebase.sh` copies the codebase from the host into ~/openvpn ( so that it can be compiled for the VMs architecture/OS)
   * `rebuild.sh` builds the server inside the VM (at ~/openvpn)
   * `start_server.sh` starts the server with a configuration from t_client.rc

provided VMs
--------------

| Name                     | external IPv4   | external IPv6              |
|--------------------------|-----------------|----------------------------|
| ubuntu_trusty64          | 192.168.33.66   | IPv4 only                  |
| ubuntu_precise64         | 192.168.33.67   | IPv4 only                  |
