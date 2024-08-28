litp create -t os-profile -p /software/profiles/rhel_6_4 -o name='sample-profile' path='/profiles/node-iso/'

litp create -t libvirt-provider -p /infrastructure/system_providers/libvirt1 -o name='libvirt1'
litp create -t libvirt-system -p /infrastructure/system_providers/libvirt1/systems/vm1 -o system_name='VM1' ram='4096M'
litp create -t libvirt-system -p /infrastructure/system_providers/libvirt1/systems/vm2 -o system_name='VM2' ram='2048M'
litp create -t disk -p /infrastructure/system_providers/libvirt1/systems/vm1/disks/disk0 -o name=sda size=40G bootable=true uuid='SATA_QEMU_HARDDISK_QM00001'
litp create -t disk -p /infrastructure/system_providers/libvirt1/systems/vm2/disks/disk0 -o name=sda size=40G bootable=true uuid='SATA_QEMU_HARDDISK_QM00001'

litp create -t network -p /infrastructure/networking/networks/n0 -o name=nodes subnet='10.10.10.0/24'

litp create -t eth -p /ms/network_interfaces/if0 -o device_name=eth0 macaddress='DE:AD:BE:EF:45:50' bridge=br0
litp create -t bridge -p /ms/network_interfaces/br0 -o device_name=br0 network_name=nodes ipaddress='10.10.10.100' forwarding_delay=4 stp=false

litp create -t system -p /infrastructure/systems/ms_system -o system_name='ms_system'

litp create -t route -p /infrastructure/networking/routes/def -o subnet='0.0.0.0/0' gateway='10.10.10.1'

litp create -t storage-profile -p /infrastructure/storage/storage_profiles/profile_1
litp create -t volume-group -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1 -o volume_group_name='vg_root'
litp create -t file-system -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1/file_systems/root -o type='ext4' mount_point='/' size='16G'
litp create -t file-system -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1/file_systems/swap -o type='swap' mount_point='swap' size='2G'
litp create -t physical-device -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1/physical_devices/internal -o device_name='sda'

litp create -t cobbler-service -p /ms/services/cobbler
litp inherit -p /ms/libvirt -s /infrastructure/system_providers/libvirt1
litp inherit -p /ms/system -s /infrastructure/systems/ms_system
litp inherit -p /ms/routes/def -s /infrastructure/networking/routes/def

litp create -t deployment -p /deployments/single_blade
litp create -t cluster -p /deployments/single_blade/clusters/cluster1

litp create -t node -p /deployments/single_blade/clusters/cluster1/nodes/node1 -o hostname='node1'
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node1/system -s /infrastructure/system_providers/libvirt1/systems/vm1
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node1/os -s /software/profiles/rhel_6_4
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node1/routes/r1 -s /infrastructure/networking/routes/def
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node1/storage_profile -s /infrastructure/storage/storage_profiles/profile_1

litp create -t node -p /deployments/single_blade/clusters/cluster1/nodes/node2 -o hostname='node2'
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node2/system -s /infrastructure/system_providers/libvirt1/systems/vm2
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node2/os -s /software/profiles/rhel_6_4
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node2/routes/r1 -s /infrastructure/networking/routes/def
litp inherit -p /deployments/single_blade/clusters/cluster1/nodes/node2/storage_profile -s /infrastructure/storage/storage_profiles/profile_1

litp create -t eth -p /deployments/single_blade/clusters/cluster1/nodes/node1/network_interfaces/if0 -o device_name=eth0 macaddress='DE:AD:BE:EF:45:57' network_name=nodes ipaddress=10.10.10.107
litp create -t eth -p /deployments/single_blade/clusters/cluster1/nodes/node2/network_interfaces/if0 -o device_name=eth0 macaddress='DE:AD:BE:EF:45:58' network_name=nodes ipaddress=10.10.10.108

litp create_plan
litp show_plan
