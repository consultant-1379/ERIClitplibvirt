"""
All constants for the libvirt plugin.
"""

from collections import namedtuple

# Constants for destination paths on nodes.
IMAGE_PATH = '/var/lib/libvirt/images/'
BASE_DESTINATION_PATH = '/var/lib/libvirt/instances/'

# Constants for configurable SSH login banners & motd message
LITP_TEMPLATES = '/opt/ericsson/nms/litp/etc/puppet/modules/litp/files'
CUSTOM_SSH_LOGIN_BANNER = 'issue.net.custom'
CUSTOM_MOTD = 'motd.custom'

# File names
VM_DATA_FILE_NAME = 'config.json'
METADATA_FILE_NAME = 'meta-data'
USERDATA_FILE_NAME = 'user-data'
# for rhel7.4 cloud-init
NETWORKCONFIG_FILE_NAME = 'network-config'

APACHE_DIR = '/var/www/html'
CUSTOM_SCRIPTS_DIR = 'vm_scripts/'

# Constants for adaptor script.
RESTART_TIMEOUT = 45

# Cloud init specific constants.
CLOUD_INIT_HEADER = '#cloud-config'

# Deployment states.
DEPLOY = 'deploy'
UPDATE = 'update'

# LITP package names.
LITP_ADAPTOR = 'ERIClitpmnlibvirt_CXP9031529'

# Map attributes in model items
NODE_IP_MAP = "node_ip_map"
NODE_MAC_ADDRESS_MAP = "node_mac_address_map"
NODE_HOSTNAME_MAP = "node_hostname_map"

# Other constants.
NFS = 'nfs'
DYNAMIC_IP = "dhcp"
DEFAULT_CLUSTER_ID = '65536'
DEFAULT_MAC_PREFIX = '52:54:00'

# MCO timeouts
MCO_RESTART_TIMEOUT = 360

# Constants for MS Kickstart Filesystems
# The data in MS_KS_FS is a subset of data in MS Kickstart and volmgr plugin
# Any changes to this data in volmgr must be replicated here.
MS_ROOT_VG_GROUP_NAME = "vg_root"
ms_ks_fs = namedtuple('ms_ks_fs', 'name mount_point')
MS_KS_FS = [ms_ks_fs('root',     '/'),
            ms_ks_fs('home',     '/home'),
            ms_ks_fs('swap',     'swap'),
            ms_ks_fs('var',      '/var'),
            ms_ks_fs('var_tmp',  '/var/tmp'),
            ms_ks_fs('var_opt_rh', '/var/opt/rh'),
            ms_ks_fs('var_lib_puppetdb', '/var/lib/puppetdb'),
            ms_ks_fs('var_log',  '/var/log'),
            ms_ks_fs('var_www',  '/var/www'),
            ms_ks_fs('software', '/software')]

FIREWALL_RULE_COMMAND_TEMPLATE = (r"\$iptables_dir/{rule[provider]} "
                                "-A {rule[chain]}"
                                "{rule[source]}{rule[proto]}{rule[dport]}"
                                "{rule[name]} -m state --state NEW "
                                "-j {rule[action]}")
FW_SOURCE_TEMPLATE = " -s %s"
FW_NAME_TEMPLATE = ' -m comment --comment "%s"'
FW_PROTO_TEMPLATE = " -p {proto} -m {proto}"
FW_DPORT_TEMPLATE = " --dport %s"
FW_CHAINS = ['INPUT', 'OUTPUT']
