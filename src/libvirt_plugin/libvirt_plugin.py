##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
from collections import defaultdict
import itertools
import json
from operator import attrgetter
import os
from urlparse import urlparse

import netaddr
from netaddr.ip import IPNetwork
import yaml
import ast

from libvirt_extension.libvirt_extension import (LibvirtExtension,
                                                 IPv6AndMaskListValidator)
from litp.core.execution_manager import ConfigTask, CallbackTask
from litp.core.litp_logging import LitpLogger
from litp.core.plugin import Plugin
from litp.core.validators import ValidationError, RegexValidator
from litp.core.exceptions import ViewError

from . import constants
from . import patterns
from . import utils
from . import exception
from .libvirt_mco_client import LibvirtMcoClient


log = LitpLogger()

CALL_TYPE_COPY_FILE = "libvirt::copy_file"
CALL_TYPE_WRITE_FILE = "libvirt::write_file"
CALL_TYPE_DECONFIGURE = "libvirt::deconfigure"
CALL_TYPE_REMOVE_IMAGE = "libvirt::remove_image"
CALL_TYPE_INSTALL_ADAPTOR = "libvirt::install_adaptor"
CALL_TYPE_REMOVE_ADAPTOR = "libvirt::remove_adaptor"
CALL_ID_WRITE_FILE = "{hostname}{unique}{instance_name}"
CALL_ID_COPY_FILE = "{hostname}image{instance_name}"
CALL_ID_DECONFIGURE = "{hostname}deconfigure{instance_name}"
CALL_ID_REMOVE_IMAGE = "{image}_libvirt_image_remove"
CALL_ID_INSTALL_ADAPTOR = "{node}_libvirt_adaptor_install"
CALL_ID_REMOVE_ADAPTOR = "{node}_libvirt_adaptor_remove"

ERROR_MSG_INVALID_HOSTNAME = ('Host "{0}" in the source_uri property does'
                              ' not resolve to an IP specified in the model '
                              'for the Management Server.')

REDEPLOY_MS = 'redeploy_ms'
PRE_OS_REINSTALL = 'pre_os_reinstall'
HA_MANAGER_ONLY = 'ha_manager_only'
INFRA_UPDATE = 'infra_update'


class VMServiceFacade(object):
    """
    Facade class which presents an idealised interface to
    'vm-services' in the LITP model.
    """

    VERSION = '1.0.0'

    def __init__(self, node, image, service, networks, ms_node,
                 clustered_service=None):
        """
        Set the underlying litp items as private instance variables.
        """
        self.node = node
        self.vm_task_item = service
        self.install_task_item = (clustered_service or service).parent
        self._image = image
        self._service = service
        self._clustered_service = clustered_service
        self._yum_repos = service.vm_yum_repos
        self._zypper_repos = service.vm_zypper_repos
        self._packages = service.vm_packages
        self._nfs_mounts = service.vm_nfs_mounts
        self._disks = service.vm_disks
        self._aliases = service.vm_aliases
        self._ssh_keys = service.vm_ssh_keys
        self._interfaces = service.vm_network_interfaces
        self._ram_mounts = service.vm_ram_mounts
        self._custom_scripts = service.vm_custom_script
        self._firewall_rules = service.vm_firewall_rules
        self._networks = networks
        self._ms_node = ms_node

    @property
    def state(self):
        if self.is_initial():
            return constants.DEPLOY
        return constants.UPDATE

    def _new_nodes(self):
        """
        Returns the item_id of the nodes where the service is not installed
        :return: set
        """
        if not self._clustered_service:
            new_nodes = set([self.node.item_id]) if \
                self._service.is_initial() else set()
        else:
            applied_nodes = utils.get_applied_node_list(
                self._clustered_service)
            current_nodes = self._clustered_service.node_list.split(',')
            new_nodes = set(current_nodes) - set(applied_nodes)
        return new_nodes

    def _removed_nodes(self):
        """
        Returns the item_id of the nodes where the service is not installed
        :return: set
        """
        if not self._clustered_service:
            removed_nodes = set([self.node.item_id]) if \
                self._service.is_for_removal() else set()
        else:
            applied_nodes = utils.get_applied_node_list(
                self._clustered_service)
            current_nodes = self._clustered_service.node_list.split(',')
            removed_nodes = set(applied_nodes) - set(current_nodes)
        return removed_nodes

    # Checks if a service is in initial state or if the node is in new nodes
    # or if the service apd is false (and the node is not for_removal)
    def is_initial(self):
        return (not self._service.is_for_removal()) and (
            self._service.is_initial() or
            self.node.item_id in self._new_nodes() or
            (not self._service.applied_properties_determinable and
             self.node.item_id not in self._removed_nodes()))

    def is_for_removal(self):
        return (self._service.is_for_removal() or
                self.node.item_id in self._removed_nodes())

    def is_service_updated_or_applied(self):
        return self._service.is_updated() or self._service.is_applied()

    def update_task_required(self):
        return (self.is_service_updated_or_applied() and
                not self.is_for_removal() and
                not self._clustered_service)

    def deployed_on_ms(self):
        return bool(self._service.get_ms())

    def for_redeploy(self, restore_mode):
        res = (self._service.is_updated()
                or self._service.has_updated_dependencies()
                or self._service.has_initial_dependencies()
                or self._service.has_removed_dependencies()
                or self._image.is_updated()
                or self._image_checksum_updated()
                or self._motd_updated()
                or self._issue_net_updated()
                or self._updated_status_timeout()
                or self.interfaces_updated()) \
                and not self.is_initial() \
                and not self.is_for_removal() \
                and not (restore_mode and self.node.is_ms())
        return res

    def get_vpath(self):
        return self._service.get_vpath()

    @classmethod
    def _in_restore_mode(cls, plugin_api_context):
        """
        Check if we are in restore mode
        :param api_context: Plugin API context
        :type api_context: class PluginApiContext
        :return: True if in_restore_mode property is set, else False
        :rtype: boolean
        """

        return any([(d.is_initial() or d.is_updated()) and\
            'true' == d.in_restore_mode \
            for d in plugin_api_context.query('deployment')])

    @classmethod
    def _is_upgrade_flag_set(cls, api_context, flag):
        """
        Check is a specific upgrade flag set
        e.g redeploy_ms which will trigger
        the generation of MS based tasks only.
        ie. LMS Redeploy Plan for RH6 Plan in RH7 Uplift.
        :param api_context: Plugin API context
        :type api_context: class PluginApiContext
        :param flag: Upgrade flag
        :type flag: string
        :return: True if flag is set on an upgrade item , else False
        :rtype: boolean
        """
        if api_context and any(
            [True for node in api_context.query('node')
             for upgrd_item in node.query('upgrade')
             if getattr(upgrd_item, flag, 'false') == 'true']):
            log.trace.info('Upgrade flag {0} is true.'.format(flag))
            return True
        else:
            return False

    @classmethod
    def from_model_gen(cls, api):
        """
        Returns a instance of `cls` for all vm-services in the model.
        """
        def nodes_in_node_list_and_applied_node_list(clustered_service):
            '''
            clustered_service.nodes only returns a the nodes in the node_list
            of the clustered service. Here we need to create a facade instance
            for all nodes, including nodes that are being removed from the
            node_list
            '''
            applied_nodes = utils.get_applied_node_list(clustered_service)
            current_nodes = clustered_service.node_list.split(',')
            cluster = clustered_service.parent.parent
            node_dict = dict((node.item_id, node) for node in cluster.nodes)
            nodes = set(applied_nodes).union(set(current_nodes))
            return [node_dict[node_id] for node_id in nodes]

        networks = api.query("network")
        ms_node = api.query("ms")[0]

        redeploy_ms = VMServiceFacade._is_upgrade_flag_set(
                                            api, REDEPLOY_MS)
        nodes = [ms_node]
        if not redeploy_ms:
            nodes.extend(api.query('node'))
        # Find VMs on nodes.
        for node in nodes:
            for service in node.services:
                if service.item_type_id == 'vm-service':
                    # Validation will have caught no matching image.
                    image = cls.get_image(api, service)
                    yield cls(node, image, service, networks, ms_node)
        # Finds VMs part of clustered service.
        if not redeploy_ms:
            for cluster in api.query('cluster'):
                for clustered_service in cluster.services:
                    for service in clustered_service.query('vm-service'):
                        for node in nodes_in_node_list_and_applied_node_list(
                                         clustered_service):
                            image = cls.get_image(api, service)
                        # if service is failover than same resources will be
                        # allocated to both active and standy. For parallel
                        # we need to iterate through available resources
                            yield cls(node, image, service, networks, ms_node,
                                    clustered_service)

    def ip_updated(self, intf):
        applied_ip_map = utils.convert_node_ip_map(
                utils.evaluate_map(intf, constants.NODE_IP_MAP,
                                                  applied=True))
        ip_map = utils.evaluate_map(intf, constants.NODE_IP_MAP)
        return (applied_ip_map.get(self.node.item_id) !=
                ip_map.get(self.node.item_id))

    def mac_updated(self, intf):
        try:
            # mac is not found when changing from failover to parallel
            applied_mac = self._get_mac(intf, applied=True)
        except KeyError:
            return True
        return self._get_mac(intf) != applied_mac

    def gateway6_updated(self, intf):
        return utils.property_updated(intf, 'gateway6')

    def gateway_updated(self, intf):
        return utils.property_updated(intf, 'gateway')

    def find_network_by_name(self, network_name):
        for network in self._networks:
            if network.name == network_name:
                return network
        return None

    def subnet_updated(self, network_name):
        network = self.find_network_by_name(network_name)
        if network and network.is_updated():
            return utils.property_updated(network, 'subnet')
        else:
            return False

    def get_updated_vm_disk_mounts(self):
        return [vm_disk for vm_disk in self._disks
                if vm_disk.is_initial() or vm_disk.is_updated() or
                vm_disk.is_for_removal()]

    def vm_disk_mounts_updated(self):
        return len(self.get_updated_vm_disk_mounts()) != 0

    def get_updated_interfaces(self):
        return [intf for intf in self._interfaces
                if intf.is_initial() or
                intf.is_for_removal() or
                not intf.applied_properties_determinable or
                self.ip_updated(intf) or self.mac_updated(intf) or
                self.gateway6_updated(intf) or self.gateway_updated(intf) or
                self.subnet_updated(intf.network_name)]

    def interfaces_updated(self):
        return len(self.get_updated_interfaces()) != 0

    def hostname_updated(self):
        applied_hostnames_map = utils.evaluate_map(self._service,
                                                   constants.NODE_HOSTNAME_MAP,
                                                   applied=True)
        hostnames_map = utils.evaluate_map(self._service,
                                           constants.NODE_HOSTNAME_MAP)
        return (applied_hostnames_map.get(self.node.item_id) !=
                hostnames_map[self.node.item_id])

    def userdata_model_items(self):
        return itertools.chain(self._yum_repos, self._zypper_repos,
                               self._packages, self._nfs_mounts,
                               self._aliases, self._ssh_keys, self._ram_mounts,
                               self._custom_scripts, self._firewall_rules)

    def config_model_items(self):
        return itertools.chain(self.get_updated_interfaces(),
                               utils.model_items_for_redeploy(
                                   self._yum_repos),
                               utils.model_items_for_redeploy(
                                   self._zypper_repos),
                               self.get_updated_vm_disk_mounts())

    # This gets task items that affect adaptor data,
    # user data and meta data tasks
    def get_service_task_items(self, service):
        return itertools.chain(service.config_model_items(),
                               service.get_updated_interfaces(),
                               service.userdata_model_items())

    def deploy_metadata(self):
        """
        Return `True` if the cloud init meta-data file needs
        to be redeployed otherwise `False`.

        It does this by checking if either the `service_name`
        attribute of `self._service` or if any children of the
        vm-network-interfaces collection is either in an Updated
        or Initial state.
        """
        if self.is_initial():
            return True

        return self.interfaces_updated()

    def deploy_networkconfig(self, service):
        """
        Return `True` if the cloud init network-config file needs
        to be redeployed otherwise `False`.

        It does this by checking if either the `service_name`
        attribute of `self._service` or if any children of the
        vm-network-interfaces collection is either in an Updated
        or Initial state.
        """
        if self.is_initial():
            return True

        network_config_path = os.path.join(
                                service.base_path,
                                service.networkconfig_file_name)

        if not os.path.isfile(network_config_path):
            return True

        return self.interfaces_updated()

    def deploy_userdata(self):
        """
        Return `True` if the cloud init user-data file needs
        to be redeployed otherwise `False`.

        It does this by checking if any children of the:
            - vm-yum-repos
            - vm-zypper-repos
            - vm-packages
            - vm-nfs-mounts
            - vm-aliases
            - vm-ssh-keys
            - vm-firewall-rules

        are either in an Initial or Updated state.
        """
        if self.is_initial():
            return True

        # torf-184632: if the image changes there might be changes in userdata
        # too, so better to trigger a reconstruction of userdata. If it did not
        # change core will remove the task from the plan
        return (utils.redeployable(self.userdata_model_items()) or
                self.hostname_updated() or self._image.is_updated() or
                self._image_checksum_updated() or
                self._motd_updated() or
                self._issue_net_updated() or
                self._updated_status_timeout())

    def update_adaptor(self, latest_version):
        """
        Return `True` if the libvirt adaptor needs to be updated
        otherwise `False`.
        """
        latest_version = '{0}-{1}'.format(
            latest_version['version'],
            latest_version['release'])
        return utils.needs_update(self.adaptor_version, latest_version)

    def deploy_image(self):
        """
        Return `True` if the vm image file needs
        to be redeployed otherwise `False`.

        This is determined by either a change in the image checksum
        or the image name being updated on the service.
        """
        if self.is_initial():
            return True
        checksum_updated = utils.property_updated(self._service,
                                                  'image_checksum')
        image_changed = utils.property_updated(self._service, 'image_name')
        return checksum_updated or image_changed

    def deploy_config(self, adaptor_version):
        """
        Return `True` if the vm config file needs
        to be redeployed otherwise `False`.
        """
        if self.is_initial():
            return True

        properties = ["cpus", "ram", "internal_status_check", "cpuset",
                      "cpunodebind"]
        service_updated = any(utils.property_updated(self._service, prop)
                              for prop in properties)

        return (
            self.interfaces_updated()
            or service_updated
            or (adaptor_version is not None and
                self.update_adaptor(adaptor_version))
            or self.deploy_image()
            or self._have_checksums_changed()
            or self.vm_disk_mounts_updated())

    @classmethod
    def get_image(cls, api, service):
        """
        Return the instance name.
        """
        image = None
        res = api.query('vm-image', name=service.image_name)
        if res:
            image = res[0]
        return image

    @property
    def instance_name(self):
        """
        Return the instance name.
        """
        return self._service.service_name

    @property
    def image_checksum(self):
        return self._service.image_checksum

    @property
    def motd_checksum(self):
        return self._service.motd_checksum

    @property
    def issue_net_checksum(self):
        return self._service.issue_net_checksum

    @property
    def base_path(self):
        return os.path.join(
            constants.BASE_DESTINATION_PATH,
            self.instance_name)

    @property
    def image_name(self):
        """
        Return the name of the vm image file.
        """
        return os.path.basename(self._image.source_uri)

    @property
    def adaptor_version(self):
        """
        Return the current adaptor version installed with this
        service.

        NOTE: A version number of 0.0-0 means the adaptor has
        not been installed. This should probably be changed as a
        in-development package may have a similar version.
        """

        if self.is_initial():
            return '0.0-0'
        return self._service.applied_properties.get(
            "adaptor_version",
            "0.0-0")

    @adaptor_version.setter
    def adaptor_version(self, value):
        self._service.adaptor_version = value

    @property
    def image_uri(self):
        return self._image.source_uri

    @property
    def adaptor_data_file_name(self):
        """
        Return the name of the JSON configuration file.
        """
        return constants.VM_DATA_FILE_NAME

    def adaptor_data(self):
        """
        Return JSON representing all information
        to be passed to the libvirt adaptor.
        """

        def get_ip_address(vm_ifaces, host_devices):
            for vm_if in vm_ifaces:
                for dev in host_devices:
                    if dev.device_name == vm_if.host_device:
                        if dev.ipaddress:
                            current_map = utils.evaluate_map(vm_if,
                                                       constants.NODE_IP_MAP)
                            node_id = self.node.item_id
                            return current_map.get(node_id, {}).get('ipv4', '')

        ipaddr = ""
        if self._service.internal_status_check == "on":
            vm_ifaces = [
                iface
                for iface in self._service.vm_network_interfaces
                if not utils.is_dynamic_ip(iface) and iface.ipaddresses
                    and not iface.is_for_removal()]
            host_devices = self.node.query("bridge")
            ipaddr = get_ip_address(vm_ifaces, host_devices)

        _vmdata = {
            'ram': self._service.ram,
            'cpu': self._service.cpus,
            'image': self.image_name,
            'interfaces': self._networking_data(),
            'yum-checksum': [repo.checksum
                             for repo in self._yum_repos
                             if not repo.is_for_removal()],
            'zypper-checksum': [repo.checksum
                                for repo in self._zypper_repos
                                if not repo.is_for_removal()],
            'image-checksum': self._service.image_checksum,
        }

        if self._service.cpuset:
            _vmdata['cpuset'] = self._service.cpuset

        if self._service.cpunodebind:
            _vmdata['cpunodebind'] = self._service.cpunodebind

        return json.dumps({
            'version': self.VERSION,
            'vm_data': _vmdata,
            'adaptor_data': {
                'internal_status_check': {
                    'active': self._service.internal_status_check,
                    'ip_address': ipaddr,
                },
                'disk_mounts': self._get_disk_mounts(),
            },
        })

    def _get_mac(self, intf, applied=False):
        """ Returns the coresponding MAC for the interface. """

        parallel = True
        if self._clustered_service and self._clustered_service.standby != '0':
            parallel = False

        cluster_id = getattr(self._service.get_cluster(),
                             'cluster_id', constants.DEFAULT_CLUSTER_ID)
        key = utils.get_interface_id(
            cluster_id=cluster_id,
            node_hostname=self.node.hostname,
            service_name=self._service.service_name,
            device_name=intf.device_name,
            parallel=parallel)

        return utils.evaluate_map(intf, constants.NODE_MAC_ADDRESS_MAP,
                                  applied)[key]

    def _networking_data(self):
        network_data = {}
        service = self._service
        for intf in service.vm_network_interfaces:
            if intf.is_for_removal():
                continue
            network_data[intf.device_name] = {
                "host_device": intf.host_device,
                "mac_address": self._get_mac(intf),
            }
        return network_data

    @property
    def metadata_file_name(self):
        """
        Return the name of the cloud init metadata file.
        """
        return constants.METADATA_FILE_NAME

    def metadata(self, api):
        """
        Return YAML cloud init metadata.
        """
        data = {}
        service = self._service
        data['instance-id'] = service.service_name
        data['network-interfaces'] = ""
        for intf in service.vm_network_interfaces:
            if intf.is_for_removal():
                continue
            ipv4address, ipv6address = self.network_info(intf)
            if not utils.is_dynamic_ip(intf):
                data['network-interfaces'] += self._get_ipv4_metadata(api,
                                                             intf, ipv4address)
            else:
                data['network-interfaces'] += self._get_dhcp_metadata(intf)
            data['network-interfaces'] += self._get_ipv6_metadata(intf,
                                                                  ipv6address)
            if ipv4address or ipv6address:
                data['network-interfaces'] += self._get_hwaddr_metadata(intf)

        return yaml.safe_dump(data, default_flow_style=False)

    def network_info(self, intf):
        current_map = utils.evaluate_map(intf, constants.NODE_IP_MAP)
        node_id = self.node.item_id
        ipv4address = current_map.get(node_id, {}).get('ipv4', '')
        ipv6address = current_map.get(node_id, {}).get('ipv6', '')
        return (ipv4address, ipv6address)

    def _get_ipv4_metadata(self, api, intf, ipv4address):
        iface_data = "auto {0}\n".format(intf.device_name)
        if ipv4address:
            network = api.query('network', name=intf.network_name)[0]
            ipnetw = IPNetwork(network.subnet)
            iface_data += "iface {0} inet static\n".format(intf.device_name)
            iface_data += "address {0}\n".format(ipv4address)
            iface_data += "network {0}\n".format(intf.network_name)
            iface_data += "netmask {0}\n".format(ipnetw.netmask)
            iface_data += "broadcast {0}\n".format(ipnetw.broadcast)
            if intf.gateway:
                iface_data += "gateway {0}\n".format(intf.gateway)
        return iface_data

    def _get_ipv6_metadata(self, intf, ipv6address):
        iface_data = ""
        if ipv6address:
            iface_data += "iface {0} inet6 static\n".format(intf.device_name)
            iface_data += "address {0}\n".format(ipv6address)
            if intf.gateway6:
                iface_data += "gateway {0}\n".format(intf.gateway6)
        return iface_data

    def _get_hwaddr_metadata(self, intf):
        return "hwaddress {0}\n".format(self._get_mac(intf))

    def _get_dhcp_metadata(self, intf):
        iface_data = "auto {0}\n".format(intf.device_name)
        iface_data += "iface {0} inet dhcp\n".format(intf.device_name)
        return iface_data

    @property
    def networkconfig_file_name(self):
        """
        Return the name of the cloud init networkconfig file.
        """
        return constants.NETWORKCONFIG_FILE_NAME

    def networkconfig(self, api):
        """
        Return YAML cloud init networkconfig.
        """
        data = {}
        data['config'] = []

        service = self._service
        for intf in service.vm_network_interfaces:
            if intf.is_for_removal():
                continue

            eth = {}
            eth['subnets'] = []
            ipv4address, ipv6address = self.network_info(intf)

            if not utils.is_dynamic_ip(intf):
                if ipv4address:
                    eth['subnets'].append(
                        self._get_ipv4_networkconfig(api, intf, ipv4address))
            else:
                eth['subnets'].append(self._get_dhcp_networkconfig())

            if ipv6address:
                eth['subnets'].append(
                    self._get_ipv6_networkconfig(intf, ipv6address))

            eth['mac_address'] = self._get_mac(intf)
            eth['name'] = intf.device_name
            eth['type'] = 'physical'
            data['config'].append(eth)

        data['version'] = 1

        return yaml.safe_dump(data, default_flow_style=False)

    def _get_ipv4_networkconfig(self, api, intf, ipv4address):
        subnet = {}

        if intf.gateway:
            subnet['gateway'] = intf.gateway

        network = api.query('network', name=intf.network_name)[0]
        ipnetw = IPNetwork(network.subnet)

        subnet['netmask'] = "{0}".format(ipnetw.netmask)
        subnet['address'] = ipv4address
        subnet['type'] = 'static'

        return subnet

    def _get_ipv6_networkconfig(self, intf, ipv6address):
        subnet = {}

        if intf.gateway6:
            subnet['gateway'] = intf.gateway6

        subnet['address'] = ipv6address
        subnet['type'] = 'static'

        return subnet

    def _get_dhcp_networkconfig(self):
        subnet = {"type": "dhcp"}
        return subnet

    @property
    def userdata_file_name(self):
        """
        Return the name of the cloud init userdata file.
        """
        return constants.USERDATA_FILE_NAME

    @property
    def userdata(self):
        """
        Return YAML cloud init userdata.
        """
        userdata = constants.CLOUD_INIT_HEADER
        userdata_dict, write_file_data = self._get_userdata_dict()
        if not userdata_dict and not write_file_data:
            return userdata
        return ("{0}\n{1}{2}").format(
            userdata,
            (yaml.safe_dump(userdata_dict,
                        default_flow_style=False) if userdata_dict else ""),
            (yaml.safe_dump(write_file_data,
                        default_style='|')if write_file_data else ""))

    @staticmethod
    def _get_timezone():
        """
        Gets the timezone of the MS
        """
        zone = []
        # Try first getting time zone from file '/etc/sysconfig/clock'
        try:
            fn = '/etc/sysconfig/clock'
            with open(fn, 'r') as f:
                clock = f.readlines()
            zone = [i for i in clock if 'zone:' in i]
        except IOError:
            log.trace.debug(
                'File: "%s" not found' % fn)
        finally:
            if not zone:
                # Try getting time zone from /usr/bin/timedatectl
                zone = [utils.get_time_zone_from_timedatectl()]

        return zone[0].strip().split()[2]

    def _get_userdata_dict(self):
        userdata = {}

        write_file_data = {}

        for (dkey, dhandler) in \
                   [('yum_repos', self._get_yum_repos),
                    ('packages', self._get_packages),
                    ('mounts', self._get_nfs_and_ram_mounts),
                    ('ssh_authorized_keys', self._get_ssh_authorized_keys)]:
            data = dhandler()
            if data:
                userdata[dkey] = data

        userdata['bootcmd'] = self._get_hostname_bootcmds()
        userdata['bootcmd'].extend(self._get_vm_firewall_rules())
        if any(self._service.vm_aliases):
            self._get_aliases(userdata['bootcmd'])
        self._get_vmmonitor_timeout(userdata['bootcmd'])

        userdata['timezone'] = self._get_timezone()
        userdata['runcmd'] = self._get_runcmds()
        zypper_repo_data = self._get_zypper_repos()
        modt_data = self._get_motd()
        ssh_banner_data = self._get_issue_net()

        self._add_write_files_entries(write_file_data, zypper_repo_data)
        self._add_write_files_entries(write_file_data, modt_data)
        self._add_write_files_entries(write_file_data, ssh_banner_data)

        if zypper_repo_data or modt_data or ssh_banner_data:
            return userdata, write_file_data
        else:
            return userdata, None

    def _add_write_files_entries(self, write_file_data, entries):
        if not entries:
            return
        if 'write_files' not in write_file_data:
            write_file_data['write_files'] = []
        write_file_data['write_files'].extend(entries)

    def _get_custom_file(self, template, target):
        if os.path.exists(template):
            with open(template, 'r') as _reader:
                _contents = _reader.read().strip()
            log.trace.debug('Using contents of file "%s" for '
                            'instance file "%s"' % (template, target))
            return [{
                'path': target,
                'content': '{0}\n'.format(_contents)
            }]
        return None

    def _get_issue_net(self):
        _file = os.path.join(constants.LITP_TEMPLATES,
                             constants.CUSTOM_SSH_LOGIN_BANNER)
        return self._get_custom_file(_file, '/etc/issue.net')

    def _get_motd(self):
        _file = os.path.join(constants.LITP_TEMPLATES,
                             constants.CUSTOM_MOTD)
        return self._get_custom_file(_file, '/etc/motd')

    def _get_bootcmd_command(self, name, cmd, args):
        """
        Returns a cloud-init-per command for userdata file.
           - cloud-init-per frequency name cmd args
        """
        frequency = 'instance'  # run only the first boot

        return ['cloud-init-per', frequency, name, cmd] + args

    def _get_vm_hostname(self):
        """
        Returns the hostname to use for the VM on the node.
        The logic is:
        - If the user doesn't supply 'hostnames', then generate the hostname
        - If the user supplies 'hostnames' for a failover Service Group, return
              that same 'hostnames' for each node
        - If the node is already in the map, and the node entry is in the
              user-supplied 'hostnames', return the map entry for that node
        - If the user supplies 'hostnames', but the node entry is not in that
              list, return the entry which is not used by another node
        """
        hostname_map = utils.evaluate_map(self._service,
                                          constants.NODE_HOSTNAME_MAP)
        hostname = ""
        if self.node.item_id in hostname_map:
            hostname = hostname_map[self.node.item_id]
        return hostname

    def _get_hostname_bootcmds(self):
        """
        Returns the commands to change the hostname.
        """
        cmds = []
        hostname = self._get_vm_hostname()

        args = ['-c', 'hostnamectl set-hostname {0}'.format(hostname)]
        cmds.append(self._get_bootcmd_command('hostname', 'sh', args))

        return cmds

    def _get_runcmds(self):
        """
        Returns the cloud-init runcmd values for the vm-service
        """
        # restart rsyslog to ensure new hostname and timezone are used in logs
        cmds = [
        'if [ -f /etc/init.d/rsyslog ]; then /sbin/service rsyslog restart; '
        'elif [ -f /usr/lib/systemd/system/rsyslog.service ]; then '
        '/bin/systemctl restart rsyslog.service; elif [ -f '
        '/etc/init.d/syslog ]; then /sbin/service syslog restart; else exit '
        '1; fi'
        ]
        #restart crond service to ensure crond and server timezone are in synch
        crond_restart_cmd = 'if [ -f /bin/systemctl ]; then /bin/systemctl ' \
                            'restart crond; fi'
        cmds.append("{0}".format(crond_restart_cmd))

        # TORF-567819: disable transparent_hugepages in VM on vApps
        virt_what_command = "/usr/sbin/virt-what"
        if utils.run_cmd(virt_what_command)[1] == 'vmware\n':
            disable_thp_cmd = 'if [ -f /bin/systemctl ]; then echo -e ' \
                              '"[vm]\ntransparent_hugepages=never" >> ' \
                              '/usr/lib/tuned/virtual-guest/tuned.conf && ' \
                              '/bin/systemctl restart tuned && tuned-adm ' \
                              'profile virtual-guest; ' \
                              'else ' \
                              'echo never > /sys/kernel/mm/' \
                              'transparent_hugepage/enabled; ' \
                              'echo never > /sys/kernel/mm/' \
                              'transparent_hugepage/defrag; ' \
                              'fi'
            cmds.append(disable_thp_cmd)

        # run script manager to call scripts past as a comma separated list
        script_names = ''
        cs_path = '/opt/ericsson/vmmonitord/bin/customscriptmanager.sh'
        for item in self._custom_scripts:
            if not item.is_for_removal():
                ms_ip = self.get_ms_ip(item)
                script_names += str(item.custom_script_names)
                cmds.append("{0} {1} {2}".format(cs_path, ms_ip, script_names))

        return cmds

    def get_ms_ip(self, custom_script):
        if custom_script.network_name:
            net = [net for net in self._networks
                   if not net.is_for_removal() and not net.is_removed()
                   and net.name == custom_script.network_name][0]
        else:
            net = [net for net in self._networks
                   if not net.is_for_removal() and not net.is_removed()
                   and net.litp_management == 'true'][0]
        intf = [intf for intf in self._ms_node.network_interfaces
                if intf.network_name == net.name][0]
        return intf.ipaddress

    def _get_nfs_and_ram_mounts(self):
        """
        Return the mount section of cloudinit userdata, includes NFS and RAM
        mounts.
        """
        nfs_and_ram_mounts = []
        for mount in self._nfs_mounts:
            if mount.is_for_removal():
                continue
            nfs_and_ram_mounts.append([
                    mount.device_path,
                    mount.mount_point,
                    constants.NFS,
                    mount.mount_options])
        for mount in self._ram_mounts:
            if mount.is_for_removal():
                continue
            nfs_and_ram_mounts.append([
                    mount.type,
                    mount.mount_point,
                    mount.type,
                    mount.mount_options])
        return nfs_and_ram_mounts

    def _ms_install_fs(self, vg, fs):
        """
        Return the kickstart filesystem name if this a MS Kickstart
        filesystem, otherwise return None.
        volmgr plugin assigns device name differently for MS KS filesystem,
        so this logic must match that of volmgr plugin to ensure VM config
        data will have the correct device name.
        """
        if (fs.type == 'ext4' and self.node.is_ms() and
                vg.volume_group_name == constants.MS_ROOT_VG_GROUP_NAME):
            return next((ks.name for ks in constants.MS_KS_FS
                        if ks.mount_point == fs.mount_point), None)
        return None

    def _get_disk_mounts(self):
        """
        Return path to block devices that should be added as disks
        to virtual machine.
        """
        vm_disks = []
        for vm_disk in self._disks:
            if vm_disk.is_for_removal():
                continue
            fs_item = vm_disk.host_file_system_item
            vg_item = fs_item.parent.parent
            ks_fs_name = self._ms_install_fs(vg_item, fs_item)
            if ks_fs_name:
                lv_name = "_".join(('lv', ks_fs_name))
            else:
                lv_name = "_".join((vg_item.item_id, fs_item.item_id))
            bd_path = os.path.join("/dev", vg_item.volume_group_name, lv_name)
            vm_disks.append([bd_path, vm_disk.mount_point])
        return vm_disks

    def _get_yum_repos(self):
        return dict(
            (repo.name, {
                'name': repo.name,
                'baseurl': repo.base_url,
                'enabled': True,
                'gpgcheck': False,
            })
            for repo in self._yum_repos if not repo.is_for_removal())

    def _get_zypper_repos(self):
        return [{
            'path': '/etc/zypp/repos.d/{0}.repo'.format(repo.name),
            'content':
             '[{0}]\n'
             'name={0}\n'
             'enabled=1\n'
             'autorefresh=0\n'
             'baseurl={1}\n'
             'gpgcheck=False\n'.format(repo.name, repo.base_url)
            }
            for repo in self._zypper_repos if not repo.is_for_removal()]

    def _get_packages(self):
        return [package.name for package in self._packages
                if not package.is_for_removal()]

    def _get_aliases(self, data):
        vm_aliases = [alias for alias in self._service.vm_aliases
                        if not alias.is_for_removal()]
        for index, alias in enumerate(vm_aliases):
            name = "alias" + str(index)
            addr_without_prefix = utils.remove_ip_prefix(alias.address)
            args = ['-c', 'echo {0} {1} >> /etc/hosts'.format(
                addr_without_prefix, alias.alias_names.replace(",", " "))]
            alias_entry = self._get_bootcmd_command(name, 'sh', args)
            data.append(alias_entry)
        return data

    def _updated_status_timeout(self):
        # Update application resource task will update the status_timeout in
        # VCS, but the VM will need to update the userdata to change the value
        # in /etc/sysconfig/vmmonitord as well
        if self._clustered_service:
            ha_cfg = utils.get_associated_haconfig(self)
            if ha_cfg and utils.property_updated(ha_cfg, 'status_timeout'):
                return True
        return False

    def _get_vmmonitor_timeout(self, data):
        status_timeout = None
        name = 'vmmonitored_timeout'
        if self._clustered_service:
            ha_srv_cfg = utils.get_associated_haconfig(self)
            if ha_srv_cfg and ha_srv_cfg.status_timeout:
                status_timeout = ha_srv_cfg.status_timeout
            if status_timeout:
                # only create file if status_timeout exists
                # otherwise ocf_monitor will use the defaul specified in
                # ocf_monitor.py
                args = ['-c', 'echo export OCF_TIMEOUT={0}  >> '
                    '/etc/sysconfig/vmmonitord'.format(status_timeout)]
                vmmonitored_timeout_entry = self._get_bootcmd_command(name,
                                                          'sh', args)
                data.append(vmmonitored_timeout_entry)

    def _get_ssh_authorized_keys(self):
        return [
            ssh_key.ssh_key
            for ssh_key in self._service.vm_ssh_keys
            if ssh_key.ssh_key and not ssh_key.is_for_removal()]

    def _get_vm_firewall_rules(self):
        ip_cmds = []
        rules = [fw_rule for fw_rule in self._firewall_rules
                if not fw_rule.is_for_removal()]

        if rules:
            get_iptable_dir = [
                'if [ -f /sbin/iptables ]; then iptables_dir="/sbin"; '
                'elif [ -f /usr/sbin/iptables ]; '
                'then iptables_dir="/usr/sbin"; fi'
            ]
            ip_cmds.extend(get_iptable_dir)
        # Cast number part of the rule name to int for natural sorting
        for rule in sorted(rules, key=lambda rule: \
                                  int(rule.properties["name"].split()[0])):
            properties = rule.properties
            properties["action"] = properties["action"].upper()
            properties["proto"] = constants.FW_PROTO_TEMPLATE.format(
                                                proto=properties["proto"])
            if "-" in properties["dport"]:
                properties["dport"] = properties["dport"].replace("-", ":")

            properties["dport"] = constants.FW_DPORT_TEMPLATE % (
                                                        properties["dport"])

            properties["name"] = constants.FW_NAME_TEMPLATE % \
                                                        properties["name"]
            if "source" in properties:
                properties["source"] = constants.FW_SOURCE_TEMPLATE % \
                                                properties["source"]
            for chain in constants.FW_CHAINS:
                properties["chain"] = chain
                ip_cmds.append(constants.FIREWALL_RULE_COMMAND_TEMPLATE.format(
                                        rule=defaultdict(str, **properties)))

        return ip_cmds

    def _image_checksum_updated(self):
        # LITPCDS-8541: If the service is initial the image_checksum property
        # will be ignored
        return (self.is_initial() or
                utils.property_updated(self._service, 'image_checksum'))

    def _motd_updated(self):
        return (self.is_initial() or
                utils.property_updated(self._service, 'motd_checksum'))

    def _issue_net_updated(self):
        return (self.is_initial() or
                utils.property_updated(self._service, 'issue_net_checksum'))

    def _have_checksums_changed(self):
        """
        Return `True` if the calculated checksum is different from the existing
        one otherwise `False`.
        """
        yum_repo = [repo for repo in self._yum_repos
                 if repo.is_initial()
                 or repo.is_for_removal()
                 or not repo.applied_properties_determinable
                 or repo.applied_properties.get("checksum") != repo.checksum]

        zypper_repo = [repo for repo in self._zypper_repos
                 if repo.is_initial()
                 or repo.is_for_removal()
                 or not repo.applied_properties_determinable
                 or repo.applied_properties.get("checksum") != repo.checksum]
        return bool(yum_repo or zypper_repo)


class LibvirtPlugin(Plugin):
    """
    LITP libvirt plugin for installation and configuration of libvirt \
    virtual machines.

    Update reconfiguration actions are supported for this plugin.

    """
    @staticmethod
    def query_not_for_removal(context, item_type_id, **properties):
        items = context.query(item_type_id, **properties)
        return [item for item in items if not item.is_for_removal()]

    def ip_address_in_subnet(self, ip_address, subnet):
        """
        Return `True` if `ipaddress` is in `subnet` otherwise `False`.
        """
        return (self.ip_obj_from_ip_address(ip_address) in
                netaddr.IPNetwork(subnet))

    def ip_obj_from_ip_address(self, ip_address):
        """
        Return a `nettaddr.IPAddress` object for the address associated with
        `vm_address`.
        """
        if utils.is_ipv6(ip_address):
            address = utils.strip_prefixlen(ip_address)
        else:
            address = ip_address
        return netaddr.IPAddress(address)

    def _get_ipv4_address_list(self, vm_iface):
        """
        Return list of ipv4 addresses from vm-network-interface ipaddresses
        property
        """
        if vm_iface.ipaddresses:
            return [ip.strip() for ip in vm_iface.ipaddresses.split(",")]
        return []

    def _get_ipv6_address_list(self, vm_iface):
        """
        Return list of ipv6 addresses from vm-network-interface ipv6addresses
        property
        """
        if vm_iface.ipv6addresses:
            return [IPv6AndMaskListValidator.normalize_ip(ip)
                    for ip in vm_iface.ipv6addresses.split(",")]
        return []

    def update_node_ip_map(self, plugin_api_context):
        """
        Update node_ip_map from {'node_name': 'ip'...} to
        {"node_name": {'ipv4': 'ip'}....}
        """
        interfaces = self.query_not_for_removal(plugin_api_context,
                                                "vm-network-interface")
        for intf in interfaces:
            need_update = True
            node_ip_map = ast.literal_eval(intf.node_ip_map)
            for ip in node_ip_map.values():
                if isinstance(ip, dict):
                    # Because is already in right format do not update it
                    need_update = False
                break

            if not need_update:
                continue
            if intf.ipaddresses == constants.DYNAMIC_IP:
                new_node_ip_map = dict()
            else:
                new_node_ip_map = dict(
                    (node, {"ipv4": ipv4_addr})
                    for node, ipv4_addr in node_ip_map.items())

            intf.node_ip_map = str(new_node_ip_map)

    def _update_adaptor(self, vm_serv, adaptor_version):
        """
        Return `True` if the libvirt adaptor needs to be updated
        otherwise `False`.
        """
        if vm_serv.is_initial():
            return True

        adaptor_version_applied = vm_serv.applied_properties.get(
                                                    'adaptor_version', '0.0-0')

        latest_version = '{0}-{1}'.format(adaptor_version['version'],
                                              adaptor_version['release'])
        return utils.needs_update(adaptor_version_applied, latest_version)

    def update_adaptor_version(self, plugin_api_context):
        """
        Check the adaptor_version for each vm-service and write to the model
        if it needs to be updated.
        """
        adaptor_version = self._get_litpmn_package_version()
        if adaptor_version is not None:
            deployments_api = plugin_api_context.query_by_vpath('/deployments')
            ms_api = plugin_api_context.query_by_vpath('/ms')
            vm_services = (self.query_not_for_removal(deployments_api,
                                                      'vm-service') +
                           self.query_not_for_removal(ms_api, 'vm-service'))
            for vm_serv in vm_services:
                if self._update_adaptor(vm_serv, adaptor_version):
                    # Write the adaptor version to model
                    vm_serv.adaptor_version = '-'.join(
                                                  (adaptor_version['version'],
                                                   adaptor_version['release']))

    def update_model(self, plugin_api_context):
        self.update_node_ip_map(plugin_api_context)
        self.update_adaptor_version(plugin_api_context)

    def validate_model(self, plugin_api_context):
        """
        libvirt provider
        ----------------
        Validates that a bridge is configured on the providers host node \
        which matches the value of the 'bridge' property on the \
        'libvirt-provider'.

        *An example error would look like the following:*

        .. code-block:: bash

            litp create_plan
            /ms/libvirt
                ValidationError    Bridge 'br0' doesn't exist on this node

        To resolve this error the model must be updated to include a matching \
        bridge in the network profile of the host node of the \
        'libvirt-provider'.

        vm service
        ----------
        The following validation is enforced for libvirt vm services.

        - "vm-image" "name" property is unique.
        - "vm-service" "service_name" property is unique.
        - "vm-image" exists for "image_name" property of "vm-service".
        - "vm-service" is only one per "clustered-service".
        """
        errors = []

        flags = [PRE_OS_REINSTALL, HA_MANAGER_ONLY, INFRA_UPDATE]
        for label in flags:
            if VMServiceFacade._is_upgrade_flag_set(plugin_api_context,
                                                    label):
                return errors

        nodes = plugin_api_context.query("ms")
        libvirt_nodes = [node for node in nodes if node.libvirt]

        for node in libvirt_nodes:
            err = self._validate_bridge(node)
            if err is not None:
                errors.append(err)
        libvirt_systems = plugin_api_context.query("libvirt-system")

        for libvirt_system in libvirt_systems:
            err = self._validate_libvirt_system_disks(libvirt_system)
            if err is not None:
                errors.append(err)

        # vm-service validation code below here.
        errors.extend(self.validate_service_not_inherited_twice(
            plugin_api_context))
        errors.extend(self.validate_service_inherit_location(
            plugin_api_context))
        # Validate that for each node each vm-service is unique

        software_api = plugin_api_context.query_by_vpath('/software')
        ms_api = plugin_api_context.query_by_vpath('/ms')

        # Validate that the service_name is unique in /software
        errors.extend(
            self._validate_unique_property(software_api.query('vm-service'),
                                           'service_name'))
        # Validate that the service_name is unique in /ms
        errors.extend(
            self._validate_unique_property(ms_api.query('vm-service'),
                                           'service_name'))

        root_api = plugin_api_context.query_by_vpath('/')
        deployments_api = plugin_api_context.query_by_vpath('/deployments')
        ms_api = plugin_api_context.query_by_vpath('/ms')
        vm_images = self.query_not_for_removal(software_api, 'vm-image')
        vm_services = (self.query_not_for_removal(deployments_api,
                                                  'vm-service') +
                       self.query_not_for_removal(ms_api,
                                                  'vm-service'))
        ms_vm_services = self.query_not_for_removal(ms_api, 'vm-service')
        vm_interfaces = (self.query_not_for_removal(deployments_api,
                                                    'vm-network-interface') +
                         self.query_not_for_removal(ms_api,
                                                    'vm-network-interface'))
        vm_ssh_keys = (self.query_not_for_removal(deployments_api,
                                                  'vm-ssh-key') +
                       self.query_not_for_removal(ms_api,
                                                  'vm-ssh-key'))
        vm_custom_scripts = (self.query_not_for_removal(software_api,
                                                       'vm-custom-script') +
                             self.query_not_for_removal(ms_api,
                                                        'vm-custom-script'))

        # Validate that only one service exists per clustered-service
        errors.extend(self._validate_no_duplicate_hostname(root_api))
        errors.extend(self._validate_one_service_per_clustered_service(
            deployments_api))
        errors.extend(self._validate_hostname_count(deployments_api))
        errors.extend(self._validate_hostname_count_ms(ms_api))

        if not VMServiceFacade._is_upgrade_flag_set(
                                        plugin_api_context, REDEPLOY_MS):
            errors.extend(self._validate_ipaddress_count(root_api))

        errors.extend(self._validate_ipaddress_count_ms(ms_api))
        errors.extend(
            self._validate_gateway_matches_ipaddresses(vm_interfaces))
        errors.extend(
            self._validate_ipaddress_on_network(vm_interfaces, root_api))
        errors.extend(
            self._validate_no_duplicated_ipaddress(vm_interfaces))
        errors.extend(
            self._validate_no_dhcp_in_mgmt_netwoks(plugin_api_context,
                                                   vm_interfaces))
        errors.extend(self._validate_host_device(root_api))
        errors.extend(
            self._validate_unique_property(vm_images, 'name'))
        errors.extend(
            self._validate_image_file_exist(vm_images))
        errors.extend(
            self._validate_md5_file(vm_images))
        errors.extend(
            self._validate_service_image_exists(vm_services, software_api))
        errors.extend(
            self._validate_images_for_removal(
                vm_services, software_api))
        errors.extend(self.validate_service_names(vm_services))

        errors.extend(self._validate_initial_ssh_key_non_empty(vm_ssh_keys))

        errors.extend(self._validate_custom_script_exist_and_is_regular_file(
            vm_custom_scripts))

        # get all ips from ms
        ms_ips = LibvirtPlugin.get_ms_ips(plugin_api_context)
        errors.extend(LibvirtPlugin._validate_vm_repos_base_ms(
            vm_services, ms_ips))

        errors.extend(LibvirtPlugin._validate_vm_disk_mounts_base_ms(
            plugin_api_context))

        alias_names = [alias.alias_names
                       for alias in plugin_api_context.query("alias")]

        errors.extend(
            LibvirtPlugin._validate_vm_image_base_ms(
                vm_images, ms_ips + [nodes[0].hostname] + alias_names))

        errors.extend(
            self._validate_repos_contain_packages(deployments_api))

        errors.extend(
            self._validate_repos_contain_packages(ms_api))

        ms_interfaces = ms_api.network_interfaces
        for vm_service in vm_services:
            vm_packages = self.query_not_for_removal(vm_service,
                                                     'vm-package')
            vm_yum_repos = self.query_not_for_removal(vm_service,
                                                      'vm-yum-repo')
            vm_zypper_repos = self.query_not_for_removal(vm_service,
                                                      'vm-zypper-repo')
            vm_firewall_rules = self.query_not_for_removal(vm_service,
                                                         'vm-firewall-rule')
            errors.extend(self._validate_no_duplicate_rule_numbers(
                vm_firewall_rules, "iptables"))
            errors.extend(self._validate_no_duplicate_rule_numbers(
                vm_firewall_rules, "ip6tables"))
            errors.extend(self._validate_mount_point_paths(vm_service))
            errors.extend(self._validate_one_gateway_per_service(vm_service))
            errors.extend(
                self._validate_unique_property(vm_packages, 'name'))
            for item in [vm_yum_repos, vm_zypper_repos]:
                errors.extend(
                    self._validate_unique_property(item, 'name'))
                errors.extend(
                    self._validate_unique_property(item, 'base_url'))
            errors.extend(self._validate_yum_or_zypper(vm_service,
                                                       vm_yum_repos,
                                                       vm_zypper_repos))
            # Validate that each service has unique device_name for interfaces
            vm_interfaces = self.query_not_for_removal(vm_service,
                                                       'vm-network-interface')
            errors.extend(self._validate_unique_property(vm_interfaces,
                                                         'device_name'))
            errors.extend(self._validate_internal_status_check(vm_service))
            errors.extend(self._validate_sequential_device_names(vm_service))
            errors.extend(self._validate_internal_status_check_accessible(
                                                                vm_service))
            errors.extend(self.validate_service_not_updated(vm_service))
            errors.extend(self._validate_network_in_ms_and_vms(
                plugin_api_context, vm_service, ms_interfaces, vm_interfaces))

            errors.extend(self._validate_cpuset_cpunodebind_exclusive(
                    vm_service))

        # Specific validations for vm-service on the ms
        errors.extend(self._validate_ms_vm_disk_mounts(ms_vm_services))
        for vm_service in ms_vm_services:
            errors.extend(self._validate_ms_internal_status_check(vm_service))
            errors.extend(self._validate_ms_cleanup_command(vm_service))

        return errors

    def _validate_cpuset_cpunodebind_exclusive(self, service):
        errors = []
        if service.cpuset is not None and service.cpunodebind is not None:
            error_message = ('The properties "cpuset" and "cpunodebind" '
                             'are mutually exclusive')
            errors.append(
                    ValidationError(item_path=service.vpath,
                                    error_message=error_message))
        return errors

    def _gather_repo_paths(self, deployment_context):
        """
        Returns a set of repository paths for all vm-yum-repos and
        vm-zypper-repos seen in the provided context
        """
        uris = set()
        for repo in (deployment_context.query("vm-yum-repo") +
                     deployment_context.query("vm-zypper-repo")):
            if repo.is_for_removal():
                continue
            uris.add(self._get_repo_dir(repo.base_url))
        return uris

    def _get_pkgs_per_repo(self, repo_paths):
        """
        Returns a dictionary associating a repository path with a
        set of package names availabe in that repository, and a set of
        invalid repo paths that could not be accessed.
        """
        repo_to_pkgs = {}
        bad_repo_paths = set()
        for repo_path in repo_paths:
            try:
                repo_to_pkgs[repo_path] = \
                    utils.get_names_of_pkgs_in_repo_by_path(repo_path)
            except exception.LibvirtYumRepoException:
                bad_repo_paths.add(repo_path)
        return repo_to_pkgs, bad_repo_paths

    @staticmethod
    def get_ms_ips(plugin_api_context):
        """Returns all ms's ip adresses"""
        ips = []
        ms = plugin_api_context.query("ms")[0]
        for intf in ms.network_interfaces:
            ips.append(intf.ipaddress)
        return ips

    @staticmethod
    def get_aliases(vm_service, ms_ips):
        """Returns all aliases that are point to ms from vm_service"""
        aliases_to_ms = []
        for ip in ms_ips:
            aliases = LibvirtPlugin.query_not_for_removal(vm_service,
                                                          "vm-alias",
                                                          address=ip)
            for alias in aliases:
                aliases_to_ms.extend(alias.alias_names.split(','))

        return set(aliases_to_ms)

    @staticmethod
    def get_base_url(url):
        return urlparse(url).netloc

    @staticmethod
    def _validate_vm_image_base_ms(vm_images, resources):
        """Validate that all vm-images are base on the ms"""
        errors = []
        for vm_image in vm_images:
            base_url = LibvirtPlugin.get_base_url(vm_image.source_uri)
            if base_url not in set(resources):
                error_message = ERROR_MSG_INVALID_HOSTNAME.format(base_url)
                errors.append(
                    ValidationError(item_path=vm_image.get_vpath(),
                                        error_message=error_message))
        return errors

    @staticmethod
    def _validate_mount_point_paths(vm_service):
        """
        Validates that mount point paths from vm-disk, NFS and RAM mounts do
        not intersect.
        """
        errors = []

        mount_points_list = []
        for vm_disk in vm_service.vm_disks:
            if vm_disk.is_for_removal():
                continue
            mount_points_list.append({
                'path': os.path.normpath(vm_disk.mount_point) + '/',
                'vpath': vm_disk.get_vpath()})

        for vm_ram_mount in vm_service.vm_ram_mounts:
            if vm_ram_mount.is_for_removal():
                continue
            mount_points_list.append({
                'path': os.path.normpath(vm_ram_mount.mount_point) + '/',
                'vpath': vm_ram_mount.get_vpath()})

        for vm_nfs in vm_service.vm_nfs_mounts:
            mount_points_list.append({
                'path': os.path.normpath(vm_nfs.mount_point) + '/',
                'vpath': vm_nfs.get_vpath()})

        mount_points_list = sorted(mount_points_list, key=lambda p: p['path'])
        while mount_points_list:
            mount_point = mount_points_list[0]
            paths = []

            for other_mount_point in mount_points_list:
                if other_mount_point['path'].startswith(mount_point['path']):
                    paths.append(other_mount_point)

            if len(paths) > 1:
                for path in paths:
                    error_message = ('The "mount_point" property "{0}" is '
                                     'already defined. The mount point must '
                                     'be unique within the '
                                     'VM.').format(mount_point['path'])
                    errors.append(
                        ValidationError(item_path=path['vpath'],
                            error_message=error_message))

            for path in paths:
                mount_points_list.remove(path)

        return errors

    @staticmethod
    def _validate_vm_disk_mounts_base_ms(api):
        """
        Validate that all vm-disk items have a valid file-system attached,
        which means that the file-system exist on MS.
        """
        errors = []
        for vm_disk in api.query('vm-disk'):
            vm_disk_vpath = vm_disk.get_vpath()
            if not vm_disk_vpath.startswith('/ms'):
                error_message = ('A vm-disk can only be used by a VM '
                                 'hosted on the management server')
                errors.append(
                    ValidationError(item_path=vm_disk_vpath,
                                    error_message=error_message))
            try:
                vm_disk.host_file_system_item
            except ViewError:
                lv = '%s/%s' % (vm_disk.host_volume_group,
                    vm_disk.host_file_system)
                error_message = ('The file-system "{0}" is undefined '
                    'for storage profile on management server.'.format(lv))
                errors.append(
                    ValidationError(item_path=vm_disk_vpath,
                                    error_message=error_message))
        return errors

    @staticmethod
    def _validate_ms_vm_disk_mounts(ms_vm_services):
        """
        Make sure vm-disk not used two times and that vm-disk is attached to
        VM, hosted on Management Server.
        """
        errors = []
        vm_disk_map = {}  # VgItemId_FSItemId: vm-disk vpath
        for vm_service in ms_vm_services:
            for vm_disk in vm_service.vm_disks:
                lv = '%s/%s' % (vm_disk.host_volume_group,
                                vm_disk.host_file_system)
                other_vm_disk = vm_disk_map.get(lv, None)

                if other_vm_disk:
                    for disk in [other_vm_disk, vm_disk]:
                        error_message = ('The file-system "{0}" is already '
                                         'defined. The file-system must be '
                                         'in use by one VM only.').format(lv)
                        errors.append(ValidationError(
                            item_path=disk.vpath,
                            error_message=error_message))
                else:
                    vm_disk_map[lv] = vm_disk
        return errors

    @staticmethod
    def _validate_vm_repos_base_ms(vm_services, ms_ips):
        """
        Validate that all vm-yum-repo and vm-zypper-repo are base on the ms
        """
        errors = []
        for vm_service in vm_services:
            all_ms_resources = ms_ips
            aliases = LibvirtPlugin.get_aliases(vm_service, ms_ips)
            all_ms_resources.extend(aliases)
            all_vm_repos = LibvirtPlugin.query_not_for_removal(
                vm_service, 'vm-yum-repo') + \
                           LibvirtPlugin.query_not_for_removal(
                vm_service, 'vm-zypper-repo')

            for vm_repo in all_vm_repos:
                base_url = LibvirtPlugin.get_base_url(vm_repo.base_url)
                if base_url not in set(all_ms_resources):
                    error_message = ('repo "{0}" is not reachable, check the '
                                     'vm-alias/IPs').format(vm_repo.name)
                    errors.append(
                        ValidationError(item_path=vm_repo.get_vpath(),
                                        error_message=error_message))
        return errors

    def validate_service_names(self, vm_services):
        """
        Validate that `service_name` is also valid to be used
        as a linux hostname.
        """
        errors = []
        for service in vm_services:
            if patterns.HOSTNAME_RE.match(service.service_name) is None:
                error = ValidationError(
                    item_path=service.vpath,
                    error_message=(
                        '"service_name" contains invalid characters, '
                        '"service_name" must be compliant with linux '
                        'hostname specification'))
                errors.append(error)
        return errors

    def _validate_initial_ssh_key_non_empty(self, vm_ssh_keys):
        """
        Validate that the `ssh_key` property of vm_ssh_key is not empty if
        the ssh key is in initial state
        """
        errors = []
        for vm_ssh_key in vm_ssh_keys:
            if vm_ssh_key.is_initial() and not vm_ssh_key.ssh_key:
                error = ValidationError(
                    item_path=vm_ssh_key.get_vpath(),
                    error_message=('the "ssh_key" property must be a '
                                   'non-empty string when first creating '
                                   'the "vm-ssh-key"'))
                errors.append(error)
        return errors

    def _get_repo_dir(self, value):
        repo_path = utils.append_slash(urlparse(value).path)
        return constants.APACHE_DIR + repo_path

    def _validate_repos_contain_packages(self, api):
        errors = []
        repo_paths = self._gather_repo_paths(api)
        repo_pkgs, bad_paths = self._get_pkgs_per_repo(repo_paths)

        for service in api.query('vm-service'):
            if service.is_for_removal():
                continue
            available_pkgs = set()
            for repo in service.vm_yum_repos:
                if repo.is_for_removal():
                    continue
                if self._get_repo_dir(repo.base_url) in bad_paths:
                    error_message = ('The repo "{0}" is not present on the '
                                     'management server'.format(repo.base_url))
                    errors.append(ValidationError(
                        item_path=repo.vpath,
                        error_message=error_message))
                    continue
                # Update the set of packages known to be available to the vm
                available_pkgs.update(
                    repo_pkgs[self._get_repo_dir(repo.base_url)])

            for repo in service.vm_zypper_repos:
                if repo.is_for_removal():
                    continue
                if self._get_repo_dir(repo.base_url) in bad_paths:
                    error_message = ('The repo "{0}" is not present on the '
                                     'management server'.format(repo.base_url))
                    errors.append(ValidationError(
                        item_path=repo.vpath,
                        error_message=error_message))
                    continue
                # Update the set of packages known to be available to the vm
                available_pkgs.update(
                    repo_pkgs[self._get_repo_dir(repo.base_url)])

            for vm_pkg in service.vm_packages:
                if vm_pkg.is_for_removal():
                    continue
                if vm_pkg.name in available_pkgs:
                    # The package is present in packages
                    continue
                errors.append(ValidationError(
                    item_path=vm_pkg.vpath,
                    error_message=('The package "{0}" does not exist in any '
                                   'defined repo'.format(vm_pkg.name))))
        return errors

    def _validate_one_service_per_clustered_service(self, api):
        errors = []
        for cluster in api.query('cluster'):
            for clustered_service in cluster.services:
                if len(self.query_not_for_removal(clustered_service,
                                                  'vm-service')) > 1:
                    errors.append(
                        ValidationError(
                            item_path=clustered_service.get_vpath(),
                            error_message=(
                                'Only one "vm-service" item is allowed for '
                                'each "clustered-service" item.')))
        return errors

    def _get_vm_service_hostnames(self, clustered_service, vm_service):
        """
        Return a list of the hostnames of a vm_service
        :param clustered_service:
        :param vm_servcies:
        :return:
        """

        if vm_service.hostnames:
            hostnames = vm_service.hostnames.split(',')
        elif not clustered_service:
            hostnames = [vm_service.service_name]
        elif clustered_service.standby != '0':
            if clustered_service.nodes:
                node = clustered_service.nodes[0]
                hostnames = [utils.generate_vm_hostname(node, vm_service,
                                                        parallel=False)]
            else:
                hostnames = []
        else:
            hostnames = [utils.generate_vm_hostname(node, vm_service,
                                                    parallel=True)
                         for node in clustered_service.nodes]
        return hostnames

    def _validate_duplicated_hostnames(self, api, hostnames):
        """
        Check if there is duplicated hostnames.
        :param hostnames: dict with a vpath list per hostname
        :return: Validation errors
        """
        errors = []
        for vm_hostname, vm_vpaths in hostnames.iteritems():
            vm_with_hostnames = []
            for vm_vpath in vm_vpaths:
                service = api.query_by_vpath(vm_vpath)
                if service.hostnames:
                    vm_with_hostnames.append(vm_vpath)
            if vm_with_hostnames and len(vm_vpaths) > 1:
                for vm_vpath in vm_vpaths:
                    error_message = ('Hostname "{0}" is used in more than'
                        ' one vm-service'.format(vm_hostname))
                    errors.append(ValidationError(
                        item_path=vm_vpath,
                        error_message=error_message))
        return errors

    def _hostnames_in_cluster(self, cluster):
        hostnames = defaultdict(list)
        for clustered_service in cluster.services:
            for vm_service in self.query_not_for_removal(clustered_service,
                                                         'vm-service'):
                vm_hostnames = self._get_vm_service_hostnames(
                    clustered_service, vm_service)
                for vm_hostname in vm_hostnames:
                    hostnames[vm_hostname].append(vm_service.get_vpath())
        return hostnames

    def _hostnames_in_ms(self, ms):
        hostnames = defaultdict(list)
        for service in self.query_not_for_removal(ms, 'vm-service'):
            hostname = self._get_vm_service_hostnames(clustered_service=None,
                                                      vm_service=service)[0]
            hostnames[hostname].append(service.get_vpath())

        return hostnames

    def _validate_no_duplicate_hostname(self, api):
        """
        Validate that there is no duplicate hostnames in a cluster and in ms.
        """
        errors = []
        for cluster in api.query('cluster'):
            hostnames = self._hostnames_in_cluster(cluster)
            errors.extend(self._validate_duplicated_hostnames(api, hostnames))
        for ms in api.query('ms'):
            hostnames = self._hostnames_in_ms(ms)
            errors.extend(self._validate_duplicated_hostnames(api, hostnames))

        return errors

    def validate_service_not_updated(self, vm_service):
        """
        Validate that the service_name is not updated after deployment.
        """
        errors = []
        if vm_service.is_updated():
            if utils.property_updated(vm_service, 'service_name'):
                errors.append(ValidationError(
                    item_path=vm_service.get_vpath(),
                    error_message=('The "service_name" property of the '
                                    '"vm-service" item cannot be updated.')
                ))
        return errors

    def validate_service_not_inherited_twice(self, api):
        errors = []
        for cluster in api.query('cluster'):
            for clustered_service in cluster.services:
                for service in self.query_not_for_removal(clustered_service,
                                                          'vm-service'):
                    for node in clustered_service.nodes:
                        for vm in node.query('vm-service',
                                          service_name=service.service_name):
                            if vm.is_for_removal():
                                continue
                            errors.append(
                                ValidationError(
                                    item_path=service.get_vpath(),
                                    error_message=(
                                        'Cannot inherit a "vm-service" to '
                                        'a node which is already a member of '
                                        'a "clustered-service" containing that'
                                        ' service.')))
        return errors

    def validate_service_inherit_location(self, api):
        errors = []
        for cluster in api.query('cluster'):
            for vm_service in self.query_not_for_removal(cluster,
                                                         'vm-service'):
                source = vm_service.get_source()
                if source and not source.get_vpath().startswith('/software'):
                    errors.append(
                        ValidationError(
                            item_path=vm_service.get_vpath(),
                            error_message=(
                                'Cannot inherit a "vm-service" from '
                                'a location not under /software.')))
        return errors

    def _validate_image_file_exist(self, vm_images):
        """Validate that image file exists"""
        errors = []
        for vm_image in vm_images:
            if not utils.exist_image_file(vm_image.source_uri):
                error_message = "image file {0} does not exist".format(
                    utils.get_image_full_path(vm_image.source_uri))
                errors.append(
                    ValidationError(item_path=vm_image.get_vpath(),
                                    error_message=error_message))
        return errors

    def _validate_custom_script_exist_and_is_regular_file(self,
                                                          vm_custom_scripts):
        """Validate that custom scripts exists"""
        errors = []
        for script_item in vm_custom_scripts:
            script_lst = script_item.custom_script_names.split(',')
            for script in script_lst:
                abs_path = utils.get_custom_script_absolute_path(script)
                if not os.path.exists(abs_path):
                    error_message = ('custom script "{0}" does not exist on '
                                     'the Management Server').format(abs_path)
                    errors.append(
                        ValidationError(item_path=script_item.get_vpath(),
                                        error_message=error_message))
                elif not utils.custom_script_is_regular_file(script):
                    error_message = ('custom script "{0}" is not a regular '
                                     'file').format(abs_path)
                    errors.append(
                        ValidationError(item_path=script_item.get_vpath(),
                                        error_message=error_message))
        return errors

    def _validate_md5_file(self, vm_images):
        """
        Validate that md5 file exists and contains right md5 string
        """
        errors = []
        for vm_image in vm_images:
            try:
                check_sum = utils.get_checksum(vm_image.source_uri)
                # Check for non-ascii chars, as they break the regex checker
                check_sum.decode('ascii')
            except (OSError, IOError):
                error_message = "md5sum file {0} does not exist".format(
                    utils.get_md5_file_name(vm_image.source_uri))
                errors.append(
                    ValidationError(item_path=vm_image.get_vpath(),
                                    error_message=error_message))
                # stop to verify the the md5 format because nothing to verify
                continue
            except UnicodeDecodeError:
                # We've encountered a non-ascii character
                error_message = ("md5sum file {0} contains non-ascii "
                                 "characters. Please ensure the contents of "
                                 "the file are correct.").format(
                                     utils.get_md5_file_name(
                                         vm_image.source_uri))
                errors.append(ValidationError(item_path=vm_image.get_vpath(),
                                              error_message=error_message))
                continue

            regex_error_desc = "The '{0}' should contain a valid md5".format(
                utils.get_md5_file_name(vm_image.source_uri))

            reg_validator = RegexValidator(
                LibvirtExtension.REGEX_CHECKSUM_STRING, regex_error_desc)
            error = reg_validator.validate(check_sum)
            if error:
                errors.append(error)
        return errors

    def _validate_gateway_matches_ipaddresses(self, vm_interfaces):
        """
        Validate that for each network interface the gateway address is the
        same type (ipv4 or ipv6) as the ip addresses specified
        """
        errors = []
        for vm_iface in vm_interfaces:
            if vm_iface.gateway6 and not vm_iface.ipv6addresses:
                error_message = ('The gateway6 property is defined without the'
                                 ' ipv6addresses property being defined.')
                errors.append(ValidationError(
                              item_path=vm_iface.get_vpath(),
                              error_message=error_message))
            if vm_iface.gateway and not vm_iface.ipaddresses:
                error_message = ('The gateway property is defined without the'
                                 ' ipaddresses property being defined.')
                errors.append(ValidationError(
                              item_path=vm_iface.get_vpath(),
                              error_message=error_message))
        return errors

    def _validate_ipaddress_count(self, plugin_api_context):
        """
        Validate that either the number of ipv4 addresses or the number of
        ipv6 addresses equals the number of active nodes for a service
        """
        errors = []
        c_services = plugin_api_context.query('clustered-service')
        for c_service in c_services:
            for vm_iface in self.query_not_for_removal(c_service,
                                                    'vm-network-interface'):
                ipv4_addresses = self._get_ipv4_address_list(vm_iface)
                ipv6_addresses = self._get_ipv6_address_list(vm_iface)

                if (len(ipv4_addresses) not in (0, int(c_service.active)) and
                    ipv4_addresses[0] != constants.DYNAMIC_IP):
                    error_message = ('The IPv4 address list count of "{0}" '
                                     'does not match the number of active '
                                     'instances which is "{1}"').format(
                                                         len(ipv4_addresses),
                                                         c_service.active)
                    errors.append(ValidationError(
                        item_path=vm_iface.get_vpath(),
                        error_message=error_message))

                if len(ipv6_addresses) not in (0, int(c_service.active)):
                    error_message = ('The IPv6 address list count of "{0}" '
                                     'does not match the number of active '
                                     'instances which is "{1}"').format(
                                                         len(ipv6_addresses),
                                                         c_service.active)
                    errors.append(ValidationError(
                        item_path=vm_iface.get_vpath(),
                        error_message=error_message))

                if not ipv4_addresses and not ipv6_addresses:
                    error_message = ('There are no IP addresses defined. '
                                     'The number of IP addresses should match '
                                     'the number of active instances which '
                                     'is "{0}"').format(c_service.active)
                    errors.append(ValidationError(
                        item_path=vm_iface.get_vpath(),
                        error_message=error_message))

        return errors

    def _validate_ipaddress_count_ms(self, ms):
        """
        Validate that either the number of ipv4 addresses or the number of
        ipv6 addresses are equals to one
        """
        errors = []
        services = ms.query('vm-service')
        for service in services:
            for vm_iface in service.vm_network_interfaces:
                ipv4_addresses = self._get_ipv4_address_list(vm_iface)
                ipv6_addresses = self._get_ipv6_address_list(vm_iface)

                if (len(ipv4_addresses) > 1 and
                    not utils.is_dynamic_ip(vm_iface)):
                    error_message = ('The IPv4 address list count must '
                                     'be equal to one for "vm-service" '
                                     'defined under the /ms location.')
                    errors.append(ValidationError(
                        item_path=vm_iface.get_vpath(),
                        error_message=error_message))

                if len(ipv6_addresses) > 1:
                    error_message = ('The IPv6 address list count must '
                                     'be equal to one for "vm-service" '
                                     'defined under the /ms location.')
                    errors.append(ValidationError(
                        item_path=vm_iface.get_vpath(),
                        error_message=error_message))

                if not ipv4_addresses and not ipv6_addresses:
                    error_message = ('There are no IP addresses defined.')
                    errors.append(ValidationError(
                        item_path=vm_iface.get_vpath(),
                        error_message=error_message))

        return errors

    def _validate_hostname_count(self, api):
        """
        Validate hostnames len match the number of active instances
        :param plugin_api_context:
        :return:
        """
        errors = []
        for c_service in api.query('clustered-service'):
            for vm_service in self.query_not_for_removal(c_service,
                                                         'vm-service'):
                if vm_service.is_for_removal():
                    continue
                hostnames = vm_service.hostnames
                if hostnames and len(hostnames.split(',')) != \
                        int(c_service.active):
                    error_message = ('Hostnames list "%s" count does not match'
                                     ' number of active instances which is '
                                     '"%s"') % (vm_service.hostnames,
                                                c_service.active)
                    errors.append(ValidationError(
                        item_path=vm_service.get_vpath(),
                        error_message=error_message))
        return errors

    def _validate_hostname_count_ms(self, ms):
        """
        The hostnames len must be equals to one
        :param plugin_api_context:
        :return:
        """
        errors = []
        for vm_service in self.query_not_for_removal(ms, 'vm-service'):
            hostnames = vm_service.hostnames
            if hostnames and len(hostnames.split(',')) != 1:
                error_message = ('Only one hostname is allowed for the '
                                 '"hostnames" property for VMs that run on the'
                                 ' management server.')
                errors.append(ValidationError(
                    item_path=vm_service.get_vpath(),
                    error_message=error_message))
        return errors

    def _check_ip_in_subnet(self, vm_iface, ip_address, network):
        errors = []
        # We don't check subnets for ipv6.
        if utils.is_ipv6(ip_address):
            return errors
        # Will be caught be subnet validation.
        if network.subnet is None:
            return errors
        if not self.ip_address_in_subnet(ip_address,
                                         network.subnet):
            error_message = ('IP address "{0}" not contained in '
                             'the subnet of network "{1}"'.format(
                    ip_address,
                    vm_iface.network_name))
            errors.append(ValidationError(
                    item_path=vm_iface.get_vpath(),
                    error_message=error_message))
        return errors

    def _validate_ipaddress_on_network(self, vm_interfaces,
                                       plugin_api_context):
        errors = []
        for vm_iface in vm_interfaces:
            networks = plugin_api_context.query('network',
                                                name=vm_iface.network_name)
            if not networks:
                error_message = ('Network "{0}" does not exist '
                                 'in the model').format(vm_iface.network_name)
                errors.append(ValidationError(item_path=vm_iface.get_vpath(),
                                   error_message=error_message))
            else:
                network = networks[0]
                if not utils.is_dynamic_ip(vm_iface):
                    ip_addresses = self._get_ipv4_address_list(vm_iface)
                    for ip_address in ip_addresses:
                        errors.extend(self._check_ip_in_subnet(vm_iface,
                                                               ip_address,
                                                               network))
                    if vm_iface.gateway:
                        errors.extend(self._check_ip_in_subnet(vm_iface,
                                                            vm_iface.gateway,
                                                               network))
        return errors

    def _validate_no_duplicated_ipaddress(self, vm_interfaces):
        errors = []
        all_ips = defaultdict(list)
        for vm_iface in vm_interfaces:
            for ip in self._get_ipv4_address_list(vm_iface):
                if ip != constants.DYNAMIC_IP:
                    all_ips[ip].append(vm_iface.get_vpath())
            for ip in self._get_ipv6_address_list(vm_iface):
                all_ips[utils.strip_prefixlen(ip)].append(vm_iface.get_vpath())

        duplicated_ips = defaultdict(set)
        for ip, vpaths in all_ips.iteritems():
            if len(vpaths) > 1:
                for vpath in vpaths:
                    duplicated_ips[vpath].add(ip)

        for vpath, ips in duplicated_ips.iteritems():
            address_name = 'addresses' if len(ips) > 1 else 'address'
            error_message = ('IP {0} {1} can only be used once in the '
                             'vm-services.'.format(address_name,
                                                   utils.format_list(ips)))
            errors.append(ValidationError(item_path=vpath,
                                          error_message=error_message))
        return errors

    def _get_management_networks_name(self, context):
        return [net.name for net in
                context.query('network', litp_management='true')
                if not net.is_for_removal() and not net.is_removed()]

    def _validate_no_dhcp_in_mgmt_netwoks(self, plugin_context, vm_interfaces):
        """
        Validates that the interfaces connected to a management network
        do not have a dynamic property.
        """
        errors = []
        for vm_interface in vm_interfaces:
            if (utils.is_dynamic_ip(vm_interface) and
                        vm_interface.network_name in
                        self._get_management_networks_name(plugin_context)):
                error_message = ('The interface "%s" must have a static ip '
                                'because it is connected to the management '
                                'network "%s".' % (vm_interface.get_vpath(),
                                                   vm_interface.network_name))
                errors.append(ValidationError(
                                item_path=vm_interface.get_vpath(),
                                error_message=error_message))
        return errors

    def _validate_network_in_ms_and_vms(self, plugin_context, vm_service,
                                        ms_interfaces, vm_interfaces):
        """
        Validates that if network name of the custom script is specified, then
        the network should be in both ms and vm
        """
        errors = []
        custom_scripts = vm_service.vm_custom_script
        ms_networks = [intf.network_name for intf in ms_interfaces]
        vm_networks = [intf.network_name for intf in vm_interfaces]
        for custom_script in custom_scripts:
            if custom_script.network_name:
                if not (custom_script.network_name in ms_networks and
                                custom_script.network_name in vm_networks):
                    error_message = ('The network "%s" must be on both '
                                'management server and vm-service "%s" ' %
                        (custom_script.network_name, vm_service.service_name))
                    errors.append(ValidationError(
                                item_path=custom_script.get_vpath(),
                                error_message=error_message))
            else:
                mgmt_net_name = self._get_management_networks_name(
                                                         plugin_context)[0]
                if mgmt_net_name not in vm_networks:
                    error_message = ('The network "%s" must be on both '
                                'management server and vm-service "%s" ' %
                                (mgmt_net_name, vm_service.service_name))
                    errors.append(ValidationError(
                                item_path=custom_script.get_vpath(),
                                error_message=error_message))
        return errors

    def _validate_internal_status_check_accessible(self, vm_service):
        """
        Validates that the vm has a static IP if the vm has the property
        internal_status_check property set to "on".
        """
        errors = []
        if vm_service.internal_status_check == "on":
            static_interfaces = [iface for iface
                                 in vm_service.vm_network_interfaces
                                 if iface.ipaddresses
                                     and not iface.is_for_removal()
                                     and not utils.is_dynamic_ip(iface)]
            if not static_interfaces:
                error_message = ('The vm-service "%s" must have a static ipv4 '
                                 'address available to check its internal '
                                 'status.' % vm_service.get_vpath())
                errors.append(ValidationError(item_path=vm_service.get_vpath(),
                                       error_message=error_message))
        return errors

    def _get_device_names_for_node(self, node_obj):
        net_interfaces = node_obj.network_interfaces
        all_devices = {}
        for net_iface in net_interfaces:
            if hasattr(net_iface, "device_name"):
                if hasattr(net_iface, "network_name"):
                    name = net_iface.device_name
                    network = net_iface.network_name
                    item_type = net_iface.item_type_id
                    all_devices[name] = {'network': network,
                                         'item_type': item_type}
                    if (hasattr(net_iface, "ipaddress") and
                        net_iface.ipaddress is not None):
                        all_devices[name]["ipaddress"] = net_iface.ipaddress
        return all_devices

    def _validate_sequential_device_names(self, vm_service):
        errors = []

        vm_ifaces = vm_service.vm_network_interfaces
        vm_iface_devices = sorted([iface.device_name for iface in vm_ifaces
                                    if not iface.is_for_removal()],
                                  key=lambda x: int(x[3:]))
        # Regex just accept ethXX as input
        numbers = [int(iface[3:]) for iface in vm_iface_devices]
        for i, num in enumerate(numbers):
            if i != num:
                error_message = ('Property "device_name" of all '
                                 'vm-network-interface items must start from'
                                 ' eth0 and be sequentially numbered')
                errors.append(ValidationError(item_path=vm_ifaces.get_vpath(),
                                              error_message=error_message))

                return errors
        return errors

    @staticmethod
    def _validate_one_gateway_per_service(vm_service):
        errs = []
        vm_interfaces = LibvirtPlugin.query_not_for_removal(vm_service,
                                                        'vm-network-interface')

        for gw in ('gateway', 'gateway6'):
            ifaces_with_gateway = [vm_iface.vpath
                                   for vm_iface in vm_interfaces
                                   if getattr(vm_iface, gw) is not None]
            if len(ifaces_with_gateway) > 1:
                for iface in ifaces_with_gateway:
                    error_message = ('VM service "{0}" has more than 1 {1} '
                                 'defined'.format(vm_service.service_name, gw))
                    errs.append(ValidationError(item_path=iface,
                                                error_message=error_message))
        return errs

    def _validate_host_device(self, plugin_api_context):
        errors = []
        c_services = plugin_api_context.query('clustered-service')
        for c_service in c_services:
            vm_interfaces = self.query_not_for_removal(c_service,
                                                       'vm-network-interface')
            vm_services = self.query_not_for_removal(c_service, 'vm-service')

            for node in c_service.nodes:
                errors.extend(self._validate_host_devices_in_node(
                    node, vm_interfaces, vm_services, c_service))

        for ms in plugin_api_context.query('ms'):
            for vm_service in self.query_not_for_removal(ms, 'vm-service'):
                vm_interfaces = self.query_not_for_removal(vm_service,
                                                        'vm-network-interface')
                errors.extend(self._validate_host_devices_in_node(
                    ms, vm_interfaces, [vm_service]))

        return errors

    def _validate_host_devices_in_node(self, node, vm_interfaces,
                                       vm_services, c_service=None):
        """
        Validate that the vm-services have the correct host devices
        configuration on the node given:
           - Host device exist on the node
           - Valid network_name
           - vm_interface on a bridge
           - Valid ip for internal status check
         :param node: node of the vm-services
         :param vm_interfaces: All the interfaces of the vm_services given
         :param vm_services: services that shares management
         :param c_service: Clustered service that manages the services
        """
        errors = []
        internal_status_checked = any(
                [service.internal_status_check == 'on'
                for service in vm_services])
        node_devices = self._get_device_names_for_node(node)
        ip_address_assigned_to_device = False
        for vm_iface in vm_interfaces:
            if vm_iface.host_device not in node_devices:
                error_message = ('Host device "{0}" does not'
                                 ' exist on node "{1}"').format(
                    vm_iface.host_device,
                    node.hostname)
                errors.append(
                    ValidationError(item_path=vm_iface.get_vpath(),
                                    error_message=error_message))
            else:
                if "ipaddress" in node_devices[vm_iface.host_device]:
                    ip_address_assigned_to_device = True
                if vm_iface.network_name != node_devices[
                    vm_iface.host_device]['network']:
                    error_message = ('Network name "{0}" on'
                                     ' vm-network-interface "{1}"'
                                     ' does not match network name'
                                     ' "{2}" of the device on node'
                                     ' "{3}"').format(
                        vm_iface.network_name,
                        vm_iface.device_name,
                        node_devices[vm_iface.host_device]['network'],
                        node.hostname
                    )
                    errors.append(
                        ValidationError(item_path=vm_iface.get_vpath(),
                                        error_message=error_message))
                if node_devices[vm_iface.host_device]['item_type'] != \
                        'bridge':
                    error_message = ('Host device "{0}" on vm-network-'
                                     'interface "{1}" must be of type'
                                     ' "bridge" not "{2}" on node '
                                     '"{3}"').format(
                        vm_iface.host_device,
                        vm_iface.device_name,
                        node_devices[vm_iface.host_device]['item_type'],
                        node.hostname
                    )
                    errors.append(
                        ValidationError(item_path=vm_iface.get_vpath(),
                                        error_message=error_message))
        if (internal_status_checked and
                not ip_address_assigned_to_device):
            error_message = ('No IPv4 address assigned on any host '
                             'device which is used by the '
                             'vm-interfaces on node "{0}"'.format(
                node.hostname))
            vpath = (c_service or vm_services[0]).get_vpath()
            errors.append(
                ValidationError(item_path=vpath, error_message=error_message))
        return errors

    def _validate_unique_property(self, items, name):
        """
        Validate that no duplicate property `name` exists on any elements
        of `items`.
        """
        duplicates = self._items_with_duplicate_property(items, name)
        errors = []
        for item in duplicates:
            duplicates_str = ('", "'.join(duplicate.vpath for duplicate in
                duplicates if duplicate != item))
            error_message = ('The "{1}" property of the "{0}" '
                             'is not unique. The "{1}" property is'
                             ' identical in the following items: "{2}"'
                             .format(item.item_type_id, name, duplicates_str))
            error = ValidationError(
                item_path=item.get_vpath(),
                error_message=error_message)
            errors.append(error)
        return errors

    def _validate_yum_or_zypper(self, vm_service, yum_items, zypper_items):
        """
        Validate that VM contains yum or vm_zypper_repo repos but not both
        """
        errors = []

        if yum_items and zypper_items:
            error_message = ('The vm-service "{0}" cannot contain both '
                             '"vm-yum-repo" and "vm-zypper-repo" items'
                             .format(vm_service.service_name))
            error = ValidationError(
                item_path=vm_service.get_vpath(),
                error_message=error_message)
            errors.append(error)
        return errors

    def _items_with_duplicate_property(self, items, name):
        """
        Return all elements of `items` which contain duplicated property
        `name`.
        """
        getter = attrgetter(name)
        duplicates = set()
        for item in items:
            duplicates.update(
                item_
                for item_ in items
                if getter(item) == getter(item_)
                and item != item_)
        return sorted(duplicates)

    def _validate_service_image_exists(self, vm_services, api):
        """
        Validate that an image exists in the model for each vm_service.
        """
        errors = []
        for service in vm_services:
            if not api.query('vm-image', name=service.image_name):
                errors.append(ValidationError(
                    item_path=service.get_vpath(),
                    error_message='No "vm-image" item found with name %s' %
                    service.image_name))
        return errors

    def _validate_images_for_removal(self, vm_services, api):
        """
        Validate that an image marked as for removal that is in use
        on a vm-service that is not for removal returns a validation
        error.
        """
        errors = []
        for service in vm_services:
            try:
                image = api.query('vm-image', name=service.image_name)[0]
            except IndexError:
                # Will be caught by `_validate_service_image_exists`.
                continue
            if not service.is_for_removal() and image.is_for_removal():
                error_message = (
                    'Can not remove "vm-image" "%s" as it is in use by '
                    '"vm-service" "%s"' % (
                        image.get_vpath(), service.get_vpath()))
                errors.append(ValidationError(
                    item_path=image.get_vpath(),
                    error_message=error_message))
        return errors

    def _validate_bridge(self, node):
        try:
            bridges = node.query('bridge')
            new_bridges = [br for br in bridges if not br.is_for_removal()]
            bridge_list = [br.device_name for br in new_bridges]
        except AttributeError as err:
            log.trace.debug(
                    "Exception occured when checking bridge list: %s" % \
                    type(err))
            bridge_list = []

        if node.libvirt.bridge not in bridge_list:
            return ValidationError(
                item_path=node.libvirt.get_vpath(),
                error_message=("Bridge '%s' doesn't exist on this node" %
                               node.libvirt.bridge),
            )
        return None

    def _validate_libvirt_system_disks(self, libvirt_system, limit=1):
        if len(libvirt_system.disks) > limit:
            return ValidationError(
                    item_path=libvirt_system.disks.get_vpath(),
                    error_message=("The libvirt plugin currently only "
                                   "supports %s disk" % str(limit))
                   )

    def _validate_internal_status_check(self, vm_service):
        errors = []
        if vm_service.internal_status_check == 'on':
            if len(list(self.query_not_for_removal(vm_service,
                                                'vm-network-interface'))) == 0:
                error_message = ('No vm-network-interfaces defined. Cannot'
                                 ' perform internal_status_check')
                errors.append(
                    ValidationError(item_path=vm_service.get_vpath(),
                                    error_message=error_message))
        return errors

    def _validate_ms_internal_status_check(self, vm_service):
        errors = []
        if vm_service.internal_status_check == 'on':
            error_message = ('The property "internal_status_check" '
                             'is not supported when the "vm-service" '
                             'is created under the /ms location.')
            errors.append(
                ValidationError(item_path=vm_service.get_vpath(),
                                error_message=error_message))
        return errors

    def _validate_ms_cleanup_command(self, vm_service):
        errors = []
        if vm_service.cleanup_command != '/bin/true':
            error_message = ('The property "cleanup_command" '
                             'is not supported when the "vm-service" '
                             'is created under the /ms location.')
            errors.append(
                ValidationError(item_path=vm_service.get_vpath(),
                                error_message=error_message))
        return errors

    def _get_identifier(self, vm):
        return (vm._service.service_name, vm.node.hostname)

    def _trim_removed_vm_list(self, initial_vms, removed_vms):
        """
        Returns a list of elements that are in removed_vms,
        but not in initial_vms. An element is considered to
        be the same if it references the same service_name
        and node.
        """
        vms_to_trim = set()
        trimmed_vms = []
        for vm in initial_vms:
            vms_to_trim.add(self._get_identifier(vm))

        for vm in removed_vms:
            if self._get_identifier(vm) in vms_to_trim:
                continue
            trimmed_vms.append(vm)

        return trimmed_vms

    def create_configuration(self, plugin_api_context):
        """
        libvirt provider
        ---------------

        Provides support for the addition, update and removal \
        of 'libvirt-provider' and 'libvirt-system' model items. \
        Creating a deployment model of nodes with libvirt-system allows \
        for the installation of nodes on libvirt Virtual Machines.

        *An example CLI showing creation of libvirt-provider' and \
        'libvirt-system' model items follow:*

        .. code-block:: bash

            litp create -t libvirt-provider \
-p /infrastructure/system_providers/libvirt1 -o name=libvirt1

            litp create -t libvirt-system \
-p /infrastructure/system_providers/libvirt1/systems/vm1 \
-o system_name='VM1'

            litp -t libvirt-system \
-p /infrastructure/system_providers/libvirt1/systems/vm2 \
-o system_name='VM2'

            litp inherit -p /ms/libvirt \
-s /infrastructure/system_providers/libvirt1

            litp create -t deployment -p /deployments/local_vm
            litp create -t cluster -p /deployments/local_vm/clusters/c1

            litp create -t node \
-p /deployments/local_vm/clusters/c1/nodes/node1 -o hostname='node1'

            litp inherit \
-p /deployments/local_vm/clusters/c1/nodes/node1/system \
-s /infrastructure/system_providers/libvirt1/systems/vm1

            litp create -t node \
-p /deployments/local_vm/clusters/c1/nodes/node2 \
-o hostname='node2'

            litp inherit \
-p /deployments/local_vm/clusters/c1/nodes/node2/system \
-s /infrastructure/system_providers/libvirt1/systems/vm2

        vm service
        ----------

        Provides support for running libvirt VMs as services.

        Example CLI:

        .. code-block:: bash

            litp create -t vm-image \
-p /software/images/image \
-o name="image" source_uri="http://ms/images/image.qcow2"

            litp create -t vm-service \
-p /software/services/vmservice \
-o service_name="vmservice" image_name="image"

            litp create -t clustered-service \
-p /deployments/d1/clusters/c1/services/vmservice \
-o name=service active=2 standby=0 node_list='node1,node2'

            litp inherit -s /software/services/vmservice \
-p /deployments/d1/clusters/c1/services/vmservice/applications/vmapplication

        For more information, see \
"Introduction to Virtual Machine Configuration" \
from :ref:`LITP References <litp-references>`.

        """
        tasks = []

        # check if an upgrade flag is set other than redeploy_ms
        # if flag is picked up return empty list of tasks.
        flags = [PRE_OS_REINSTALL, HA_MANAGER_ONLY, INFRA_UPDATE]
        for label in flags:
            if VMServiceFacade._is_upgrade_flag_set(plugin_api_context,
                                                    label):
                return tasks

        restore_mode = VMServiceFacade._in_restore_mode(plugin_api_context)

        # find all libvirt providers
        ms = plugin_api_context.query("ms")[0]

        # find all nodes
        nodes = plugin_api_context.query("node")

        # workaround for limitation in core, to avoid corruption if
        # the user write the node_ip_map
        root_api = plugin_api_context.query_by_vpath('/')
        interfaces = root_api.query('vm-network-interface')
        for interface in interfaces:
            if interface.is_initial():
                interface.node_ip_map = "{}"

        # Similarly to avoid corruption for hostname_ip_map
        vm_services = root_api.query('vm-service')
        for vm_service in vm_services:
            if vm_service.is_initial():
                if vm_service.node_hostname_map != "{}":
                    vm_service.node_hostname_map = "{}"

        # add tasks for new systems as specified by 'libvirt-provider' items
        new_nodes = [node for node in nodes if node.system
                     and node.system.is_initial()
                     and node.system.item_type_id == 'libvirt-system']
        self._add_new_system_tasks(ms, new_nodes, tasks)

        # add tasks for systems for removal
        removal_nodes = [node for node in nodes if node.system
                         and node.system.is_for_removal()
                         and node.system.item_type_id == 'libvirt-system']
        self._add_removal_system_tasks(ms, removal_nodes, tasks)

        # vm-service tasks.

        utils.update_maps_for_services(plugin_api_context)
        utils.update_repo_checksums(plugin_api_context)
        utils.update_service_image_checksums(plugin_api_context)
        utils.update_banner_checksums(plugin_api_context, 'issue_net')
        utils.update_banner_checksums(plugin_api_context, 'motd')

        services_list = list(
            VMServiceFacade.from_model_gen(plugin_api_context))

        adaptor_version = self._get_litpmn_package_version()
        if adaptor_version is not None:
            tasks.extend(self.get_adaptor_install_tasks(
                services_list,
                adaptor_version))

        initial_vms = [service for service in services_list
                       if service.is_initial()]
        redeploy_vms = [service for service in services_list
                        if service.for_redeploy(restore_mode)]
        removed_vms = [service for service in services_list
                       if service.is_for_removal()]
        removed_vms = self._trim_removed_vm_list(initial_vms + redeploy_vms,
                                                 removed_vms)

        # LITPCDS-12221: We require the storage items as they may be needed
        # by the vm-services even if there is not real link
        infrastructure = plugin_api_context.query_by_vpath('/infrastructure')
        storage_model_items = infrastructure.query('sfs-export')

        replaced_remove_image = defaultdict(set)
        for service in initial_vms + redeploy_vms:
            log.trace.info("Create task to {state} the VM {vm} on "
                           "node {node}".format(
                state=service.state.capitalize(),
                vm=service.instance_name,
                node=service.node.hostname))

            required_items = []
            if service.deployed_on_ms():
                required_items = storage_model_items

            required_tasks = []
            service_tasks = []
            if service.deploy_image():
                copy_task = self.get_copy_image_task(service, required_items)
                copy_task_id = (copy_task.call_type, copy_task.call_id)
                tasks.append(copy_task)
                required_tasks.append(copy_task_id)
                if (service.image_name not in
                    replaced_remove_image[service.node.item_id]):
                    replaced_remove_image[service.node.item_id].add(
                        service.image_name)
                    copy_task.replaces.add((CALL_TYPE_REMOVE_IMAGE,
                                            CALL_ID_REMOVE_IMAGE.format(
                                                image=service.image_name)))

            if service.deploy_config(adaptor_version):
                service_tasks.append(
                    self.get_write_adaptor_task(
                        service,
                        required_tasks + required_items))

            if service.deploy_metadata():
                service_tasks.append(
                    self.get_write_metadata_task(
                        service,
                        plugin_api_context,
                        required_tasks + required_items))

            if service.deploy_networkconfig(service):
                service_tasks.append(
                    self.get_write_networkconfig_task(
                        service,
                        plugin_api_context,
                        required_tasks + required_items))

            if service.deploy_userdata():
                service_tasks.append(self.get_write_userdata_task(
                    service,
                    required_tasks + required_items))

            tasks.extend(service_tasks)
            if service_tasks and service.update_task_required():
                tasks.append(self.get_update_task(service, service_tasks))
            if service_tasks:
                tasks.extend(self.get_cleanup_images_task(service,
                                                         services_list, tasks))

        if removed_vms:
            service_removal_tasks = self.get_removal_tasks(removed_vms)
            tasks.extend(service_removal_tasks)
            tasks.extend(self.get_adaptor_removal_tasks(services_list,
                                                        service_removal_tasks))
            tasks.extend(self.get_image_removal_tasks(services_list))
            for service in removed_vms:
                tasks.extend(self.get_cleanup_images_task(service,
                                                         services_list, tasks))

        log.trace.debug('Below are the numbered tasks and the tasks that '
            'each require returned from the Libvirt plugin:')
        for number, task in enumerate(tasks):
            log.trace.debug("Task {0}: {1}. It requires: {2}".format(number,
            task, task.requires))
        return tasks

    def cleanup_task_for_node(self, service, tasks):
        """
        Return the existing cleanup task for the node of the specified or
        return None if no such task exists.
        """
        return next((task for task in tasks
                     if hasattr(task, 'callback') and
                     task.call_type == 'cb_cleanup_vm_images' and
                     task.kwargs['hostname'] == service.node.hostname), None)

    def get_image_whitelist(self, service, vm_services):
        """
        Return image whitlelist for the specified service. That is the list of
        images in use on the node of that service.
        """
        return ([srv.image_name for srv in vm_services
                 if srv.node == service.node
                    and not srv.is_for_removal()])

    def get_cleanup_images_task(self, service, vm_services, existing_tasks):
        if self.cleanup_task_for_node(service, existing_tasks):
            return []
        if service.node.is_for_removal():
            return []

        task_description = ('Remove unused VM image files on node "{0}"'
                                                .format(service.node.hostname))

        new_task = CallbackTask(service._service,
                                task_description,
                                self.cb_cleanup_vm_images,
                                hostname=service.node.hostname,
                                image_whitelist=','.join(
                                    self.get_image_whitelist(service,
                                                                vm_services)))
        if service.node.is_ms():
            new_task.requires.update([task for task in existing_tasks
                                       if task.model_item == service._service])
        return [new_task]

    def cb_cleanup_vm_images(self, callback_api, hostname, image_whitelist):
        api = LibvirtMcoClient(hostname)
        api.node_image_cleanup(image_whitelist)

    def get_adaptor_removal_tasks(self, vm_services, service_removal_tasks):
        '''
        Returns tasks to remove the libvirt adaptor for nodes where no
        more vm-services exist
        '''
        tasks = []
        nodes_to_keep = set()
        adaptor_already_removed = set()
        # Get nodes where vm_services still exist
        for vm_service in vm_services:
            if not vm_service.is_for_removal():
                nodes_to_keep.add(vm_service.node)
        for vm_service in vm_services:
            if vm_service.is_for_removal():
                if (vm_service.node not in nodes_to_keep and
                    vm_service.node not in adaptor_already_removed):
                    adaptor_already_removed.add(vm_service.node)
                    tasks.append(self.get_remove_adaptor_task(vm_service))
        # setup requires to service removal tasks to ensure the adaptor
        # is not removed until all services are removed
        for task in tasks:
            for service_task in service_removal_tasks:
                if service_task.node.hostname == task.node.hostname:
                    task.requires.add(service_task)
        return tasks

    def get_image_removal_tasks(self, vm_services):
        '''
        Returns tasks to remove vm-images from nodes that no longer have
        any services that use those images.
        '''
        tasks = []
        node_to_image = defaultdict(list)
        # Get a list of images used by services on each node
        for vm_service in vm_services:
            if not vm_service.is_for_removal():
                node_to_image[vm_service.node].append(vm_service.image_name)
        for vm_service in vm_services:
            if vm_service.is_for_removal():
                if (vm_service.image_name not in
                    node_to_image.get(vm_service.node, [])):
                    # Prevent the task being generated twice
                    node_to_image[vm_service.node].append(
                        vm_service.image_name)
                    tasks.append(self.get_remove_image_task(vm_service))
        return tasks

    def get_remove_adaptor_task(self, vm_service):
        task_description = (
            'Remove libvirt adaptor on node "{0}"'.format(
                vm_service.node.hostname))
        replace_list = [(CALL_TYPE_INSTALL_ADAPTOR,
                         CALL_ID_INSTALL_ADAPTOR.format(
                             node=vm_service.node.item_id))]
        task = ConfigTask(
            vm_service.node,
            vm_service.vm_task_item,
            task_description,
            call_type=CALL_TYPE_REMOVE_ADAPTOR,
            call_id=CALL_ID_REMOVE_ADAPTOR.format(
                node=vm_service.node.item_id)
            )
        task.replaces.update(replace_list)
        return task

    def get_remove_image_task(self, vm_service):
        task_description = (
            'Remove VM image file "{image}" on '
            'node "{node}"'.format(image=vm_service.image_name,
                                   node=vm_service.node.hostname))
        task = ConfigTask(
            vm_service.node,
            vm_service.vm_task_item,
            task_description,
            call_type=CALL_TYPE_REMOVE_IMAGE,
            call_id=CALL_ID_REMOVE_IMAGE.format(
                image=vm_service.image_name),
            target_path=constants.IMAGE_PATH,
            file_name=vm_service.image_name,
            )
        return task

    def get_removal_tasks(self, vm_services):
        tasks = []
        for vm_service in vm_services:
            task = self.get_service_deconfigure_task(vm_service)
            if vm_service._clustered_service:
                task.model_items.add(vm_service._clustered_service)
            tasks.append(task)
        return tasks

    def get_adaptor_install_tasks(self, vm_services, pkg_version):
        tasks = []

        if not vm_services:
            return tasks

        nodes = []
        for vm_service in vm_services:
            if vm_service.is_for_removal():
                continue
            if not vm_service.update_adaptor(pkg_version):
                continue

            if vm_service.adaptor_version == "0.0-0":
                task_description = (
                    'Install libvirt adaptor version "{0}", release "{1}" '
                    'on node "{2}"'.format(
                        pkg_version['version'],
                        pkg_version['release'],
                        vm_service.node.hostname))
                log.trace.info(
                    'Ensure that libvirt adaptor version "{0}" released "{1}"'
                    ' is installed in node "{2}" for vm-service "{3}"'.format(
                        pkg_version['version'],
                        pkg_version['release'],
                        vm_service.node.hostname,
                        vm_service.instance_name))
            else:
                task_description = (
                    'Update libvirt adaptor to version "{0}", release "{1}" '
                    'on node "{2}"'.format(
                        pkg_version['version'],
                        pkg_version['release'],
                        vm_service.node.hostname))

                log.trace.info(
                    'Ensure that libvirt adaptor is updated from version '
                    '"{0}" to version "{1}" in node "{2}" for vm-service '
                    '{3}'.format(
                        vm_service.adaptor_version,
                        pkg_version['version'] + '-' + pkg_version['release'],
                        vm_service.node.hostname,
                        vm_service.instance_name))

            if vm_service.node not in nodes:
                replace_list = [(CALL_TYPE_REMOVE_ADAPTOR,
                                 CALL_ID_REMOVE_ADAPTOR.format(
                                     node=vm_service.node.item_id))]
                task = ConfigTask(
                    vm_service.node,
                    vm_service.install_task_item,
                    task_description,
                    call_type=CALL_TYPE_INSTALL_ADAPTOR,
                    call_id=CALL_ID_INSTALL_ADAPTOR.format(
                        node=vm_service.node.item_id),
                    version=(
                        pkg_version['version']
                        + '-' + pkg_version['release']))
                task.replaces.update(replace_list)
                tasks.append(task)
                nodes.append(vm_service.node)

        return tasks

    def get_service_deconfigure_task(self, service):
        log.trace.info('Create task to deconfigure vm-service "{0}" '
                       'on node "{1}"'.format(service.instance_name,
                                              service.node.hostname))

        task = self._deconfigure_task(
            service.node,
            service.vm_task_item,
            service.instance_name)
        return task

    def get_copy_image_task(self, service, requires):
        log.trace.info('Ensure that image "{0}" with checksum "{1}" is used'
            ' for vm-service "{2}" on node "{3}"'.format(service.image_name,
            service.image_checksum, service.instance_name,
            service.node.hostname))

        task = self._copy_file_task(
            service.node,
            service.vm_task_item,
            service.image_uri,
            constants.IMAGE_PATH,
            service.image_name,
            service.instance_name,
            service.image_checksum,
            service.state)
        if service._clustered_service:
            task.model_items.add(service._clustered_service)
        task.requires.update(requires)
        return task

    def get_write_adaptor_task(self, service, requires):
        task = self._write_file_task(
            service.node, service.vm_task_item,
            ('Copy VM config file to node "{0}" for instance "{1}" as part '
             'of VM {2}'.format(
                 service.node.hostname,
                 service.instance_name,
                 service.state)),
            service.adaptor_data(),
            service.base_path,
            service.adaptor_data_file_name,
            unique='config',
            instance_name=service.instance_name)
        replace_list = [(CALL_TYPE_DECONFIGURE,
                         CALL_ID_DECONFIGURE.format(
                             hostname=service.node.hostname,
                             instance_name=service.instance_name))]
        task.replaces.update(replace_list)
        task.requires.update(requires)
        task.model_items.update(service.config_model_items())
        if service._clustered_service:
            task.model_items.add(service._clustered_service)
        return task

    def get_write_metadata_task(self, service, api, requires):
        task = self._write_file_task(
            service.node, service.vm_task_item,
            ('Copy VM cloud init metadata file to node "{0}" for instance '
                '"{1}" as part of VM {2}'.format(
                    service.node.hostname,
                    service.instance_name,
                    service.state)),
            service.metadata(api),
            service.base_path,
            service.metadata_file_name,
            unique='metadata',
            instance_name=service.instance_name)
        task.requires.update(requires)
        for redeploy_item in service.get_updated_interfaces():
            task.model_items.add(redeploy_item)
        if service._clustered_service:
            task.model_items.add(service._clustered_service)
        return task

    def get_write_networkconfig_task(self, service, api, requires):
        task = self._write_file_task(
            service.node, service.vm_task_item,
            ('Copy VM cloud init networkconfig file to node "{0}" '
                'for instance "{1}" as part of VM {2}'.format(
                    service.node.hostname,
                    service.instance_name,
                    service.state)),
            service.networkconfig(api),
            service.base_path,
            service.networkconfig_file_name,
            unique='networkconfig',
            instance_name=service.instance_name)
        task.requires.update(requires)
        for redeploy_item in service.get_updated_interfaces():
            task.model_items.add(redeploy_item)
        if service._clustered_service:
            task.model_items.add(service._clustered_service)
        return task

    def get_write_userdata_task(self, service, requires):
        task = self._write_file_task(
            service.node, service.vm_task_item,
            ('Copy VM cloud init userdata file to node "{0}" for instance '
                '"{1}" as part of VM {2}'.format(
                    service.node.hostname,
                    service.instance_name,
                    service.state)),
            service.userdata,
            service.base_path,
            service.userdata_file_name,
            unique='userdata',
            instance_name=service.instance_name)
        task.requires.update(requires)
        redeploy_items = utils.model_items_for_redeploy(
            service.userdata_model_items())
        for redeploy_item in redeploy_items:
            task.model_items.add(redeploy_item)
        if service._clustered_service:
            task.model_items.add(service._clustered_service)
        return task

    def _write_file_task(self, node, task_item, description, content,
                         target_path, file_name, unique, instance_name):
        """
        Return a Configtask for writing a file on the node.

        `unique` argument is required for ensuring the `unique_id`
        attribute of `ConfigTask` is actually unique if this task
        is used multiple times in the same plan.
        """
        log.trace.debug('Copying file "%s" to node "%s" for instance "%s"' % (
            file_name, node.hostname, instance_name))
        return ConfigTask(
            node,
            task_item,
            description,
            call_type=CALL_TYPE_WRITE_FILE,
            call_id=CALL_ID_WRITE_FILE.format(hostname=node.hostname,
                                              unique=unique,
                                              instance_name=instance_name),
            content=content,
            target_path=target_path,
            file_name=file_name)

    def get_update_task(self, service, requires):
        task = CallbackTask(service.vm_task_item,
                            'Restart service "{0}" on node '
                            '"{1}"'.format(service.instance_name,
                                           service.node.hostname),
                            self.cb_restart_vm_service,
                            service.node.hostname,
                            service.get_vpath())
        task.requires.update(requires)

        items = service.get_service_task_items(service)
        for item in items:
            task.model_items.add(item)
        return task

    def cb_restart_vm_service(self, callback_api, hostname, service_vpath):
        service = callback_api.query_by_vpath(service_vpath)
        api = LibvirtMcoClient(hostname)
        api.restart(service.service_name, service.start_command,
                    service.stop_command)

    def get_ms_os_version(self):
        fn = '/etc/redhat-release'
        with open(fn, 'r') as f:
            redhat_release = f.readlines()
        return "rhel{0}".format(redhat_release[0].split('release')[1].split(
            '.')[0].strip(' '))

    def _copy_file_task(self, node, task_item, source_uri, target_path,
                        file_name, instance_name, image_checksum,
                        service_state):
        log.trace.debug("Added task for new 'vm-service' %s on node: '%s'"
            % (instance_name, node.hostname))
        return ConfigTask(
            node,
            task_item,
            ('Copy VM image file "{0}" to node "{1}" for instance "{2}"'
             ' as part of VM {3}'.format(file_name, node.hostname,
                           instance_name, service_state)),
            call_type=CALL_TYPE_COPY_FILE,
            call_id=CALL_ID_COPY_FILE.format(hostname=node.hostname,
                                             instance_name=instance_name),
            source_file_path=source_uri,
            target_path=target_path,
            file_name=file_name,
            instance_name=instance_name,
            latest_checksum=image_checksum,
            base_os=node.os.version if not node.is_ms() else
                        self.get_ms_os_version()
        )

    def _deconfigure_task(self, node, task_item, instance_name):
        replace_list = [(CALL_TYPE_COPY_FILE,
                         CALL_ID_COPY_FILE.format(
                             hostname=node.hostname,
                             instance_name=instance_name))]
        for unique in ["config", "metadata", "userdata", "networkconfig"]:
            replace_list.append((CALL_TYPE_WRITE_FILE,
                                 CALL_ID_WRITE_FILE.format(
                                     hostname=node.hostname,
                                     unique=unique,
                                     instance_name=instance_name)))

        task = ConfigTask(
            node,
            task_item,
            ('Remove instance directory for instance "{0}" on '
             'node "{1}"'.format(instance_name, node.hostname)),
            call_type=CALL_TYPE_DECONFIGURE,
            call_id=CALL_ID_DECONFIGURE.format(hostname=node.hostname,
                                               instance_name=instance_name),
            instance_name=instance_name,
            base_os=node.os.version if not node.is_ms() else
                       self.get_ms_os_version()
        )
        task.replaces.update(replace_list)
        return task

    def _add_new_system_tasks(self, ms, nodes,  tasks):
        # add puppet tasks for all added libvirt-system
        log.trace.debug("Added tasks for new 'libvirt-system' items: '%s'" % \
                        str(nodes))
        tasks.extend([self._new_system_task(ms, node)
                          for node in nodes])

    def _new_system_task(self, ms, node):
        return ConfigTask(
                    ms, node.system,
                    'Create VM "%s"' % node.system.system_name,
                    "koan::config",
                    node.system.system_name,
                    **(self._get_values(ms, node)))

    def _get_values(self, ms, node):
        values = {}
        values['bridge'] = ms.libvirt.bridge
        values['cobbler_server'] = ms.query('bridge',
            device_name=ms.libvirt.bridge)[0].ipaddress
        values['path'] = node.system.path
        values['system_name'] = node.system.system_name
        values['cobbler_system'] = node.hostname
        return values

    def _add_removal_system_tasks(self, ms, nodes, tasks):
        # add puppet tasks for all for removal libvirt-system
        log.trace.debug("Added tasks for removal of 'libvirt-system' " + \
                        "items: '%s'" % str(nodes))
        tasks.extend([self._remove_system_task(ms, node.system)
                          for node in nodes])

    def _remove_system_task(self, ms, system):
        return ConfigTask(ms, system,
                    'Delete VM "%s"' % system.system_name,
                    "koan::remove",
                    system.system_name,
                    **(self._get_removal_values(system)))

    def _get_removal_values(self, item):
        values = {}
        values['system_name'] = item.system_name
        values['path'] = item.path
        return values

    def _get_litpmn_package_version(self):
        """
        Get the latest version of the package "ERIClitpmnlibvirt_CXP9031529"
        or None if it is not found
        :return: Version of the package or None
        :rtype: str or None
        """

        pkg_version = utils.get_litp_package_version(constants.LITP_ADAPTOR)
        if pkg_version is None:
            log.event.error("Could not find package %s in the YUM "
                            "repositories" % constants.LITP_ADAPTOR)
        return pkg_version

    def _validate_no_duplicate_rule_numbers(self, vm_fw_rules, provider):
        """
        Validate the rule number part of each of the firewall rule names
        in a service is unique for a given provider, iptables or ip6tables
        """
        errors = []
        err_message = "Rule number must be unique. '{0}' is already in use."

        rule_nums = [rule.name.split()[0] for rule in vm_fw_rules
                                            if provider == rule.provider]

        duplicate_rule_nums = list(set([num for num in rule_nums
                                            if rule_nums.count(num) > 1]))

        if duplicate_rule_nums:
            for rule in vm_fw_rules:
                rule_num = rule.name.split()[0]
                if rule_num in duplicate_rule_nums and not rule.is_applied():
                    errors.append(ValidationError(item_path=rule.vpath,
                            error_message=err_message.format(rule_num)))
        return errors
