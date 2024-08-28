import json
import textwrap
import unittest

import mock
import yaml
from libvirt_extension.libvirt_extension import LibvirtExtension
from litp.core.execution_manager import (ExecutionManager, ConfigTask,
                                         CallbackTask)
from litp.core.model_item import ModelItem
from litp.core.model_manager import ModelManager
from litp.core.model_type import Child, Collection, ItemType
from litp.core.plugin_context_api import PluginApiContext
from litp.core.plugin_manager import PluginManager
from litp.core.puppet_manager import PuppetManager
from litp.core.validators import ValidationError
from litp.extensions.core_extension import CoreExtension
from network_extension.network_extension import NetworkExtension
from yum_extension.yum_extension import YumExtension

from libvirt_plugin import constants
from libvirt_plugin import exception
from libvirt_plugin.libvirt_plugin import (LibvirtPlugin, VMServiceFacade,
                                           CALL_ID_COPY_FILE,
                                           CALL_ID_WRITE_FILE,
                                           CALL_TYPE_COPY_FILE,
                                           CALL_TYPE_WRITE_FILE,
                                           ERROR_MSG_INVALID_HOSTNAME)
#from nose.tools import nottest


def _mock_vm(name, url, vpath):
    """
    Helper function for creating mock vm-service items.
    """
    vm_item = mock.Mock(source_url=url, get_vpath=lambda: vpath)
    vm_item.name = name
    return vm_item

def _mock_vm_interface_query(a, mac="{}", cluster_standby='1', **kwargs):
    if a == 'network':
        network = mock.MagicMock()
        network.subnet = "10.10.11.0/24"
        return [network]
    elif a == 'vm-network-interface':
        vm_interface = mock.MagicMock()
        vm_interface.node_mac_address_map = mac
        vm_interface.device_name = 'eth0'
        return [vm_interface]

def _build_mock_network(name='mgmt', subnet='10.10.10.0/24'):
    network = mock.Mock()
    network.name = name
    network.subnet = subnet
    network.litp_management = "true" if name=="mgmt" else "false"
    network.is_for_removal = mock.Mock(return_value=False)
    network.is_removed = mock.Mock(return_value=False)
    network.applied_properties = {'name' : network.name,
                                  'subnet' : network.subnet,
                                  'litp_management' : network.litp_management}
    return network

class TestLibvirtValidation(unittest.TestCase):
    def setUp(self):
        self.plugin = LibvirtPlugin()
        self.m1 = mock.Mock(attr=1, item_type_id='mock',
                            get_vpath=lambda: 'vpath1')
        self.m2 = mock.Mock(attr=2, item_type_id='mock',
                            get_vpath=lambda: 'vpath2')
        self.m3 = mock.Mock(attr=3, item_type_id='mock',
                            get_vpath=lambda: 'vpath3')
        self.m4 = mock.Mock(attr=3, item_type_id='mock',
                            get_vpath=lambda: 'vpath4')

        self.api = mock.Mock()
        self.plugin = LibvirtPlugin()
        # Some mock VM items defined here to help reduce
        # clutter in tests.
        self.vm_1 = _mock_vm('vm1_name', 'vm1_path', 'vm1_vpath')
        self.vm_2 = _mock_vm('vm2_name', 'vm2_path', 'vm2_vpath')
        self.vm_dupe = _mock_vm('vm1_name', 'vm1_path', 'dupe_vpath')
        self.networks = [ _build_mock_network() ]

    def test_validate_images_for_removal_image_for_remove(self):
        vm_service = mock.Mock(
            is_for_removal=lambda: False,
            get_vpath=lambda: 'service_vpath1')
        vm_image = mock.Mock(
            is_for_removal=lambda: True,
            get_vpath=lambda: 'image_vpath1')
        api = mock.Mock(query=mock.Mock(return_value=[vm_image]))
        # pylint: disable=protected-access
        errors = self.plugin._validate_images_for_removal(
            [vm_service], api)
        self.assertEqual(1, len(errors))
        error = errors[0]
        self.assertEqual('image_vpath1', error.item_path)
        self.assertEqual(
            'Can not remove "vm-image" "image_vpath1" as it is in use by '
            '"vm-service" "service_vpath1"',
            error.error_message)

    def test_validate_images_for_removal_service_for_removal(self):
        vm_service = mock.Mock(
            is_for_removal=lambda: True,
            get_vpath=lambda: 'service_vpath2')
        vm_image = mock.Mock(
            is_for_removal=lambda: False,
            get_vpath=lambda: 'image_vpath2')
        api = mock.Mock(query=mock.Mock(return_value=[vm_image]))
        # pylint: disable=protected-access
        errors = self.plugin._validate_images_for_removal(
            [vm_service], api)
        self.assertEqual(0, len(errors))

    def test_validate_images_for_removal_service_image_for_removal(self):
        vm_service = mock.Mock(
            is_for_removal=lambda: True,
            get_vpath=lambda: 'service_vpath3')
        vm_image = mock.Mock(
            is_for_removal=lambda: True,
            get_vpath=lambda: 'image_vpath3')
        api = mock.Mock(query=mock.Mock(return_value=[vm_image]))
        # pylint: disable=protected-access
        errors = self.plugin._validate_images_for_removal(
            [vm_service], api)
        self.assertEqual(0, len(errors))

    def test_validate_images_for_removal_no_image(self):
        vm_service = mock.Mock(
            is_for_removal=lambda: True,
            get_vpath=lambda: 'service_vpath4')
        api = mock.Mock(query=mock.Mock(return_value=[]))
        # pylint: disable=protected-access
        errors = self.plugin._validate_images_for_removal(
            [vm_service], api)
        self.assertEqual(0, len(errors))

    def test_validate_images_for_removal_two_images(self):
        vm_service = mock.Mock(
            is_for_removal=lambda: False,
            get_vpath=lambda: 'service_vpath5a')
        vm_service2 = mock.Mock(
            is_for_removal=lambda: True,
            get_vpath=lambda: 'service_vpath5b')
        vm_image = mock.Mock(
            is_for_removal=lambda: True,
            get_vpath=lambda: 'image_vpath5')
        api = mock.Mock(query=mock.Mock(return_value=[vm_image]))
        # pylint: disable=protected-access
        errors = self.plugin._validate_images_for_removal(
            [vm_service, vm_service2], api)
        self.assertEqual(1, len(errors))
        error = errors[0]
        self.assertEqual('image_vpath5', error.item_path)
        self.assertEqual(
            'Can not remove "vm-image" "image_vpath5" as it is in use by '
            '"vm-service" "service_vpath5a"',
            error.error_message)

    def test_validate_service_names(self):
        invalid = [
            mock.Mock(service_name='-', vpath='vpath'),
            mock.Mock(service_name='1', vpath='vpath'),
            mock.Mock(service_name='-a', vpath='vpath'),
            mock.Mock(service_name='1a', vpath='vpath'),
            mock.Mock(service_name='-0', vpath='vpath'),
            mock.Mock(service_name='--', vpath='vpath'),
            mock.Mock(service_name='0-', vpath='vpath'),
            mock.Mock(service_name='a0-', vpath='vpath')]
        self.assertEqual(
            len(invalid),
            len(self.plugin.validate_service_names(invalid)))
        valid = [
            mock.Mock(service_name='a9-s', vpath='vpath'),
            mock.Mock(service_name='a91', vpath='vpath'),
            mock.Mock(service_name='a9-a', vpath='vpath'),
            mock.Mock(service_name='a91a', vpath='vpath'),
            mock.Mock(service_name='a9-0', vpath='vpath'),
            mock.Mock(service_name='a9--s', vpath='vpath'),
            mock.Mock(service_name='a90-s', vpath='vpath')]
        self.assertEqual(
            0,
            len(self.plugin.validate_service_names(valid)))

    def test_items_with_duplicate_property_no_duplicates(self):
        self.assertEqual(
            [],
            self.plugin._items_with_duplicate_property(
                (self.m1, self.m2, self.m3), 'attr'))

    def test_items_with_duplicate_property_duplicates(self):
        self.assertEqual(
            sorted([self.m3, self.m4]),
            self.plugin._items_with_duplicate_property(
                (self.m1, self.m2, self.m3, self.m4), 'attr'))
        new_m = mock.Mock(attr=1)
        self.assertEqual(
            sorted([self.m1, self.m3, self.m4, new_m]),
            self.plugin._items_with_duplicate_property(
                (self.m1, self.m2, self.m3, self.m4, new_m), 'attr'))

    def test_validate_unique_property_no_dupes(self):
        errors = self.plugin._validate_unique_property([
            self.m1, self.m2, self.m3], 'attr')
        self.assertEqual([], errors)

    def test_validate_unique_property_with_dupes(self):
        errors = self.plugin._validate_unique_property([
            self.m1, self.m2, self.m3, self.m3], 'attr')
        for error in errors:
            self.assertTrue(isinstance(error, ValidationError))
            self.assertTrue(
                error.error_message == '"mock" "attr" property is not unique')
            self.assertTrue(error.item_path in ('vpath3', 'vpath4'))
            self.assertFalse('vpath1' == error.item_path)
            self.assertFalse('vpath2' == error.item_path)

    def test_get_alias(self):
        vm_service = mock.Mock()
        alias = mock.Mock()
        alias.alias_names = "alias,alias2"
        alias.is_for_removal.return_value = False
        vm_service.query.return_value = [alias]
        ms_ips = ['10.10.10.100']
        self.assertEqual(set(['alias', 'alias2']),
                         self.plugin.get_aliases(vm_service, ms_ips))

    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_base_url")
    def test_validate_vm_image_base_ms_have_error(self, get_base_url):
        vm_image = mock.Mock()
        vm_images = [vm_image]
        ms_ips = ['10.10.10.100']
        ms_hostname = "my_host"
        get_base_url.return_value = "unknow_host"

        error =  self.plugin._validate_vm_image_base_ms(
            vm_images, ms_ips + [ms_hostname] + ["my_alias"])[0]
        self.assertEqual(ERROR_MSG_INVALID_HOSTNAME.format(get_base_url.return_value),
                         error.error_message)

    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_base_url")
    def test_validate_vm_image_base_ms_have_no_error(self, get_base_url):
        vm_image = mock.Mock()
        vm_images = [vm_image]
        ms_ips = ['10.10.10.100']
        ms_hostname = "my_host"
        get_base_url.return_value = "my_alias"

        errors =  self.plugin._validate_vm_image_base_ms(
            vm_images, ms_ips + [ms_hostname] + ["my_alias"])
        self.assertEqual([], errors)

    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_aliases")
    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_base_url")
    def test_validate_vm_repos_base_ms_have_error(self, get_base_url, get_aliases):
        vm_service = mock.Mock()
        vm_services = [vm_service]
        repo = mock.Mock()
        repo.name = "my_repo"
        repo.is_for_removal.return_value = False
        vm_service.query.return_value = [repo]

        ms_ips = ['10.10.10.100']
        get_aliases.return_value = ["msx"]
        get_base_url.return_value = "msy"

        error =  self.plugin._validate_vm_repos_base_ms(vm_services, ms_ips)[0]
        self.assertTrue('check the vm-alias/IPs' in error.error_message)

    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_aliases")
    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_base_url")
    def test_validate_vm_repos_base_ms_no_error(self, get_base_url, get_aliases):
        vm_service = mock.Mock()
        vm_services = [vm_service]
        repo = mock.Mock()
        repo.name = "my_repo"
        vm_service.query.return_value = [repo]

        ms_ips = ['10.10.10.100']
        get_aliases.return_value = ["msx"]
        get_base_url.return_value = "msx"

        self.assertEqual([],
                       self.plugin._validate_vm_repos_base_ms(
                           vm_services, ms_ips))

    def test_validate_initial_ssh_key_non_empty(self):
        ssh_key1 = mock.Mock(ssh_key="ssh-rsa AAAAB3NzaC1yc2EA root@rh6-ms1")
        ssh_key1.is_initial.return_value = True
        ssh_key2 = mock.Mock(ssh_key="")
        ssh_key2.is_initial.return_value = False

        vm_ssh_keys = [ssh_key1, ssh_key2]
        errors =  self.plugin._validate_initial_ssh_key_non_empty(vm_ssh_keys)
        self.assertEqual([], errors)

    def test_validate_initial_ssh_key_empty(self):
        ssh_key1 = mock.Mock(ssh_key="")
        ssh_key1.is_initial.return_value = True
        ssh_key2 = mock.Mock(ssh_key=None)
        ssh_key2.is_initial.return_value = True

        vm_ssh_keys = [ssh_key1, ssh_key2]
        errors =  self.plugin._validate_initial_ssh_key_non_empty(vm_ssh_keys)
        self.assertEqual(2, len(errors))

    @mock.patch('libvirt_plugin.utils.exist_image_file')
    def test_validate_image_file_exist_no_error(self, exist_img_file):
        vm_images = [mock.Mock(), mock.Mock()]
        vm_images[0].source_uri = "http://ms1/images/fmmed-1.0.1.qcow2"
        vm_images[1].source_uri = "http://ms1/images/fmmed-1.0.2.qcow2"
        exist_img_file.return_value = True
        self.assertEqual([],
                        self.plugin._validate_image_file_exist(vm_images))

    @mock.patch('libvirt_plugin.utils.exist_image_file')
    def test_validate_image_file_exist_errors(self, exist_img_file):
        def exist_img_file_side_effect(source_uri):
            if source_uri == "http://ms1/images/fmmed-1.0.1.qcow2":
                return True
            if source_uri == "http://ms1/images/fmmed-1.0.2.qcow2":
                return False

        vm_images = [mock.Mock(), mock.Mock()]
        vm_images[0].source_uri = "http://ms1/images/fmmed-1.0.1.qcow2"
        vm_images[1].source_uri = "http://ms1/images/fmmed-1.0.2.qcow2"
        exist_img_file.side_effect = exist_img_file_side_effect

        errors = self.plugin._validate_image_file_exist(vm_images)
        self.assertEqual(1, len(errors))
        self.assertEqual(("image file /var/www/html/images/fmmed-1.0.2.qcow2"
                          " does not exist"),
                         errors[0].error_message)

    def test_validate_service_image_exists(self):
        self.api.query.return_value = [mock.Mock()]
        vm_services = [self.vm_1, self.vm_2]
        self.assertEqual(
            [], self.plugin._validate_service_image_exists(
                vm_services, self.api))

    def test_validate_service_no_image_exists(self):
        self.api.query.return_value = []
        vm_services = [self.vm_1, self.vm_2]
        self.assertEqual(
            2, len(self.plugin._validate_service_image_exists(
                vm_services, self.api)))
        vm_services = [self.vm_2]
        self.assertEqual(
            1, len(self.plugin._validate_service_image_exists(
                vm_services, self.api)))
        vm_services = []
        self.assertEqual(
            [], self.plugin._validate_service_image_exists(
                vm_services, self.api))

    #NETWORK
    def test_validate_ipaddress_count(self):
        c_service = mock.Mock(active='2', standby='0')
        #second query returns a interface
        vm_interface = mock.Mock(ipaddresses='val1,val2', ipv6addresses=None,
                                 get_vpath=lambda: 'vm_iface_vpath')
        vm_interface.is_for_removal.return_value = False
        c_service.query.return_value = [vm_interface]
        # first query returns a c_service
        self.api.query.return_value = [c_service]
        errors = self.plugin._validate_ipaddress_count(self.api)
        self.assertEqual(len(errors), 0)

        # negative ipv4
        c_service.active = '1'
        errors = self.plugin._validate_ipaddress_count(self.api)
        err_msg = ('The IPv4 address list count of "2" does not match the '
                   'number of active instances which is "1"')
        expected = ValidationError(item_path="vm_iface_vpath",
                                   error_message=err_msg)
        self.assertEqual(errors[0], expected)
        self.assertEqual(1, len(errors))

        # ipv6addresses
        c_service.active = '2'
        vm_interface = mock.Mock(ipaddresses=None, ipv6addresses='val1,val2',
                                 get_vpath=lambda: 'vm_iface_vpath')
        vm_interface.is_for_removal.return_value = False
        c_service.query.return_value = [vm_interface]
        errors = self.plugin._validate_ipaddress_count(self.api)
        self.assertEqual(0, len(errors))

        # negative ipv6
        c_service.active = '1'
        errors = self.plugin._validate_ipaddress_count(self.api)
        err_msg = ('The IPv6 address list count of "2" does not match the '
                   'number of active instances which is "1"')
        expected = ValidationError(item_path="vm_iface_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[0])
        self.assertEqual(1, len(errors))

        # "dhcp" is the value for ipaddresses
        vm_interface = mock.Mock(ipaddresses='dhcp', ipv6addresses=None,
                                 get_vpath=lambda: 'vm_iface_vpath')
        vm_interface.is_for_removal.return_value = False
        c_service.active = '2'
        c_service.query.return_value = [vm_interface]
        errors = self.plugin._validate_ipaddress_count(self.api)
        self.assertEqual(0, len(errors))

        # No ipaddresses or ipv6addresses
        vm_interface = mock.Mock(ipaddresses=None, ipv6addresses=None,
                                 get_vpath=lambda: 'vm_iface_vpath')
        vm_interface.is_for_removal.return_value = False
        c_service.active = '2'
        c_service.query.return_value = [vm_interface]
        errors = self.plugin._validate_ipaddress_count(self.api)
        err_msg = ('There are no IP addresses defined. The number of IP '
                   'addresses should match the number of active instances '
                   'which is "2"')
        expected = ValidationError(item_path="vm_iface_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[0])
        self.assertEqual(1, len(errors))

    def test_validate_gateway_matches_ipaddresses(self):
        # ipv4 addresses and ipv4 gateway
        vm_interfaces = [mock.Mock(ipaddresses='ip1,ip2', ipv6addresses=None,
                                   gateway='gway', gateway6=None)]
        errors = self.plugin._validate_gateway_matches_ipaddresses(
                                                                vm_interfaces)
        self.assertEqual(0, len(errors))

        # ipv4 addresses and ipv6 gateway
        vm_interfaces = [mock.Mock(ipaddresses='ip1,ip2', ipv6addresses=None,
                                   gateway=None, gateway6='gway',
                                   get_vpath=lambda: 'vm_iface_vpath')]
        errors = self.plugin._validate_gateway_matches_ipaddresses(
                                                                vm_interfaces)
        err_msg = ('The gateway6 property is defined without the ipv6addresses'
                   ' property being defined.')
        expected = ValidationError(item_path="vm_iface_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[0])
        self.assertEqual(1, len(errors))

        # ipv6 addresses and ipv6 gateway
        vm_interfaces = [mock.Mock(ipaddresses=None, ipv6addresses='ip1,ip2',
                                   gateway=None, gateway6='gway')]
        errors = self.plugin._validate_gateway_matches_ipaddresses(
                                                                vm_interfaces)
        self.assertEqual(0, len(errors))

        # ipv6 addresses and ipv4 gateway
        vm_interfaces = [mock.Mock(ipaddresses=None, ipv6addresses='ip1,ip2',
                                   gateway='gway', gateway6=None,
                                   get_vpath=lambda: 'vm_iface_vpath')]
        errors = self.plugin._validate_gateway_matches_ipaddresses(
                                                                vm_interfaces)
        err_msg = ('The gateway property is defined without the ipaddresses '
                   'property being defined.')
        expected = ValidationError(item_path="vm_iface_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[0])
        self.assertEqual(1, len(errors))

    def test_validate_ipaddress_on_network(self):
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.ipaddresses = '10.10.10.1,10.10.10.2'
        vm_iface1.gateway = '10.10.10.11'
        vm_interfaces = [vm_iface1]
        #self.plugin.vm_address_in_subnet = mock.Mock()
        net = mock.Mock()
        net.subnet = '10.10.10.0/24'
        net.name = 'net1'
        self.api.query.return_value = [net]
        errors = self.plugin._validate_ipaddress_on_network(vm_interfaces,
                                                                self.api)
        self.assertEqual(len(errors), 0)

        #negative 1
        net.subnet = '10.11.11.0/24'
        errors = self.plugin._validate_ipaddress_on_network(vm_interfaces,
                                                                self.api)
        err_msg = 'IP address "10.10.10.1" not contained in the subnet of network'
        self.assert_(len(errors) == 3 and err_msg in str(errors[0]))

        # negative 2
        self.api.query.return_value = []
        errors = self.plugin._validate_ipaddress_on_network(vm_interfaces,
                                                                self.api)
        err_msg = 'Network "net1" does not exist in the model'
        self.assert_(len(errors) == 1 and err_msg in str(errors[0]))

    def test_validate_dhcp_interface_in_mgmt_network_fail(self):
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'mgmt'
        vm_iface1.ipaddresses = 'dhcp'

        vm_iface2 = mock.Mock()
        vm_iface2.item_id = 'id1'
        vm_iface2.network_name = 'net1'
        vm_iface2.ipaddresses = 'dhcp'

        vm_interfaces = [vm_iface1, vm_iface2]

        mgmt_network = mock.Mock()
        mgmt_network.name="mgmt"
        mgmt_network.litp_management='true'
        mgmt_network.is_for_removal.return_value = False
        mgmt_network.is_removed.return_value = False
        plugin_context = mock.MagicMock()
        plugin_context.query.return_value  = [mgmt_network]


        errors = self.plugin._validate_no_dhcp_in_mgmt_netwoks(plugin_context,
                                                               vm_interfaces)
        self.assertEqual(1, len(errors))

    def test_validate_dhcp_interface_in_non_mgmt_network_pass(self):
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.ipaddresses = 'dhcp'

        vm_iface2 = mock.Mock()
        vm_iface2.item_id = 'id1'
        vm_iface2.network_name = 'mgmt'
        vm_iface2.ipaddresses = '10.10.10.12'

        vm_interfaces = [vm_iface1, vm_iface2]

        mgmt_network = mock.Mock()
        mgmt_network.name="mgmt"
        mgmt_network.litp_management='true'
        mgmt_network.is_for_removal.return_value = False
        mgmt_network.is_removed.return_value = False
        plugin_context = mock.MagicMock()
        plugin_context.query.return_value  = [mgmt_network]


        errors = self.plugin._validate_no_dhcp_in_mgmt_netwoks(plugin_context,
                                                               vm_interfaces)
        self.assertEqual(len(errors), 0)

    def test_validate_internal_status_check_accessible_pass(self):
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.ipaddresses = 'dhcp'
        vm_iface1.is_for_removal.return_value=False

        vm_iface2 = mock.Mock()
        vm_iface2.item_id = 'id1'
        vm_iface2.network_name = 'mgmt'
        vm_iface2.ipaddresses = '10.10.10.12'
        vm_iface2.is_for_removal.return_value=False

        vm_service = mock.Mock()
        vm_service.internal_status_check = "on"
        vm_service.vm_network_interfaces = [vm_iface1, vm_iface2]


        error = self.plugin._validate_internal_status_check_accessible(
                                                                    vm_service)

        self.assertTrue(error == [])

    def test_validate_internal_status_check_accessible_fail(self):
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.ipaddresses = 'dhcp'

        vm_iface2 = mock.Mock()
        vm_iface2.item_id = 'id1'
        vm_iface2.network_name = 'mgmt'
        vm_iface2.ipaddresses = 'dhcp'

        vm_service = mock.Mock()
        vm_service.internal_status_check = "on"
        vm_service.vm_network_interfaces = [vm_iface1, vm_iface2]


        errors = self.plugin._validate_internal_status_check_accessible(
                                                                    vm_service)
        self.assertTrue(len(errors) == 1)
        self.assertTrue(isinstance(errors[0], ValidationError))

    def test_validate_sequential_device_names(self):
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.device_name = "eth0"
        vm_iface1.is_for_removal.return_value = False
        vm_iface2 = mock.Mock()
        vm_iface2.item_id = 'id2'
        vm_iface2.network_name = 'net1'
        vm_iface2.device_name = "eth1"
        vm_iface2.is_for_removal.return_value = False
        vm_service = mock.Mock()
        ifaces_collection = mock.Mock()
        ifaces_collection.get_vpath.return_value = '/test/vpath'
        ifaces_collection.__iter__ = mock.Mock(return_value=iter([vm_iface1,
                                                                  vm_iface2]))
        vm_service.vm_network_interfaces = ifaces_collection
        self.assertFalse(self.plugin._validate_sequential_device_names(vm_service))
        vm_ifaces = []
        for x in range(0, 13):
            vm_ifaces.append(mock.Mock(item_id = 'id1', network_name = 'net1',
        device_name = "eth%s" % x))
        ifaces_collection.__iter__ =  mock.Mock(return_value=iter(vm_ifaces))
        self.assertFalse(self.plugin._validate_sequential_device_names(vm_service))

    def test_validate_sequential_device_names_with_device_for_removal(self):
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.device_name = "eth0"
        vm_iface1.is_for_removal.return_value = True
        vm_iface2 = mock.Mock()
        vm_iface2.item_id = 'id2'
        vm_iface2.network_name = 'net1'
        vm_iface2.device_name = "eth1"
        vm_iface2.is_for_removal.return_value = False
        vm_service = mock.Mock()
        ifaces_collection = mock.Mock()
        ifaces_collection.get_vpath.return_value = '/test/vpath'
        ifaces_collection.__iter__ = mock.Mock(return_value=iter([vm_iface1,
                                                                  vm_iface2]))
        vm_service.vm_network_interfaces = ifaces_collection
        errors = self.plugin._validate_sequential_device_names(vm_service)
        self.assertEquals(1, len(errors))
        self.assertEquals('/test/vpath', errors[0].item_path)
        self.assertEquals('Property "device_name" of all vm-network-interface items '
                          'must start from eth0 and be sequentially numbered',
                            errors[0].error_message)

    def test_validate_host_device_on_ms(self):
        ms1 = mock.Mock()
        ms1.hostname = "ms1"
        iface1 = mock.Mock()
        iface1.device_name = "br1"
        iface1.network_name = "net1"
        iface1.item_type_id = "bridge"
        ms1.network_interfaces = [iface1]
        ms1.item_id = 'ms1'
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.host_device = "br1"
        vm_iface1.device_name = "eth1"
        vm_iface1.is_for_removal.return_value = False
        vm_service = mock.Mock()
        vm_service.query.return_value = [vm_iface1]
        vm_service.is_for_removal.return_value = False
        ms1.query.return_value = [vm_service]

        def mock_query(item_type):
            if item_type == 'clustered-service':
                return []
            elif item_type == 'ms':
                return [ms1]
            else:
                self.fail('item_type "%s" unexpected in call api.query')

        self.api.query = mock_query
        errors = self.plugin._validate_host_device(self.api)

        self.assertEqual(len(errors), 0)
        iface1.device_name = "br0"
        errors = self.plugin._validate_host_device(self.api)
        err_msg = 'Host device "br1" does not exist on node "ms1"'
        self.assert_(len(errors) == 1 and err_msg in str(errors[0]))

        iface1.device_name = "br1"
        vm_iface1.network_name = 'net0'
        errors = self.plugin._validate_host_device(self.api)
        err_msg = ('Network name "net0" on vm-network-interface "eth1" does not '
                   'match network name "net1" of the device on node "ms1"')
        self.assert_(len(errors) == 1 and err_msg in str(errors[0]))

        iface1.device_name = "br1"
        vm_iface1.network_name = 'net1'
        iface1.item_type_id = "eth"
        errors = self.plugin._validate_host_device(self.api)
        err_msg = ('Host device "br1" on vm-network-interface "eth1"'
                                    ' must be of type "bridge"'
                                    ' not "eth"')
        self.assert_(len(errors) == 1 and err_msg in str(errors[0]))

    def test_validate_host_device(self):
        node1 = mock.Mock()
        node1.hostname = "mn1"
        iface1 = mock.Mock()
        iface1.device_name = "br1"
        iface1.network_name = "net1"
        iface1.item_type_id = "bridge"
        node1.network_interfaces = [iface1]
        node1.item_id = 'node1'
        c_service = mock.Mock()
        c_service.active = '2'
        c_service.standby = '0'
        c_service.nodes = [node1]
        vm_iface1 = mock.Mock()
        vm_iface1.item_id = 'id1'
        vm_iface1.network_name = 'net1'
        vm_iface1.host_device = "br1"
        vm_iface1.device_name = "eth1"
        vm_iface1.is_for_removal.return_value = False
        c_service.query.return_value = [vm_iface1]
        c_service.is_for_removal.return_value = False

        def mock_query(item_type):
            if item_type == 'clustered-service':
                return [c_service]
            elif item_type == 'ms':
                return []
            else:
                self.fail('item_type "%s" unexpected in call api.query')

        self.api.query = mock_query
        errors = self.plugin._validate_host_device(self.api)

        self.assertEqual(len(errors), 0)
        iface1.device_name = "br0"
        errors = self.plugin._validate_host_device(self.api)
        err_msg = 'Host device "br1" does not exist on node "mn1"'
        self.assert_(len(errors) == 1 and err_msg in str(errors[0]))

        iface1.device_name = "br1"
        vm_iface1.network_name = 'net0'
        errors = self.plugin._validate_host_device(self.api)
        err_msg = ('Network name "net0" on vm-network-interface "eth1" does not '
                   'match network name "net1" of the device on node "mn1"')
        self.assert_(len(errors) == 1 and err_msg in str(errors[0]))

        iface1.device_name = "br1"
        vm_iface1.network_name = 'net1'
        iface1.item_type_id = "eth"
        errors = self.plugin._validate_host_device(self.api)
        err_msg = ('Host device "br1" on vm-network-interface "eth1"'
                                    ' must be of type "bridge"'
                                    ' not "eth"')
        self.assert_(len(errors) == 1 and err_msg in str(errors[0]))

    def test_validate_no_duplicated_ipaddress(self):
        vm_iface1 = mock.Mock(item_id='id1',
                              network_name='net1',
                              host_device="br1",
                              ipaddresses='10.10.10.1,10.10.10.2',
                              ipv6addresses=None,
                              get_vpath=lambda: 'vm_iface1_vpath')
        errors = self.plugin._validate_no_duplicated_ipaddress([vm_iface1])
        self.assertEqual(0, len(errors))

        #negative IPv4
        vm_iface1.ipaddresses = '10.10.10.1, 10.10.10.2, 10.10.10.3'
        vm_iface2 = mock.Mock(item_id='id2',
                              network_name='net2',
                              host_device="br1",
                              ipaddresses='10.10.10.3,10.10.10.4',
                              ipv6addresses=None,
                              get_vpath=lambda: 'vm_iface2_vpath')
        errors = self.plugin._validate_no_duplicated_ipaddress([vm_iface1,
                                                                vm_iface2])
        err_msg = ('IP address "10.10.10.3" can only be used'
                   ' once in the vm-services.')
        expected = ValidationError(item_path="vm_iface2_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[0])

        err_msg = ('IP address "10.10.10.3" can only be used'
                   ' once in the vm-services.')
        expected = ValidationError(item_path="vm_iface1_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[1])
        self.assertEqual(2, len(errors))

        #negative IPv6
        vm_iface1.ipaddresses = None
        vm_iface1.ipv6addresses = ('2001:f0d0:1884:34c4::1,'
                                   '2001:f0d0:1884:34c4::2/64,'
                                   '2001:f0d0:1884:34c4::3/64')
        vm_iface2.ipaddresses = None
        vm_iface2.ipv6addresses = ('2001:f0d0:1884:34c4::1/64,'
                                   '2001:f0d0:1884:34c4::4/64')
        errors = self.plugin._validate_no_duplicated_ipaddress([vm_iface1,
                                                                vm_iface2])

        err_msg = ('IP address "2001:f0d0:1884:34c4::1" can only be used'
                   ' once in the vm-services.')
        expected = ValidationError(item_path="vm_iface2_vpath",
                                    error_message=err_msg)
        self.assertEqual(expected, errors[0])

        err_msg = ('IP address "2001:f0d0:1884:34c4::1" can only be used'
                   ' once in the vm-services.')
        expected = ValidationError(item_path="vm_iface1_vpath",
                                    error_message=err_msg)
        self.assertEqual(expected, errors[1])

        self.assertEqual(2, len(errors))

        #negative IPv6 duplciate on same interface
        vm_iface1.ipaddresses = None
        vm_iface1.ipv6addresses = ('2001:f0d0:1884:34c4::1,'
                                   '2001:f0d0:1884:34c4::1/64,'
                                   '2001:f0d0:1884:34c4::3/64')
        vm_iface2.ipaddresses = None
        vm_iface2.ipv6addresses = ('2001:f0d0:1884:34c4::2/64,'
                                   '2001:f0d0:1884:34c4::4/64')
        errors = self.plugin._validate_no_duplicated_ipaddress([vm_iface1,
                                                                vm_iface2])

        err_msg = ('IP address "2001:f0d0:1884:34c4::1" can only be used'
                   ' once in the vm-services.')
        expected = ValidationError(item_path="vm_iface1_vpath",
                                    error_message=err_msg)
        self.assertEqual(expected, errors[0])

        self.assertEqual(1, len(errors))

    def test_validate_no_duplicated_two_ipaddress(self):
        vm_iface1 = mock.Mock(item_id='id1',
                              network_name='net1',
                              host_device="br1",
                              ipaddresses='10.10.10.1,10.10.10.2',
                              ipv6addresses=None,
                              get_vpath=lambda: 'vm_iface1_vpath')
        errors = self.plugin._validate_no_duplicated_ipaddress([vm_iface1])
        self.assertEqual(0, len(errors))

        #negative IPv4
        vm_iface1.ipaddresses = '10.10.10.1, 10.10.10.2, 10.10.10.3'
        vm_iface2 = mock.Mock(item_id='id2',
                              network_name='net2',
                              host_device="br1",
                              ipaddresses='10.10.10.2,10.10.10.3',
                              ipv6addresses=None,
                              get_vpath=lambda: 'vm_iface2_vpath')
        errors = self.plugin._validate_no_duplicated_ipaddress([vm_iface1,
                                                                vm_iface2])
        err_msg = ('IP addresses "10.10.10.2" and "10.10.10.3" can only be '
                   'used once in the vm-services.')
        expected = ValidationError(item_path="vm_iface2_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[0])

        err_msg = ('IP addresses "10.10.10.2" and "10.10.10.3" can only be '
                   'used once in the vm-services.')
        expected = ValidationError(item_path="vm_iface1_vpath",
                                   error_message=err_msg)
        self.assertEqual(expected, errors[1])
        self.assertEqual(2, len(errors))

    def test_validate_service_unique_per_node_and_ms(self):
        mock_api = mock.Mock()
        vm_service1 = mock.Mock(service_name="fmmed")
        vm_service1.is_for_removal.return_value = False
        vm_service2 = mock.Mock(service_name="fmmed")
        vm_service2.is_for_removal.return_value = False
        vm_service3 = mock.Mock(service_name="fmmed")
        vm_service3.is_for_removal.return_value = False
        node = mock.Mock(hostname="mn1")
        node.get_vpath.return_value="/ms"
        node.query.return_value = [vm_service1]
        ms = mock.Mock(hostname="ms1")
        ms.get_vpath.return_value="/ms"
        ms.query.return_value = [vm_service2, vm_service3]
        mock_api.query.side_effect = [[node], [ms]]

    def test_trim_removed_vm_list_removes_overlapping_items(self):
        self.plugin._get_identifier = lambda x: (x[0], x[1])
        initial_list = [('vm1', 'mn1',
            '/deployments/d1/clusters/c1/services/cs2/applications/vm1'),
                        ('vm1', 'mn2',
            '/deployments/d1/clusters/c1/services/cs2/applications/vm1')]
        removal_list = [('vm1', 'mn1',
            '/deployments/d1/clusters/c1/services/cs1/applications/vm1'),
                ('vm2', 'mn1',
                    '/deployments/d1/clusters/c1/services/cs1/applications/vm2'),
                ('vm2', 'mn2',
                    '/deployments/d1/clusters/c1/services/cs1/applications/vm2')]
        trimmed_list = self.plugin._trim_removed_vm_list(initial_list,
                removal_list)
        self.assertEqual(2, len(trimmed_list))
        self.assertTrue(initial_list[0] not in trimmed_list)
        self.assertTrue(removal_list[0] not in trimmed_list)
        self.assertTrue(removal_list[1] in trimmed_list)
        self.assertTrue(removal_list[2] in trimmed_list)

    def test_trim_removed_vm_list_no_initial_list(self):
        self.plugin._get_identifier = lambda x: (x[0], x[1])
        initial_list = list()
        removal_list = [('vm1', 'mn1',
                    '/deployments/d1/clusters/c1/nodes/n1/services/vm1'),
                ('vm2', 'mn1',
                    '/deployments/d1/clusters/c1/services/cs1/applications/vm2'
                    ),
                ('vm2', 'mn2',
                    '/deployments/d1/clusters/c1/servides/cs1/applications/vm2'
                    )]
        trimmed_list = self.plugin._trim_removed_vm_list(initial_list,
                removal_list)
        self.assertEqual(3, len(trimmed_list))
        self.assertTrue(removal_list[0] in trimmed_list)
        self.assertTrue(removal_list[1] in trimmed_list)
        self.assertTrue(removal_list[2] in trimmed_list)

    def test_trim_removed_vm_list_no_removal_list(self):
        self.plugin._get_identifier = lambda x: (x[0], x[1])
        initial_list = [('vm1', 'mn1',
            '/deployments/d1/clusters/c1/services/cs1/applications/vm1'),
                        ('vm1', 'mn2',
            '/deployments/d1/clusters/c1/services/cs1/applications/vm1')]
        removal_list = list()
        trimmed_list = self.plugin._trim_removed_vm_list(initial_list,
                removal_list)
        self.assertEqual(0, len(trimmed_list))

    def test_get_identifier(self):
        facade_item = mock.Mock()
        facade_item._service.service_name = 'vm1'
        facade_item.node.hostname = 'mn1'

        self.assertEqual(('vm1', 'mn1'),
                         self.plugin._get_identifier(facade_item))

    def test_gather_repo_paths(self):
        # Mock _get_repo_dir
        self.plugin._get_repo_dir = lambda x: x
        vm_repos = [mock.Mock(base_url="url1", is_for_removal=(lambda: False)),
                    mock.Mock(base_url="url2", is_for_removal=(lambda: False)),
                    mock.Mock(base_url="url1", is_for_removal=(lambda: False)),
                    mock.Mock(base_url="url2", is_for_removal=(lambda: False)),
                    mock.Mock(base_url="url3", is_for_removal=(lambda: False)),
                    mock.Mock(base_url="remove_me",
                        is_for_removal=(lambda: True))]
        context_api = mock.Mock()
        context_api.query.return_value = vm_repos

        results = self.plugin._gather_repo_paths(context_api)
        self.assertEquals(sorted(list(results)), ['url1', 'url2', 'url3'])

    @mock.patch("libvirt_plugin.utils.get_names_of_pkgs_in_repo_by_path")
    def test_get_pkgs_per_repo(self, mock_pkgs_per_repo):
        paths = ['path1', 'path2', 'path3', 'path4', 'path5']
        repo_to_pkgs = {'path1': set(['finger', 'telnet']),
                        'path2': set(['fmmed', 'pmmed']),
                        'path3': set(['jboss', 'websphere'])}
        def checker(path):
            if path in repo_to_pkgs:
                return repo_to_pkgs[path]
            raise exception.LibvirtYumRepoException
        mock_pkgs_per_repo.side_effect = checker

        pkg_dict, bad_repo_paths  = self.plugin._get_pkgs_per_repo(paths)
        self.assertEqual(pkg_dict, {'path1': set(repo_to_pkgs['path1']),
                                    'path2': set(repo_to_pkgs['path2']),
                                    'path3': set(repo_to_pkgs['path3'])
                                    })
        self.assertEqual(bad_repo_paths, set(['path4', 'path5']))

    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin."
                "_get_repo_dir")
    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin."
                "_get_pkgs_per_repo")
    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin."
                "_gather_repo_paths")
    def test_validate_repos_contain_packages(self, mock_gather_paths,
                                             mock_get_pkgs, mock_get_repo_dir):
        def get_repo_dir(url):
            return url
        api = mock.Mock()
        service = mock.Mock()
        service.is_for_removal.return_value = False
        service.vm_yum_repos = [mock.Mock(base_url='url1',
                                          vpath='vpath1'),
                                mock.Mock(base_url='bad_path1',
                                          vpath='bad_vpath')]
        service.vm_zypper_repos = [mock.Mock(base_url='url2',
                                          vpath='vpath2'),
                                mock.Mock(base_url='bad_path2',
                                          vpath='bad_vpath2')]
        service.vm_yum_repos[0].is_for_removal.return_value = False
        service.vm_yum_repos[1].is_for_removal.return_value = False
        service.vm_packages = [mock.Mock(vpath='pkg1_vpath'),
                               mock.Mock(vpath='pkg3_vpath')]
        service.vm_packages[0].name = 'pkg1'
        service.vm_packages[1].name = 'pkg3'
        service.vm_packages[0].is_for_removal.return_value = False
        service.vm_packages[1].is_for_removal.return_value = False
        api.query.return_value = [service]
        paths = ['path1', 'path2']
        mock_get_repo_dir.side_effect = get_repo_dir
        mock_gather_paths.return_value = paths

        repo_pkgs = {'url1': set(['pkg1', 'pkg2']),
                     'url2': set(['pkg3', 'pkg4'])}
        mock_get_pkgs.return_value = (repo_pkgs, set(['bad_path1']))

        errors = self.plugin._validate_repos_contain_packages(api)
        self.assertEqual(len(errors), 2)
        err1 = {'message': ('The repo "bad_path1" is not present on '
                            'the management server'),
                'uri': 'bad_vpath',
                'error': 'ValidationError'}
        err2 = {'message': ('The package "pkg3" does not exist in '
                            'any defined repo'),
                'uri': 'pkg3_vpath',
                'error': 'ValidationError'}
        self.assertEqual(err1, errors[0].to_dict())
        self.assertEqual(err2, errors[1].to_dict())

    def test_cpuset_cpunodebind_exclusive(self):
        service = mock.Mock(vpath='vm_path')

        service.cpuset = None
        service.cpunodebind = None
        errors = self.plugin._validate_cpuset_cpunodebind_exclusive(service)
        self.assertEqual(len(errors), 0)

        service.cpuset = '0'
        errors = self.plugin._validate_cpuset_cpunodebind_exclusive(service)
        self.assertEqual(len(errors), 0)

        service.cpuset = None
        service.cpunodebind = '1'
        errors = self.plugin._validate_cpuset_cpunodebind_exclusive(service)
        self.assertEqual(len(errors), 0)

        service.cpuset = '0-9'
        service.cpunodebind = '1'
        errors = self.plugin._validate_cpuset_cpunodebind_exclusive(service)
        self.assertEqual(len(errors), 1)
        err1 = {'message': ('The properties "cpuset" and "cpunodebind" '
                            'are mutually exclusive'),
                'uri': 'vm_path',
                'error': 'ValidationError'}
        self.assertEqual(err1, errors[0].to_dict())


class TestVMServiceFacade(unittest.TestCase):
    def setUp(self):
        self.ms_node = mock.Mock(
            network_interfaces=[mock.Mock(
                    network_name="mgmt",
                    ipaddress="192.168.0.10")])
        self.node = mock.Mock(item_id="node1", hostname='n1')
        self.task_item = mock.Mock()
        self.image = mock.Mock(source_uri='/foo/bar/bang/image.qcow2')
        self.clustered_service = mock.Mock(
            name='test_clustered_svc', node_list='n1', nodes=[self.node],
            service_id='test_vm_service')
        self.ha_svc_cfg = mock.Mock(status_timeout=40)
        self.clustered_service.query.return_value = [self.ha_svc_cfg]
        self.service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                                 vm_yum_repos=[], vm_zypper_repos=[],
                                 vm_nfs_mounts=[], vm_ram_mounts=[],
                                 vm_disk_mounts=[], vm_packages=[],
                                 cpus=2, cpuset=None, cpunodebind=None,
                                 ram='256M', vm_firewall_rules=[],
                                 internal_status_check='on', vm_ssh_keys=[], hostnames=None,
                                 node_hostname_map='{"node1": "test_vm_service"}')
        self.service.service_name = 'test_vm_service'
        self.service.query.return_value = []

        self.networks = [ _build_mock_network() ]
        self.facade = VMServiceFacade(self.node, self.image, self.service,
                                      self.networks, self.ms_node)

    def test_init(self):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        self.assertTrue(facade.node == self.node)
        self.assertTrue(facade._image == self.image)
        self.assertTrue(facade._service == self.service)
        self.assertTrue(facade._yum_repos == self.service.vm_yum_repos)
        self.assertTrue(facade._zypper_repos == self.service.vm_zypper_repos)
        self.assertTrue(facade._packages == self.service.vm_packages)

    def test_state(self):
        self.service.is_initial = lambda: False
        self.assertEqual(constants.UPDATE, self.facade.state)
        self.service.is_initial = lambda: True
        self.service.is_for_removal = lambda: False
        self.assertEqual(constants.DEPLOY, self.facade.state)

        self.service.is_initial = lambda: False
        self.facade._new_nodes = lambda: ['node1']
        self.assertEqual(constants.DEPLOY, self.facade.state)

        self.is_initial = lambda: False
        self.facade._new_nodes = lambda: []
        self.assertEqual(constants.UPDATE, self.facade.state)

    def test_image_uri(self):
        self.assertEqual(
            self.facade.image_uri,
            '/foo/bar/bang/image.qcow2')

    def test_adaptor_data_file_name(self):
        self.assertEqual(
            constants.VM_DATA_FILE_NAME,
            self.facade.adaptor_data_file_name)

    def test_metadata_file_name(self):
        self.assertEqual(
            constants.METADATA_FILE_NAME,
            self.facade.metadata_file_name)

    def test_networkconfig_file_name(self):
        self.assertEqual(
            constants.NETWORKCONFIG_FILE_NAME,
            self.facade.networkconfig_file_name)

    def test_userdata_file_name(self):
        self.assertEqual(
            constants.USERDATA_FILE_NAME,
            self.facade.userdata_file_name)

    def test_get_dhcp_metadata(self):
        intf = mock.Mock(device_name="eth0")
        metadata = self.facade._get_dhcp_metadata(intf)
        self.assertEqual("auto eth0\niface eth0 inet dhcp\n", metadata)

    def test_instance_name(self):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        self.assertEqual('test_vm_service', facade.instance_name)
        self.service.service_name = 'foobar'
        self.assertEqual('foobar', facade.instance_name)

    def test_image_name(self):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        self.assertEqual('image.qcow2', facade.image_name)
        self.image.source_uri = 'http://ffhwjifojew/image1.qcow2'
        self.assertEqual('image1.qcow2', facade.image_name)

    def test_base_path(self):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        self.assertEqual(
            constants.BASE_DESTINATION_PATH
            + 'test_vm_service',
            facade.base_path)

    def test_userdata(self):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.clustered_service)
        facade._get_timezone = mock.Mock()
        facade._get_timezone.return_value = 'Europe/mock'
        custom_scripts = mock.Mock(custom_script_names="fname1.sh,fname2,fname3.py",
                                   network_name="mgmt")
        facade._custom_scripts = [custom_scripts]
        self.assertEqual({'timezone': 'Europe/mock',
                          'bootcmd': [['cloud-init-per',
                                       'instance',
                                       'hostname',
                                       'sh',
                                       '-c',
                                       'hostnamectl set-hostname test_vm_service'],
                                     ['cloud-init-per',
                                      'instance',
                                      'vmmonitored_timeout',
                                      'sh',
                                      '-c',
                                      'echo export OCF_TIMEOUT=40  >> '
                                      '/etc/sysconfig/vmmonitord']
                                      ],
                           'runcmd': ['if [ -f /etc/init.d/rsyslog ];'
                                      ' then /sbin/service rsyslog restart;'
                                      ' elif [ -f /usr/lib/systemd/system/rsyslog.service ];'
                                      ' then /bin/systemctl restart rsyslog.service;'
                                      ' elif [ -f /etc/init.d/syslog ];'
                                      ' then /sbin/service syslog restart;'
                                      ' else exit 1; fi', 'if [ -f /bin/systemctl ];'
                                      ' then /bin/systemctl restart crond; fi']},
                         yaml.load(facade.userdata))

    def test_userdata_repos_and_packages(self):
        vm_yum_repo = mock.Mock()
        vm_yum_repo.name = 'enm'
        vm_yum_repo.base_url = 'http://example.com/yum_repo'
        vm_yum_repo.is_for_removal.return_value = False
        vm_yum_repo2 = mock.Mock()
        vm_yum_repo2.name = '3pp'
        vm_yum_repo2.base_url = 'http://example.com/3pp'
        vm_yum_repo2.is_for_removal.return_value = False
        package1 = mock.Mock()
        package1.name = 'fmmed'
        package1.is_for_removal.return_value = False
        package2 = mock.Mock()
        package2.name = 'pmmed'
        package2.is_for_removal.return_value = False
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[vm_yum_repo, vm_yum_repo2],
                            vm_zypper_repos=[],
                            vm_packages=[package1, package2], cpus=2,
                            ram='256M', vm_nfs_mounts=[], vm_firewall_rules=[],
                            vm_disk_mounts=[], vm_ram_mounts=[],
                            service_name="mock_service", vm_ssh_keys=[],
                            hostnames=None, node_hostname_map='{"node1": "mock_service"}')
        service.query.return_value = []
        facade = VMServiceFacade(self.node, self.image, service,
                                 self.networks, self.ms_node, self.clustered_service)
        facade._get_timezone = mock.Mock()
        facade._get_timezone.return_value = 'Europe/mock'
        timezone = 'Europe/mock'
        custom_scripts = mock.Mock(custom_script_names="fname1.sh,fname2,fname3.py",
                                   network_name="mgmt")
        facade._custom_scripts = [custom_scripts]
        expected = {
            'bootcmd': [['cloud-init-per',
                         'instance',
                         'hostname',
                         'sh',
                         '-c',
                         'hostnamectl set-hostname mock_service'],
                        ['cloud-init-per', 'instance', 'vmmonitored_timeout',
                         'sh', '-c',
                         'echo export OCF_TIMEOUT=40  >> '
                         '/etc/sysconfig/vmmonitord']],
            'runcmd': ['if [ -f /etc/init.d/rsyslog ];'\
                       ' then /sbin/service rsyslog restart;'\
                       ' elif [ -f /usr/lib/systemd/system/rsyslog.service ];'\
                       ' then /bin/systemctl restart rsyslog.service;'\
                       ' elif [ -f /etc/init.d/syslog ];'\
                       ' then /sbin/service syslog restart;'\
                       ' else exit 1; fi', 'if [ -f /bin/systemctl ];'\
                       ' then /bin/systemctl restart crond; fi'],
            'yum_repos': {
                'enm': {
                    'enabled': True,
                    'baseurl': 'http://example.com/yum_repo',
                    'name': 'enm',
                    'gpgcheck': False
                },
                '3pp': {
                    'enabled': True,
                    'baseurl': 'http://example.com/3pp',
                    'name': '3pp',
                    'gpgcheck': False
                }
            },
            'timezone': timezone,
            'packages': ['fmmed', 'pmmed']
        }
        self.assertEqual(expected, yaml.load(facade.userdata))
        expected_string =("#cloud-config\n"
                          "bootcmd:\n- - cloud-init-per\n"
                          "  - instance\n  - hostname\n"
                          "  - sh\n  - -c\n  - hostnamectl set-hostname mock_service\n"
                          "- - cloud-init-per\n  - instance\n"
                          "  - vmmonitored_timeout\n  - sh\n  - -c\n"
                          "  - echo export OCF_TIMEOUT=40  >> /etc/sysconfig/vmmonitord\n"
                          "packages:\n- fmmed\n- pmmed\nruncmd:\n"
                          "- if [ -f /etc/init.d/rsyslog ]; "
                          "then /sbin/service rsyslog restart;"
                          " elif [ -f /usr/lib/systemd/system/rsyslog.service\n"
                          "  ]; then /bin/systemctl restart rsyslog.service; "
                          "elif [ -f /etc/init.d/syslog ];\n"
                          "  then /sbin/service syslog restart; else exit 1; fi\n"
                          "- if [ -f /bin/systemctl ]; then /bin/systemctl restart crond; fi\n"
                          "timezone: %s\nyum_repos:\n  3pp:\n"
                          "    baseurl: http://example.com/3pp\n    enabled: true\n"
                          "    gpgcheck: false\n    name: 3pp\n  enm:\n"
                          "    baseurl: http://example.com/yum_repo\n"
                          "    enabled: true\n    gpgcheck: false\n"
                          "    name: enm\n"%timezone)
        self.assertEqual(expected_string, facade.userdata)

    def test_userdata_zypper_repos_and_packages(self):
        vm_zypper_repo = mock.Mock()
        vm_zypper_repo.name = 'enm'
        vm_zypper_repo.base_url = 'http://example.com/zypper_repo'
        vm_zypper_repo.is_for_removal.return_value = False
        vm_zypper_repo2 = mock.Mock()
        vm_zypper_repo2.name = '3pp'
        vm_zypper_repo2.base_url = 'http://example.com/3pp'
        vm_zypper_repo2.is_for_removal.return_value = False
        package1 = mock.Mock()
        package1.name = 'fmmed'
        package1.is_for_removal.return_value = False
        package2 = mock.Mock()
        package2.name = 'pmmed'
        package2.is_for_removal.return_value = False
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[],
                            vm_zypper_repos=[vm_zypper_repo, vm_zypper_repo2],
                            vm_packages=[package1, package2], cpus=2,
                            ram='256M', vm_nfs_mounts=[], vm_firewall_rules=[],
                            vm_disk_mounts=[], vm_ram_mounts=[],
                            service_name="mock_service", vm_ssh_keys=[],
                            hostnames=None, node_hostname_map='{"node1": "mock_service"}')
        service.query.return_value = []
        facade = VMServiceFacade(self.node, self.image, service,
                                 self.networks, self.ms_node, self.clustered_service)
        facade._get_timezone = mock.Mock()
        facade._get_timezone.return_value = 'Europe/mock'
        timezone = 'Europe/mock'
        custom_scripts = mock.Mock(custom_script_names="fname1.sh,fname2,fname3.py",
                                   network_name="mgmt")
        facade._custom_scripts = [custom_scripts]
        expected = {
            'bootcmd': [['cloud-init-per',
                         'instance',
                         'hostname',
                         'sh',
                         '-c',
                         'hostnamectl set-hostname mock_service'],
                        ['cloud-init-per', 'instance', 'vmmonitored_timeout',
                         'sh', '-c',
                         'echo export OCF_TIMEOUT=40  >> '
                         '/etc/sysconfig/vmmonitord']],
            'runcmd': ['if [ -f /etc/init.d/rsyslog ];'
                       ' then /sbin/service rsyslog restart;'
                       ' elif [ -f /usr/lib/systemd/system/rsyslog.service ];'
                       ' then /bin/systemctl restart rsyslog.service;'
                       ' elif [ -f /etc/init.d/syslog ];'
                       ' then /sbin/service syslog restart;'
                       ' else exit 1; fi', 'if [ -f /bin/systemctl ];'
                       ' then /bin/systemctl restart crond; fi'],
            'write_files': [{
                'content':
                    '[enm]\n'
                    'name=enm\n'
                    'enabled=1\n'
                    'autorefresh=0\n'
                    'baseurl=http://example.com/zypper_repo\n'
                    'gpgcheck=False\n',
                'path': '/etc/zypp/repos.d/enm.repo'},
                {'content':
                     '[3pp]\n'
                     'name=3pp\n'
                     'enabled=1\n'
                     'autorefresh=0\n'
                     'baseurl=http://example.com/3pp\n'
                     'gpgcheck=False\n',
                 'path': '/etc/zypp/repos.d/3pp.repo'}],
            'timezone': timezone,
            'packages': ['fmmed', 'pmmed']
        }
        self.assertEqual(expected, yaml.load(facade.userdata))
        expected_string = ('#cloud-config\n'
                           'bootcmd:\n- - cloud-init-per\n'
                           '  - instance\n  - hostname\n  - sh\n  - -c\n'
                           '  - hostnamectl set-hostname mock_service\n- - cloud-init-per\n'
                           '  - instance\n  - vmmonitored_timeout\n  - sh\n'
                           '  - -c\n  - echo export OCF_TIMEOUT=40  >> /etc/sysconfig/vmmonitord\n'
                           'packages:\n- fmmed\n- pmmed\nruncmd:\n'
                           '- if [ -f /etc/init.d/rsyslog ]; then /sbin/service rsyslog restart;'
                           ' elif [ -f /usr/lib/systemd/system/rsyslog.service\n'
                           '  ]; then /bin/systemctl restart rsyslog.service;'
                           ' elif [ -f /etc/init.d/syslog ];\n'
                           '  then /sbin/service syslog restart; else exit 1; fi\n'
                           "- if [ -f /bin/systemctl ]; then /bin/systemctl restart crond; fi\n"\
                           'timezone: %s\n"write_files":\n- "content": |\n'
                           '    [enm]\n    name=enm\n    enabled=1\n    autorefresh=0\n'
                           '    baseurl=http://example.com/zypper_repo\n    gpgcheck=False\n'
                           '  "path": |-\n    /etc/zypp/repos.d/enm.repo\n- "content": |\n'
                           '    [3pp]\n    name=3pp\n    enabled=1\n    autorefresh=0\n'
                           '    baseurl=http://example.com/3pp\n    gpgcheck=False\n  "path": |-\n'
                           '    /etc/zypp/repos.d/3pp.repo\n'%timezone)
        self.assertEqual(expected_string, facade.userdata)

    def test_userdata_mounts(self):
        vm_nfs_mount = mock.Mock(device_path='172.17.42.1:/vx/nfs1',
                                 mount_point='/mnt/nfs1',
                                 mount_options='retrans=8,rsize=32768',
                                 is_for_removal=lambda: False)
        vm_ram_mount = mock.Mock(type='tmpfs',
                                 mount_point='/mnt/tmp1',
                                 mount_options='size=96%',
                                 is_for_removal=lambda: False)
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_zypper_repos=[], vm_packages=[],
                            cpus=2, ram='256M',
                            vm_disk_mounts=[],
                            vm_nfs_mounts=[vm_nfs_mount],
                            vm_ram_mounts=[vm_ram_mount],
                            service_name='mock_service',
                            vm_ssh_keys=[], hostnames=None,
                            vm_firewall_rules=[],
                            node_hostname_map='{"node1": "mock_service"}')
        service.query.return_value = []
        facade = VMServiceFacade(self.node, self.image, service,
                                 self.networks, self.ms_node, self.clustered_service)
        facade._get_timezone = mock.Mock()
        facade._get_timezone.return_value = 'Europe/mock'
        timezone = 'Europe/mock'
        custom_scripts = mock.Mock(custom_script_names="fname1.sh,fname2,fname3.py",
                                   network_name="mgmt")
        facade._custom_scripts = [custom_scripts]

        expected = {
            'bootcmd': [['cloud-init-per',
                         'instance',
                         'hostname',
                         'sh',
                         '-c',
                         'hostnamectl set-hostname mock_service'],
                        ['cloud-init-per', 'instance', 'vmmonitored_timeout',
                         'sh', '-c',
                         'echo export OCF_TIMEOUT=40  >> '
                         '/etc/sysconfig/vmmonitord']
                        ],
            'runcmd': ['if [ -f /etc/init.d/rsyslog ];'
                       ' then /sbin/service rsyslog restart;'
                       ' elif [ -f /usr/lib/systemd/system/rsyslog.service ];'
                       ' then /bin/systemctl restart rsyslog.service;'
                       ' elif [ -f /etc/init.d/syslog ];'
                       ' then /sbin/service syslog restart;'
                       ' else exit 1; fi', 'if [ -f /bin/systemctl ];'
                       ' then /bin/systemctl restart crond; fi'],
            'mounts': [['172.17.42.1:/vx/nfs1', '/mnt/nfs1',
                        'nfs', 'retrans=8,rsize=32768'],
                       ['tmpfs', '/mnt/tmp1', 'tmpfs', 'size=96%']],
            'timezone': timezone,
        }
        self.assertEqual(expected, yaml.load(facade.userdata))
        expected_string = "#cloud-config\nbootcmd:\n"\
                           "- - cloud-init-per\n  - instance\n"\
                           "  - hostname\n  - sh\n  - -c\n"\
                           "  - hostnamectl set-hostname mock_service\n- - cloud-init-per\n"\
                           "  - instance\n  - vmmonitored_timeout\n  - sh\n  - -c\n"\
                           "  - echo export OCF_TIMEOUT=40  >> /etc/sysconfig/vmmonitord\n"\
                           "mounts:\n- - 172.17.42.1:/vx/nfs1\n  - /mnt/nfs1\n  - nfs\n"\
                           "  - retrans=8,rsize=32768\n- - tmpfs\n  - /mnt/tmp1\n  - tmpfs\n"\
                           "  - size=96%\nruncmd:\n- if [ -f /etc/init.d/rsyslog ];"\
                           " then /sbin/service rsyslog restart; elif [ -f /usr/lib/systemd/system/rsyslog.service\n"\
                           "  ]; then /bin/systemctl restart rsyslog.service; elif [ -f /etc/init.d/syslog ];\n"\
                           "  then /sbin/service syslog restart; else exit 1; fi\n"\
                           "- if [ -f /bin/systemctl ]; then /bin/systemctl restart crond; fi\n"\
                           "timezone: {0}\n".format(timezone)
        self.assertEqual(expected_string, facade.userdata)

    def test_userdata_bootcmd(self):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.clustered_service)
        facade._get_timezone = mock.Mock()
        facade._get_timezone.return_value = 'Europe/mock'
        custom_scripts = mock.Mock(custom_script_names="fname1.sh,fname2,fname3.py",
                                   network_name="mgmt")
        facade._custom_scripts = [custom_scripts]
        facade._clustered_service = mock.Mock()
        facade._clustered_service.query.return_value = [mock.Mock(status_timeout=50)]
        expected = {'timezone': 'Europe/mock',
                    'runcmd': ['if [ -f /etc/init.d/rsyslog ];'\
                               ' then /sbin/service rsyslog restart;'\
                               ' elif [ -f /usr/lib/systemd/system/rsyslog.service ];'\
                               ' then /bin/systemctl restart rsyslog.service;'\
                               ' elif [ -f /etc/init.d/syslog ];'\
                               ' then /sbin/service syslog restart;'\
                               ' else exit 1; fi', 'if [ -f /bin/systemctl ];'\
                               ' then /bin/systemctl restart crond; fi'],
                    'bootcmd': [['cloud-init-per',
                                 'instance',
                                 'hostname',
                                 'sh',
                                 '-c',
                                 'hostnamectl set-hostname test_vm_service'],
                                ['cloud-init-per', 'instance', 'alias0', 'sh',
                                 '-c', 'echo 10.10.20.1 host1 >> /etc/hosts'],
                                ['cloud-init-per', 'instance', 'alias1', 'sh',
                                 '-c', 'echo 10.10.20.2 host2 host22.domain '
                                       '>> /etc/hosts'],
                                ['cloud-init-per', 'instance',
                                 'vmmonitored_timeout', 'sh', '-c',
                                 'echo export OCF_TIMEOUT=50  >> '
                                 '/etc/sysconfig/vmmonitord']]}
        alias1 = mock.MagicMock()
        alias1.address = "10.10.20.1"
        alias1.alias_names = "host1"
        alias1.is_for_removal.return_value = False
        alias2 = mock.MagicMock()
        alias2.address = "10.10.20.2"
        alias2.alias_names = "host2,host22.domain"
        alias2.is_for_removal.return_value = False
        self.service.vm_aliases = [alias1, alias2]
        a = yaml.load(facade.userdata)
        self.assertEqual(expected, a)

    def test_userdata_runcmd(self):
        custom_scripts = mock.Mock(custom_script_names="fname1.sh,fname2,fname3.py",
                                   network_name="mgmt",
                                   is_for_removal=lambda: False)
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_zypper_repos=[], vm_packages=[],
                            cpus=2, ram='256M',
                            vm_disk_mounts=[],
                            vm_nfs_mounts=[],
                            vm_ram_mounts=[],
                            vm_firewall_rules=[],
                            vm_custom_script=[custom_scripts],
                            service_name='mock_service',
                            vm_ssh_keys=[], hostnames='mock_service',
                            node_hostname_map='{"node1": "mock_service"}')
        facade = VMServiceFacade(self.node, self.image, service,
                                 self.networks, self.ms_node, self.task_item)
        facade._get_timezone = mock.Mock()
        facade._get_timezone.return_value = 'Europe/mock'
        facade._get_vmmonitor_timeout = mock.Mock(side_effect=lambda x: x)
        timezone = 'Europe/mock'

        expected = {
            'bootcmd': [['cloud-init-per',
                         'instance',
                         'hostname',
                         'sh',
                         '-c',
                         'hostnamectl set-hostname mock_service']],
            'runcmd': ['if [ -f /etc/init.d/rsyslog ];'\
                       ' then /sbin/service rsyslog restart;'\
                       ' elif [ -f /usr/lib/systemd/system/rsyslog.service ];'\
                       ' then /bin/systemctl restart rsyslog.service;'\
                       ' elif [ -f /etc/init.d/syslog ];'\
                       ' then /sbin/service syslog restart;'\
                       ' else exit 1; fi', 'if [ -f /bin/systemctl ];'\
                       ' then /bin/systemctl restart crond; fi',
                       '/opt/ericsson/vmmonitord/bin/customscriptmanager.sh 192.168.0.10 fname1.sh,fname2,fname3.py'],
            'timezone': timezone,
        }
        self.assertEqual(expected, yaml.load(facade.userdata))
        expected_string = ("#cloud-config\n"\
                          "bootcmd:\n- - cloud-init-per\n"\
                          "  - instance\n  - hostname\n  - sh\n"\
                          "  - -c\n  - hostnamectl set-hostname mock_service\nruncmd:\n"\
                          "- if [ -f /etc/init.d/rsyslog ];"\
                          " then /sbin/service rsyslog restart;"\
                          " elif [ -f /usr/lib/systemd/system/rsyslog.service\n"\
                          "  ]; then /bin/systemctl restart rsyslog.service;"\
                          " elif [ -f /etc/init.d/syslog ];\n"\
                          "  then /sbin/service syslog restart;"\
                          " else exit 1; fi\n"\
                          "- if [ -f /bin/systemctl ]; then /bin/systemctl restart crond; fi\n"\
                          "- /opt/ericsson/vmmonitord/bin/customscriptmanager.sh"\
                          " 192.168.0.10 fname1.sh,fname2,fname3.py\n"\
                          "timezone: %s\n"%timezone)
        self.assertEqual(expected_string, facade.userdata)

    def test_get_nfs_and_ram_mounts(self):
        facade = VMServiceFacade(
            mock.Mock(),
            mock.Mock(),
            mock.MagicMock(
                vm_nfs_mounts=[mock.Mock(device_path='device_path',
                                         mount_point='mount_point',
                                         mount_options='mount_options',
                                         is_for_removal=lambda: False),
                               mock.Mock(is_for_removal=lambda: True)],
                vm_ram_mounts=[mock.Mock(type='tmpfs',
                                         mount_point='mount_point_1',
                                         mount_options='mount_options_1',
                                         is_for_removal=lambda: False),
                               mock.Mock(is_for_removal=lambda: True)],
                          ),
            self.networks,
            self.ms_node,
            None)
        self.assertEquals(
            [['device_path', 'mount_point', 'nfs', 'mount_options'],
             ['tmpfs', 'mount_point_1', 'tmpfs', 'mount_options_1']],
            facade._get_nfs_and_ram_mounts())

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._ms_install_fs')
    def test_get_disk_mounts(self, patch_ms_install_fs):
        patch_ms_install_fs.return_value = False

        vg = mock.Mock(item_id='vg1', volume_group_name='testvg')
        fs_item = mock.Mock(item_id='fs1', type='ext4')
        fs_item.parent = mock.Mock()
        fs_item.parent.item_id='file_systems'
        fs_item.parent.parent = vg

        vm_disk = mock.Mock(
            host_volume_group='vg1',
            host_file_system='fs1',
            mount_point='/mnt',
            host_file_system_item=fs_item
        )
        vm_disk.is_for_removal.return_value = False

        facade = VMServiceFacade(
            mock.Mock(),
            mock.Mock(),
            mock.MagicMock(vm_disks=[vm_disk]),
            self.networks,
            self.ms_node,
            None)

        self.assertEquals(
            [['/dev/testvg/vg1_fs1', '/mnt']],
            facade._get_disk_mounts())

        patch_ms_install_fs.return_value = constants.MS_KS_FS[8].name

        self.assertEquals(
            [['/dev/testvg/lv_var_www', '/mnt']],
            facade._get_disk_mounts())

    def test_ms_install_fs(self):
        fs = mock.Mock(type='ext4',
                       mount_point=constants.MS_KS_FS[0].mount_point)
        vg = mock.Mock(volume_group_name=constants.MS_ROOT_VG_GROUP_NAME)

        facade = VMServiceFacade(
            mock.Mock(is_ms=lambda: True),
            mock.Mock(),
            mock.MagicMock(),
            self.networks,
            self.ms_node,
            None)

        self.assertEquals(facade._ms_install_fs(vg, fs), constants.MS_KS_FS[0].name)

        fs.type = 'swap'
        self.assertEquals(facade._ms_install_fs(vg, fs), None)

        fs.type = 'ext4'
        fs.mount_point = '/mnt'
        self.assertEquals(facade._ms_install_fs(vg, fs), None)

        fs.mount_point = constants.MS_KS_FS[0].mount_point
        vg.volume_group_name='vg1'
        self.assertEquals(facade._ms_install_fs(vg, fs), None)

    def test_metadata(self):

        def exec_test_metadata(expected, interface1, interface2):
            self.node.item_id = "node1"
            self.node.hostname = 'node1'

            cluster = mock.Mock(item_id="cluster1",
                                cluster_id=65535)

            self.service.vm_network_interfaces = [interface1, interface2]

            self.api = mock.MagicMock()
            self.api.query = _mock_vm_interface_query

            self.task_item.standby = 1
            facade = VMServiceFacade(self.node, self.image, self.service,
                                     self.networks, self.ms_node,
                                     self.task_item)
            facade._service.get_cluster.return_value = cluster
            facade.node.hostname = 'mn1'

            facade.metadata(self.api)

            a = yaml.load(facade.metadata(self.api))
            self.assertEqual(expected, a)

            facade.node.hostname = 'foobar'
            self.assertTrue(
                yaml.load(facade.metadata(self.api))['instance-id']
                == 'test_vm_service')

        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet static
                        address 10.10.10.1
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet static
                        address 10.10.10.2
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}

        interface1 = mock.MagicMock(device_name="eth0",
                         network_name="test_network",
                         node_ip_map="{'node1': {'ipv4': '10.10.10.1'}}",
                         node_mac_address_map=
                           "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                         gateway="10.10.11.1",
                         gateway6="",
                         is_for_removal=mock.MagicMock(return_value=False),
                         mac_prefix='52:54:00')

        interface2 = mock.MagicMock(device_name="eth1",
                         network_name = "test_network",
                         node_ip_map="{'node1': {'ipv4': '10.10.10.2'}}",
                         node_mac_address_map=
                           "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                         gateway="10.10.11.1",
                         gateway6="",
                         is_for_removal=mock.MagicMock(return_value=False),
                         mac_prefix='52:54:00')

        exec_test_metadata(expected, interface1, interface2)

        # test for ipv6 addresses
        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet6 static
                        address 2001:f0d0:1884:1b42::1
                        gateway 2001:f0d0:1884:1b42::11
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet6 static
                        address 2001:f0d0:1884:1b42::2
                        gateway 2001:f0d0:1884:1b42::2
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}

        interface1 = mock.MagicMock(device_name="eth0",
                   network_name="test_network",
                   node_ip_map="{'node1': {'ipv6': '2001:f0d0:1884:1b42::1'}}",
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                   gateway="",
                   gateway6="2001:f0d0:1884:1b42::11",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        interface2 = mock.MagicMock(device_name="eth1",
                   network_name = "test_network",
                   node_ip_map="{'node1': {'ipv6': '2001:f0d0:1884:1b42::2'}}",
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                   gateway="",
                   gateway6="2001:f0d0:1884:1b42::2",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        exec_test_metadata(expected, interface1, interface2)

        # test for ipv4 and ipv6 dual stack
        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet static
                        address 10.10.11.1
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.10.11
                        iface eth0 inet6 static
                        address 2001:f0d0:1884:1b42::1
                        gateway 2001:f0d0:1884:1b42::11
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet dhcp
                        iface eth1 inet6 static
                        address 2001:f0d0:1884:1b42::2
                        gateway 2001:f0d0:1884:1b42::4
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}

        interface1 = mock.MagicMock(device_name="eth0",
                   network_name="test_network",
                   node_ip_map=("{'node1': {'ipv4': '10.10.11.1',"
                                          "'ipv6': '2001:f0d0:1884:1b42::1'}}"),
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                   gateway="10.10.10.11",
                   gateway6="2001:f0d0:1884:1b42::11",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        interface2 = mock.MagicMock(device_name="eth1",
                   network_name = "test_network",
                   node_ip_map="{'node1': {'ipv6': '2001:f0d0:1884:1b42::2'}}",
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                   gateway="10.10.10.4",
                   gateway6="2001:f0d0:1884:1b42::4",
                   ipaddresses="dhcp",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        exec_test_metadata(expected, interface1, interface2)

    def test_networkconfig(self):

        def exec_test_networkconfig(expected, interface1, interface2):
            self.node.item_id = "node1"
            self.node.hostname = 'node1'

            cluster = mock.Mock(item_id="cluster1",
                                cluster_id=65535)

            self.service.vm_network_interfaces = [interface1, interface2]

            self.api = mock.MagicMock()
            self.api.query = _mock_vm_interface_query

            self.task_item.standby = 1
            facade = VMServiceFacade(self.node, self.image, self.service,
                                     self.networks, self.ms_node,
                                     self.task_item)
            facade._service.get_cluster.return_value = cluster
            facade.node.hostname = 'mn1'

            y = facade.networkconfig(self.api)

            a = yaml.load(y)
            self.assertEqual(expected, a)

            facade.node.hostname = 'foobar'
            self.assertTrue(a['version'] == 1)

        expected = {'version': 1,
                    'config': [{'subnets': [{'netmask': '255.255.255.0',
                                             'type': 'static',
                                             'gateway': '10.10.11.1',
                                             'address': '10.10.10.1'}],
                                'type': 'physical',
                                'name': 'eth0',
                                'mac_address': '52:54:00:f1:80:7b'},
                               {'subnets': [{'netmask': '255.255.255.0',
                                             'type': 'static',
                                             'gateway': '10.10.11.1',
                                             'address': '10.10.10.2'
                                                         }],
                                             'type': 'physical',
                                             'name': 'eth1',
                                             'mac_address': '52:54:00:e6:44:f6'
                                             }]}

        interface1 = mock.MagicMock(device_name="eth0",
                         network_name="test_network",
                         node_ip_map="{'node1': {'ipv4': '10.10.10.1'}}",
                         node_mac_address_map=
                           "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                         gateway="10.10.11.1",
                         gateway6="",
                         is_for_removal=mock.MagicMock(return_value=False),
                         mac_prefix='52:54:00')

        interface2 = mock.MagicMock(device_name="eth1",
                         network_name = "test_network",
                         node_ip_map="{'node1': {'ipv4': '10.10.10.2'}}",
                         node_mac_address_map=
                           "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                         gateway="10.10.11.1",
                         gateway6="",
                         is_for_removal=mock.MagicMock(return_value=False),
                         mac_prefix='52:54:00')

        exec_test_networkconfig(expected, interface1, interface2)

        # test for ipv6 addresses
        expected = {'version': 1,
                    'config': [{'subnets': [{'type': 'static',
                                             'gateway': '2001:f0d0:1884:1b42::11',
                                             'address': '2001:f0d0:1884:1b42::1'
                                            }],
                                'type': 'physical',
                                'name': 'eth0',
                                'mac_address':'52:54:00:f1:80:7b'},
                                {'subnets': [{'type': 'static',
                                              'gateway':'2001:f0d0:1884:1b42::2',
                                              'address': '2001:f0d0:1884:1b42::2'}],
                                'type': 'physical',
                                'name': 'eth1',
                                'mac_address': '52:54:00:e6:44:f6'}]}

        interface1 = mock.MagicMock(device_name="eth0",
                   network_name="test_network",
                   node_ip_map="{'node1': {'ipv6': '2001:f0d0:1884:1b42::1'}}",
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                   gateway="",
                   gateway6="2001:f0d0:1884:1b42::11",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        interface2 = mock.MagicMock(device_name="eth1",
                   network_name = "test_network",
                   node_ip_map="{'node1': {'ipv6': '2001:f0d0:1884:1b42::2'}}",
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                   gateway="",
                   gateway6="2001:f0d0:1884:1b42::2",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        exec_test_networkconfig(expected, interface1, interface2)

        # test for ipv4 and ipv6 dual stack
        expected = {'version': 1,
                    'config': [{'subnets': [{'netmask': '255.255.255.0',
                                             'type': 'static',
                                             'gateway': '10.10.10.11',
                                             'address': '10.10.11.1'},
                                {'type': 'static',
                                 'gateway': '2001:f0d0:1884:1b42::11',
                                 'address': '2001:f0d0:1884:1b42::1'}],
                                'type': 'physical',
                                'name': 'eth0',
                                'mac_address': '52:54:00:f1:80:7b'},
                               {'subnets': [{'type': 'dhcp'},
                                            {'type': 'static',
                                             'gateway':'2001:f0d0:1884:1b42::4',
                                             'address':'2001:f0d0:1884:1b42::2'}],
                                'type': 'physical',
                                'name': 'eth1',
                                'mac_address': '52:54:00:e6:44:f6'}]}

        interface1 = mock.MagicMock(device_name="eth0",
                   network_name="test_network",
                   node_ip_map=("{'node1': {'ipv4': '10.10.11.1',"
                                          "'ipv6': '2001:f0d0:1884:1b42::1'}}"),
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                   gateway="10.10.10.11",
                   gateway6="2001:f0d0:1884:1b42::11",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        interface2 = mock.MagicMock(device_name="eth1",
                   network_name = "test_network",
                   node_ip_map="{'node1': {'ipv6': '2001:f0d0:1884:1b42::2'}}",
                   node_mac_address_map=
                           "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                   gateway="10.10.10.4",
                   gateway6="2001:f0d0:1884:1b42::4",
                   ipaddresses="dhcp",
                   is_for_removal=mock.MagicMock(return_value=False),
                   mac_prefix='52:54:00')

        exec_test_networkconfig(expected, interface1, interface2)

    def test_metadata_updated(self):

        def exec_test_metadata_updated(expected, interface1, interface2):
            self.node.item_id = "node1"
            self.node.hostname = 'node1'
            cluster = mock.Mock(item_id="cluster1",
                                cluster_id=65535)

            self.service.vm_network_interfaces = [interface1, interface2]
            self.service.get_cluster.return_value = cluster

            self.api = mock.MagicMock()
            self.api.query = _mock_vm_interface_query

            self.task_item.standby = 1
            facade = VMServiceFacade(self.node, self.image, self.service,
                                     self.networks, self.ms_node,
                                     self.task_item)
            facade._service.get_cluster.return_value = cluster
            facade.node.hostname = 'mn1'

            a = yaml.load(facade.metadata(self.api))
            self.assertEqual(expected, a)

        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet static
                        address 10.10.10.3
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet static
                        address 10.10.10.4
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}

        interface1 = mock.MagicMock(device_name = "eth0",
                 network_name="test_network",
                 applied_properties=
                   {'node_ip_map': "{\"node3\" : {\"ipv4\": \"10.10.10.1\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_updated=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.3'}}",
                 node_mac_address_map=
                            "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                 ipaddresses="10.10.10.3",
                 gateway="10.10.11.1",
                 gateway6="",
                 mac_prefix = '52:54:00')

        interface2 = mock.MagicMock(network_name="test_network",
                 device_name="eth1",
                 applied_properties=
                   {'node_ip_map': "{\"node3\" : {\"ipv4\": \"10.10.10.2\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_applied=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.4'}}",
                 node_mac_address_map=
                   "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                 ipaddresses="10.10.10.4",
                 gateway="10.10.11.1",
                 gateway6="",
                 mac_prefix = '52:54:00')

        exec_test_metadata_updated(expected, interface1, interface2)

        # test for ipv6 addresses
        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet6 static
                        address 2001:f0b4:1224:1884::1/64
                        gateway 2001:f0b4:1224:1884::11/64
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet6 static
                        address 2001:f0b4:1224:1884::2/64
                        gateway 2001:f0b4:1224:1884::12/64
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}
        interface1 = mock.MagicMock(device_name = "eth0",
                 network_name="test_network",
                 applied_properties=
                   {'node_ip_map': "{\"node3\" : {\"ipv6\": \"2001:f0b4:1224:1884::21/64\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_updated=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv6': '2001:f0b4:1224:1884::1/64'}}",
                 node_mac_address_map=
                            "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                 gateway="",
                 gateway6="2001:f0b4:1224:1884::11/64",
                 mac_prefix = '52:54:00')

        interface2 = mock.MagicMock(network_name="test_network",
                 device_name="eth1",
                 applied_properties=
                   {'node_ip_map': "{\"node3\" : {\"ipv6\": \"2001:f0b4:1224:1884::22/64\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_applied=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv6': '2001:f0b4:1224:1884::2/64'}}",
                 node_mac_address_map=
                   "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                 ipaddresses="10.10.10.4",
                 gateway="",
                 gateway6="2001:f0b4:1224:1884::12/64",
                 mac_prefix = '52:54:00')

        exec_test_metadata_updated(expected, interface1, interface2)

        # test for ipv4 and ipv6 dual stack
        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet static
                        address 10.10.10.3
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        iface eth0 inet6 static
                        address 2001:f0b4:1224:1884::3/64
                        gateway 2001:f0b4:1224:1884::11/64
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet static
                        address 10.10.10.4
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        iface eth1 inet6 static
                        address 2001:f0b4:1224:1884::4/64
                        gateway 2001:f0b4:1224:1884::12/64
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}

        interface1 = mock.MagicMock(device_name = "eth0",
                 network_name="test_network",
                 applied_properties=
                   {'node_ip_map': "{\"node3\" : {\"ipv4\": \"10.10.10.1\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_updated=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map=("{'node1': {'ipv4': '10.10.10.3',"
                                       "'ipv6': '2001:f0b4:1224:1884::3/64'}}"),
                 node_mac_address_map=
                            "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                 gateway="10.10.11.1",
                 gateway6="2001:f0b4:1224:1884::11/64",
                 mac_prefix = '52:54:00')

        interface2 = mock.MagicMock(network_name="test_network",
                 device_name="eth1",
                 applied_properties=
                   {'node_ip_map': "{\"node3\" : {\"ipv4\": \"10.10.10.2\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_applied=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map=("{'node1': {'ipv4': '10.10.10.4',"
                                       "'ipv6': '2001:f0b4:1224:1884::4/64'}}"),
                 node_mac_address_map=
                   "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                 ipaddresses="10.10.10.4",
                 gateway="10.10.11.1",
                 gateway6="2001:f0b4:1224:1884::12/64",
                 mac_prefix = '52:54:00')

        exec_test_metadata_updated(expected, interface1, interface2)

    def test_metadata_updated_use_same_address_as_applied_map(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.cluster_id = 65535

        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet static
                        address 10.10.10.1
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet static
                        address 10.10.10.2
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}
        self.node.item_id = 'node1'
        self.node.hostname = 'node1'

        interface1 = mock.MagicMock(device_name="eth0",
                 network_name="test_network",
                 applied_properties=
                   {'node_ip_map': "{\"node1\" : {\"ipv4\": \"10.10.10.1\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_updated=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.1'}}",
                 ipaddresses="10.10.10.3,10.10.10.1",
                 gateway="10.10.11.1",
                 gateway6="",
                 mac_prefix='52:54:00',
                 node_mac_address_map=
                   "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}")

        interface2 = mock.MagicMock(network_name="test_network",
                 device_name="eth1",
                 applied_properties=
                   {'node_ip_map': "{\"node1\" : {\"ipv4\": \"10.10.10.2\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_applied=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.2'}}",
                 ipaddresses="10.10.10.4,10.10.10.2",
                 gateway="10.10.11.1",
                 gateway6="",
                 mac_prefix='52:54:00',
                 node_mac_address_map=
                   "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}")

        self.service.vm_network_interfaces = [interface1, interface2]
        self.service.get_cluster.return_value = cluster

        self.api = mock.MagicMock()
        self.api.query = _mock_vm_interface_query

        self.task_item.standby= 1
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        facade._service.get_cluster.return_value = cluster
        facade.node.hostname = 'mn1'

        a = yaml.load(facade.metadata(self.api))
        self.assertEqual(expected, a)

    def test_metadata_update_same_ip_as_current_map(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.cluster_id = 65535

        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet static
                        address 10.10.10.3
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet static
                        address 10.10.10.4
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}

        self.node.item_id = 'node1'
        self.node.hostname = 'node1'

        interface1 = mock.MagicMock(device_name="eth0",
                 network_name="test_network",
                 applied_properties=
                   {'node_ip_map': "{\"node1\" : {\"ipv4\": \"10.10.10.1\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_updated=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.3'}}",
                 node_mac_address_map=
                            "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                 ipaddresses="10.10.10.3",
                 mac_prefix='52:54:00',
                 gateway="10.10.11.1",
                 gateway6="")

        interface2 = mock.MagicMock(network_name="test_network",
                 device_name="eth1",
                 applied_properties=
                   {'node_ip_map': "{\"node1\" : {\"ipv4\": \"10.10.10.2\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_applied=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.4'}}",
                 node_mac_address_map=
                            "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                 ipaddresses="10.10.10.4",
                 mac_prefix='52:54:00',
                 gateway="10.10.11.1",
                 gateway6="")

        self.service.vm_network_interfaces = [interface1, interface2]
        self.service.get_cluster.return_value = cluster

        self.api = mock.MagicMock()
        self.api.query = _mock_vm_interface_query

        self.task_item.standby = 1
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        facade._service.get_cluster.return_value = cluster
        facade.node.hostname = 'mn1'

        a = yaml.load(facade.metadata(self.api))
        self.assertEqual(expected, a)

    def test_metadata_updated_new_address_parallel(self):
        expected = {'instance-id': "test_vm_service",
                    "network-interfaces": textwrap.dedent(
                        """
                        auto eth0
                        iface eth0 inet static
                        address 10.10.10.3
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:f1:80:7b
                        auto eth1
                        iface eth1 inet static
                        address 10.10.10.4
                        network test_network
                        netmask 255.255.255.0
                        broadcast 10.10.11.255
                        gateway 10.10.11.1
                        hwaddress 52:54:00:e6:44:f6
                        """).lstrip()}

        cluster = mock.Mock(item_id="cluster1")
        cluster.cluster_id = 65535

        self.node.item_id = "node1"
        self.node.hostname = 'node1'

        interface1 = mock.MagicMock(device_name="eth0",
                 network_name="test_network",
                 applied_properties=
                   {'node_ip_map': "{\"node1\" : {\"ipv4\": \"10.10.10.1\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_updated=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.3'}}",
                 node_mac_address_map=
                   "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}",
                 ipaddresses="10.10.10.3",
                 mac_prefix='52:54:00',
                 gateway="10.10.11.1",
                 gateway6="")

        interface2 = mock.MagicMock(network_name="test_network",
                 device_name="eth1",
                 applied_properties=
                   {'node_ip_map': "{\"node1\" : {\"ipv4\": \"10.10.10.2\"}}"},
                 is_initial=mock.MagicMock(return_value=False),
                 is_applied=mock.MagicMock(return_value=True),
                 is_for_removal=mock.MagicMock(return_value=False),
                 node_ip_map="{'node1': {'ipv4': '10.10.10.4'}}",
                 node_mac_address_map=
                   "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}",
                 ipaddresses="10.10.10.4",
                 mac_prefix='52:54:00',
                 gateway="10.10.11.1",
                 gateway6="")

        self.service.vm_network_interfaces = [interface1, interface2]
        self.service.get_cluster.return_value = cluster

        self.api = mock.MagicMock()
        self.api.query = _mock_vm_interface_query

        self.task_item.standby = 1
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        facade._service.get_cluster.return_value = cluster
        facade.node.hostname = 'mn1'

        a = yaml.load(facade.metadata(self.api))
        self.assertEqual(expected, a)
        self.assertEqual("{'node1': {'ipv4': '10.10.10.3'}}",
                         interface1.node_ip_map)
        self.assertEqual("{'node1': {'ipv4': '10.10.10.4'}}",
                         interface2.node_ip_map)

    def test_adaptor_data(self):

        api = mock.MagicMock()
        api.query = _mock_vm_interface_query

        cluster = mock.Mock(item_id="cluster1")
        cluster.cluster_id = 65535
        self.node.hostname = 'node1'
        self.service.get_cluster.return_value = cluster
        self.service.image_checksum = 'md5'

        self.task_item.standby = '1'
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)

        network = mock.MagicMock()
        network.subnet = "10.10.11.0/24"
        interface1 = mock.MagicMock()
        interface1.device_name = "eth0"
        interface1.network_name = "test_network"
        interface1.ipaddresses = '10.10.10.1'
        interface1.mac_prefix = '52:54:00'
        interface1.node_mac_address_map = "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}"
        interface1.node_ip_map = "{'node1': {'ipv4': '10.10.10.1'}}"
        interface1.is_for_removal.return_value = False

        interface2 = mock.MagicMock()
        interface2.network_name = "test_network"
        interface2.device_name = "eth1"
        interface2.ipaddresses = '10.10.10.2'
        interface2.mac_prefix = '52:54:00'
        interface2.node_mac_address_map = "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}"
        interface2.node_ip_map = "{'node1': {'ipv4': '10.10.10.1'}}"
        interface2.is_for_removal.return_value = False

        interface1.host_device="br0"
        interface2.host_device="br1"
        self.service.vm_network_interfaces = [interface1, interface2]

        cluster = mock.Mock(item_id="cluster1")
        cluster.cluster_id = 65535

        facade._service.get_cluster.return_value = cluster
        facade.node.hostname = 'mn1'
        facade.node.item_id = 'node1'
        facade._disks = []

        expected = {
            'adaptor_data': {
                'internal_status_check': {
                        'active': 'on',
                        'ip_address': '10.10.10.1'
                        },
                'disk_mounts': []
            },
            'version': '1.0.0',
            'vm_data': {
                'ram': '256M',
                'cpu': 2,
                'image': 'image.qcow2',
                'interfaces': {"eth0": {'host_device': 'br0', 'mac_address': '52:54:00:f1:80:7b'},
                               "eth1": {'host_device': 'br1', 'mac_address': '52:54:00:e6:44:f6'}},
                'image-checksum': 'md5',
                'yum-checksum': [],
                'zypper-checksum': [],
            }
        }
        not_for_removal = mock.Mock(return_value=False)
        host_devices = [mock.Mock(device_name="br0",
                                  ipaddress="10.10.10.100",
                                  is_for_removal=not_for_removal),
                        mock.Mock(device_name="br1",
                                  ipaddress="10.10.10.110",
                                  node_ip_map=
                                          "{'node1': {'ipv4': '10.10.10.1'}}",
                                  is_for_removal=not_for_removal)]
        self.node.query = mock.Mock(return_value=host_devices)

        self.assertEqual(
            expected,
            json.loads(facade.adaptor_data()))

    def test_adaptor_data_with_intf_for_removal(self):

        api = mock.MagicMock()
        api.query = _mock_vm_interface_query

        cluster = mock.Mock(item_id="cluster1")
        cluster.cluster_id = 65535
        self.node.hostname = 'node1'
        self.service.get_cluster.return_value = cluster
        self.service.image_checksum = 'md5'

        self.task_item.standby = '1'
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)

        network = mock.MagicMock()
        network.subnet = "10.10.11.0/24"
        interface1 = mock.MagicMock()
        interface1.device_name = "eth0"
        interface1.network_name = "test_network"
        interface1.ipaddresses = '10.10.10.1'
        interface1.mac_prefix = '52:54:00'
        interface1.node_mac_address_map = "{'65535test_vm_serviceeth0':'52:54:00:f1:80:7b'}"
        interface1.node_ip_map = "{'node1': {'ipv4': '10.10.10.1'}}"
        interface1.is_for_removal.return_value = False

        interface2 = mock.MagicMock()
        interface2.network_name = "test_network"
        interface2.device_name = "eth1"
        interface2.ipaddresses = '10.10.10.2'
        interface2.mac_prefix = '52:54:00'
        interface2.node_mac_address_map = "{'65535test_vm_serviceeth1':'52:54:00:e6:44:f6'}"
        interface2.node_ip_map = "{'node1': {'ipv4': '10.10.10.1'}}"
        interface2.is_for_removal.return_value = True

        interface1.host_device="br0"
        interface2.host_device="br1"
        self.service.vm_network_interfaces = [interface1, interface2]

        cluster = mock.Mock(item_id="cluster1")
        cluster.cluster_id = 65535

        facade._service.get_cluster.return_value = cluster
        facade.node.hostname = 'mn1'
        facade.node.item_id = 'node1'
        facade._disks = []

        expected = {
            'adaptor_data': {
                'internal_status_check': {
                        'active': 'on',
                        'ip_address': '10.10.10.1'
                        },
                'disk_mounts': []
            },
            'version': '1.0.0',
            'vm_data': {
                'ram': '256M',
                'cpu': 2,
                'image': 'image.qcow2',
                'interfaces': {"eth0": {'host_device': 'br0', 'mac_address': '52:54:00:f1:80:7b'}},
                'image-checksum': 'md5',
                'yum-checksum': [],
                'zypper-checksum': [],
            }
        }
        host_devices = [mock.Mock(device_name="br0",
                                  ipaddress="10.10.10.100"),
                        mock.Mock(device_name="br1",
                                  ipaddress="10.10.10.110",
                                  node_ip_map=
                                          "{'node1': {'ipv4': '10.10.10.1'}}")]
        self.node.query = mock.Mock(return_value=host_devices)

        self.assertEqual(
            expected,
            json.loads(facade.adaptor_data()))

    @mock.patch('libvirt_plugin.utils.get_time_zone_from_timedatectl')
    def test_get_timezone_no_file(self, get_timedatect):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        get_timedatect.return_value = "Time zone: Zone/Mock (UTC, +0000)"
        self.assertEqual("Zone/Mock", facade._get_timezone())

    @mock.patch('libvirt_plugin.utils.get_time_zone_from_timedatectl')
    def test_get_timezone_empty_file(self, get_timedatect):
        facade = VMServiceFacade(self.node, self.image, self.service,
                                 self.networks, self.ms_node, self.task_item)
        with mock.patch('__builtin__.open') as mock_open:
            # spec makes the mock object behave like a file object
            m = mock.MagicMock(spec=file)
            # needs to be accessed this way due to the context manager madness
            m.__enter__.return_value.readlines.return_value = []
            mock_open.return_value = m
            get_timedatect.return_value = \
                'Time zone: Europe/timedatectl (CEST, +0200)\n'
            self.assertEqual("Europe/timedatectl", facade._get_timezone())

    def test_from_model_gen(self):
        def mock_query(item_type, name=None):
            cs = mock.MagicMock()
            cs.standby = "0"
            cs.nodes = ['101', '102']

            cs.query = mock.MagicMock(return_value=[])
            if item_type == 'node':
                return []
            elif item_type == 'vm-image':
                return [mock.MagicMock()]
            elif item_type == 'ms':
                return [mock.Mock(network_interfaces=[
                            mock.Mock(network_name="mgmt",
                                      litp_management="true")],
                                  services=[])]
            elif item_type == 'network':
                return []
            elif item_type == 'cluster':
                cluster = mock.MagicMock()
                cluster.nodes = [mock.Mock(item_id='101'),
                                 mock.Mock(item_id='102')]
                cs_service = mock.MagicMock()
                cs_service.image_name = "test_name"
                cs_service.query = mock.MagicMock(return_value=[mock.MagicMock()])
                cs_service.standby = "0"
                cs_service.node_list = "101,102"
                cs_service.nodes = ['101', '102']
                cs_service.applied_properties = {}
                cs_service.parent.parent = cluster
                cluster.services = [cs_service]
                return [cluster]
        api = mock.MagicMock()
        api.query = mock_query

        aservice = mock.MagicMock()
        aservice.vm_yum_repos = "repos"
        aservice.vm_packages = "packages"

        aitem = mock.MagicMock()

        services = list(VMServiceFacade('a', 'b', aservice, self.networks,
                                        self.ms_node,
                                        aitem).from_model_gen(api))
        self.assertEquals(2, len(services))

    def test_in_restore_mode_True(self):

        def mock_query(item_type):
            if item_type == 'deployment':
                deployment =  mock.MagicMock()
                deployment.in_restore_mode='true'
                return [deployment]

        api = mock.MagicMock()
        api.query = mock_query
        result = VMServiceFacade._in_restore_mode(api)
        self.assertTrue(result)

    def test_in_restore_mode_False(self):

        def mock_query(item_type):
            if item_type == 'deployment':
                deployment =  mock.MagicMock()
                deployment.in_restore_mode='false'
                return [deployment]

        api = mock.MagicMock()
        api.query = mock_query
        result = VMServiceFacade._in_restore_mode(api)
        self.assertFalse(result)

    def test_is_upgrade_flag_set_True(self):

        def mock_query(item_type):
            if item_type == 'node':
                node =  mock.MagicMock()
                node.query = mock.MagicMock(
                    return_value = [mock.MagicMock(redeploy_ms='true')])
                return [node]

        api = mock.MagicMock()
        api.query = mock_query
        result = VMServiceFacade._is_upgrade_flag_set(api, 'redeploy_ms')
        self.assertTrue(result)

    def test_is_upgrade_flag_set_False(self):

        def mock_query(item_type):
            if item_type == 'node':
                node =  mock.MagicMock()
                node.query = mock.MagicMock(
                    return_value = [mock.MagicMock(redeploy_ms='false')])
                return [node]

        api = mock.MagicMock()
        api.query = mock_query
        result = VMServiceFacade._is_upgrade_flag_set(api, 'redeploy_ms')
        self.assertFalse(result)

    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set")
    def test_from_model_gen_lms_redeploy(self, mock_flag):
        mock_flag.return_value = 'true'

        def mock_query(item_type, name=None):
            cs = mock.MagicMock()
            cs.standby = "0"
            cs.nodes = ['101', '102']

            cs.query = mock.MagicMock(return_value=[])
            if item_type == 'node':
                node =  mock.MagicMock()
                node.query = mock.MagicMock(return_value=[])
                return [node]
            elif item_type == 'vm-image':
                return [mock.MagicMock()]
            elif item_type == 'ms':
                return [mock.Mock(network_interfaces=[
                            mock.Mock(network_name="mgmt",
                                      litp_management="true")],
                                  services=[])]
            elif item_type == 'network':
                return []
            elif item_type == 'cluster':
                cluster = mock.MagicMock()
                cluster.nodes = [mock.Mock(item_id='101'),
                                 mock.Mock(item_id='102')]
                cs_service = mock.MagicMock()
                cs_service.image_name = "test_name"
                cs_service.query = mock.MagicMock(return_value=[mock.MagicMock()])
                cs_service.standby = "0"
                cs_service.node_list = "101,102"
                cs_service.nodes = ['101', '102']
                cs_service.applied_properties = {}
                cs_service.parent.parent = cluster
                cluster.services = [cs_service]
                return [cluster]

        api = mock.MagicMock()
        api.query = mock_query

        aservice = mock.MagicMock()
        aservice.vm_yum_repos = "repos"
        aservice.vm_packages = "packages"

        aitem = mock.MagicMock()

        services = list(VMServiceFacade('a', 'b', aservice, self.networks,
                                        self.ms_node,
                                        aitem).from_model_gen(api))
        self.assertEquals(0, len(services))
        self.assertEquals(1, mock_flag.call_count)

    def test_have_checksums_changed(self):

        repo = mock.Mock(is_initial=mock.Mock(return_value=True),
                         is_for_removal=mock.Mock(return_value=False))
        self.facade._yum_repos = [repo]
        self.assertEqual(True,
                         self.facade._have_checksums_changed())

        repo = mock.Mock(is_initial=mock.Mock(return_value=False),
                         is_for_removal=mock.Mock(return_value=False),
                         checksum='md5',
                         applied_properties={'checksum': 'md5'})
        self.facade._yum_repos = [repo]
        self.assertEqual(False,
                         self.facade._have_checksums_changed())

        repo = mock.Mock(is_initial=mock.Mock(return_value=False),
                         checksum='md5',
                         applied_properties={'checksum': 'notmd5'})
        self.facade._yum_repos = [repo]
        self.assertEqual(True,
                         self.facade._have_checksums_changed())

    @mock.patch('libvirt_plugin.libvirt_plugin.os.path')
    def test_get_custom_file(self, mock_os_path):
        mock_os_path.exists.return_value = False
        result = self.facade._get_custom_file('dummy_template', 'dummy_target')
        self.assertIsNone(result)
        mock_os_path.exists.assert_called_once_with('dummy_template')
        mock_os_path.exists.return_value = True
        with mock.patch('__builtin__.open', mock.mock_open(read_data='file content'),
                        create=True) as m:
            result = self.facade._get_custom_file('dummy_template', 'dummy_target')
            self.assertEqual(result, [{'path': 'dummy_target', 'content': 'file content\n'}])
        m.assert_called_once_with('dummy_template', 'r')

    def test_motd_checksum(self):
        self.service.motd_checksum = 'mocked_motd_checksum'
        result = self.facade.motd_checksum
        self.assertEqual(result, 'mocked_motd_checksum')

    def test_issue_net_checksum(self):
        self.service.issue_net_checksum = 'mocked_issue_net_checksum'
        result = self.facade.issue_net_checksum
        self.assertEqual(result, 'mocked_issue_net_checksum')

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._get_vmmonitor_timeout')
    def test_get_ssh_authorized_keys(self, vm_timeout):
        vm_timeout.return_value = False
        ssh_key_1 = mock.Mock(ssh_key="type1 key1 comment1")
        ssh_key_2 = mock.Mock(ssh_key="type2 key2 comment2")
        ssh_key_1.is_for_removal.return_value = False
        ssh_key_2.is_for_removal.return_value = False

        vm_custom_scripts = mock.Mock(custom_script_names="fname1.sh,fname2,fname3.py",
                                      network_name="mgmt")

        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_zypper_repos=[], vm_packages=[],
                            vm_nfs_mounts=[], vm_disk_mounts=[],
                            vm_ram_mounts=[], vm_firewall_rules=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[ssh_key_1, ssh_key_2], hostnames=None,
                            node_hostname_map='{"node1": "test_vm_service"}',
                            vm_custom_script=[vm_custom_scripts])
        service.query.return_value = []
        facade = VMServiceFacade(self.node, self.image, service, self.networks,
                                 self.ms_node, self.task_item)
        facade._get_timezone = mock.Mock()
        facade._get_timezone.return_value = 'Europe/mock'
        timezone = 'Europe/mock'
        expected = {
            'bootcmd': [['cloud-init-per',
                         'instance',
                         'hostname',
                         'sh',
                         '-c',
                         'hostnamectl set-hostname test_vm_service']],
            'timezone': timezone,
            'ssh_authorized_keys': ['type1 key1 comment1',
                                    'type2 key2 comment2'],
            'runcmd': ['if [ -f /etc/init.d/rsyslog ]; then /sbin/service rsyslog restart;'
                       ' elif [ -f /usr/lib/systemd/system/rsyslog.service ];'
                       ' then /bin/systemctl restart rsyslog.service;'
                       ' elif [ -f /etc/init.d/syslog ];'
                       ' then /sbin/service syslog restart;'
                       ' else exit 1; fi', 'if [ -f /bin/systemctl ];'
                       ' then /bin/systemctl restart crond; fi']
        }
        self.assertEqual(expected, yaml.load(facade.userdata))
        expected_string = "#cloud-config\nbootcmd:\n"\
                          "- - cloud-init-per\n"\
                          "  - instance\n  - hostname\n  - sh\n  - -c\n"\
                          "  - hostnamectl set-hostname test_vm_service\nruncmd:\n"\
                          "- if [ -f /etc/init.d/rsyslog ]; then /sbin/service rsyslog restart;"\
                          " elif [ -f /usr/lib/systemd/system/rsyslog.service\n"\
                          "  ]; then /bin/systemctl restart rsyslog.service; elif [ -f /etc/init.d/syslog ];\n"\
                          "  then /sbin/service syslog restart; else exit 1; fi\n"\
                          "- if [ -f /bin/systemctl ]; then /bin/systemctl restart crond; fi\n"\
                          "ssh_authorized_keys:\n- type1 key1 comment1\n"\
                          "- type2 key2 comment2\ntimezone: %s\n"%timezone
        self.assertEqual(expected_string, facade.userdata)

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._get_vmmonitor_timeout')
    def test_get_vm_firewall_rules(self, vm_timeout):
        vm_timeout.return_value = False
        rule_1 = mock.Mock(properties={"name":"10 some name",
                                        "provider":"iptables",
                                        "action":"accept",
                                        "source":"10.10.10.10/22",
                                        "proto":"tcp",
                                        "dport":"22"}
                            )
        rule_2 = mock.Mock(properties={"name":"1 some other name",
                                        "provider":"ip6tables",
                                        "action":"accept",
                                        "proto":"udp",
                                        "dport":"8080"}
                            )
        rule_3 = mock.Mock(properties={"name":"100 name",
                                        "provider":"iptables",
                                        "action":"drop",
                                        "proto":"tcp",
                                        "dport":"1000-1050"}
                            )
        rule_4 = mock.Mock(properties={"name":"50 another_name",
                                        "provider":"iptables",
                                        "action":"accept",
                                        "proto":"udp",
                                        "dport":"2020"}
                            )

        rule_1.is_for_removal.return_value = False
        rule_2.is_for_removal.return_value = False
        rule_3.is_for_removal.return_value = False
        rule_4.is_for_removal.return_value = False

        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_zypper_repos=[],
                            vm_packages=[], vm_nfs_mounts=[],
                            vm_disk_mounts=[], vm_ram_mounts=[],
                            vm_firewall_rules=[rule_1, rule_2, rule_3, rule_4],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames=None,
                            node_hostname_map='{"node1": "test_vm_service"}',
                            vm_custom_script=[], image_name='test_image_name')

        facade = VMServiceFacade(self.node, self.image, service, self.networks,
                                 self.ms_node, self.task_item)

        facade._get_timezone = lambda : []
        facade._get_runcmds = lambda : []
        facade._get_hostname_bootcmds = lambda : []

        expected = {
            'timezone': [],
            'runcmd': [],
            'bootcmd': ['if [ -f /sbin/iptables ]; then iptables_dir="/sbin"; elif [ -f /usr/sbin/iptables ]; then iptables_dir="/usr/sbin"; fi',
                        "\\$iptables_dir/ip6tables -A INPUT -p udp -m udp --dport 8080 -m comment --comment \"1 some other name\" -m state --state NEW -j ACCEPT",
                        "\\$iptables_dir/ip6tables -A OUTPUT -p udp -m udp --dport 8080 -m comment --comment \"1 some other name\" -m state --state NEW -j ACCEPT",
                        "\\$iptables_dir/iptables -A INPUT -s 10.10.10.10/22 -p tcp -m tcp --dport 22 -m comment --comment \"10 some name\" -m state --state NEW -j ACCEPT",
                        "\\$iptables_dir/iptables -A OUTPUT -s 10.10.10.10/22 -p tcp -m tcp --dport 22 -m comment --comment \"10 some name\" -m state --state NEW -j ACCEPT",
                        "\\$iptables_dir/iptables -A INPUT -p udp -m udp --dport 2020 -m comment --comment \"50 another_name\" -m state --state NEW -j ACCEPT",
                        "\\$iptables_dir/iptables -A OUTPUT -p udp -m udp --dport 2020 -m comment --comment \"50 another_name\" -m state --state NEW -j ACCEPT",
                        "\\$iptables_dir/iptables -A INPUT -p tcp -m tcp --dport 1000:1050 -m comment --comment \"100 name\" -m state --state NEW -j DROP",
                        "\\$iptables_dir/iptables -A OUTPUT -p tcp -m tcp --dport 1000:1050 -m comment --comment \"100 name\" -m state --state NEW -j DROP"]
        }
        self.assertEqual(expected, yaml.load(facade.userdata))

    @mock.patch('libvirt_plugin.utils.get_checksum')
    def test_image_checksum_initial(self, get_checksum):
        self.service.is_initial.return_value = True
        get_checksum.return_value = 'md5'
        self.facade._image.checksum = 'md5'
        self.assertEqual(True, self.facade._image_checksum_updated())

    def test_image_checksum_updated(self):
        self.service.is_initial.return_value = False
        self.facade._service.image_checksum = 'other_md5'
        self.facade._service.applied_properties = {'image_checksum':
                                                       'md5'}
        self.assertEqual(True, self.facade._image_checksum_updated())

        # If the applied_property is equal to get_checksum then return False
        self.facade._service.image_checksum = 'md5'
        self.assertEqual(False, self.facade._image_checksum_updated())

    def test_deploy_metadata(self):
        self.service.is_initial = lambda: False
        self.service.get_cluster.return_value = mock.Mock(cluster_id="1524")
        self.facade.vm_task_item = mock.Mock(standby="0")

        interface1 = mock.Mock(device_name="eth0", gateway=None, gateway6=None)
        interface1.is_initial.return_value = False
        interface1.is_for_removal.return_value = False
        interface1.applied_properties = {'node_ip_map':
                                           "{'node1': {'ipv4': '10.10.10.10'}}",
                                         'node_mac_address_map':
                                             "{'1524n1-fooeth0':'mac1'}",
                                         'ipaddresses': '10.10.10.10',
                                         'network_name': 'mgmt'}
        interface1.node_ip_map = "{'node1': {'ipv4': '10.10.10.10'}}"
        interface1.node_mac_address_map = "{'1524n1-fooeth0':'mac1'}"
        interface1.network_name = 'mgmt'

        interface2 = mock.Mock(device_name="eth1", gateway=None, gateway6=None)
        interface2.is_initial.return_value = False
        interface2.is_for_removal.return_value = False
        interface2.applied_properties = {'node_ip_map':
                                           "{'node1': {'ipv4': '10.10.10.11'}}",
                                         'node_mac_address_map':
                                             "{'1524n1-fooeth1':'mac2'}",
                                         'ipaddresses': '10.10.10.11',
                                         'network_name': 'mgmt'}
        interface2.node_ip_map = "{'node1': {'ipv4': '10.10.10.11'}}"
        interface2.node_mac_address_map = "{'1524n1-fooeth1':'mac2'}"
        interface2.network_name = 'mgmt'

        interface3 = mock.Mock(device_name="eth1", gateway=None, gateway6=None)
        interface3.is_initial.return_value = False
        interface3.is_for_removal.return_value = False
        interface3.applied_properties = {'node_ip_map': "{}",
                                         'node_mac_address_map':
                                             "{'1524n1-fooeth1':'mac2'}",
                                         'ipaddresses': 'dhcp',
                                         'network_name': 'mgmt'}
        interface3.node_ip_map = "{}"
        interface3.ipaddresses = 'dhcp'
        interface3.network_name = 'mgmt'
        interface3.node_mac_address_map = "{'1524n1-fooeth1':'mac2'}"

        interfaces = [interface1, interface2, interface3]
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertFalse(self.facade.deploy_metadata())

        # Expands network subnet
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._networks[0].subnet = '10.10.10.0/23'
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

        # Reset network to not affect following tests
        self.facade._networks[0].subnet = '10.10.10.0/24'

        # Interface 2 initial
        interface2.is_initial.return_value = True
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

        # Updates interface
        interface2.node_ip_map = "{'node1': {'ipv4': '10.10.10.12'}}"
        interface2.is_initial.return_value = False
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

        # Updates mac
        interface2.node_ip_map = "{'node1': {'ipv4': '10.10.10.11'}}"
        interface2.node_mac_address_map = "{'1524n1-fooeth1':'mac3'}"
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

        # Updates interface 3
        interface2.node_mac_address_map = "{'1524n1-fooeth1':'mac2'}"
        interface3.ipaddresses = "10.10.10.13"
        interface3.node_ip_map = "{'node1': {'ipv4': '10.10.10.13'}}"
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

        # updates interface 2
        interface3.ipaddresses = "dhcp"
        interface3.node_ip_map = "{}"
        interface2.ipaddresses = "dhcp"
        interface2.node_ip_map = "{}"
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

        #updates interface 2
        interface2.ipaddresses='10.10.10.11'
        interface2.node_ip_map = "{'node1': {'ipv4': '10.10.10.11'}}"
        interface2.gateway = '10.10.10.1'
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

        #Updates interface 2
        interface2.gateway = None
        interface2.gateway6 = '2607:f0d0:1002:7516::1'
        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade._service.applied_properties = {'service_name': 'foo'}
            self.facade._service.service_name = 'foo'
            self.assertTrue(self.facade.deploy_metadata())

    def test_deploy_userdata(self):
        self.service.is_initial = lambda: False
        self.service.applied_properties = {'node_hostname_map':
                                             "{'node1': 'n1-service1'}"}
        self.service.node_hostname_map = "{'node1': 'n1-service1'}"

        self.facade.hostname_updated = mock.Mock(return_value=False)
        self.facade.userdata_model_items = mock.Mock(return_value=[])
        self.facade._image.is_updated = mock.Mock(return_value=False)
        self.facade._image_checksum_updated = mock.Mock(return_value=False)
        self.facade._updated_status_timeout = mock.Mock(return_value=False)
        self.facade._motd_updated = mock.Mock(return_value=False)
        self.facade._issue_net_updated = mock.Mock(return_value=False)

        redeployable_path = 'libvirt_plugin.libvirt_plugin.utils.redeployable'
        with mock.patch(redeployable_path) as redeployable:
            redeployable.return_value = False
            self.assertFalse(self.facade.deploy_userdata())

            self.facade._image.is_updated.return_value = True
            self.assertTrue(self.facade.deploy_userdata())
            self.facade._image.is_updated.return_value = False

            self.facade._image_checksum_updated.return_value = True
            self.assertTrue(self.facade.deploy_userdata())
            self.facade._image_checksum_updated.return_value = False

            self.facade._updated_status_timeout.return_value = True
            self.assertTrue(self.facade.deploy_userdata())
            self.facade._updated_status_timeout.return_value = False

            self.facade._motd_updated.return_value = True
            self.assertTrue(self.facade.deploy_userdata())
            self.facade._motd_updated.return_value = False

            self.facade._issue_net_updated.return_value = True
            self.assertTrue(self.facade.deploy_userdata())
            self.facade._issue_net_updated.return_value = False

            redeployable.return_value = True
            self.assertTrue(self.facade.deploy_userdata())

            self.facade.hostname_updated.return_value = True
            self.assertTrue(self.facade.deploy_userdata())

    def test_deploy_image(self):
        self.service.is_initial = lambda: False
        self.facade._service.applied_properties = {'image_name': 'foo',
                                                   'image_checksum':
                                                       'checksum'}
        self.facade._service.image_name = 'foo'
        self.facade._service.image_checksum = 'checksum'
        self.assertFalse(self.facade.deploy_image())
        self.facade._service.image_name = 'bar'
        self.assertTrue(self.facade.deploy_image())
        self.facade._service.applied_properties['image_checksum'] = 'new'
        self.assertTrue(self.facade.deploy_image())

    def test_deploy_config(self):
        self.service.is_initial = lambda: False
        self.service.get_cluster.return_value = mock.Mock(cluster_id="1524")
        self.service.applied_properties = {
            "cpus": self.service.cpus,
            "ram": self.service.ram,
            "internal_status_check": self.service.internal_status_check
        }
        self.facade.vm_task_item = mock.Mock(standby="0")

        interface1 = mock.Mock(device_name="eth0", gateway=None, gateway6=None)
        interface1.is_initial.return_value = False
        interface1.is_for_removal.return_value = False
        interface1.applied_properties_determinable = True
        interface1.applied_properties = {'node_ip_map':
                                             "{'node1': '10.10.10.10'}",
                                         'node_mac_address_map':
                                             "{'1524n1-test_vm_serviceeth0':'mac1'}",
                                         'ipaddresses': '10.10.10.10',
                                         'network_name': 'mgmt'}
        interface1.node_ip_map = "{'node1': {'ipv4': '10.10.10.10'}}"
        interface1.node_mac_address_map = "{'1524n1-test_vm_serviceeth0':'mac1'}"
        interface1.network_name = 'mgmt'

        interface2 = mock.Mock(device_name="eth1", gateway=None, gateway6=None)
        interface2.is_initial.return_value = False
        interface2.is_for_removal.return_value = False
        interface2.applied_properties_determinable = True
        interface2.applied_properties = {'node_ip_map':
                                             "{'node1': '10.10.10.11'}",
                                         'node_mac_address_map':
                                             "{'1524n1-test_vm_serviceeth1':'mac2'}",
                                         'ipaddresses': '10.10.10.11',
                                         'network_name': 'mgmt'}
        interface2.node_ip_map = "{'node1': {'ipv4': '10.10.10.11'}}"
        interface2.node_mac_address_map = "{'1524n1-test_vm_serviceeth1':'mac2'}"
        interface2.network_name = 'mgmt'
        interfaces = [interface1, interface2]

        with mock.patch.object(self.facade, '_interfaces', interfaces):
            self.facade.get_updated_vm_disk_mounts = mock.Mock()
            self.facade.get_updated_vm_disk_mounts.return_value = []
            self.facade.deploy_image = lambda: False
            self.facade._have_checksums_changed = lambda: False
            self.assertFalse(self.facade.deploy_config(None))

            # Expands network subnet
            self.facade._networks[0].subnet = '10.10.10.0/23'
            self.assertTrue(self.facade.deploy_config(None))

            # Reset network to not affect following tests
            self.facade._networks[0].subnet = '10.10.10.0/24'

            self.facade.deploy_image = lambda: True
            self.facade._have_checksums_changed = lambda: False
            self.assertTrue(self.facade.deploy_config(None))
            self.facade.deploy_image = lambda: False
            self.facade._have_checksums_changed = lambda: True
            self.assertTrue(self.facade.deploy_config(None))

            # interface initial
            interface2.is_initial.return_value = True
            self.facade.deploy_image = lambda: False
            self.facade._have_checksums_changed = lambda: False
            self.assertTrue(self.facade.deploy_config(None))

            # updates interfaces
            interface2.is_initial.return_value = False
            interface2.node_mac_address_map = "{'1524n1-test_vm_serviceeth1':'mac3'}"
            self.facade.deploy_image = lambda: False
            self.facade._have_checksums_changed = lambda: False
            self.assertTrue(self.facade.deploy_config(None))

    def test_deploy_config_properties_no_updated(self):
        self.service.is_initial = lambda: False
        self.facade.deploy_image = lambda: False
        self.facade._have_checksums_changed = lambda: False
        self.facade._disks = []

        self.service.applied_properties = {"cpus": self.service.cpus,
            "ram": self.service.ram,
            "internal_status_check": self.service.internal_status_check,
            "adaptor_version": "1.1.0-1",
            "vm_disk_mounts": [],
        }

        pkg_version = {"name":"ERIClitpmnlibvirt_CXP9031529",
                       "version":"1.1.0","release":"1", "arch":"noarch"}

        # No package found
        self.assertFalse(self.facade.deploy_config(None))
        # Same package version
        self.assertFalse(self.facade.deploy_config(pkg_version))

    def test_deploy_config_properties_updated(self):
        self.service.is_initial = lambda: False
        self.facade.deploy_image = lambda: False
        self.facade._have_checksums_changed = lambda: False

        self.service.applied_properties = {"cpus": self.service.cpus,
            "ram": self.service.ram,
            "internal_status_check": self.service.internal_status_check,
            "adaptor_version": "1.1.0-1"}

        pkg_version = {"name":"ERIClitpmnlibvirt_CXP9031529",
                       "version":"1.1.0","release":"2", "arch":"noarch"}

        # package version updated
        self.assertTrue(self.facade.deploy_config(pkg_version))

        # cpus updated
        self.service.applied_properties["cpus"] = "5"
        self.assertTrue(self.facade.deploy_config(None))

    def test_redeployable_initial(self):
        self.service.is_initial = lambda: True
        self.service.is_for_removal = lambda: False
        self.assertTrue(self.facade.deploy_config(None))
        self.assertTrue(self.facade.deploy_image())
        self.assertTrue(self.facade.deploy_userdata())
        self.assertTrue(self.facade.deploy_metadata())

    def test_new_nodes_clustered_service_initial(self):
        node = mock.Mock(spec=ModelItem, item_id='n1')
        clustered_service = mock.Mock(node_list='n1',
                                      nodes=[node])
        clustered_service.applied_properties.get.side_effect = AttributeError
        facade = VMServiceFacade(node, mock.Mock(), self.service,
                                 self.networks, self.ms_node, clustered_service)
        self.assertEquals(set(['n1']), facade._new_nodes())

    def test_new_nodes_clustered_service(self):
        node1 = mock.Mock(spec=ModelItem, item_id='node1')

        clustered_service = mock.Mock(node_list='node1,new_node1,new_node2,node2')
        clustered_service.applied_properties.get.return_value = 'node1,node2'
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node, clustered_service)
        self.assertEquals(set(['new_node1','new_node2']), facade._new_nodes())

    def test_is_for_removal__nothing_for_removal(self):
        node1 = mock.Mock(spec=ModelItem, item_id='node1')

        clustered_service = mock.Mock(node_list='node1,node2')
        clustered_service.applied_properties.get.return_value = 'node1,node3'
        self.service.is_for_removal.return_value = False
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node, clustered_service)
        self.assertFalse(facade.is_for_removal())

    def test_is_for_removal__no_service(self):
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        self.service.is_for_removal.return_value = True
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service=None)
        self.assertTrue(facade.is_for_removal())

    def test_is_for_removal__no_service_no_removal(self):
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        self.service.is_for_removal.return_value = False
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service=None)
        self.assertFalse(facade.is_for_removal())

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._removed_nodes')
    def test_is_for_removal_one_node(self, patch_remove_nodes):
        patch_remove_nodes.return_value = set(['node1'])
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        self.service.is_for_removal.return_value = False
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service=None)
        self.assertEqual(facade.is_for_removal(), True)

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._removed_nodes')
    def test_is_initial_apd_sg_node_for_removal_false(self, patch_remove_nodes):
        patch_remove_nodes.return_value = set(['node1'])
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        self.service.is_for_removal.return_value = False
        self.service.is_initial.return_value = False
        self.service.applied_properties_determinable = False
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service=None)
        self.assertEqual(facade.is_initial(), False)

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._new_nodes')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._removed_nodes')
    def test_is_initial_apd_sg_node_for_removal_true(self, patch_remove_nodes, patch_new_nodes):
        patch_remove_nodes.return_value = set()
        patch_new_nodes.return_value = set()
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        self.service.is_for_removal.return_value = False
        self.service.is_initial.return_value = False
        self.service.applied_properties_determinable = False
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service=None)
        self.assertEqual(facade.is_initial(), True)

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._new_nodes')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._removed_nodes')
    def test_is_initial_apd_true_sg_node_for_removal_true(self, patch_remove_nodes, patch_new_nodes):
        patch_remove_nodes.return_value = set()
        patch_new_nodes.return_value = set()
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        self.service.is_for_removal.return_value = False
        self.service.is_initial.return_value = False
        self.service.applied_properties_determinable = True
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service=None)
        self.assertEqual(facade.is_initial(), False)

    def test_is_initial_clustered_service_new_node(self):
        new_node1 = mock.Mock(spec=ModelItem, item_id='new_node1')

        clustered_service = mock.Mock(node_list='node1,node3,new_node1,node2')
        clustered_service.applied_properties.get.return_value = 'node1,node2,node3'
        self.service.is_initial.return_value = False
        self.service.is_for_removal.return_value = False
        facade = VMServiceFacade(new_node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service)
        self.assertEquals(set(['new_node1']), facade._new_nodes())
        self.assertTrue(facade.is_initial())

    def test_is_initial_clustered_service_no_new_node(self):
        node1 = mock.Mock(spec=ModelItem, item_id='node1')

        clustered_service = mock.Mock(node_list='node1,node3,new_node1,node2')
        clustered_service.applied_properties.get.return_value = 'node1,node2,node3'
        self.service.is_initial.return_value = False
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service)
        self.assertEquals(set(['new_node1']), facade._new_nodes())
        self.assertFalse(facade.is_initial())

    def test_removed_nodes_clustered_service_initial(self):
        node = mock.Mock(spec=ModelItem, item_id='n1')
        clustered_service = mock.Mock(node_list='n1',
                                      nodes=[node])
        clustered_service.applied_properties.get.side_effect = AttributeError
        facade = VMServiceFacade(node, mock.Mock(), self.service,
                                 self.networks, self.ms_node, clustered_service)
        self.assertEquals(set(), facade._removed_nodes())

    def test_removed_nodes_clustered_service(self):
        node1 = mock.Mock(spec=ModelItem, item_id='node1')

        clustered_service = mock.Mock(node_list='node2')
        clustered_service.applied_properties.get.return_value = 'node1,node2,node3'
        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                 self.networks, self.ms_node,
                                 clustered_service)
        self.assertEquals(set(['node1','node3']),
                          facade._removed_nodes())

    def test_removed_nodes_service(self):
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        self.service.is_for_removal = lambda:True

        facade = VMServiceFacade(node1, mock.Mock(), self.service,
                                self.networks, self.ms_node)
        self.assertEquals(set(['node1']),
                          facade._removed_nodes())

    def test_config_model_items(self):
        interface1 = mock.Mock(is_initial=lambda:True, network_name='mgmt')
        self.facade._interfaces = [interface1]
        repo1 = mock.Mock(get_state=lambda:ModelItem.Initial)
        repo2 = mock.Mock(get_state=lambda:ModelItem.Updated)
        repo3 = mock.Mock(get_state=lambda:ModelItem.Applied)
        self.facade._yum_repos = [repo1, repo2, repo3]
        self.facade._zypper_repos = [repo1, repo2, repo3]
        self.facade._disks = []
        self.assertEquals(set([interface1, repo1, repo2]),
                          set(self.facade.config_model_items()))

    def test_update_task_required(self):
        service = mock.Mock()
        service.is_initial.return_value = False
        service.is_updated.return_value = True
        service.is_applied.return_value = True
        service.is_for_removal.return_value = False
        node1 = mock.Mock(spec=ModelItem, item_id='node1')
        facade = VMServiceFacade(node1, mock.Mock(), service, self.networks,
                                 self.ms_node)

        self.assertTrue(facade.update_task_required())

        # initial service
        service.is_initial.return_value = True
        service.is_updated.return_value = False
        service.is_applied.return_value = False
        self.assertFalse(facade.update_task_required())

        # service for removal
        service.is_initial.return_value = False
        service.is_updated.return_value = False
        service.is_applied.return_value = False
        service.is_for_removal.return_value = True
        self.assertFalse(facade.update_task_required())

        #service updated
        #service.is_updated.return_value = True
        #service.is_applied.return_value = False
        #self.assertTrue(facade.update_task_required())

        #service applied
        #service.is_updated.return_value = False
        #service.is_applied.return_value = True
        #self.assertTrue(facade.update_task_required())

        # non clustered service
        #service.is_for_removal.return_value = False
        #clustered_service = mock.MagicMock()
        #facade = VMServiceFacade(node1, mock.Mock(), service,
        #                         self.networks, clustered_service)
        #self.assertFalse(bool(facade.update_task_required()))

    def test_deploy_userdata_with_new_image(self):
        self.facade.hostname_updated = mock.Mock(return_value=False)
        self.facade.userdata_model_items = mock.Mock(return_value=[])
        self.facade._image.is_updated = mock.Mock(return_value=False)
        self.facade._image_checksum_updated = mock.Mock(return_value=False)
        self.facade._updated_status_timeout = mock.Mock(return_value=False)
        self.facade._motd_updated = mock.Mock(return_value=False)
        self.facade._issue_net_updated = mock.Mock(return_value=False)

        self.assertFalse(self.facade.deploy_userdata())

        self.facade._image.is_updated = mock.Mock(return_value=True)
        self.assertTrue(self.facade.deploy_userdata())
        self.facade._image.is_updated = mock.Mock(return_value=False)

        self.assertFalse(self.facade.deploy_userdata())
        self.facade._image_checksum_updated = mock.Mock(return_value=True)
        self.assertTrue(self.facade.deploy_userdata())
        self.facade._image_checksum_updated = mock.Mock(return_value=False)

        self.assertFalse(self.facade.deploy_userdata())
        self.facade._updated_status_timeout = mock.Mock(return_value=True)
        self.assertTrue(self.facade.deploy_userdata())
        self.facade._updated_status_timeout = mock.Mock(return_value=False)

    def test_updated_status_timeout(self):
        ha_cfg = mock.Mock()
        ha_cfg.applied_properties = {'status_timeout': '60'}
        ha_cfg.status_timeout = '60'
        self.facade._clustered_service = mock.Mock()
        self.facade._clustered_service.query.return_value = [ha_cfg]
        self.assertFalse(self.facade._updated_status_timeout())
        ha_cfg.status_timeout = '50'
        self.assertTrue(self.facade._updated_status_timeout())
        self.facade._clustered_service.query.return_value = []
        self.assertFalse(self.facade._updated_status_timeout())

    def test_deploy_config_cpuset(self):
        service = mock.Mock(name='mocked_service',
                            cpus=2, ram='256M', cpuset=None, cpunodebind=None,
                            internal_status_check='off',
                            vm_network_interfaces=[], vm_yum_repos=[],
                            vm_zypper_repos=[],
                            vm_disk_mounts=[], is_initial=lambda: False,
                            applied_properties={},
                            image_checksum='123',
                            service_name='test',
                            image_name='img',
                            vm_disks=[])
        service.applied_properties = {
            'cpus': 2,
            'ram': '256M',
            'internal_status_check': 'off',
            'image_checksum': '123',
            'service_name': 'test',
            'image_name': 'img'
        }

        instance = VMServiceFacade(self.node, self.image, service,
                                   self.networks, self.ms_node)

        self.assertFalse(instance.deploy_config(None))

        # Expect a change if cpuset is set on an applied item with cpuset unset
        service.cpuset = '1,2,3'
        self.assertTrue(instance.deploy_config(None))

        # Expect no change if cpuset hasn't changed
        service.applied_properties['cpuset'] = '0-1'
        service.cpuset = '0-1'
        self.assertFalse(instance.deploy_config(None))

        # Expect a change if cpuset is updated
        service.cpuset = '0-9'
        self.assertTrue(instance.deploy_config(None))

        # Expect a change if cpuset is deleted
        service.cpuset = None
        self.assertTrue(instance.deploy_config(None))

    def test_adapter_data_cpuset(self):
        service = mock.Mock(name='mocked_service',
                            cpus=2, ram='256M', cpuset=None, cpunodebind=None,
                            internal_status_check='off',
                            vm_network_interfaces=[], vm_yum_repos=[],
                            vm_zypper_repos=[], vm_disk_mounts=[])
        service.vm_disks = []
        service.image_checksum = 'image_checksum'

        instance = VMServiceFacade(self.node, self.image, service,
                                   self.networks, self.ms_node)
        config = json.loads(instance.adaptor_data())
        self.assertFalse('cpuset' in config['vm_data'])

        service.cpuset = '0-2'
        config = json.loads(instance.adaptor_data())
        self.assertTrue('cpuset' in config['vm_data'])
        self.assertEqual('0-2', config['vm_data']['cpuset'])

        service.cpuset = '8,9'
        config = json.loads(instance.adaptor_data())
        self.assertTrue('cpuset' in config['vm_data'])
        self.assertEqual('8,9', config['vm_data']['cpuset'])

        service.cpuset = None
        config = json.loads(instance.adaptor_data())
        self.assertFalse('cpuset' in config['vm_data'])

    def test_deploy_config_cpunodebind(self):
        service = mock.Mock(name='mocked_service',
                            cpus=2, ram='256M', cpuset=None, cpunodebind=None,
                            internal_status_check='off',
                            vm_network_interfaces=[], vm_yum_repos=[],
                            vm_zypper_repos=[],
                            vm_disk_mounts=[], is_initial=lambda: False,
                            applied_properties={},
                            image_checksum='123',
                            service_name='test',
                            image_name='img',
                            vm_disks=[])
        service.applied_properties = {
            'cpus': 2,
            'ram': '256M',
            'internal_status_check': 'off',
            'image_checksum': '123',
            'service_name': 'test',
            'image_name': 'img'
        }

        instance = VMServiceFacade(self.node, self.image, service,
                                   self.networks, self.ms_node)

        self.assertFalse(instance.deploy_config(None))

        # Expect a change if cpuset is set on an applied item with cpuset unset
        service.cpunodebind = '1,2,3'
        self.assertTrue(instance.deploy_config(None))

        # Expect no change if cpuset hasn't changed
        service.applied_properties['cpunodebind'] = '0-1'
        service.cpunodebind = '0-1'
        self.assertFalse(instance.deploy_config(None))

        # Expect a change if cpuset is updated
        service.cpunodebind = '0'
        self.assertTrue(instance.deploy_config(None))

        # Expect a change if cpuset is deleted
        service.cpunodebind = None
        self.assertTrue(instance.deploy_config(None))

    def test_adapter_data_cpunodebind(self):
        service = mock.Mock(name='mocked_service',
                            cpus=2, ram='256M', cpuset=None, cpunodebind=None,
                            internal_status_check='off',
                            vm_network_interfaces=[], vm_yum_repos=[],
                            vm_zypper_repos=[], vm_disk_mounts=[])
        service.vm_disks = []
        service.image_checksum = 'image_checksum'

        instance = VMServiceFacade(self.node, self.image, service,
                                   self.networks, self.ms_node)
        config = json.loads(instance.adaptor_data())
        self.assertFalse('cpunodebind' in config['vm_data'])

        service.cpunodebind = '0'
        config = json.loads(instance.adaptor_data())
        self.assertTrue('cpunodebind' in config['vm_data'])
        self.assertEqual('0', config['vm_data']['cpunodebind'])

        service.cpunodebind = '8,9'
        config = json.loads(instance.adaptor_data())
        self.assertTrue('cpunodebind' in config['vm_data'])
        self.assertEqual('8,9', config['vm_data']['cpunodebind'])

        service.cpunodebind = None
        config = json.loads(instance.adaptor_data())
        self.assertFalse('cpunodebind' in config['vm_data'])


class TestLibvirtPlugin(unittest.TestCase):

    def setUp(self):
        self.model = ModelManager()
        self.puppet_manager = PuppetManager(self.model)
        self.plugin_manager = PluginManager(self.model)
        self.context = PluginApiContext(self.model)
        self.execution = ExecutionManager(self.model,
                                          self.puppet_manager,
                                          self.plugin_manager)

        self.plugin_manager.add_property_types(
            CoreExtension().define_property_types())
        self.plugin_manager.add_item_types(
            CoreExtension().define_item_types())
        self.plugin_manager.add_property_types(
            NetworkExtension().define_property_types())
        self.plugin_manager.add_item_types(
            NetworkExtension().define_item_types())
        self.plugin_manager.add_property_types(
            YumExtension().define_property_types())
        self.plugin_manager.add_item_types(
            YumExtension().define_item_types())
        self.plugin_manager.add_property_types(
            LibvirtExtension().define_property_types())
        self.plugin_manager.add_item_types(
            LibvirtExtension().define_item_types())

        self.plugin_manager.add_default_model()
        self.plugin = LibvirtPlugin()
        self.plugin_manager.add_plugin('TestPlugin', 'some.test.plugin',
                                       '1.0.0', self.plugin)

        self.model.item_types.pop('root')
        self.model.register_item_type(ItemType("root",
                                        nodes=Collection("node"),
                                        ms=Child("ms"),
                                        libvirt1=Child("libvirt-provider")
                                        )
                                     )
        self.model.create_root_item("root", "/")

        my_yum_base_class = mock.Mock()
        my_yum_base_class.return_value = my_yum_base_class
        my_yum_base_class.doPackageLists.return_value = mock.Mock(available=[], installed=[])
        self.yumbase_mock = my_yum_base_class

        self.networks = [ _build_mock_network() ]

    def setup_base_model(self):
        self.setup_libvirt_model_items()

    def setup_libvirt_model_items(self):
        self.libvirt_provider = self.model.create_item("libvirt-provider",
                                                       "/libvirt1",
                                                       name="libvirt1",
                                                       bridge='br0')
        self.assertEqual(ModelItem, type(self.libvirt_provider))
        self.vm1 = self.model.create_item("libvirt-system",
                                          "/libvirt1/systems/vm1",
                                          system_name="vm1")
        self.assertEqual(ModelItem, type(self.vm1))
        self.vm2 = self.model.create_item("libvirt-system",
                                          "/libvirt1/systems/vm2",
                                          system_name="vm2")
        self.libvirt = self.model.create_inherited("/libvirt1",
                                              "/ms/libvirt")
        self.assertEqual(ModelItem, type(self.libvirt))

        self.eth0 = self.model.create_item("eth",
                                           "/ms/network_interfaces/if0",
                                           network_name="nodes",
                                           device_name="eth0",
                                           ipaddress="10.10.10.100",
                                           macaddress="08:00:27:5B:C1:3F")
        self.assertEqual(ModelItem, type(self.eth0))

    def setup_multiple_disks_on_libvirt_items(self):
        disk1 = self.model.create_item("disk",
                                       "/libvirt1/systems/vm1/disks/disk1",
                                       name="sda1", size="28G", uuid="ATA1")
        self.assertEqual(ModelItem, type(disk1))
        disk2 = self.model.create_item("disk",
                                       "/libvirt1/systems/vm1/disks/disk2",
                                       name="sda2", size="28G", uuid="ATA1")
        self.assertEqual(ModelItem, type(disk2))

    def setup_2_nodes(self):
        self.node1 = self.model.create_item("node", "/nodes/node1",
                                             hostname="node1")
        self.assertEqual(ModelItem, type(self.node1))
        self.node2 = self.model.create_item("node", "/nodes/node2",
                                            hostname="node2")
        self.assertEqual(ModelItem, type(self.node2))
        self.node1_system = self.model.create_inherited(
                                              "/libvirt1/systems/vm1",
                                              "/nodes/node1/system")

        self.assertEqual(ModelItem, type(self.node1_system))
        self.node2_system = self.model.create_inherited(
                                              "/libvirt1/systems/vm2",
                                              "/nodes/node2/system")
        self.assertEqual(ModelItem, type(self.node2_system))

    def setup_bridge(self):
        self.br0 = self.model.create_item("bridge",
                                          "/ms/network_interfaces/if1",
                                          device_name="br0",
                                          stp="false",
                                          forwarding_delay="30",
                                          network_name="nodes",
                                          ipaddress="10.10.10.101")
        self.assertEqual(ModelItem, type(self.br0))

        self.model.update_item("/ms/network_interfaces/eth0",
                               bridge="br0")

    def query(self, item_type=None, **kwargs):
        return self.context.query(item_type, **kwargs)

    def query_by_vpath(self, vpath):
        if vpath == "/":
            root = mock.MagicMock()
            root.query = self.context.query
            return root

        return self.context.query_by_vpath(vpath)

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_remove_1_vms(self, repo_cmd_mock):
        self.setup_base_model()
        self.setup_2_nodes()

        self.model.set_all_applied()

        result = self.model.remove_item("/nodes/node1/system")
        self.assertNotEqual(list, type(result))

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(1, len(tasks))

        task0 = tasks[0]
        self.assertEqual(ConfigTask, type(task0))
        self.assertEqual("Initial", task0.state)
        self.assertEqual("/nodes/node1/system", task0.model_item.get_vpath())
        self.assertEqual('Delete VM "vm1"', task0.description)
        self.assertEqual("koan::remove", task0.call_type)
        self.assertEqual("vm1", task0.call_id)
        self.assertEqual("vm1", task0.kwargs['system_name'])
        self.assertEqual("/var/lib/libvirt/images", task0.kwargs['path'])

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_remove_2_vms(self, repo_cmd_mock):
        self.setup_base_model()
        self.setup_2_nodes()

        self.model.set_all_applied()

        result = self.model.remove_item("/nodes/node2/system")
        self.assertNotEqual(list, type(result))
        result = self.model.remove_item("/nodes/node1/system")
        self.assertNotEqual(list, type(result))

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(2, len(tasks))

        task1_expected_props = [ConfigTask,
                                '/nodes/node1/system',
                                'Initial',
                                'koan::remove',
                                '/var/lib/libvirt/images',
                                'Delete VM "vm1"',
                                'vm1',
                                'vm1']

        task2_expected_props = [ConfigTask,
                                '/nodes/node2/system',
                                'Initial',
                                'koan::remove',
                                '/var/lib/libvirt/images',
                                'Delete VM "vm2"',
                                'vm2',
                                'vm2']

        task_expected_props = [task1_expected_props, task2_expected_props]
        for task in tasks:
            task_props = [type(task),
                          task.model_item.get_vpath(),
                          task.state,
                          task.call_type,
                          task.kwargs['path'],
                          task.description,
                          task.call_id,
                          task.kwargs['system_name']]
            self.assertTrue(any(prop == task_props for prop in task_expected_props))

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_positive_with_2_nodes(self, repo_cmd_mock):
        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()

        repo_cmd_mock.return_value = None
        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(2, len(tasks))

        task1_expected_props = [ConfigTask,
                                '/nodes/node1/system',
                                'Initial',
                                'koan::config',
                                '/var/lib/libvirt/images',
                                'br0',
                                '10.10.10.101',
                                'Create VM "vm1"',
                                'vm1',
                                'vm1',
                                'node1']

        task2_expected_props = [ConfigTask,
                                '/nodes/node2/system',
                                'Initial',
                                'koan::config',
                                '/var/lib/libvirt/images',
                                'br0',
                                '10.10.10.101',
                                'Create VM "vm2"',
                                'vm2',
                                'vm2',
                                'node2']

        expected_props = [task1_expected_props, task2_expected_props]
        for task in tasks:
            task_props = [type(task),
                          task.model_item.get_vpath(),
                          task.state,
                          task.call_type,
                          task.kwargs['path'],
                          task.kwargs['bridge'],
                          task.kwargs['cobbler_server'],
                          task.description,
                          task.call_id,
                          task.kwargs['system_name'],
                          task.kwargs['cobbler_system']]
            self.assertTrue(any(prop == task_props for prop in expected_props))

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_no_providers(self, repo_cmd_mock):
        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(0, len(tasks))

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_provider_no_nodes(self, repo_cmd_mock):
        self.setup_base_model()

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(0, len(tasks))

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_add_1_vms(self, repo_cmd_mock):
        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()

        self.model.set_all_applied()

        vm3 = self.model.create_item("libvirt-system",
                                     "/libvirt1/systems/vm3",
                                     system_name="vm3")

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(0, len(tasks))

        self.assertEqual(ModelItem, type(vm3))
        node3 = self.model.create_item("node", "/nodes/node3",
                                       hostname="node3")

        self.assertEqual(ModelItem, type(node3))
        node3_system = self.model.create_inherited("/libvirt1/systems/vm3",
                                              "/nodes/node3/system")
        self.assertEqual(ModelItem, type(node3_system))

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(1, len(tasks))

        task0 = tasks[0]
        self.assertEqual(ConfigTask, type(task0))
        self.assertEqual("Initial", task0.state)
        self.assertEqual("/nodes/node3/system", task0.model_item.get_vpath())
        self.assertEqual('Create VM "vm3"', task0.description)
        self.assertEqual("koan::config", task0.call_type)
        self.assertEqual("vm3", task0.call_id)
        self.assertEqual("vm3", task0.kwargs['system_name'])
        self.assertEqual("br0", task0.kwargs['bridge'])
        self.assertEqual("/var/lib/libvirt/images", task0.kwargs['path'])
        self.assertEqual("10.10.10.101", task0.kwargs['cobbler_server'])
        self.assertEqual("node3", task0.kwargs['cobbler_system'])

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_positive_with_mixed_nodes(self,
                                                            repo_cmd_mock):

        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()

        # add in a vbox-system
        vbox1 = self.model.create_item('system',
                               "/infrastructure/systems/vbox1",
                               system_name="Vbox1")
        self.assertEqual(ModelItem, type(vbox1))
        node3 = self.model.create_item("node", "/nodes/node3",
                                       hostname="node3")
        self.assertEqual(ModelItem, type(node3))
        node3_system = self.model.create_inherited(
                                               "/infrastructure/systems/vbox1",
                                               "/nodes/node3/system")
        self.assertEqual(ModelItem, type(node3_system))

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(2, len(tasks))
        task1_expected_props = [ConfigTask,
                                '/nodes/node1/system',
                                'Initial',
                                'koan::config',
                                '/var/lib/libvirt/images',
                                'br0',
                                '10.10.10.101',
                                'Create VM "vm1"',
                                'vm1',
                                'vm1',
                                'node1']

        task2_expected_props = [ConfigTask,
                                '/nodes/node2/system',
                                'Initial',
                                'koan::config',
                                '/var/lib/libvirt/images',
                                'br0',
                                '10.10.10.101',
                                'Create VM "vm2"',
                                'vm2',
                                'vm2',
                                'node2']

        expected_props = [task1_expected_props, task2_expected_props]
        for task in tasks:
            task_props = [type(task),
                          task.model_item.get_vpath(),
                          task.state,
                          task.call_type,
                          task.kwargs['path'],
                          task.kwargs['bridge'],
                          task.kwargs['cobbler_server'],
                          task.description,
                          task.call_id,
                          task.kwargs['system_name'],
                          task.kwargs['cobbler_system']]
            self.assertTrue(any(prop == task_props for prop in expected_props))

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_clear_node_ip_map(self, repo_cmd_mock):
        self.intf1 = mock.Mock()
        self.intf1.item_id = 'id1'
        self.intf1.network_name = 'net1'
        self.intf1.node_ip_map = '{"a": "1"}'
        self.intf1.is_initial = mock.MagicMock(return_value = True)

        self.intf2 = mock.Mock()
        self.intf2.item_id = 'id2'
        self.intf2.network_name = 'net2'
        self.intf2.node_ip_map = '{"b": "2"}'
        self.intf2.is_initial = mock.MagicMock(return_value = False)

        def mock_query_by_vpath(path):
            def mock_query(item_type, **kwargs):
                return [self.intf1, self.intf2]

            root = mock.MagicMock()
            root.query = mock_query
            return root

        api = mock.MagicMock()
        api.query = self.query
        api.query_by_vpath = mock_query_by_vpath
        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()

        repo_cmd_mock.return_value = None

        self.plugin.create_configuration(api)

        self.assertEquals("{}", self.intf1.node_ip_map)
        self.assertEquals('{"b": "2"}', self.intf2.node_ip_map)

    def test_bridge_validation_error_no_interfaces(self):
        self.setup_base_model()
        self.setup_2_nodes()

        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(1, len(errors))

        error = errors[0]
        expected_error = ValidationError(
                    item_path="/ms/libvirt",
                    error_message="Bridge 'br0' doesn't exist on this node"
                )
        self.assertEqual(ValidationError, type(error))
        self.assertEqual(expected_error, error)

    def test_bridge_validation_error_no_bridge(self):
        self.setup_base_model()
        self.setup_2_nodes()

        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(1, len(errors))

        error = errors[0]
        expected_error = ValidationError(
                    item_path="/ms/libvirt",
                    error_message="Bridge 'br0' doesn't exist on this node"
                )
        self.assertEqual(ValidationError, type(error))
        self.assertEqual(expected_error, error)

    def test_bridge_validation_error_wrong_bridge(self):
        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()
        self.model.update_item("/libvirt1", bridge="br123")

        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(1, len(errors))

        error = errors[0]
        expected_error = ValidationError(
                    item_path="/ms/libvirt",
                    error_message="Bridge 'br123' doesn't exist on this node"
                )
        self.assertEqual(ValidationError, type(error))
        self.assertEqual(error, expected_error)

    def test_bridge_validation_no_errors(self):
        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()

        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))

    def test_validation_of_libvirt_system_disks_with_1_error(self):
        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_multiple_disks_on_libvirt_items()
        self.setup_bridge()

        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(1, len(errors))

        error = errors[0]
        expected_error = ValidationError(
                    item_path="/libvirt1/systems/vm1/disks",
                    error_message="The libvirt plugin currently "
                                  "only supports 1 disk"
                )
        self.assertEqual(ValidationError, type(error))
        self.assertEqual(error, expected_error)

    def test_validation_of_libvirt_system_disks_no_errors(self):
        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()

        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))

    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set")
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_vm_service_no_node_link(self, repo_cmd_mock,
                                                                upgrade_flag):
        upgrade_flag.side_effect = [False, False, False]
        vm_image = self.model.create_item("vm-image", "/software/images/vm1",
                                     name="image",
                                     source_uri="http://test.ie")
        self.assertTrue(isinstance(vm_image, ModelItem))

        vm_service = self.model.create_item("vm-service",
                                          "/software/services/vm_service",
                                          service_name="vm_service",
                                          image_name="image")
        self.assertTrue(isinstance(vm_service, ModelItem))

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(0, len(tasks))

    @mock.patch('libvirt_plugin.utils.get_checksum')
    @mock.patch('libvirt_plugin.utils.exist_image_file')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade')
    def test_validate_model_vm_service_on_ms(self, vm_service_facade_patch,
                                             exist_image_patch,
                                             get_checksum_patch):
        nodes = self.query("ms")
        ms = nodes[0]
        vm_service_facade_patch.get_md5_file_name.return_value = "file.md5"
        exist_image_patch.return_value = True
        get_checksum_patch.return_value = '34d3e5f564534edf3458e8d834567a21'
        vm_image = self.model.create_item("vm-image", "/software/images/vm1",
                                     name="image",
                                     source_uri="http://%s" % ms.hostname)
        self.assertTrue(isinstance(vm_image, ModelItem))

        vm_service = self.model.create_item("vm-service",
                                          "/ms/services/vm_service",
                                          service_name="vmservice",
                                          internal_status_check="off",
                                          image_name="image")
        self.assertTrue(isinstance(vm_service, ModelItem))

        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(0, len(errors))

    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set")
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade')
    def test_create_configuration_vm_service(self, vm_service_facade_patch,
                                             repo_cmd_mock, upgrade_flag):
        upgrade_flag.side_effect = [False, False, False]
        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        the_check_sum = "the md5 file"
        node = mock.Mock(hostname="node1")
        image = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2",
                          checksum=the_check_sum)
        vm_service = mock.Mock(get_state=lambda: 'Initial',
                               is_initial=lambda: True,
                               for_redeploy=lambda: False,
                               is_for_removal=lambda: False,
                               instance_name = "fmmed1")

        vm_serv_facade = VMServiceFacade(node, image, vm_service,
                                         self.networks, ms_node, None)

        vm_service_facade_patch.from_model_gen = \
            lambda y : [vm_serv_facade]

        self.plugin.get_adaptor_install_tasks = mock.Mock()
        self.plugin.get_adaptor_install_tasks.return_value = []
        self.plugin.get_write_adaptor_task = mock.Mock()
        self.plugin.get_write_metadata_task = mock.Mock()
        self.plugin.get_write_networkconfig_task = mock.Mock()
        self.plugin.get_write_userdata_task = mock.Mock()
        self.plugin.get_update_task = mock.Mock()
        self.plugin.get_cleanup_images_task = mock.Mock()
        self.plugin.get_cleanup_images_task.return_value = []

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)

        self.assertEqual(6, len(tasks))
        copy_task = tasks[0]
        self.assertEqual(copy_task.requires, set([]))
        copy_task_id = (copy_task.call_type, copy_task.call_id)
        self.plugin.get_write_adaptor_task.assert_called_once_with(
                                          vm_serv_facade, [copy_task_id])
        self.plugin.get_write_metadata_task.assert_called_once_with(
                                          vm_serv_facade, self, [copy_task_id])
        self.plugin.get_write_networkconfig_task.assert_called_once_with(
                                          vm_serv_facade, self, [copy_task_id])
        self.plugin.get_write_userdata_task.assert_called_once_with(
                                          vm_serv_facade, [copy_task_id])
        self.plugin.get_update_task.assert_called_once_with(vm_serv_facade,
                                                [tasks[1], tasks[2],tasks[3],tasks[4]])
        self.plugin.get_cleanup_images_task.assert_called_once_with(vm_serv_facade,
                                                       [vm_serv_facade], tasks)

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade.hostname_updated')
    @mock.patch('libvirt_plugin.utils.update_maps_for_services')
    @mock.patch('libvirt_plugin.utils.update_service_image_checksums')
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_configuration_adaptor_version_upd(self, repo_cmd_patch,
                      upd_checksums_patch, upd_maps_patch, hostname_upd_patch):
        repo_cmd_patch.return_value = 'ERIClitpmnlibvirt_CXP9031529 1.0.1 1 noarch'
        upd_checksums_patch.return_value = None
        upd_maps_patch.return_value = None
        hostname_upd_patch.return_value = False

        self.setup_base_model()
        self.setup_2_nodes()
        self.setup_bridge()

        ms = self.query("ms")[0]
        vm_image = self.model.create_item("vm-image", "/software/images/vm1",
                                   name="image",
                                   source_uri="http://ms1/images/fmmed-1.0.1.qcow2")
        vm_service = self.model.create_item("vm-service",
                                            "/ms/services/vm_service",
                                            service_name="vmservice",
                                            internal_status_check="off",
                                            image_name="image",
                                            adaptor_version="1.0.1-0")

        self.model.set_all_applied()
        vm_service.set_updated()

        tasks = self.plugin.create_configuration(self)

        self.assertEqual(5, len(tasks))
        task = tasks[0]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("libvirt::install_adaptor", task.call_type)
        self.assertEqual("ms_libvirt_adaptor_install", task.call_id)
        self.assertEqual("/ms/services", task.model_item.get_vpath())
        self.assertEqual('Update libvirt adaptor to version "1.0.1", release '
                     '"1" on node "{0}"'.format(ms.hostname), task.description)
        self.assertEqual("1.0.1-1", task.kwargs['version'])
        task = tasks[1]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("libvirt::write_file", task.call_type)
        self.assertEqual("{0}configvmservice".format(ms.hostname),task.call_id)
        self.assertEqual("/ms/services/vm_service",task.model_item.get_vpath())
        self.assertEqual('Copy VM config file to node "{0}" for instance '
                         '"vmservice" as part of VM update'.format(ms.hostname)
                                                             ,task.description)
        task = tasks[3]
        self.assertEqual(CallbackTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("cb_restart_vm_service", task.call_type)
        self.assertEqual("/ms/services/vm_service",task.model_item.get_vpath())
        self.assertEqual('Restart service "vmservice" on node '
                                  '"{0}"'.format(ms.hostname),task.description)
        task = tasks[4]
        self.assertEqual(CallbackTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("cb_cleanup_vm_images", task.call_type)
        self.assertEqual('Remove unused VM image files on node '
                                  '"{0}"'.format(ms.hostname),task.description)
        self.assertEqual(task.kwargs, {'image_whitelist':'fmmed-1.0.1.qcow2',
                                       'hostname':'{0}'.format(ms.hostname) })
        self.assertEqual(task.get_model_item().vpath,
                                                 '/ms/services/vm_service')

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set')
    def test_upgrade_flag_set_returns_no_validation_errors(self, upgrade_flag):
        self.setup_base_model()
        self.setup_2_nodes()

        upgrade_flag.side_effect = [True, False, False, False]
        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(0, len(errors))

        upgrade_flag.side_effect = [False, True, True, False]
        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(0, len(errors))

        upgrade_flag.side_effect = [False, False, True, False]
        errors = self.plugin.validate_model(self)
        self.assertEqual(list, type(errors))
        self.assertEqual(0, len(errors))

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade')
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_upgrade_flag_set_creates_no_tasks(self, repo_cmd_mock,
                                                     vm_service_facade_patch,
                                                     upgrade_flag):
        upgrade_flag.return_value = True

        the_check_sum = "the md5 file"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node = mock.Mock(hostname="node1",
                         get_vpath=lambda: "vpath_node1",
                         is_ms=lambda: False,
                         is_for_removal=lambda: False)
        image = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2",
                          checksum=the_check_sum)

        service1 = mock.Mock(get_state=lambda:'Initial',
                             is_initial=lambda: True,
                             is_updated=lambda: False,
                             is_applied=lambda: False,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: False,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed1")

        service2 = mock.Mock(get_state=lambda:'Updated',
                             is_initial=lambda: False,
                             is_updated=lambda: True,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: True,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed2")

        vm_serv_facade1 = VMServiceFacade(node, image, service1, self.networks,
                                          ms_node)
        vm_serv_facade1.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade1.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade1.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade1.metadata = mock.Mock(return_value='')
        vm_serv_facade1.networkconfig = mock.Mock(return_value='')
        vm_serv_facade1.adaptor_data = mock.Mock(return_value='')
        vm_serv_facade1._get_userdata_dict = mock.Mock(return_value=['', ''])

        vm_serv_facade2 = VMServiceFacade(node, image, service2, self.networks,
                                          ms_node)
        vm_serv_facade2.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade2.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade2.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade2._get_userdata_dict = mock.Mock(return_value=['', ''])
        vm_serv_facade2.metadata = mock.Mock(return_value='')
        vm_serv_facade2.networkconfig = mock.Mock(return_value='')
        vm_serv_facade2.adaptor_data = mock.Mock(return_value='')

        vm_service_facade_patch.from_model_gen = \
            lambda y: [vm_serv_facade1, vm_serv_facade2]

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)

        self.assertEqual(tasks, [])

    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._in_restore_mode")
    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set")
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade')
    def test_create_configuration_restore_ms_service(self, vm_service_facade_patch,
                                                                repo_cmd_mock,
                                                                upgrade_flag,
                                                                in_restore_mode):

        upgrade_flag.side_effect = [False, False, False]
        in_restore_mode.side_effect = [True, True]
        the_check_sum = "the md5 file"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node = mock.Mock(hostname="node1",
                         get_vpath=lambda: "vpath_node1",
                         is_ms=lambda: False,
                         is_for_removal=lambda: False)
        image = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2",
                          checksum=the_check_sum)

        service1 = mock.Mock(get_state=lambda:'Initial',
                             is_initial=lambda: True,
                             is_updated=lambda: False,
                             is_applied=lambda: False,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: False,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed1")

        service2 = mock.Mock(get_state=lambda:'Updated',
                             is_initial=lambda: False,
                             is_updated=lambda: True,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: True,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed2")

        vm_serv_facade1 = VMServiceFacade(node, image, service1, self.networks,
                                          ms_node)
        vm_serv_facade1.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade1.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade1.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade1.metadata = mock.Mock(return_value='')
        vm_serv_facade1.networkconfig = mock.Mock(return_value='')
        vm_serv_facade1.adaptor_data = mock.Mock(return_value='')
        vm_serv_facade1._get_userdata_dict = mock.Mock(return_value=['', ''])

        vm_serv_facade2 = VMServiceFacade(ms_node, image, service2, self.networks,
                                          ms_node)
        vm_serv_facade2.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade2.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade2.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade2._get_userdata_dict = mock.Mock(return_value=['', ''])
        vm_serv_facade2.metadata = mock.Mock(return_value='')
        vm_serv_facade2.networkconfig = mock.Mock(return_value='')
        vm_serv_facade2.adaptor_data = mock.Mock(return_value='')

        vm_service_facade_patch.from_model_gen = \
            lambda y: [vm_serv_facade1, vm_serv_facade2]

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)

        self.assertEqual(6, len(tasks))

        copy_task_s1 = tasks[0]
        self.assertEqual(copy_task_s1.description, ('Copy VM image file '
        '"fmmed-1.0.1.qcow2" to node "node1" for instance "fmmed1" as part '
       'of VM deploy'))
        self.assertEqual(copy_task_s1.requires, set([]))
        copy_task_s1__id = (copy_task_s1.call_type, copy_task_s1.call_id)

        task = tasks[1]
        self.assertEqual(task.description, ('Copy VM config file to node '
        '"node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[2]
        self.assertEqual(task.description, ('Copy VM cloud init metadata file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[3]
        self.assertEqual(task.description, ('Copy VM cloud init networkconfig file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[4]
        self.assertEqual(task.description, ('Copy VM cloud init userdata file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))

        task = tasks[5]
        self.assertEqual(task.description, ('Remove unused VM image files on '
        'node "node1"'))

    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._in_restore_mode")
    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set")
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade')
    def test_create_configuration_restore_non_ms_service(self, vm_service_facade_patch,
                                                                repo_cmd_mock,
                                                                upgrade_flag,
                                                                in_restore_mode):

        upgrade_flag.side_effect = [False, False, False]
        in_restore_mode.side_effect = [True, True]
        the_check_sum = "the md5 file"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node = mock.Mock(hostname="node1",
                         get_vpath=lambda: "vpath_node1",
                         is_ms=lambda: False,
                         is_for_removal=lambda: False)
        image = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2",
                          checksum=the_check_sum)

        service1 = mock.Mock(get_state=lambda:'Initial',
                             is_initial=lambda: True,
                             is_updated=lambda: False,
                             is_applied=lambda: False,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: False,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed1")

        service2 = mock.Mock(get_state=lambda:'Updated',
                             is_initial=lambda: False,
                             is_updated=lambda: True,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: True,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed2")

        vm_serv_facade1 = VMServiceFacade(node, image, service1, self.networks,
                                          ms_node)
        vm_serv_facade1.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade1.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade1.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade1.metadata = mock.Mock(return_value='')
        vm_serv_facade1.networkconfig = mock.Mock(return_value='')
        vm_serv_facade1.adaptor_data = mock.Mock(return_value='')
        vm_serv_facade1._get_userdata_dict = mock.Mock(return_value=['', ''])

        vm_serv_facade2 = VMServiceFacade(node, image, service2, self.networks,
                                          ms_node)
        vm_serv_facade2.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade2.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade2.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade2._get_userdata_dict = mock.Mock(return_value=['', ''])
        vm_serv_facade2.metadata = mock.Mock(return_value='')
        vm_serv_facade2.networkconfig = mock.Mock(return_value='')
        vm_serv_facade2.adaptor_data = mock.Mock(return_value='')

        vm_service_facade_patch.from_model_gen = \
            lambda y: [vm_serv_facade1, vm_serv_facade2]

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)

        self.assertEqual(11, len(tasks))
        copy_task_s1 = tasks[0]
        self.assertEqual(copy_task_s1.description, ('Copy VM image file '
        '"fmmed-1.0.1.qcow2" to node "node1" for instance "fmmed1" as part '
       'of VM deploy'))
        self.assertEqual(copy_task_s1.requires, set([]))
        copy_task_s1__id = (copy_task_s1.call_type, copy_task_s1.call_id)

        task = tasks[1]
        self.assertEqual(task.description, ('Copy VM config file to node '
        '"node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[2]
        self.assertEqual(task.description, ('Copy VM cloud init metadata file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[3]
        self.assertEqual(task.description, ('Copy VM cloud init networkconfig file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[4]
        self.assertEqual(task.description, ('Copy VM cloud init userdata file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))

        task = tasks[5]
        self.assertEqual(task.description, ('Remove unused VM image files on '
        'node "node1"'))

        self.assertEqual(task.requires, set())
        copy_task_s2 = tasks[6]
        self.assertEqual(copy_task_s2.description, ('Copy VM image file '
        '"fmmed-1.0.1.qcow2" to node "node1" for instance "fmmed2" as part '
       'of VM update'))
        self.assertEqual(copy_task_s2.requires, set())
        copy_task_s2__id = (copy_task_s2.call_type, copy_task_s2.call_id)

        task = tasks[7]
        self.assertEqual(task.description, ('Copy VM config file to node '
        '"node1" for instance "fmmed2" as part of VM update'))
        self.assertEqual(task.requires, set([copy_task_s2__id]))
        ###
        task = tasks[8]
        self.assertEqual(task.description, ('Copy VM cloud init networkconfig file '
        'to node "node1" for instance "fmmed2" as part of VM update'))
        ###
        task = tasks[9]
        self.assertEqual(task.description, ('Copy VM cloud init userdata file '
        'to node "node1" for instance "fmmed2" as part of VM update'))
        task = tasks[10]
        self.assertEqual(task.description, ('Restart service "fmmed2" on node '
        '"node1"'))

        self.assertEqual(task.requires, set([tasks[8], tasks[7], tasks[9]]))

    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._in_restore_mode")
    @mock.patch("libvirt_plugin.libvirt_plugin.VMServiceFacade._is_upgrade_flag_set")
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade')
    def test_create_configuration_task_requires(self, vm_service_facade_patch,
                                                                repo_cmd_mock,
                                                                upgrade_flag,
                                                                in_restore_mode):

        upgrade_flag.side_effect = [False, False, False]
        in_restore_mode.side_effect = [False, False]
        the_check_sum = "the md5 file"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node = mock.Mock(hostname="node1",
                         get_vpath=lambda: "vpath_node1",
                         is_ms=lambda: False,
                         is_for_removal=lambda: False)
        image = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2",
                          checksum=the_check_sum)

        service1 = mock.Mock(get_state=lambda:'Initial',
                             is_initial=lambda: True,
                             is_updated=lambda: False,
                             is_applied=lambda: False,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: False,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed1")

        service2 = mock.Mock(get_state=lambda:'Updated',
                             is_initial=lambda: False,
                             is_updated=lambda: True,
                             is_for_removal=lambda: False,
                             update_task_required=lambda: True,
                             _image_checksum_updated=lambda: False,
                             service_name="fmmed2")

        vm_serv_facade1 = VMServiceFacade(node, image, service1, self.networks,
                                          ms_node)
        vm_serv_facade1.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade1.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade1.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade1.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade1.metadata = mock.Mock(return_value='')
        vm_serv_facade1.networkconfig = mock.Mock(return_value='')
        vm_serv_facade1.adaptor_data = mock.Mock(return_value='')
        vm_serv_facade1._get_userdata_dict = mock.Mock(return_value=['', ''])

        vm_serv_facade2 = VMServiceFacade(node, image, service2, self.networks,
                                          ms_node)
        vm_serv_facade2.userdata_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_updated_interfaces = mock.Mock(return_value=[])
        vm_serv_facade2.config_model_items = mock.Mock(return_value=[])
        vm_serv_facade2.get_service_task_items = mock.Mock(return_value=[])
        vm_serv_facade2.hostname_updated = mock.Mock(return_value=False)
        vm_serv_facade2._get_userdata_dict = mock.Mock(return_value=['', ''])
        vm_serv_facade2.metadata = mock.Mock(return_value='')
        vm_serv_facade2.networkconfig = mock.Mock(return_value='')
        vm_serv_facade2.adaptor_data = mock.Mock(return_value='')

        vm_service_facade_patch.from_model_gen = \
            lambda y: [vm_serv_facade1, vm_serv_facade2]

        repo_cmd_mock.return_value = None

        tasks = self.plugin.create_configuration(self)

        self.assertEqual(11, len(tasks))
        copy_task_s1 = tasks[0]
        self.assertEqual(copy_task_s1.description, ('Copy VM image file '
        '"fmmed-1.0.1.qcow2" to node "node1" for instance "fmmed1" as part '
       'of VM deploy'))
        self.assertEqual(copy_task_s1.requires, set([]))
        copy_task_s1__id = (copy_task_s1.call_type, copy_task_s1.call_id)

        task = tasks[1]
        self.assertEqual(task.description, ('Copy VM config file to node '
        '"node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[2]
        self.assertEqual(task.description, ('Copy VM cloud init metadata file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[3]
        self.assertEqual(task.description, ('Copy VM cloud init networkconfig file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))
        task = tasks[4]
        self.assertEqual(task.description, ('Copy VM cloud init userdata file '
        'to node "node1" for instance "fmmed1" as part of VM deploy'))
        self.assertEqual(task.requires, set([copy_task_s1__id]))

        task = tasks[5]
        self.assertEqual(task.description, ('Remove unused VM image files on '
        'node "node1"'))

        self.assertEqual(task.requires, set())
        copy_task_s2 = tasks[6]
        self.assertEqual(copy_task_s2.description, ('Copy VM image file '
        '"fmmed-1.0.1.qcow2" to node "node1" for instance "fmmed2" as part '
       'of VM update'))
        self.assertEqual(copy_task_s2.requires, set())
        copy_task_s2__id = (copy_task_s2.call_type, copy_task_s2.call_id)

        task = tasks[7]
        self.assertEqual(task.description, ('Copy VM config file to node '
        '"node1" for instance "fmmed2" as part of VM update'))
        self.assertEqual(task.requires, set([copy_task_s2__id]))
        ###
        task = tasks[8]
        self.assertEqual(task.description, ('Copy VM cloud init networkconfig file '
        'to node "node1" for instance "fmmed2" as part of VM update'))
        ###
        task = tasks[9]
        self.assertEqual(task.description, ('Copy VM cloud init userdata file '
        'to node "node1" for instance "fmmed2" as part of VM update'))
        task = tasks[10]
        self.assertEqual(task.description, ('Restart service "fmmed2" on node '
        '"node1"'))

        self.assertEqual(task.requires, set([tasks[8], tasks[7], tasks[9]]))


    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_create_an_vm_image(self, repo_cmd_mock):

        repo_cmd_mock.return_value = ("ERIClitpmnlibvirt_CXP9031529 "
                                      "1.1.1 1 noarch")
        vm_image = self.model.create_item("vm-image", "/software/images/vm1",
                                     name="vm1", source_uri="http://test.ie")

        self.assertTrue(isinstance(vm_image, ModelItem))

        tasks = self.plugin.create_configuration(self)
        self.assertEqual(list, type(tasks))
        self.assertEqual(0, len(tasks))

    def test_get_write_userdata_task(self):
        service = mock.Mock(spec=VMServiceFacade)
        node_mock = mock.Mock()
        repo1 = mock.Mock(item_id='repo1', get_state=lambda: ModelItem.Initial)
        repo2 = mock.Mock(item_id='repo1', get_state=lambda: ModelItem.Applied)
        pkg1 = mock.Mock(item_id='repo1', get_state=lambda: ModelItem.Updated)
        pkg2 = mock.Mock(item_id='repo1', get_state=lambda: ModelItem.Applied)
        repos = [repo1, repo2]
        pkgs = [pkg1, pkg2]
        node_mock.hostname = 'mn1'
        service.node = node_mock
        service.userdata = '#config\nrepos'
        service.base_path = '/base/path'
        service.userdata_file_name = 'file_name'
        service.instance_name = 'fmmed'
        service.state = 'one_state'
        service.vm_task_item = mock.Mock()
        service.userdata_model_items.return_value = repos + pkgs
        service._clustered_service = None

        write_file_task = mock.Mock(requires=set(), model_items=set())
        self.plugin._write_file_task = mock.Mock(return_value=write_file_task)
        copy_task = mock.Mock()
        task = self.plugin.get_write_userdata_task(service, [copy_task])

        self.plugin._write_file_task.assert_called_once_with(
              node_mock,
              service.vm_task_item,
              'Copy VM cloud init userdata file to node "mn1" for instance'
              ' "fmmed" as part of VM one_state',
              '#config\nrepos',
              '/base/path',
              'file_name',
              unique='userdata',
              instance_name='fmmed')
        self.assertEquals(set([copy_task]), task.requires)
        self.assertEquals(set([repo1, pkg1]), task.model_items)

    @mock.patch('libvirt_plugin.libvirt_plugin.log')
    def test_get_copy_image_task(self, log_mock):
        service = mock.Mock()
        service.image_checksum = 'md5'
        node_mock = mock.Mock()
        node_mock.hostname = 'mn1'
        service.node = node_mock
        service.image_uri = 'http:example.com/3pp'
        service.image_name = 'fmmed_image'
        service.instance_name = 'fmmed'
        service.state = 'foo'
        service.vm_task_item = mock.Mock()
        task1 = mock.Mock()
        task2 = mock.Mock()

        mock_task = mock.Mock(requires=set())
        self.plugin._copy_file_task = mock.Mock(return_value=mock_task)
        task = self.plugin.get_copy_image_task(service, [task1, task2])
        self.plugin._copy_file_task.assert_called_once_with(
              node_mock,
              service.vm_task_item,
              service.image_uri,
              constants.IMAGE_PATH,
              service.image_name,
              'fmmed',
              service.image_checksum,
              'foo')
        self.assertEqual(set([task1, task2]), task.requires)
        log_mock.trace.info.assert_called_once_with('Ensure that image '
            '"fmmed_image" with checksum "md5" is used for vm-service "fmmed"'
            ' on node "mn1"')
        self.assertEqual(service.image_checksum, "md5")

    @mock.patch('libvirt_plugin.libvirt_plugin.log')
    def test_get_service_deconfigure_task(self, log_mock):
        service = mock.Mock()
        service.instance_name = 'mock_vm'
        node_mock = mock.Mock()
        node_mock.hostname = 'mn1'
        service.node = node_mock
        service.vm_task_item = mock.Mock()
        self.plugin._deconfigure_task = mock.Mock()

        task = self.plugin.get_service_deconfigure_task(service)
        self.plugin._deconfigure_task.assert_called_once_with(
                node_mock,
                service.vm_task_item,
                'mock_vm')
        log_mock.trace.info.assert_called_once_with('Create task to deconfigure'
                                                    ' vm-service "mock_vm" on node'
                                                    ' "mn1"')

    def test__deconfigure_task(self):
        node_mock = mock.Mock(hostname='mn1')
        task_item = mock.Mock()
        instance_name = 'vm1'

        task = self.plugin._deconfigure_task(node_mock, task_item,
                instance_name)
        copy_file_format_args = {'hostname': 'mn1',
                                 'instance_name': instance_name}
        # Check it replaces libvirt::copy_file
        self.assertTrue((CALL_TYPE_COPY_FILE, CALL_ID_COPY_FILE.format(
                hostname='mn1', instance_name=instance_name))
                in task.replaces)
        # Check it replace libvirt::write_file for config/{user,meta}data
        for unique in ('config', 'metadata', 'userdata', 'networkconfig'):
            copy_file_format_args['unique'] = unique
            self.assertTrue(
                    (CALL_TYPE_WRITE_FILE, CALL_ID_WRITE_FILE.format(
                        **copy_file_format_args)) in task.replaces)

    def test_get_removal_tasks_no_services(self):
        self.assertEqual([], self.plugin.get_removal_tasks([]))

    def test_get_removal_tasks(self):
        service = mock.Mock()
        service._clustered_service = None
        self.plugin.get_service_deconfigure_task = mock.Mock()
        self.plugin.get_service_deconfigure_task.return_value = 'mock'

        self.assertEqual(['mock'], self.plugin.get_removal_tasks([service]))
        self.plugin.get_service_deconfigure_task.assert_called_once_with(service)

    def test_get_adaptor_update_same_version(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.get_vpath.return_value = "vpath_node1"
        node1.item_id = "mn1"
        node1.get_cluster.return_value = cluster
        service_item = mock.Mock()
        service_item.adaptor_version = "1.1.0-1"
        service_item.is_initial.return_value = False
        service_item.applied_properties = {"adaptor_version": "1.1.0-1"}
        service_item.query.return_value = []
        service_item.get_vpath.return_value = "vpath_clu_services"
        vm_service1 = VMServiceFacade(node1, mock.Mock(), service_item,
                                      self.networks, ms_node)

        pkg_version = {
                  "name":"ERIClitpmnlibvirt_CXP9031529", "version":"1.1.0",
                  "release":"1", "arch":"noarch"}

        tasks = self.plugin.get_adaptor_install_tasks([vm_service1],
                                                      pkg_version)

        self.assertEqual(0, len(tasks))

        self.assertEqual(service_item.adaptor_version, "1.1.0-1")

    def test_get_adaptor_removal_tasks_remove_both(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.item_id = 'node1'
        node2 = mock.Mock()
        node2.hostname = 'mn2'
        node2.item_id = 'node2'
        service_item1 = mock.Mock()
        service_item1.is_for_removal.return_value = False
        service_item2 = mock.Mock()
        service_item2.is_for_removal.return_value = False
        clust_service = mock.Mock()
        clust_service.node_list = "node1"
        clust_service.applied_properties = {"node_list": "node1,node2"}
        clust_service2 = mock.Mock()
        clust_service2.node_list = "node1,node2"
        clust_service2.applied_properties = {"node_list": "node1,node2"}
        vm_service1 = VMServiceFacade(node1,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img1"),
                                      service_item1,
                                      self.networks,
                                      ms_node,
                                      clust_service)
        vm_service2 = VMServiceFacade(node2,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img1"),
                                      service_item1,
                                      self.networks,
                                      ms_node,
                                      clust_service)
        tasks = self.plugin.get_adaptor_removal_tasks([vm_service1,
                                                       vm_service2],
                                                      [mock.Mock(),
                                                       mock.Mock()])
        tasks.extend(self.plugin.get_image_removal_tasks([vm_service1,
                                                          vm_service2]))
        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0].format_parameters()['call_type'],
                         'libvirt::remove_adaptor')
        self.assertEqual(tasks[0].format_parameters()['call_id'],
                         'node2_libvirt_adaptor_remove')
        self.assertEqual(tasks[1].format_parameters()['call_type'],
                         'libvirt::remove_image')
        self.assertEqual(tasks[1].format_parameters()['call_id'],
                         'img1_libvirt_image_remove')

    def test_get_adaptor_removal_tasks_dont_remove(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.item_id = 'node1'
        node2 = mock.Mock()
        node2.hostname = 'mn2'
        node2.item_id = 'node2'
        service_item1 = mock.Mock()
        service_item1.is_for_removal.return_value = False
        service_item2 = mock.Mock()
        service_item2.is_for_removal.return_value = False
        clust_service = mock.Mock()
        clust_service.node_list = "node1"
        clust_service.applied_properties = {"node_list": "node1,node2"}
        clust_service2 = mock.Mock()
        clust_service2.node_list = "node2"
        clust_service2.applied_properties = {"node_list": "node2"}
        vm_service1 = VMServiceFacade(node1,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img1"),
                                      service_item1,
                                      self.networks,
                                      ms_node,
                                      clust_service)
        vm_service2 = VMServiceFacade(node2,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img1"),
                                      service_item1,
                                      self.networks,
                                      ms_node,
                                      clust_service)
        vm_service3 = VMServiceFacade(node2,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img1"),
                                      service_item2,
                                      self.networks,
                                      ms_node,
                                      clust_service2)
        tasks = self.plugin.get_adaptor_removal_tasks([vm_service1,
                                                       vm_service2,
                                                       vm_service3],
                                                      [mock.Mock(),
                                                       mock.Mock()])
        tasks.extend(self.plugin.get_image_removal_tasks([vm_service1,
                                                          vm_service2,
                                                          vm_service3]))
        self.assertEqual(len(tasks), 0)

    def test_get_adaptor_removal_tasks_remove_image(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.item_id = 'node1'
        node2 = mock.Mock()
        node2.hostname = 'mn2'
        node2.item_id = 'node2'
        service_item1 = mock.Mock()
        service_item1.is_for_removal.return_value = False
        service_item2 = mock.Mock()
        service_item2.is_for_removal.return_value = False
        clust_service = mock.Mock()
        clust_service.node_list = "node1"
        clust_service.applied_properties = {"node_list": "node1,node2"}
        clust_service2 = mock.Mock()
        clust_service2.node_list = "node1,node2"
        clust_service2.applied_properties = {"node_list": "node1,node2"}
        vm_service1 = VMServiceFacade(node1,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img1"),
                                      service_item1,
                                      self.networks,
                                      ms_node,
                                      clust_service)
        vm_service2 = VMServiceFacade(node2,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img1"),
                                      service_item1,
                                      self.networks,
                                      ms_node,
                                      clust_service)
        vm_service3 = VMServiceFacade(node2,
                                      mock.Mock(source_uri =
                                                "http://ms1/images/img2"),
                                      service_item2,
                                      self.networks,
                                      ms_node,
                                      clust_service2)
        tasks = self.plugin.get_adaptor_removal_tasks([vm_service1,
                                                       vm_service2,
                                                       vm_service3],
                                                      [mock.Mock(),
                                                       mock.Mock()])
        tasks.extend(self.plugin.get_image_removal_tasks([vm_service1,
                                                          vm_service2,
                                                          vm_service3]))
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].format_parameters()['call_type'],
                         'libvirt::remove_image')
        self.assertEqual(tasks[0].format_parameters()['call_id'],
                         'img1_libvirt_image_remove')

    def test_get_adaptor_install_tasks(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.get_vpath.return_value = "vpath_node1"
        node1.item_id = "mn1"
        node1.get_cluster.return_value = cluster
        service_item = mock.Mock()
        service_item.adaptor_version = "1.1.0-1"
        service_item.is_initial.return_value = False
        service_item.is_for_removal.return_value = False
        service_item.applied_properties = {"adaptor_version": "1.1.0-1"}
        service_item.query.return_value = []
        service_item.parent.get_vpath.return_value = "vpath_clu_services"
        vm_service1 = VMServiceFacade(node1, mock.Mock(), service_item,
                                      self.networks, ms_node)

        pkg_version = {
                  "name":"ERIClitpmnlibvirt_CXP9031529", "version":"1.1.1",
                  "release":"1", "arch":"noarch"}

        tasks = self.plugin.get_adaptor_install_tasks([vm_service1],
                                                      pkg_version)

        self.assertEqual(1, len(tasks))
        task = tasks[0]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("vpath_clu_services", task.model_item.get_vpath())
        self.assertEqual('Update libvirt adaptor to version "1.1.1", release "1" on node "mn1"', task.description)
        self.assertEqual("libvirt::install_adaptor", task.call_type)
        self.assertEqual("mn1_libvirt_adaptor_install", task.call_id)
        self.assertEqual("1.1.1-1", task.kwargs['version'])

    def test_get_adaptor_install_after_failure(self):
        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.get_vpath.return_value = "vpath_node1"
        node1.item_id = "mn1"
        node1.get_cluster.return_value = cluster
        service_item = mock.Mock()
        service_item.adaptor_version = "1.1.1-1"
        service_item.is_initial.return_value = False
        service_item.is_for_removal.return_value = False
        service_item.applied_properties = {"adaptor_version": "1.1.0-1"}
        service_item.query.return_value = []
        service_item.parent.get_vpath.return_value = "vpath_clu_services"
        vm_service1 = VMServiceFacade(node1, mock.Mock(), service_item,
                                      self.networks, ms_node)

        pkg_version = {"name":"ERIClitpmnlibvirt_CXP9031529",
                       "version":"1.1.1", "release": "1", "arch":"noarch"}

        tasks = self.plugin.get_adaptor_install_tasks([vm_service1],
                                                      pkg_version)

        self.assertEqual(1, len(tasks))
        task = tasks[0]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("vpath_clu_services", task.model_item.get_vpath())
        self.assertEqual('Update libvirt adaptor to version "1.1.1", release "1" on node "mn1"', task.description)
        self.assertEqual("libvirt::install_adaptor", task.call_type)
        self.assertEqual("mn1_libvirt_adaptor_install", task.call_id)
        self.assertEqual("1.1.1-1", task.kwargs['version'])

        self.assertEqual(service_item.adaptor_version, "1.1.1-1")
        self.assertEqual(service_item.applied_properties, {"adaptor_version": "1.1.0-1"})

    def test_get_adaptor_install_tasks_no_version(self):

        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.get_vpath.return_value = "vpath_node1"
        node1.item_id = "mn1"
        node1.get_cluster.return_value = cluster
        task_item = mock.Mock()
        task_item.parent.get_vpath.return_value = "vpath_clu_services"
        task_item.node_list="mn1"
        task_item.applied_properties={}
        service_item1 = mock.Mock()
        service_item1.adaptor_version = None
        service_item1.is_for_removal.return_value = False
        service_item1.applied_properties = {}
        service_item1.query.return_value = []
        vm_service1 = VMServiceFacade(node1, mock.Mock(), service_item1,
                                      self.networks, ms_node, task_item)

        node2 = mock.Mock()
        node2.hostname = 'mn2'
        node2.get_vpath.return_value = "vpath_node2"
        node2.item_id = "mn2"
        node2.get_cluster.return_value = cluster
        task_item = mock.Mock()
        task_item.parent.get_vpath.return_value = "vpath_clu_services"
        task_item.node_list="mn1"
        task_item.applied_properties={}
        service_item2 = mock.Mock()
        service_item2.adaptor_version = None
        service_item2.is_for_removal.return_value = False
        service_item2.applied_properties = {}
        service_item2.query.return_value = []
        vm_service2 = VMServiceFacade(node2, mock.Mock(), service_item2,
                                      self.networks, ms_node, task_item)

        pkg_version = {
                  "name":"ERIClitpmnlibvirt_CXP9031529", "version":"1.1.1",
                  "release":"1", "arch":"noarch"}

        tasks = self.plugin.get_adaptor_install_tasks([vm_service1, vm_service2],
                                                      pkg_version)
        self.assertEqual(2, len(tasks))
        task = tasks[0]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("vpath_clu_services", task.model_item.get_vpath())
        self.assertEqual('Install libvirt adaptor version "1.1.1", release "1" on node "mn1"', task.description)
        self.assertEqual("libvirt::install_adaptor", task.call_type)
        self.assertEqual("mn1_libvirt_adaptor_install", task.call_id)
        self.assertEqual("1.1.1-1", task.kwargs['version'])

        task = tasks[1]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("vpath_clu_services", task.model_item.get_vpath())
        self.assertEqual('Install libvirt adaptor version "1.1.1", release "1" on node "mn2"', task.description)
        self.assertEqual("libvirt::install_adaptor", task.call_type)
        self.assertEqual("mn2_libvirt_adaptor_install", task.call_id)
        self.assertEqual("1.1.1-1", task.kwargs['version'])

    def test_get_adaptor_install_tasks_initial(self):

        cluster = mock.Mock(item_id="cluster1")
        cluster.get_vpath.return_value = "vpath_cluster"

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node1 = mock.Mock()
        node1.hostname = 'mn1'
        node1.get_vpath.return_value = "vpath_node1"
        node1.item_id = "mn1"
        node1.get_cluster.return_value = cluster
        clustered_service1 = mock.Mock()
        clustered_service1.parent.get_vpath.return_value = "vpath_clu_services1"
        clustered_service1.node_list="mn1"
        clustered_service1.applied_properties={}
        service_item1 = mock.Mock()
        service_item1.adaptor_version = None
        service_item1.applied_properties = {}
        service_item1.query.return_value = []
        service_item1.is_initial.return_value = True
        service_item1.is_for_removal.return_value = False
        vm_service1 = VMServiceFacade(node1, mock.Mock(), service_item1,
                                      self.networks, ms_node,
                                      clustered_service1)

        node2 = mock.Mock()
        node2.hostname = 'mn2'
        node2.get_vpath.return_value = "vpath_node2"
        node2.item_id = "mn2"
        node2.get_cluster.return_value = cluster
        clustered_service2 = mock.Mock()
        clustered_service2.parent.get_vpath.return_value = "vpath_clu_services2"
        clustered_service2.node_list="mn1"
        clustered_service2.applied_properties={}
        service_item2 = mock.Mock()
        service_item2.adaptor_version = None
        service_item2.applied_properties = {}
        service_item2.is_initial.return_value = True
        service_item2.is_for_removal.return_value = False
        service_item2.query.return_value = []
        vm_service2 = VMServiceFacade(node2, mock.Mock(), service_item2,
                                      self.networks, ms_node,
                                      clustered_service2)

        pkg_version = {
                  "name":"ERIClitpmnlibvirt_CXP9031529", "version":"1.1.1",
                  "release":"1", "arch":"noarch"}

        tasks = self.plugin.get_adaptor_install_tasks([vm_service1, vm_service2],
                                                      pkg_version)
        self.assertEqual(2, len(tasks))
        task = tasks[0]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("vpath_clu_services1", task.model_item.get_vpath())
        self.assertEqual('Install libvirt adaptor version "1.1.1", release "1" on node "mn1"', task.description)
        self.assertEqual("libvirt::install_adaptor", task.call_type)
        self.assertEqual("mn1_libvirt_adaptor_install", task.call_id)
        self.assertEqual("1.1.1-1", task.kwargs['version'])

        task = tasks[1]
        self.assertEqual(ConfigTask, type(task))
        self.assertEqual("Initial", task.state)
        self.assertEqual("vpath_clu_services2", task.model_item.get_vpath())
        self.assertEqual('Install libvirt adaptor version "1.1.1", release "1" on node "mn2"', task.description)
        self.assertEqual("libvirt::install_adaptor", task.call_type)
        self.assertEqual("mn2_libvirt_adaptor_install", task.call_id)
        self.assertEqual("1.1.1-1", task.kwargs['version'])

    def test_get_write_adaptor_task(self):
        service = mock.Mock()
        service.node.hostname = "hostname"
        service.vm_task_item = mock.Mock()
        service.adaptor_data = mock.Mock()
        result_of_the_function = mock.Mock()
        service.adaptor_data.return_value = result_of_the_function
        service.adaptor_data_file_name = mock.Mock()
        interface1 = mock.Mock()
        repo1 = mock.Mock()
        service.config_model_items = mock.Mock(return_value=[interface1,
                                                             repo1])

        service.instance_name = "instance_name"
        userdata = mock.Mock()
        service.userdata = userdata
        service.metadata.return_value =  mock.Mock()
        service.base_path = "base_path"
        service.state = 'service_state'
        service.metadata_file_name = "file_name"
        service.userdata_file_name = "userdata_file_name"
        service._clustered_service = None

        api = mock.Mock()

        write_config_task = mock.Mock(requires=set(), model_items=set())
        self.plugin._write_file_task = mock.Mock(return_value=write_config_task)
        copy_tasks = [mock.Mock(), mock.Mock()]
        task = self.plugin.get_write_adaptor_task(service, copy_tasks)

        self.plugin._write_file_task.assert_called_once_with(
            service.node, service.vm_task_item,
            'Copy VM config file to node "hostname" for instance "instance_name" as part of VM service_state',
            result_of_the_function , "base_path", service.adaptor_data_file_name, instance_name='instance_name', unique='config')

        self.assertEquals(set([interface1, repo1]), task.model_items)
        self.assertEquals(set(copy_tasks), task.requires)

    def test_get_write_metadata_task(self):
        service = mock.Mock()
        service.node = mock.Mock()
        service.vm_task_item = mock.Mock()
        service.metadata.return_value = mock.Mock()
        service.base_path = mock.Mock()
        service.metadata_file_name = mock.Mock()
        interface1 = mock.Mock()
        service.get_updated_interfaces = mock.Mock(return_value=[interface1])

        service.node.hostname = "hostname"
        service.instance_name = "instance_name"
        service.state = "service_state"
        service._clustered_service = None
        api = mock.Mock()
        write_metadata_task = mock.Mock(requires=set(), model_items=set())
        self.plugin._write_file_task = mock.Mock(return_value=write_metadata_task)

        copy_tasks = [mock.Mock(), mock.Mock()]
        task = self.plugin.get_write_metadata_task(service, api, copy_tasks)
        self.plugin._write_file_task.assert_called_once_with(
            service.node, service.vm_task_item, 'Copy VM cloud init metadata '
                                             'file to node "hostname" for '
                                             'instance "instance_name" as part '
                                             'of VM service_state',
            service.metadata(), service.base_path, service.metadata_file_name,
            instance_name='instance_name', unique='metadata')

        self.assertEquals(set([interface1]), task.model_items)
        self.assertEquals(set(copy_tasks), task.requires)

    def test_get_update_task(self):
        service = mock.Mock(instance_name='service1')
        service.node = mock.Mock(hostname='node1')
        service.vm_task_item = mock.Mock()
        service.get_vpath.return_value = 'service_vpath'
        required_tasks = [mock.Mock(), mock.Mock()]
        service.get_service_task_items = mock.Mock(return_value = [])
        task = self.plugin.get_update_task(service, required_tasks)
        self.assertEqual(('node1', 'service_vpath'), task.args)
        self.assertEqual(self.plugin.cb_restart_vm_service, task.callback)
        self.assertEquals(set(required_tasks), task.requires)

    def test_get_vm_service_hostnames(self):
        clustered_service = mock.Mock()
        vm_service = mock.Mock(hostnames="service1,service2")
        hostnames = self.plugin._get_vm_service_hostnames(clustered_service,
                                                          vm_service)
        self.assertEquals(["service1", "service2"], hostnames)

    def test_get_vm_service_hostnames_failover(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        clustered_service = mock.Mock(standby="1", nodes=[node1, node2])
        vm_service = mock.Mock(service_name="service1", hostnames=None)
        hostnames = self.plugin._get_vm_service_hostnames(clustered_service,
                                                          vm_service)
        self.assertEquals(["service1"], hostnames)

    def test_get_vm_service_hostnames_empty_node_list(self):
        clustered_service = mock.Mock(standby="1", nodes=[])
        vm_service = mock.Mock(service_name="service1", hostnames=None)
        hostnames = self.plugin._get_vm_service_hostnames(clustered_service,
                                                          vm_service)
        self.assertEquals([], hostnames)

    def test_get_vm_service_hostnames_parallel(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        clustered_service = mock.Mock(standby="0", nodes=[node1, node2])
        vm_service = mock.Mock(service_name="service1", hostnames=None)
        hostnames = self.plugin._get_vm_service_hostnames(clustered_service,
                                                          vm_service)
        self.assertEquals(["node1-service1", "node2-service1"], hostnames)

    def test_validate_no_duplicate_hostname(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        clustered_service = mock.Mock(standby="0", nodes=[node1, node2])
        vm_service1 = mock.Mock(service_name="service1", hostnames=None)
        vm_service1.get_vpath.return_value = "vpath-service1"
        vm_service1.is_for_removal.return_value = False

        vm_service2 = mock.Mock(hostnames="node1-service1")
        vm_service2.get_vpath.return_value = "vpath-service2"
        vm_service2.is_for_removal.return_value = False

        clustered_service.query.return_value = [vm_service1, vm_service2]

        cluster = mock.Mock(services=[clustered_service])

        ms = mock.Mock(item_id='ms1')
        ms_vm_service1 = mock.Mock(service_name="service1", hostnames=None)
        ms_vm_service1.get_vpath.return_value = "vpath-ms-service1"
        ms_vm_service1.is_for_removal.return_value = False

        ms_vm_service2 = mock.Mock(hostnames="service1")
        ms_vm_service2.get_vpath.return_value = "vpath-ms-service2"
        ms_vm_service2.is_for_removal.return_value = False

        ms.query.return_value = [ms_vm_service1, ms_vm_service2]

        api = mock.Mock()
        api.query.side_effect = [[cluster], [ms]]

        api.query_by_vpath.side_effect = [vm_service1, vm_service2,
                                          vm_service2, ms_vm_service1,
                                          ms_vm_service2]

        errors = self.plugin._validate_no_duplicate_hostname(api)

        self.assertEquals(4, len(errors))
        self.assertTrue(isinstance(errors[0], ValidationError))
        self.assertEqual('vpath-service1', errors[0].item_path)
        self.assertEqual('Hostname "node1-service1" is used in more '
                         'than one vm-service', errors[0].error_message)
        self.assertTrue(isinstance(errors[1], ValidationError))
        self.assertEqual('vpath-service2', errors[1].item_path)
        self.assertEqual('Hostname "node1-service1" is used in more '
                         'than one vm-service', errors[1].error_message)
        self.assertTrue(isinstance(errors[2], ValidationError))
        self.assertEqual('vpath-ms-service1', errors[2].item_path)
        self.assertEqual('Hostname "service1" is used in more '
                         'than one vm-service', errors[2].error_message)
        self.assertTrue(isinstance(errors[3], ValidationError))
        self.assertEqual('vpath-ms-service2', errors[3].item_path)
        self.assertEqual('Hostname "service1" is used in more '
                         'than one vm-service', errors[3].error_message)

    def test_validate_duplicate_hostname_one_for_removal(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        clustered_service = mock.Mock(standby="0", nodes=[node1, node2])
        vm_service1 = mock.Mock(service_name="service1", hostnames=None)
        vm_service1.get_vpath.return_value = "vpath-service1"
        vm_service1.is_for_removal.return_value = False

        vm_service2 = mock.Mock(hostnames="node1-service1")
        vm_service2.get_vpath.return_value = "vpath-service2"
        vm_service2.is_for_removal.return_value = True

        clustered_service.query.return_value = [vm_service1, vm_service2]

        cluster = mock.Mock(services=[clustered_service])

        ms = mock.Mock(item_id='ms1')
        ms_vm_service1 = mock.Mock(service_name="service1",
                                   hostnames="service1")
        ms_vm_service1.get_vpath.return_value = "vpath-service1"
        ms_vm_service1.is_for_removal.return_value = False

        ms_vm_service2 = mock.Mock(hostnames="service1")
        ms_vm_service2.get_vpath.return_value = "vpath-service2"
        ms_vm_service2.is_for_removal.return_value = True

        ms.query.return_value = [ms_vm_service1, ms_vm_service2]

        api = mock.Mock()
        api.query.side_effect = [[cluster], [ms]]

        errors = self.plugin._validate_no_duplicate_hostname(api)

        self.assertEquals(0, len(errors))

    def test_validate_hostname_count_parallel(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        clustered_service_parallel = mock.Mock(standby="0", active="2",
                                               nodes=[node1, node2])
        vm_service1 = mock.Mock(service_name="service11", hostnames="name1", is_for_removal=lambda: False)
        vm_service1.get_vpath.return_value = "vpath-service11"

        vm_service2 = mock.Mock(hostnames="service21,service22", is_for_removal=lambda: False)
        vm_service1.get_vpath.return_value = "vpath-service2"

        clustered_service_parallel.query.return_value = [vm_service1, vm_service2]

        api = mock.Mock()
        api.query.return_value = [clustered_service_parallel]

        errors = self.plugin._validate_hostname_count(api)

        self.assertEquals(1, len(errors))
        self.assertTrue(isinstance(errors[0], ValidationError))

    def test_validate_hostname_count_failover(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")

        clustered_service_failover = mock.Mock(standby="1", active="1",
                                               nodes=[node1, node2])
        vm_service1 = mock.Mock(service_name="service1", hostnames="name1,name2", is_for_removal=lambda: False)
        vm_service1.get_vpath.return_value = "vpath-service11"

        vm_service2 = mock.Mock(hostnames="service1", is_for_removal=lambda: False)
        vm_service1.get_vpath.return_value = "vpath-service2"

        clustered_service_failover.query.return_value = [vm_service1, vm_service2]
        api = mock.Mock()
        api.query.return_value = [clustered_service_failover]
        errors = self.plugin._validate_hostname_count(api)

        self.assertEquals(1, len(errors))
        self.assertTrue(isinstance(errors[0], ValidationError))

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_get_litpmn_package_version(self, repo_cmd_mock):
        pkg_name = "ERIClitpmnlibvirt_CXP9031529"

        repo_cmd_mock.return_value = ("ERIClitpmnlibvirt_CXP9031529 "
                                      "1.1.1 1 noarch")
        expected = {"name":pkg_name, "version":"1.1.1", "release":"1",
                     "arch":"noarch"}

        pkg_version = self.plugin._get_litpmn_package_version()

        self.assertEqual(expected, pkg_version)

        exp_query = ('repoquery --repoid=a'
                     ' --repofrompath=a,/var/www/html/litp -a'
                     ' --queryformat "%{NAME} %{VERSION} %{RELEASE} %{ARCH}"'
                     ' ERIClitpmnlibvirt_CXP9031529')
        repo_cmd_mock.assert_called_once_with(exp_query)

    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    @mock.patch('libvirt_plugin.libvirt_plugin.log')
    def test_get_litpmn_package_version_fail(self, log_mock, repo_cmd_mock):
        pkg_name = "ERIClitpmnlibvirt_CXP9031529"

        repo_cmd_mock.return_value = None

        pkg_version = self.plugin._get_litpmn_package_version()
        self.assertEqual(None, pkg_version)

        exp_query = ('repoquery --repoid=a'
                     ' --repofrompath=a,/var/www/html/litp -a'
                     ' --queryformat "%{NAME} %{VERSION} %{RELEASE} %{ARCH}"'
                     ' ERIClitpmnlibvirt_CXP9031529')
        repo_cmd_mock.assert_called_once_with(exp_query)

        log_mock.event.error.assert_called_once_with("Could not find package ERIClitpmnlibvirt_CXP9031529 "
                                                     "in the YUM repositories")

    @mock.patch("libvirt_plugin.libvirt_plugin.LibvirtPlugin._get_litpmn_package_version")
    def test_update_adaptor_version(self, patch_get_pkg_ver):
        patch_get_pkg_ver.return_value = {'version':'1.1.1', 'release':'1'}

        self.setup_base_model()
        ms = self.query("ms")[0]
        vm_image = self.model.create_item("vm-image", "/software/images/vm1",
                                   name="image",
                                   source_uri="http://{0}".format(ms.hostname))
        vm_service = self.model.create_item("vm-service",
                                            "/ms/services/vm_service",
                                            service_name="vmservice",
                                            image_name="image",
                                            adaptor_version="1.0.1-0")
        self.model.set_all_applied()
        self.plugin.update_adaptor_version(self)

        self.assertTrue(vm_service.is_updated())
        self.assertEqual(vm_service.adaptor_version, "1.1.1-1")
        self.assertEqual(vm_service._applied_properties['adaptor_version'], "1.0.1-0")

        patch_get_pkg_ver.return_value = {'version':'1.1.1', 'release':'1'}
        self.model.set_all_applied()

        self.plugin.update_adaptor_version(self)

        self.assertFalse(vm_service.is_updated())
        self.assertEqual(vm_service.adaptor_version, "1.1.1-1")
        self.assertEqual(vm_service._applied_properties['adaptor_version'], "1.1.1-1")

    def test_get_cleanup_images_task(self):
        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node_1 = mock.Mock(item_id='n1', hostname='n1',
                           is_ms=lambda: False,
                           is_for_removal=lambda: False)
        node_2 = mock.Mock(item_id='n1', hostname='n2',
                           is_ms=lambda: False,
                           is_for_removal=lambda: False)

        clustered_service_1 = mock.Mock(node_list='n1,n2',
                                        applied_properties={})
        vm_service_1 = mock.Mock(is_for_removal=lambda: True)
        vm_service_2 = mock.Mock(is_for_removal=lambda: False)
        vm_service_3 = mock.Mock(is_for_removal=lambda: False)
        image_1 = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2")
        image_2 = mock.Mock(source_uri="http://ms1/images/abcde-1.0.1.qcow2")

        vm_serv_facade_1 = VMServiceFacade(node_1, mock.Mock(), vm_service_1,
                                           self.networks, ms_node,
                                           clustered_service_1)
        vm_serv_facade_2 = VMServiceFacade(node_1, image_1, vm_service_2,
                                           self.networks, ms_node,
                                           clustered_service_1)
        vm_serv_facade_3 = VMServiceFacade(node_2, image_1, vm_service_2,
                                           self.networks, ms_node,
                                           clustered_service_1)
        vm_serv_facade_4 = VMServiceFacade(node_1, image_2, vm_service_3,
                                           self.networks, ms_node,
                                           clustered_service_1)

        vm_services = [vm_serv_facade_1, vm_serv_facade_2,
                       vm_serv_facade_3, vm_serv_facade_4]
        task1 = mock.Mock(model_item=vm_service_2)
        node2_task = mock.Mock(node=node_2)
        existing_tasks = [task1, node2_task]

        task = self.plugin.get_cleanup_images_task(vm_serv_facade_1, vm_services, existing_tasks)
        self.assertEqual(len(task), 1)
        self.assertEqual(task[0].kwargs, {'hostname': 'n1',
                                          'image_whitelist': 'fmmed-1.0.1.qcow2,abcde-1.0.1.qcow2'})
        self.assertEqual(task[0].requires, set())
        self.assertEqual(task[0].model_item, vm_service_1)

        task = self.plugin.get_cleanup_images_task(vm_serv_facade_2, vm_services, existing_tasks)
        self.assertEqual(len(task), 1)
        self.assertEqual(task[0].kwargs, {'hostname': 'n1',
                                          'image_whitelist': 'fmmed-1.0.1.qcow2,abcde-1.0.1.qcow2'})
        self.assertEqual(task[0].requires, set())
        self.assertEqual(task[0].model_item, vm_service_2)

        task = self.plugin.get_cleanup_images_task(vm_serv_facade_3, vm_services, existing_tasks)
        self.assertEqual(len(task), 1)
        self.assertEqual(task[0].kwargs, {'hostname': 'n2',
                                          'image_whitelist': 'fmmed-1.0.1.qcow2'})
        self.assertEqual(task[0].requires, set())
        self.assertEqual(task[0].model_item, vm_service_2)

        task = self.plugin.get_cleanup_images_task(vm_serv_facade_4, vm_services, existing_tasks)
        self.assertEqual(len(task), 1)
        self.assertEqual(task[0].kwargs, {'hostname': 'n1',
                                          'image_whitelist': 'fmmed-1.0.1.qcow2,abcde-1.0.1.qcow2'})
        self.assertEqual(task[0].requires, set())
        self.assertEqual(task[0].model_item, vm_service_3)

    @mock.patch('libvirt_plugin.libvirt_plugin.VMServiceFacade._removed_nodes')
    def test_get_cleanup_images_task_node(self, patch_removed_nodes):
        patch_removed_nodes.return_value = set()

        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        node_1 = mock.Mock(hostname='mn1', is_ms=lambda: False,
                           is_for_removal=lambda: False)
        vm_service_1 = mock.Mock(is_for_removal=lambda: False)
        vm_service_2 = mock.Mock(is_for_removal=lambda: False)
        vm_service_3 = mock.Mock(is_for_removal=lambda: True)
        image_1 = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2")
        image_2 = mock.Mock(source_uri="http://ms1/images/fmmed-2.0.2.qcow2")
        image_3 = mock.Mock(source_uri="http://ms1/images/fmmed-3.0.3.qcow2")
        vm_serv_facade_1 = VMServiceFacade(node_1, image_1, vm_service_1,
                                           self.networks, ms_node,
                                           mock.Mock())
        vm_serv_facade_2 = VMServiceFacade(node_1, image_2, vm_service_2,
                                           self.networks, ms_node,
                                           mock.Mock())
        vm_serv_facade_3 = VMServiceFacade(node_1, image_3, vm_service_3,
                                           self.networks, ms_node,
                                           mock.Mock())
        vm_services = [vm_serv_facade_1, vm_serv_facade_2, vm_serv_facade_3]
        task1 = mock.Mock(callback=mock.Mock(),
                          call_type='cb_cleanup_vm_images',
                          kwargs={'hostname':'mn1'})
        task2 = mock.Mock(model_item=vm_service_1)

        existing_tasks = [task1]
        task = self.plugin.get_cleanup_images_task(vm_serv_facade_1, vm_services, existing_tasks)
        self.assertEqual(len(task), 0)

        existing_tasks = [task2]
        task = self.plugin.get_cleanup_images_task(vm_serv_facade_1, vm_services, existing_tasks)
        self.assertEqual(len(task), 1)
        self.assertEqual(task[0].kwargs, {'hostname': 'mn1',
                                          'image_whitelist': 'fmmed-1.0.1.qcow2,fmmed-2.0.2.qcow2'})
        self.assertEqual(task[0].requires, set())
        self.assertEqual(task[0].model_item, vm_service_1)

    def test_get_cleanup_images_task_ms(self):
        ms_node = mock.Mock(hostname='ms1', is_ms=lambda: True,
                            is_for_removal=lambda: False,
                            network_interfaces=[mock.Mock(network_name="mgmt",
                                                          litp_management="true")])
        ms_vm_service = mock.Mock(is_for_removal=lambda: False)
        image_1 = mock.Mock(source_uri="http://ms1/images/fmmed-1.0.1.qcow2")
        vm_serv_facade = VMServiceFacade(ms_node, image_1, ms_vm_service,
                                         self.networks, ms_node, None)
        vm_services = [vm_serv_facade]
        task1 = mock.Mock(callback=mock.Mock(),
                          call_type='cb_cleanup_vm_images',
                          kwargs={'hostname':'ms1'})
        task2 = mock.Mock(model_item=ms_vm_service)

        existing_tasks = [task1]
        task = self.plugin.get_cleanup_images_task(vm_serv_facade, vm_services, existing_tasks)
        self.assertEqual(len(task), 0)

        existing_tasks = [task2]
        task = self.plugin.get_cleanup_images_task(vm_serv_facade, vm_services, existing_tasks)
        self.assertEqual(len(task), 1)
        self.assertEqual(task[0].kwargs, {'hostname': 'ms1',
                                          'image_whitelist': 'fmmed-1.0.1.qcow2'})
        self.assertEqual(task[0].requires, set([task2]))
        self.assertEqual(task[0].model_item, ms_vm_service)

    def test_validate_no_duplicate_rule_numbers(self):
        err_message = "Rule number must be unique. '{0}' is already in use."

        rule_1 = mock.MagicMock()
        rule_1.name = "123 rulename"
        rule_1.vpath = "/pretend/path"
        rule_1.provider = "iptables"
        rule_1.is_applied.return_value = True

        rule_2 = mock.MagicMock()
        rule_2.name = "456 another_name"
        rule_2.vpath = "/another/path"
        rule_2.provider = "iptables"
        rule_2.is_applied.return_value = True

        # No clash across different rule tables
        rule_3 = mock.MagicMock()
        rule_3.name = "456 duplicate_name"
        rule_3.vpath = "/duplicate/path"
        rule_3.provider = "ip6tables"
        rule_3.is_applied.return_value = False

        # Rules with no duplicate rule numbers
        rules = [rule_1, rule_2, rule_3]

        errors = self.plugin._validate_no_duplicate_rule_numbers(rules, 'iptables')
        self.assertEqual([], errors)

        # Introduce a rule with a duplicate rule number
        rule_4 = mock.MagicMock()
        rule_4.name = "123 duplicate_rulenumber"
        rule_4.vpath = "/garbage/path"
        rule_4.provider = "iptables"
        rule_4.is_applied.return_value = False

        rules.append(rule_4)

        errors = self.plugin._validate_no_duplicate_rule_numbers(rules, 'iptables')

        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0], ValidationError(item_path=rule_4.vpath,
                    error_message=err_message.format(rule_4.name.split()[0])))
