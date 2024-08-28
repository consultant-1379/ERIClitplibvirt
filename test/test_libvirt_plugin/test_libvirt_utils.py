import unittest
import mock
import yum

from libvirt_plugin import utils
from litp.core.model_item import ModelItem
from libvirt_plugin import constants
from libvirt_plugin import exception


class TestLibvirtUtils(unittest.TestCase):

    def test_is_ipv6(self):
        ipv6 = "FE80::0202:B3FF:FE1E:8329"
        self.assertTrue(utils.is_ipv6(ipv6))

    def test_is_ipv6_false(self):
        ipv6 = "FE80::0202:B3FF:FE1E:8329:MM"
        self.assertFalse(utils.is_ipv6(ipv6))

    def test_needs_update_release(self):
        version = "1.1.1-1"
        new_version = "1.1.1-2"
        self.assertTrue(utils.needs_update(version, new_version))

    def test_needs_update_false(self):
        version = "1.1.1-2"
        new_version = "1.1.1-2"
        self.assertFalse(utils.needs_update(version, new_version))

    def test_needs_update_version(self):
        version = "1.1.1-1"
        new_version = "1.1.2-1"
        self.assertTrue(utils.needs_update(version, new_version))

    @mock.patch('libvirt_plugin.utils.log')
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_litp_package_version(self, repo_mock, log_mock):
        pkg_name = "ERIClitpmnlibvirt_CXP9031529"
        pkg = mock.Mock(ver='1.1.1', release='1', arch='noarch')

        repo_mock.return_value = "ERIClitpmnlibvirt_CXP9031529 1.1.1 1 noarch"
        expected = {"name":pkg_name, "version":"1.1.1",
                    "release": "1", "arch":"noarch"}

        pkg = utils.get_litp_package_version(pkg_name)
        self.assertEqual(expected, pkg)

        repo_mock.assert_called_once_with('repoquery --repoid=a --repofrompath=a,/var/www/html/litp -a --queryformat "%{NAME} %{VERSION} %{RELEASE} %{ARCH}" ERIClitpmnlibvirt_CXP9031529')

    @mock.patch('libvirt_plugin.utils.log')
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_litp_package_version_cmd_fail(self, repo_mock, log_mock):
        pkg_name = "ERIClitpmnlibvirt_CXP9031529"
        yum_handler = mock.Mock()
        yum_logger = mock.Mock(handlers=[yum_handler])

        repo_mock.return_value = None

        pkg = utils.get_litp_package_version(pkg_name)

        self.assertEqual(None, pkg)

        repo_mock.assert_called_once_with('repoquery --repoid=a --repofrompath=a,/var/www/html/litp -a --queryformat "%{NAME} %{VERSION} %{RELEASE} %{ARCH}" ERIClitpmnlibvirt_CXP9031529')

    @mock.patch('libvirt_plugin.utils.log')
    @mock.patch('libvirt_plugin.utils._execute_repoquery_command')
    def test_litp_package_version_cmd_error(self, repo_mock, log_mock):
        pkg_name = "ERIClitpmnlibvirt_CXP9031529"

        repo_mock.side_effect = exception.LibvirtYumRepoException("ERROR")
        pkg = utils.get_litp_package_version(pkg_name)

        self.assertEqual(None, pkg)

        log_mock.trace.error.assert_called_once_with(
            "Failure to execute reqoquery: ERROR")

    @mock.patch('libvirt_plugin.utils.run_cmd')
    def test_get_time_zone_from_timedatectl(self, mock_run_cmd):
        stdout = "Time zone: Europe/Dublin (GMT, +0000)"
        mock_run_cmd.return_value = 0, stdout, ""
        self.assertEqual(stdout, utils.get_time_zone_from_timedatectl())

    @mock.patch('libvirt_plugin.utils.log')
    @mock.patch('libvirt_plugin.utils.run_cmd')
    def test_get_time_zone_from_timedatectl_ERROR(self, mock_run_cmd, log_mock):
        cmd = "/usr/bin/timedatectl | grep 'Time zone' | " \
              "sed -e 's/^[[:space:]]*//'"
        error_msg = 'Error could not run command "{0}": Return code: "0" ' \
                    'error msg: "ERROR"'.format(cmd)

        mock_run_cmd.return_value = 0, "", "ERROR"
        utils.get_time_zone_from_timedatectl()
        log_mock.trace.error.assert_called_once_with(error_msg)

    @mock.patch('libvirt_plugin.utils.log')
    @mock.patch('libvirt_plugin.utils.run_cmd')
    def test_get_time_zone_from_timedatectl_RC1(self, mock_run_cmd,
                                                      log_mock):
        cmd = "/usr/bin/timedatectl | grep 'Time zone' | " \
              "sed -e 's/^[[:space:]]*//'"
        error_msg = 'Error could not run command "{0}": Return code: "1" ' \
                    'error msg: ""'.format(cmd)

        mock_run_cmd.return_value = 1, "", ""
        utils.get_time_zone_from_timedatectl()
        log_mock.trace.error.assert_called_once_with(error_msg)

    @mock.patch('libvirt_plugin.utils.run_cmd')
    def test_get_names_of_pkgs_in_repo_by_path(self, mock_run_cmd):
        mock_run_cmd.return_value = 0, "pkg1\npkg2\npkg3", ""
        pkgs = utils.get_names_of_pkgs_in_repo_by_path("/var/www/html/litp")
        self.assertEqual(set(["pkg1", "pkg2", "pkg3"]), pkgs)

    @mock.patch('libvirt_plugin.utils.run_cmd')
    def test_get_names_of_pkgs_in_repo_by_path_retry1(self, mock_run_cmd):
        mock_run_cmd.side_effect = [(0, "", "ERROR"),
                                    (0, "pkg1\npkg2\npkg3", "")]
        pkgs = utils.get_names_of_pkgs_in_repo_by_path("/var/www/html/litp")
        self.assertEqual(set(["pkg1", "pkg2", "pkg3"]), pkgs)
        expected = [mock.call('repoquery --repoid=a '
                              '--repofrompath=a,/var/www/html/litp -a '
                              '--queryformat "%{NAME}"'),
                    mock.call('repoquery --repoid=a '
                              '--repofrompath=a,/var/www/html/litp -a '
                              '--queryformat "%{NAME}"')]
        mock_run_cmd.assert_has_calls(expected)

    @mock.patch('libvirt_plugin.utils.run_cmd')
    def test_get_names_of_pkgs_in_repo_by_path_retry2(self, mock_run_cmd):
        mock_run_cmd.side_effect = [(0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "pkg1\npkg2\npkg3", "")]
        self.assertRaises(exception.LibvirtYumRepoException,
                          utils.get_names_of_pkgs_in_repo_by_path,
                          "/var/www/html/litp")
        expected = [mock.call('repoquery --repoid=a '
                              '--repofrompath=a,/var/www/html/litp -a '
                              '--queryformat "%{NAME}"'),
                    mock.call('repoquery --repoid=a '
                              '--repofrompath=a,/var/www/html/litp -a '
                              '--queryformat "%{NAME}"'),
                    mock.call('repoquery --repoid=a '
                              '--repofrompath=a,/var/www/html/litp -a '
                              '--queryformat "%{NAME}"'),
                    mock.call('repoquery --repoid=a '
                              '--repofrompath=a,/var/www/html/litp -a '
                              '--queryformat "%{NAME}"')]
        mock_run_cmd.assert_has_calls(expected)

    def test_append_slash(self):
        some_value = 'some_value'
        self.assertFalse(some_value.endswith('/'))
        some_string = utils.append_slash(some_value)
        self.assertTrue(some_string.endswith('/'))

    def test_evaluate_map(self):
        service = mock.MagicMock()
        service.ip_map = "{'a': '1', 'b': '2'}"
        res = utils.evaluate_map(service, "ip_map")
        self.assertTrue(isinstance(res, dict))

        service.map_list = "['a', 'b']"
        self.assertRaises(Exception, utils.evaluate_map, service, "map_list")

        service.map_err = "{'a': '1', 'b': }"
        self.assertRaises(Exception, utils.evaluate_map, service, "map_err")

    def test_update_service_hostname_map_failover(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames=None,
                            node_hostname_map='{}')
        service.query.return_value = []

        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=False)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'test_vm_service',"
                          " 'node2': 'test_vm_service'}"))

    def test_update_service_hostname_map_failover_hostnames(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames="vm1",
                            node_hostname_map='{}')
        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=False)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'vm1', 'node2': 'vm1'}"))

    def test_update_service_hostname_map_parallel(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames=None,
                            node_hostname_map='{}')
        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=True)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'node1-test_vm_service',"
                          " 'node2': 'node2-test_vm_service'}"))

    def test_update_service_hostname_map_hostnames(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        service = mock.Mock(applied_properties={},
                            vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames="vm1,vm2",
                            node_hostname_map='{}')
        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=True)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'vm1', 'node2': 'vm2'}"))

    def test_update_service_hostname_map_hostnames_2(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        service = mock.Mock(applied_properties={},
                            vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames="vm1,vm2",
                            node_hostname_map=('{}'))
        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=True)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'vm1', 'node2': 'vm2'}"))

    def test_update_service_hostname_map_failover_to_parallel(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        service = mock.Mock(applied_properties={},
                            vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames="vm1,vm2",
                            node_hostname_map=('{}'))
        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=True)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'vm1', 'node2': 'vm2'}"))

    def test_update_service_hostname_map_changed_hostname(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node2")
        service = mock.Mock(applied_properties={"node_hostname_map":
                                                    ('{"node1": "vm2",'
                                                     ' "node2": "vm1"}')},
                            vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames="vm1,vm3",
                            node_hostname_map='{}')
        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=True)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'vm3', 'node2': 'vm1'}"))

    def test_update_service_hostname_map_changed_node(self):
        node1 = mock.Mock(item_id="node1")
        node2 = mock.Mock(item_id="node3")
        service = mock.Mock(applied_properties={"node_hostname_map":
                                                    ('{"node1": "vm2",'
                                                     ' "node2": "vm1"}')},
                            vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames="vm1,vm3",
                            node_hostname_map='{}')
        utils._update_service_hostname_map(service, [node1, node2],
                                           parallel=True)
        self.assertEqual(service.node_hostname_map,
                         ("{'node1': 'vm1', 'node3': 'vm3'}"))

    def test_generate_vm_hostname_failover(self):
        node = mock.Mock(item_id="node1")
        vm_service = mock.Mock(service_name="service1")
        self.assertEquals("service1",
                          utils.generate_vm_hostname(node, vm_service,
                                                     parallel=False))

    def test_generate_vm_hostname_parallel(self):
        node = mock.Mock(item_id="node1")
        vm_service = mock.Mock(service_name="service1")
        self.assertEquals("node1-service1",
                          utils.generate_vm_hostname(node, vm_service,
                                                     parallel=True))

    def test_generate_vm_hostname_parallel_one_node(self):
        node = mock.Mock(item_id="node1")
        vm_service = mock.Mock(service_name="service1")
        self.assertEquals("node1-service1",
                          utils.generate_vm_hostname(node, vm_service,
                                                     parallel=True))

    @mock.patch('libvirt_plugin.utils.collate_attributes')
    def test_model_items_for_redeploy(self, collate):
        item1 = mock.Mock()
        item2 = mock.Mock()
        item3 = mock.Mock()
        item4 = mock.Mock()
        item5 = mock.Mock()
        collate.return_value=[(item1, ModelItem.Initial),
                              (item2, ModelItem.Updated),
                              (item3, ModelItem.Applied),
                              (item4, ModelItem.Initial),
                              (item5, ModelItem.ForRemoval)]
        self.assertEqual(set(utils.model_items_for_redeploy([])),
                         set([item1, item2, item4, item5]))

    def test_property_updated(self):
        item = mock.MagicMock(cpus="1")
        item.applied_properties = {"cpus": "2"}
        self.assertTrue(utils.property_updated(item, "cpus"))

    def test_property_no_updated(self):
        item = mock.MagicMock(cpus="2")
        item.applied_properties = {"cpus": "2"}
        self.assertFalse(utils.property_updated(item, "cpus"))

    def test_property_updated_no_property(self):
        item = mock.MagicMock(cpus="2")
        item.applied_properties = {}
        self.assertTrue(utils.property_updated(item, "cpus"))

    def test_update_service_mac_map(self):
        intf = mock.Mock(device_name="abc", mac_prefix='52:54:00',
                         applied_properties={},
                         is_for_removal=mock.Mock(return_value=False))
        service = mock.Mock(vm_network_interfaces=[intf],
                            get_cluster=mock.Mock(return_value='a'),
                            service_name="service_name")
        service_nodes = [mock.Mock(hostname="abc")]
        api = mock.MagicMock()
        api.query = _mock_vm_interface_query
        utils._update_service_mac_map(service, service_nodes, api)
        self.assertEqual("{'65536abc-service_nameabc': '52:54:00:11:84:33'}",
                         intf.node_mac_address_map)

    def test_update_service_mac_map_skips_interface_for_removal(self):
        intf = mock.Mock(device_name="abc", mac_prefix='52:54:00',
                        applied_properties={},
                        node_mac_address_map='{}',
                        is_for_removal=mock.Mock(return_value=True))
        service = mock.Mock(vm_network_interfaces=[intf],
                            get_cluster=mock.Mock(return_value='a'),
                            service_name="service_name")
        service_nodes = [mock.Mock(hostname="abc")]
        api = mock.MagicMock()
        api.query = _mock_vm_interface_query
        utils._update_service_mac_map(service, service_nodes, api)
        self.assertEqual("{}", intf.node_mac_address_map)

    def test_find_mac(self):
        api = mock.MagicMock()
        api.query = _mock_vm_interface_query

        interface1 = mock.MagicMock()
        interface1.device_name = "eth0"

        key = '65535mn1eth0'
        mac = '52:54:00:ee:2b:de'

        # test if node with specified mac not found
        result = utils._find_mac(api, mac)
        self.assertEqual(None, result)

        ## test if it finds node with specified mac
        api.query = _wrap_vm_interface_query(
            mac="{\"65535mn1eth0\" : \"52:54:00:ee:2b:de\"}")

        interface1.node_mac_address_map = utils.update_map({}, key, mac)
        result = utils._find_mac(api, mac)
        self.assertEqual(key, result)

        ## test cluster standby attribute
        api.query = _wrap_vm_interface_query(
            mac="{\"65535test_vm_service-mn1eth0\" : \"52:54:00:f1:0e:17\"}",
            cluster_standby='0')
        interface1.node_mac_address_map = utils.update_map({}, key, mac)

        result = utils._find_mac(api, '52:54:00:f1:0e:17')
        self.assertEqual('65535test_vm_service-mn1eth0', result)


    def test_find_available_mac(self):
        api = mock.MagicMock()
        api.query = _wrap_vm_interface_query()

        # test the case when mac address not used
        r = utils._find_available_mac('test', '52:54:00', api)
        self.assertEqual('52:54:00:ee:4a:aa', r)

        r = utils._find_available_mac('31227ieatrcxb5403-cmserveth0', '52:54:00', api)
        self.assertEqual('52:54:00:c9:c2:3f', r)

        r = utils._find_available_mac('41227ieatrcxb6741-ebsm5eth0', '52:54:00', api)
        self.assertEqual('52:54:00:b9:fc:67', r)

        # the case when mac address used by different interface
        # mac should be incremented by 1
        api.query = _wrap_vm_interface_query(mac="{\"test1\" : \"52:54:00:ee:4a:aa\"}")
        r = utils._find_available_mac('test', '52:54:00', api)
        self.assertEqual('52:54:00:ee:4a:ab', r)

        # the case when mac address used by the same interface
        api.query = _wrap_vm_interface_query(mac="{\"test\" : \"52:54:00:f1:80:7b\"}")
        r = utils._find_available_mac('65535mn1test_vm_serviceeth0', '52:54:00', api)
        self.assertEqual('52:54:00:b9:b2:e2', r)

    def test_update_repo_checksums(self):
        nfr = mock.Mock(return_value=False)

        repo1 = mock.Mock(base_url="http://ms/3pp", is_for_removal=nfr)
        repo2 = mock.Mock(base_url="http://dep/3pp", is_for_removal=nfr)

        dep_api = mock.Mock(query=mock.Mock(return_value=[repo1]))
        ms_api = mock.Mock(query=mock.Mock(return_value=[repo2]))
        qbv = mock.Mock(side_effect=[dep_api, ms_api])
        api = mock.Mock(query_by_vpath=qbv,
                        query=mock.Mock(return_value=[repo1, repo2]))
        with mock.patch('__builtin__.open', mock.mock_open(read_data=''),
                        create=True) as m:
            utils.update_repo_checksums(api)
        self.assertEqual('d41d8cd98f00b204e9800998ecf8427e', repo1.checksum)
        self.assertEqual('d41d8cd98f00b204e9800998ecf8427e', repo2.checksum)

    @mock.patch('libvirt_plugin.utils.os.path')
    def test_get_template_checksum(self, mock_os_path):
        # Test case: File exists and has content
        mock_os_path.exists.return_value = True

        with mock.patch('__builtin__.open', mock.mock_open(read_data='test data'),
                        create=True) as m:
            result = utils._get_template_checksum('dummy/path')
        self.assertEqual(result, 'eb733a00c0c9d336e65691a37ab54293')  # MD5 for 'test data'

        # Test case: File exists but is empty
        with mock.patch('__builtin__.open', mock.mock_open(read_data=''),
                        create=True) as m:
            result = utils._get_template_checksum('dummy/path')
        self.assertEqual(result, 'd41d8cd98f00b204e9800998ecf8427e')  # MD5 for empty string

        # Test case: File does not exist
        mock_os_path.exists.return_value = False
        result = utils._get_template_checksum('dummy/path')
        self.assertIsNone(result)

    @mock.patch('libvirt_plugin.utils._get_template_checksum')
    def test_update_banner_checksums(self, mock_get_checksum):
        nfr = mock.Mock(return_value=False)
        service1 = mock.Mock(is_for_removal=nfr)
        service2 = mock.Mock(is_for_removal=nfr)

        dep_api = mock.Mock(query=mock.Mock(return_value=[service1]))
        ms_api = mock.Mock(query=mock.Mock(return_value=[service2]))
        qbv = mock.Mock(side_effect=[dep_api, ms_api, dep_api, ms_api, dep_api, ms_api, dep_api, ms_api])
        api = mock.Mock(query_by_vpath=qbv)

        mock_get_checksum.return_value = 'checksum_value'

        # Test with 'issue_net' checksum type
        utils.update_banner_checksums(api, 'issue_net')
        self.assertEqual(service1.issue_net_checksum, 'checksum_value')
        self.assertEqual(service2.issue_net_checksum, 'checksum_value')

        # Test with 'motd' checksum type
        utils.update_banner_checksums(api, 'motd')
        self.assertEqual(service1.motd_checksum, 'checksum_value')
        self.assertEqual(service2.motd_checksum, 'checksum_value')

        # Test with invalid checksum type
        with self.assertRaises(ValueError):
            utils.update_banner_checksums(api, 'invalid_type')

    @mock.patch('libvirt_plugin.utils.get_checksum')
    def test_update_service_image_checksums(self, chksum_patch):
        s1 = mock.Mock(is_for_removal=mock.Mock(return_value=False),
                       image_name="image1")
        s2 = mock.Mock(is_for_removal=mock.Mock(return_value=False),
                       image_name="image2")
        im1 = mock.Mock(is_for_removal=mock.Mock(return_value=False),
                        source_uri='uri1')
        im1.name="image1"
        im2 = mock.Mock(is_for_removal=mock.Mock(return_value=False),
                        source_uri='uri2')
        im2.name="image2"
        dep_api = mock.Mock(query=mock.Mock(return_value=[s1]))
        ms_api = mock.Mock(query=mock.Mock(return_value=[s2]))
        qbv = mock.Mock(side_effect=[dep_api, ms_api])
        api = mock.Mock(query_by_vpath=qbv,
                        query=mock.Mock(return_value=[im1, im2]))

        chksum_patch.side_effect = ["chk1", "chk2"]
        utils.update_service_image_checksums(api)
        self.assertEqual("chk1", s1.image_checksum)
        self.assertEqual("chk2", s2.image_checksum)


class TestLibvirtUtilsUpdateNodeIpMap(unittest.TestCase):
    def setUp(self):
        self.intf = mock.Mock(applied_properties={},
                              node_ip_map={},
                              is_for_removal=mock.Mock(return_value=False),
                              ipaddresses="",
                              ipv6addressess="")
        self.service = mock.Mock(query=mock.Mock(return_value=[self.intf]))
        self.nodes = [mock.Mock(item_id="n1"),
                      mock.Mock(item_id="n2")
                     ]

    def test_update_node_ip_map(self):
        self.intf.ipaddresses = "10.10.10.1"
        self.intf.ipv6addresses = "2607:f0d0:1002:0011::2/64"
        utils._update_service_node_ip_map(self.service,
                                          self.nodes,
                                          parallel=False)
        self.assertEqual(
            {'n1': {'ipv4': '10.10.10.1', 'ipv6': '2607:f0d0:1002:0011::2/64'},
             'n2': {'ipv4': '10.10.10.1', 'ipv6': '2607:f0d0:1002:0011::2/64'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

        self.intf.applied_properties = {"node_ip_map":
                                       str({"n1": {'ipv4': "10.10.10.1",
                                                   'ipv6': '2607:f0d0:1002:0011::1/64'},
                                            "n2": {'ipv4': "10.10.10.2",
                                                    'ipv6': '2607:f0d0:1002:0011::2/64'}})}

        self.intf.ipaddresses = "10.10.10.3,10.10.10.1"
        self.intf.ipv6addresses = "2607:f0d0:1002:0011::1/64,2607:f0d0:1002:0011::2/64"
        utils._update_service_node_ip_map(self.service,
                                                  self.nodes,
                                                  parallel=True)
        self.assertEqual(
            {'n1': {'ipv4': '10.10.10.1', 'ipv6': '2607:f0d0:1002:0011::1/64'},
             'n2': {'ipv4': '10.10.10.3', 'ipv6': '2607:f0d0:1002:0011::2/64'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

        self.intf.applied_properties = {"node_ip_map":
                                       str({"n1": {'ipv4': "10.10.10.1",
                                                   'ipv6': '2607:f0d0:1002:0011::1/64'},
                                            "n2": {'ipv4': "10.10.10.2",
                                                    'ipv6': '2607:f0d0:1002:0011::2/64'}})}

        self.intf.ipaddresses = "10.10.10.4,10.10.10.1,10.10.10.3,10.10.10.2"
        self.intf.ipv6addresses = ('2607:f0d0:1002:0011::1/64,'
                                  '2607:f0d0:1002:0011::2/64,'
                                  '2607:f0d0:1002:0011::3/64,'
                                  '2607:f0d0:1002:0011::4/64')
        self.nodes = [mock.Mock(item_id="n4"),
                     mock.Mock(item_id="n3"),
                     mock.Mock(item_id="n5"),
                     mock.Mock(item_id="n1")
                     ]
        utils._update_service_node_ip_map(self.service,
                                          self.nodes,
                                          parallel=True)
        self.assertEqual(
            {'n1': {'ipv4': '10.10.10.1', 'ipv6': '2607:f0d0:1002:0011::1/64'},
             'n3': {'ipv4': '10.10.10.3', 'ipv6': '2607:f0d0:1002:0011::3/64'},
             'n4': {'ipv4': '10.10.10.4', 'ipv6': '2607:f0d0:1002:0011::2/64'},
             'n5': {'ipv4': '10.10.10.2', 'ipv6': '2607:f0d0:1002:0011::4/64'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

    def test_update_node_ip_map_with_ipv4_applied_dhcp_ipv6_static(self):
        self.intf.applied_properties = {"node_ip_map":
                                       str({"n1": {'ipv6': '2607:f0a0:1002:0011::1/64'},
                                            "n2": {'ipv6': '2607:f0a0:1002:0011::2/64'}}),
                                       "ipaddresses": constants.DYNAMIC_IP}
        self.intf.ipaddresses = "10.10.10.2,10.10.10.1"
        self.intf.ipv6addresses = "2607:f0a0:1002:0011::1/64,2607:f0a0:1002:0011::2/64"

        utils._update_service_node_ip_map(self.service, self.nodes, parallel=True)
        self.assertEqual(
            {'n1': {'ipv4': '10.10.10.2', 'ipv6': '2607:f0a0:1002:0011::1/64'},
             'n2': {'ipv4': '10.10.10.1', 'ipv6': '2607:f0a0:1002:0011::2/64'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

    def test_update_node_ip_map_with_old_ipv4_only_map_applied(self):
        self.intf.applied_properties = {"node_ip_map":
                                       str({"n1": "10.10.10.2",
                                            "n2": "10.10.10.1"}),
                                       "ipaddresses": "10.10.10.2,10.10.10.1"}
        self.intf.ipaddresses = "10.10.10.3,10.10.10.4"
        self.intf.ipv6addresses = ""

        utils._update_service_node_ip_map(self.service, self.nodes, parallel=True)
        self.assertEqual(
            {'n1': {'ipv4': '10.10.10.3'},
             'n2': {'ipv4': '10.10.10.4'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

    def test_update_node_ip_map_with_ipv4_new_dhcp_ipv6_static(self):
        self.intf.applied_properties = {"node_ip_map":
                                   str({"n1": {'ipv6': '2607:f0d0:1002:0011::2/64'},
                                        "n2": {'ipv6': '2607:f0d0:1002:0011::2/64'}}),
                                   "ipaddresses": "10.10.10.2,10.10.10.1"}

        self.intf.ipaddresses = constants.DYNAMIC_IP
        self.intf.ipv6addresses = "2607:f0a0:1002:0012::2/64,2607:f0d0:1002:0013::2/64"

        utils._update_service_node_ip_map(self.service, self.nodes, parallel=True)
        self.assertEqual(
            {'n1': {'ipv6': '2607:f0a0:1002:0012::2/64'},
             'n2': {'ipv6': '2607:f0d0:1002:0013::2/64'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

    def test_update_node_ip_map_with_ipv4_only_dhcp_ipv6_static(self):
        self.intf.applied_properties = {"node_ip_map":
                                       str({"n1": {'ipv6': '2607:f0d0:1002:0011::2/64'},
                                            "n2": {'ipv6': '2607:f0d0:1002:0011::2/64'}}),
                                       "ipaddresses": constants.DYNAMIC_IP}

        self.intf.ipaddresses = constants.DYNAMIC_IP
        self.intf.ipv6addresses = "2607:f0a0:1002:0011::2/64,2607:f0d0:1002:0013::2/64"

        utils._update_service_node_ip_map(self.service, self.nodes, parallel=True)
        self.assertEqual(
            {'n1': {'ipv6': '2607:f0a0:1002:0011::2/64'},
             'n2': {'ipv6': '2607:f0d0:1002:0013::2/64'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

    def test_update_node_ip_map_with_ipv4_with_dhcp_update_to_static(self):
        self.intf.applied_properties = {"ipaddresses": constants.DYNAMIC_IP}

        self.intf.ipaddresses = "10.10.10.2,10.10.10.1"
        self.intf.ipv6addresses = ""

        utils._update_service_node_ip_map(self.service, self.nodes, parallel=True)
        self.assertEqual(
            {'n1': {'ipv4': '10.10.10.2'},
             'n2': {'ipv4': '10.10.10.1'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

    def test_update_node_ip_map_with_ipv4_with_static_update_to_dhcp(self):
        self.intf.applied_properties = {"ipaddresses": "10.10.10.2,10.10.10.1"}

        self.intf.ipaddresses = constants.DYNAMIC_IP
        self.intf.ipv6addresses = ""

        utils._update_service_node_ip_map(self.service, self.nodes, parallel=True)
        self.assertEqual({}, utils.evaluate_map(self.intf, "node_ip_map"))

    def test_update_node_ip_map_with_ipv4_with_static_update_ipv4_and_ipv6(self):
        self.intf.applied_properties = {"ipaddresses": "10.10.10.2,10.10.10.1"}

        self.intf.ipaddresses = "10.10.10.1,10.10.10.4"
        self.intf.ipv6addresses = "2607:f0a0:1002:0011::2/64,2607:f0d0:1002:0013::2/64"

        utils._update_service_node_ip_map(self.service, self.nodes, parallel=True)
        self.assertEqual(
            {'n1': {'ipv4': '10.10.10.1',
                    'ipv6': '2607:f0a0:1002:0011::2/64'},
             'n2': {'ipv4': '10.10.10.4',
                    'ipv6': '2607:f0d0:1002:0013::2/64'}},
            utils.evaluate_map(self.intf, "node_ip_map"))

    def test_get_associated_haconfig(self):
        ha_cfg1 = mock.Mock(service_id='another_service')
        ha_cfg2 = mock.Mock(service_id='a_vm_service')
        clustered_service = mock.Mock()
        clustered_service.query.return_value = [ha_cfg1, ha_cfg2]
        service = mock.Mock(vm_aliases=[], vm_network_interfaces=[],
                            vm_yum_repos=[], vm_packages=[], vm_nfs_mounts=[],
                            cpus=2, ram='256M', service_name='test_vm_service',
                            vm_ssh_keys=[], hostnames=None,
                            node_hostname_map='{}', item_id='a_vm_service')
        facade = mock.Mock(_service=service,
                           _clustered_service=clustered_service)
        self.assertEqual(ha_cfg2, utils.get_associated_haconfig(facade))

        # no matching service
        ha_cfg2 = mock.Mock(service_id='yet_another_vm_service')
        clustered_service.query.return_value = [ha_cfg1, ha_cfg2]
        self.assertEqual(None, utils.get_associated_haconfig(facade))

        # no service at all
        clustered_service.query.return_value = []
        self.assertEqual(None, utils.get_associated_haconfig(facade))

        # only one service, so no service_id property set
        ha_cfg2 = mock.Mock()
        clustered_service.query.return_value = [ha_cfg2]
        self.assertEqual(ha_cfg2, utils.get_associated_haconfig(facade))


def test_collate_attributes():
    """
    Test for `collate_attributes` utility function.
    """

    # Empty input.
    elems = []
    assert [] == list(utils.collate_attributes(elems, 'foo'))

    # All attribute elems.
    elems = [mock.Mock(attr=1), mock.Mock(attr=2), mock.Mock(attr=3)]
    assert [(elems[0], 1),
            (elems[1], 2),
            (elems[2], 3)] == list(utils.collate_attributes(elems, 'attr'))

    # All callable elems.
    elems = [
        mock.Mock(attr=lambda: 1),
        mock.Mock(attr=lambda: 2),
        mock.Mock(attr=lambda: 3)]
    assert [(elems[0], 1),
            (elems[1], 2),
            (elems[2], 3)] == list(utils.collate_attributes(elems, 'attr'))

    # Mixed callable and attribute.
    elems = [
        mock.Mock(attr=lambda: 1),
        mock.Mock(attr=2),
        mock.Mock(attr=lambda: 3)]
    assert [(elems[0], 1),
            (elems[1], 2),
            (elems[2], 3)] == list(utils.collate_attributes(elems, 'attr'))

    # Test optional arguments.
    attr = mock.Mock()
    elems = [mock.Mock(attr=attr)]
    list(utils.collate_attributes(
        elems, 'attr', 'foo', 'bar', bang='bob'))
    assert attr.called_once_with('foo', 'bar', bang='bob')

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

def _wrap_vm_interface_query(mac='{}', cluster_standby='1'):
    def newfunc(a):
        return _mock_vm_interface_query(
            a,
            mac=mac,
            cluster_standby=cluster_standby,
        )
    return newfunc

def test_redeployable():
    """
    Test the `redeployable` utility function.
    """

    # Test empty input.
    assert False == utils.redeployable([])

    # Test no updates or initial.
    assert False == utils.redeployable([
        mock.Mock(get_state=lambda: 'foo'),
        mock.Mock(get_state=lambda: 'bar')])

    # Test all initial.
    assert True == utils.redeployable([
        mock.Mock(get_state=lambda: ModelItem.Initial),
        mock.Mock(get_state=lambda: ModelItem.Initial)])

    # Test partial initial.
    assert True == utils.redeployable([
        mock.Mock(get_state=lambda: ModelItem.Initial),
        mock.Mock(get_state=lambda: 'foo')])

    # Test all updated.
    assert True == utils.redeployable([
        mock.Mock(get_state=lambda: ModelItem.Updated),
        mock.Mock(get_state=lambda: ModelItem.Updated)])

    # Test partial updated.
    assert True == utils.redeployable([
        mock.Mock(get_state=lambda: ModelItem.Updated),
        mock.Mock(get_state=lambda: 'foo')])

    # Test mixed updated and initial.
    assert True == utils.redeployable([
        mock.Mock(get_state=lambda: ModelItem.Updated),
        mock.Mock(get_state=lambda: ModelItem.Initial)])


def test_format_list_error():
    assert '' == utils.format_list([])

    assert '"vpath1"' == utils.format_list(["vpath1"])

    assert '"vpath1" and "vpath2"' == utils.format_list(['vpath1', 'vpath2'])

    assert '"vpath1", "vpath2" and "vpath3"' == utils.format_list(['vpath1', 'vpath2', 'vpath3'])

    assert '"vpath1", "vpath2", "vpath3" and "vpath4"' == utils.format_list(['vpath2', 'vpath1', 'vpath3', "vpath4"])

    assert '"aaa", "bbb", "ccc" and "zzz"' == utils.format_list(['aaa', 'ccc', 'zzz', 'bbb'])

def test_convert_node_ip_map():
    # Test old to new conversion
    assert utils.convert_node_ip_map({'n1': '192.168.0.4', 'n2': '192.168.0.4'}) == {'n1': {'ipv4': '192.168.0.4'}, 'n2': {'ipv4': '192.168.0.4'}}

    # Test idempotence
    assert utils.convert_node_ip_map({'n1': {'ipv4': '192.168.0.4'}, 'n2': {'ipv4': '192.168.0.4'}}) == {'n1': {'ipv4': '192.168.0.4'}, 'n2': {'ipv4': '192.168.0.4'}}

    # Test is copy
    assert utils.convert_node_ip_map({'n1': {'ipv4': '192.168.0.4'}, 'n2': {'ipv4': '192.168.0.4'}}) is not {'n1': {'ipv4': '192.168.0.4'}, 'n2': {'ipv4': '192.168.0.4'}}
