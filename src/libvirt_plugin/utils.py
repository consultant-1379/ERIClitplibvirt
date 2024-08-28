import os
import re
import ast
import netaddr
from rpmUtils.miscutils import compareEVR, stringToVersion
import subprocess
from urlparse import urlparse

from litp.core.litp_logging import LitpLogger
from litp.core.model_item import ModelItem
import hashlib
from . import constants
from . import exception
from itertools import count


log = LitpLogger()


def is_ipv6(address):
    """
    Return `True` if `address` is a valid ipv6 address otherwise `False`.
    """
    return netaddr.valid_ipv6(strip_prefixlen(address))


def strip_prefixlen(address):
    """
    Strip the prefixlen from an ipv6 address.
    """
    return address.split('/', 1)[0]


def run_cmd(cmd):
    """
    Run a shell command, capturing stdout & stderr
    """
    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True)

    outs, errs = p.communicate()

    return p.returncode, outs, errs


def get_time_zone_from_timedatectl():
    """
    Run a shell command, to capture timezone from
    """
    cmd = "/usr/bin/timedatectl | grep 'Time zone' | " \
          "sed -e 's/^[[:space:]]*//'"
    result, stdout, stderr = run_cmd(cmd)
    if result == 0 and not stderr:
        return stdout
    else:
        log.trace.error('Error could not run command "{0}": Return code: '
                        '"{1}" error msg: "{2}"'.format(cmd, result, stderr))


def needs_update(deployed_version, new_version):
    """
    Return `True` if `deployed_version` is older than `new_version`.

    The given version strings are RPM versions in the format 'a.b-c' so we
    use methods from rpmUtils to parse and compare them.
    """
    return compareEVR(stringToVersion(deployed_version),
                      stringToVersion(new_version)) < 0


def _execute_repoquery_command(cmd):
    # intermittent failure of reqoquery has been seen before (LITPCDS-10800)
    REPOQUERY_RETRIES = 4

    retries = REPOQUERY_RETRIES
    while True:
        result, stdout, stderr = run_cmd(cmd)
        if result == 0 and not stderr:
            return stdout
        else:
            retries -= 1
            if retries == 0:
                msg = ('Error executing repoquery command: "{0}", result:'
                       ' {1}, stderr {2}'.format(cmd, result, stderr))
                log.event.error(msg)
                raise exception.LibvirtYumRepoException(msg)
            else:
                log.event.error("repoquery failure, will retry, return code:"
                                " {0}, stderr: {1}".format(result, stderr))


def get_litp_package_version(pkg_name):
    # using --repoid disables all repositories not explicitly enabled with
    # --repoid, --repofrompath specifies a particular repo (not enabled by
    # default in YUM configuration). 'a' is used to identify the combination
    # as both arguments can be used multiple times.
    command = ('repoquery --repoid=a --repofrompath=a,/var/www/html/litp -a '
               '--queryformat "%{NAME} %{VERSION} %{RELEASE} %{ARCH}" '
               + pkg_name)
    try:
        stdout = _execute_repoquery_command(command)
        if stdout:
            info = stdout.split()
            return {"name": pkg_name,
                    "version": info[1],
                    "release": info[2],
                    "arch": info[3]}
    except exception.LibvirtYumRepoException as ex:
        log.trace.error("Failure to execute reqoquery: " + str(ex))
        return None


def get_names_of_pkgs_in_repo_by_path(repo_path):
    # using --repoid disables all repositories not explicitly enabled with
    # --repoid, --repofrompath specifies a particular repo (not enabled by
    # default in YUM configuration). 'a' is used to identify the combination
    # as both arguments can be used multiple times.
    command = ('repoquery --repoid=a --repofrompath=a,' + repo_path +
               ' -a --queryformat "%{NAME}"')
    stdout = _execute_repoquery_command(command)
    pkgs = set()
    for pkg in stdout.splitlines():
        pkgs.add(pkg)
    return pkgs


def append_slash(value):
    return value if value.endswith('/') else value + '/'


def collate_attributes(items, attribute, *args, **kwargs):
    """
    Generator which collates all attributes `attribute` of each
    element in `items`. If the given attribute of the element is
    callable, the yielded result is the result of calling the attribute
    with `args` and `kwargs`.
    """
    for item in items:
        result = getattr(item, attribute)
        try:
            result = result(*args, **kwargs)
        except TypeError:
            pass
        yield (item, result)


def redeployable(elems):
    """
    Utility function which receives a sequence of model items
    and returns `True` if any of them are in an Initial or
    Updated state.

    Uses `any` instead of `bool` so as to return at the first
    sign of a redeployable item and not consume the entire
    `collate_attributes` generator.
    """
    return any(
        set((ModelItem.Initial, ModelItem.Updated, ModelItem.ForRemoval))
        & set(dict(collate_attributes(elems, 'get_state')).values()))


def model_items_for_redeploy(elems):
    redeploy_states = set((ModelItem.Initial, ModelItem.Updated,
                           ModelItem.ForRemoval))
    item_states = dict(collate_attributes(elems, 'get_state'))
    return [model_item for model_item in item_states
            if item_states[model_item] in redeploy_states]


def property_updated(item, prop):
    """
    Compare the property with value in applied_properties.
    :param item: Item from the model
    :type item: ModelItem
    :param property: property name
    :type item: str
    :return: bool
    """
    value = getattr(item, prop)
    applied_property_value = item.applied_properties.get(prop)
    return value != applied_property_value


def is_dynamic_ip(vm_iface, applied=False):
    if applied:
        return (vm_iface.applied_properties.get('ipaddresses') ==
                constants.DYNAMIC_IP)
    return vm_iface.ipaddresses == constants.DYNAMIC_IP


def evaluate_map(item, map_name, applied=False):
    msg = ("the map '{0}' of model_item {1} is corrupted."
           " Please restore its value to default i.e. empty"
           " dictionary".format(map_name, item.get_vpath()))

    map_to_evaluate = item.applied_properties[map_name] if applied \
        else getattr(item, map_name)

    try:
        result = ast.literal_eval(map_to_evaluate)
    except SyntaxError:
        raise exception.LibvirtPluginError(msg)

    if isinstance(result, dict):
        return result
    else:
        raise exception.LibvirtPluginError(msg)


def update_map(map_dict, key, value):
    map_dict[key.encode('ascii')] = value.encode('ascii')
    return str(map_dict)


def _update_service_node_ip_map(service, service_nodes, parallel=True):
    """
    Updates the node_ip_map for each vm-network-interface under a given
    vm-service. If the service is deployed for the first time, the ip
    addresses(ether ipv4 or ipv6) are distributed to any node.
    If the ipaddress list(ipv4 or ipv6) is updated, if the service on a
    particular host node was previously given an ip address (check in
    applied_properties) then it should be the same after update.
    For a failover services there is only one IP address so it is chosen
    """
    def collect_ips(available_ips):
        dict_ipvs = dict()

        for key, value in available_ips.iteritems():
            if value:
                update_map(dict_ipvs, key, value[0])
        return dict_ipvs

    def encode(to_encode):
        return to_encode.encode("ascii")

    def move_ip_to_map(new_map, node, available_ips, ipv, ip_to_move):
        available_ips[ipv].remove(ip_to_move)
        ip_map = new_map.get(encode(node), {})
        ip_map[encode(ipv)] = encode(ip_to_move)
        new_map[encode(node)] = ip_map

    for intf in service.query('vm-network-interface'):
        if intf.is_for_removal():
            continue
        available_ipsv4 = (
            intf.ipaddresses.split(',') if (intf.ipaddresses and \
                                            not is_dynamic_ip(intf))
                           else [])
        available_ipsv6 = (intf.ipv6addresses.split(',') if intf.ipv6addresses
                           else [])

        new_map = dict()
        last_config = dict()

        node_ids = [node.item_id for node in service_nodes]
        available_ips = {'ipv4': available_ipsv4, 'ipv6': available_ipsv6}
        if not available_ipsv4 and not available_ipsv6:
            new_ip_map = str({})
        elif not parallel:
            for node in node_ids:
                new_map[encode(node)] = collect_ips(available_ips)

            new_ip_map = str(new_map)
        else:
            if "node_ip_map" in intf.applied_properties:
                last_config = convert_node_ip_map(evaluate_map(
                        intf, constants.NODE_IP_MAP, applied=True))

            for ipv in ["ipv4", "ipv6"]:
                for node in node_ids:
                    old_ip = last_config.get(node, {}).get(ipv)
                    if old_ip:
                        if old_ip in available_ips[ipv]:
                            move_ip_to_map(new_map, node, available_ips,
                                           ipv, old_ip)

            for ipv in ["ipv4", "ipv6"]:
                for node in node_ids:
                    for available_ip in available_ips[ipv]:
                        if not new_map.get(node, {}).get(ipv):
                            move_ip_to_map(new_map, node, available_ips,
                                           ipv, available_ip)
                            break

            new_ip_map = str(new_map)

        intf.node_ip_map = new_ip_map


def get_interface_id(cluster_id, node_hostname, service_name, device_name,
                     parallel):
    """
    Returns unique network interface identifier.
    Used to generate MAC addresses.
    """
    service_hostname = node_hostname + '-' + service_name if parallel \
                                                          else service_name
    return "{0}{1}{2}".format(cluster_id, service_hostname, device_name)


def _update_service_mac_map(service, service_nodes, api, parallel=True):
    """
    Returns SHA256 of concatenated cluster_id, node hostname
    (i.e. ``mn1``), service hostname ( ``vmservice`` ) and
    device name ( ``ethN`` ).

    Updates intf.node_mac_address_map if necessary.
    """
    for intf in service.vm_network_interfaces:
        if intf.is_for_removal():
            continue
        new_node_mac_address_map = dict()

        mac_prefix = str(intf.mac_prefix if intf.mac_prefix \
                                     else constants.DEFAULT_MAC_PREFIX)

        m_map = evaluate_map(intf,
                             constants.NODE_MAC_ADDRESS_MAP, applied=True) \
            if intf.applied_properties.get("node_mac_address_map") else dict()

        for node in service_nodes:
            cluster_id = getattr(service.get_cluster(), 'cluster_id',
                                 constants.DEFAULT_CLUSTER_ID)
            key = get_interface_id(
                cluster_id=cluster_id,
                node_hostname=node.hostname,
                service_name=service.service_name,
                device_name=intf.device_name,
                parallel=parallel)
            new_node_mac_address_map[key] =  \
                m_map[key] if m_map.get(key, "").startswith(mac_prefix) \
                           else _find_available_mac(key, mac_prefix, api)

        intf.node_mac_address_map = str(new_node_mac_address_map)


def _find_mac(api, mac_address):
    """
    Returns string, that uniquely identifies node
    with requested mac address.
    If no such node found, returns None.
    """
    for intf in api.query('vm-network-interface'):
        mac_map = evaluate_map(intf, constants.NODE_MAC_ADDRESS_MAP)
        if mac_map:
            for key, value in mac_map.iteritems():
                if value == mac_address:
                    return key


def _find_available_mac(key, mac_prefix, api):
    """
    Receives ``key``, which string of concatenated
    cluster_id, node hostname, service hostname, device name
    and returns first not used MAC address.

    ``mac_prefix`` -- first three bytes of MAC address
    """
    hash_key = hashlib.sha512(key).hexdigest()[:18]
    hash_key = hash_key[:2] + hash_key[8:10] + hash_key[16:18]

    for counter in count():
        h = format(int(hash_key, 16) + counter, '06x')
        mac = '%s:%s:%s:%s' % (mac_prefix, h[:2], h[2:4], h[4:])
        vm_intf_uniq_id = _find_mac(api, mac)
        if not vm_intf_uniq_id or vm_intf_uniq_id == key:
            break

    return mac


def _update_service_hostname_map(service, service_nodes, parallel=True):
    """
    Updates the node_hostname_map for a given vm-service. If there is no
    hostnames property in the service, the hostnames for each instance
    of a vm is generated by the method generate_vm_hostname.
    If there is a hostnames property, then during deployment, the hostnames
    addresses are distributed to any node. If the hostnames property is
    updated and the hostname on a particular host node was previously
    given an instance of a vm-service on a particular host node (check in
    applied_properties) then it should be the same after update.
    For a failover services there is only one hostname so it is chosen
    """
    new_map = dict()
    last_config = dict()
    node_ids = [node.item_id for node in service_nodes]
    hostnames = getattr(service, "hostnames", "")

    if not hostnames:
        for node in service_nodes:
            hostname = generate_vm_hostname(node, service, parallel)
            new_hostname_map = update_map(new_map, node.item_id, hostname)
    else:
        available_names = hostnames.split(',')

        if not parallel:
            for node in node_ids:
                new_hostname_map = update_map(new_map, node,
                                              available_names[0])
        else:
            if "node_hostname_map" in service.applied_properties:
                last_config = \
                    evaluate_map(service, constants.NODE_HOSTNAME_MAP,
                                 applied=True)

            available_nodes = [node for node in node_ids]
            for node in node_ids:
                old_name = last_config.get(node)
                if old_name in available_names:
                    available_nodes.remove(node)
                    available_names.remove(old_name)
                    new_hostname_map = update_map(new_map, node, old_name)
            for index, node in enumerate(available_nodes):
                name = available_names[index]
                new_hostname_map = update_map(new_map, node, name)

    service.node_hostname_map = new_hostname_map


def update_maps_for_services(api):
    # Find VMs on nodes.
    for node in api.query('node') + api.query('ms'):
        for service in node.services:
            if service.is_for_removal():
                continue
            if service.item_type_id == 'vm-service':
                _update_service_node_ip_map(service, [node])
                _update_service_hostname_map(service, [node])
                _update_service_mac_map(service, [node], api)
    # Finds VMs part of clustered service.
    for cluster in api.query('cluster'):
        for clustered_service in cluster.services:
            parallel = True if clustered_service.standby == "0" else False
            for service in clustered_service.query('vm-service'):
                if service.is_for_removal():
                    continue
                _update_service_node_ip_map(
                    service,
                    clustered_service.nodes,
                    parallel=parallel)
                _update_service_hostname_map(
                    service,
                    clustered_service.nodes,
                    parallel=parallel)
                _update_service_mac_map(
                    service,
                    clustered_service.nodes,
                    api,
                    parallel=parallel)


def update_repo_checksums(api):

    deployments_api = api.query_by_vpath('/deployments')
    ms_api = api.query_by_vpath("/ms")
    repos = deployments_api.query("vm-yum-repo") +\
            ms_api.query("vm-yum-repo") +\
            deployments_api.query("vm-zypper-repo") +\
            ms_api.query("vm-zypper-repo")
    repolist = [repo for repo in repos
                if not repo.is_for_removal()]
    recorded_checksums = {}
    for repo in repolist:
        url = append_slash(urlparse(repo.base_url).path)
        repomd_file = constants.APACHE_DIR + url + "repodata/repomd.xml"
        if repomd_file in recorded_checksums:
            repo.checksum = recorded_checksums[repomd_file]
            continue
        with open(repomd_file) as rf:
            md5sum = hashlib.md5(rf.read()).hexdigest()
            repo.checksum = md5sum
            recorded_checksums[repomd_file] = md5sum


def _get_template_checksum(template):
    if os.path.exists(template):
        with open(template) as _reader:
            return hashlib.md5(_reader.read()).hexdigest()


def update_banner_checksums(api, checksum_type):
    if checksum_type == 'issue_net':
        template_constant = constants.CUSTOM_SSH_LOGIN_BANNER
        checksum_attr = 'issue_net_checksum'
    elif checksum_type == 'motd':
        template_constant = constants.CUSTOM_MOTD
        checksum_attr = 'motd_checksum'
    else:
        raise ValueError("Invalid checksum type")

    checksum = _get_template_checksum(
        os.path.join(constants.LITP_TEMPLATES, template_constant))

    if checksum:
        deployments_api = api.query_by_vpath('/deployments')
        ms_api = api.query_by_vpath("/ms")
        vm_services = (deployments_api.query("vm-service") +
                       ms_api.query("vm-service"))

        services = [service for service in vm_services
                    if not service.is_for_removal()]
        for service in services:
            setattr(service, checksum_attr, checksum)


def update_service_image_checksums(api):
    """
    Set the image_checksum property of the vm-service
    """
    deployments_api = api.query_by_vpath('/deployments')
    ms_api = api.query_by_vpath("/ms")
    vm_images = [image for image in api.query('vm-image')
                 if not image.is_for_removal()]
    vm_image_dict = {}
    for image in vm_images:
        vm_image_dict[image.name] = image

    recorded_checksums = {}
    vm_services = deployments_api.query("vm-service") + \
        ms_api.query("vm-service")
    services = [service for service in vm_services
                if not service.is_for_removal()]
    for service in services:
        image = vm_image_dict[service.image_name]
        if image.source_uri not in recorded_checksums:
            checksum = get_checksum(image.source_uri)
            recorded_checksums[image.source_uri] = checksum
        service.image_checksum = recorded_checksums[image.source_uri]


def generate_vm_hostname(node, vm_service, parallel):
    hostname = vm_service.service_name
    if parallel:
        hostname = node.item_id.replace("_", "-") + '-' + hostname
    return hostname


def quote(word):
    """ Add double quotes before and after word if neccessary """
    if not word.startswith('"'):
        word = '"' + word
    if not word.endswith('"'):
        word = word + '"'
    return word


def text_join(args, sep=', ', last=' and '):
    """ Add separator between args and last before last arg in list """
    if len(args) < 2:
        return sep.join(args)
    return sep.join(args[:-1]) + last + args[-1]


def convert_node_ip_map(node_ip_map):
    """Returns a copy of node_ip_map in a format as currently used by the
    plugin
    """
    clone = {}
    for key, value in node_ip_map.items():
        if isinstance(value, str):
            value = {'ipv4': value}
        clone[key] = value
    return clone


def format_list(errors):
    """
    Returns a string of correctly formatted errors, sorted alphabetically
    :param: errors (list of strings)
    :return: formatted_errors (str)
    """
    errors = [quote(error) for error in sorted(errors)]
    return text_join(errors)


def get_applied_node_list(clustered_service):
    try:
        applied_nodes = clustered_service.\
            applied_properties.get('node_list').split(',')
    except AttributeError:
        applied_nodes = []
    return applied_nodes


def exist_image_file(source_uri):
    """Return True if the image file exists"""
    image_full_path = get_image_full_path(source_uri)
    try:
        with open(image_full_path):
            return True
    except (OSError, IOError) as ex:
        log.trace.info("Could not open image {0}. Error: {1}".format(
                image_full_path, ex))
        return False


def get_image_full_path(source_uri):
    """
    Return the full path of the image file
    source_uri have to be libvirt_url type.
    """
    path = urlparse(source_uri).path[1:]
    full_path = os.path.join(constants.APACHE_DIR, path)
    return full_path


def custom_script_exists(file_name):
    """"Return True if the custom script exists"""
    custom_script_path = get_custom_script_absolute_path(file_name)
    return os.path.exists(custom_script_path)


def custom_script_is_regular_file(file_name):
    """Return True if the custom script is a regular file"""
    custom_script_path = get_custom_script_absolute_path(file_name)
    return os.path.isfile(custom_script_path) and not os.path.islink(
        custom_script_path)


def get_custom_script_absolute_path(file_name):
    """"Return True if the custom script exists"""
    abs_path = os.path.join(constants.APACHE_DIR,
                            constants.CUSTOM_SCRIPTS_DIR, file_name)
    return abs_path


def remove_ip_prefix(ipaddr):
    """Strips a CIDR prefix from a IP address"""
    return re.sub(r'\/\d+$', '', ipaddr)


def get_md5_file_name(source_uri):
    """
    Return the full path of the md5 file
    source_uri have to be libvirt_url type.
    """
    path = urlparse(source_uri).path[1:]
    full_path = os.path.join(constants.APACHE_DIR, path)
    basic_path = full_path + ".md5"
    return basic_path


def get_checksum(path_md5_file):
    md5_file_name = get_md5_file_name(path_md5_file)
    with open(md5_file_name) as md5_file:
        return md5_file.read().strip()


def get_associated_haconfig(vm_service):
    service_id = vm_service._service.item_id
    ha_configs = vm_service._clustered_service.query("ha-service-config")
    if len(ha_configs) == 1:
        return ha_configs[0]
    for ha_config in ha_configs:
        if ha_config.service_id == service_id:
            return ha_config
    return None
