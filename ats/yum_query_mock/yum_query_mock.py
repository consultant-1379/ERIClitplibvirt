import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

import libvirt_plugin.utils
import libvirt_plugin.exception

def get_pkgs_mock(repo_name):
    pkgs = set()
    if repo_name == "LITP":
        pkgs.update(["pkg1", "pkg2", "pkg3", "pkg4"])
    if repo_name == "/var/www/html/3pp/":
        pkgs.update(["pkg1", "pkg2", "pkg3", "pkg4", "VRTSsfmh", "pkg_name1_foo", "EXTRlitprubyrgen_CXP9031337", "EXTRlitplibyaml_CXP9030603", "EXTRlitppassenger_CXP9030924"])
    if repo_name == "/var/www/html/5pp/" or \
       repo_name == "/var/www/html/4pp/":
        msg = ("Error getting yum information for {0}, result 1,"
               " stderr ERROR".format(repo_name))
        log.event.error(msg)
        raise libvirt_plugin.exception.LibvirtYumRepoException(msg)

    return pkgs

def get_litp_pkg_mock(pkg_name):
    if pkg_name == "ERIClitpmnlibvirt_CXP9031529":
         return {"name": "ERIClitpmnlibvirt_CXP9031529", "version": "1.1.1", "release": "1", "arch": "noarch"}

try:
    setattr(libvirt_plugin.utils, "get_names_of_pkgs_in_repo_by_path", get_pkgs_mock)
    setattr(libvirt_plugin.utils, "get_litp_package_version", get_litp_pkg_mock)
except:
    import traceback
    traceback.print_exc()

class YumMockPlugin(Plugin):
    pass
