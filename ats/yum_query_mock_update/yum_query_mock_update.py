import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

import libvirt_plugin.utils
import libvirt_plugin.exception

def get_litp_pkg_mock_update(pkg_name):
    if pkg_name == "ERIClitpmnlibvirt_CXP9031529":
         return {"name": "ERIClitpmnlibvirt_CXP9031529", "version": "1.2.1", "release": "1", "arch": "noarch"}

try:
    setattr(libvirt_plugin.utils, "get_litp_package_version", get_litp_pkg_mock_update)
except:
    import traceback
    traceback.print_exc()

class YumMockPluginUpdate(Plugin):
    pass
