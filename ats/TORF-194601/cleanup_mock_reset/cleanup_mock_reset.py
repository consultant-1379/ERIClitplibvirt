import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

import libvirt_plugin.utils
import libvirt_plugin.exception


try:
    setattr(libvirt_plugin.libvirt_plugin.LibvirtPlugin, "get_cleanup_images_task",
            libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_cleanup_images_task_holder)
except:
    import traceback
    traceback.print_exc()

class CleanupMockResetPlugin(Plugin):
    pass
