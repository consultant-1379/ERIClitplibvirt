import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

import libvirt_plugin.utils
import libvirt_plugin.exception

from litp.core.execution_manager import CallbackTask
import libvirt_plugin.libvirt_plugin


def gen_cleanup_mock(self, service, vm_services, existing_tasks):
    if self.cleanup_task_for_node(service, existing_tasks):
        return []
    if service.node.is_for_removal():
        return []

    task_description = ('Remove unused VM image files on node "{0}"'
                                            .format(service.node.hostname))
    if service.node.hostname == "mn3":
        method = CleanupMockPlugin.mock_callback_node3
    else:
        method = CleanupMockPlugin.mock_callback_node2

    new_task = CallbackTask(service._service,
                            task_description,
                            method,
                            hostname=service.node.hostname,
                            image_whitelist=','.join(
                                self.get_image_whitelist(service,
                                                         vm_services)))
    if service.node.is_ms():
        new_task.requires.update([task for task in existing_tasks
                                   if task.model_item == service._service])
    return [new_task]


try:
    setattr(libvirt_plugin.libvirt_plugin.LibvirtPlugin, "get_cleanup_images_task_holder",
            libvirt_plugin.libvirt_plugin.LibvirtPlugin.get_cleanup_images_task)
    setattr(libvirt_plugin.libvirt_plugin.LibvirtPlugin, "get_cleanup_images_task", gen_cleanup_mock)
except:
    import traceback
    traceback.print_exc()

class CleanupMockPlugin(Plugin):
    def mock_callback_node2(self, callback_api, hostname, image_whitelist):
        pass

    def mock_callback_node3(self, callback_api, hostname, image_whitelist):
        pass

