from litp.core.plugin import Plugin
from litp.core.execution_manager import CallbackTask
from litp.core.litp_logging import LitpLogger
log = LitpLogger()


class ClusteringPlugin(Plugin):
    """
    A mock plugin to manage clustered service
    """

    def create_configuration(self, context_api):
        return self.get_cs_create_tasks(context_api)

    def get_cs_create_tasks(self, context_api):
        tasks = []
        for cs in context_api.query("clustered-service"):
            if cs.is_initial():
                tasks.append(CallbackTask(cs,
                    "Mock create clustered-service {0}".format(cs.name),
                    self.cb_create_cs_task,
                    service_name=cs.name))
        return tasks

    def cb_create_cs_task(self, callback_api, service_name):
        """Dummy task"""
        pass
