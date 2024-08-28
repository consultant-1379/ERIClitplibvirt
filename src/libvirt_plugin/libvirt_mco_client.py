##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.rpc_commands import run_rpc_command
from litp.core.litp_logging import LitpLogger
from .exception import LibvirtMcoException
from .constants import MCO_RESTART_TIMEOUT

log = LitpLogger()


class LibvirtMcoClient(object):

    def __init__(self, node):
        self.node = node
        self.agent = "libvirt_mco_agent"

    def _get_mco_libvirt_command(self, action, args=None):
        command = "\"mco rpc {0} {1} ".format(self.agent, action)
        if args is not None:
            for a, v in args.iteritems():
                command += '{0}="{1}" '.format(a, v)
        command += "-I {0}\" ".format(self.node)
        return command

    def _gen_err_str(self, action, args=None):
        return "Failure to execute command: {0}"\
            .format(self._get_mco_libvirt_command(action, args))

    def _call_mco(self, mco_action, args, timeout=None, retries=1,
                  expected_errors=None):
        """
        general method to run MCollective commands using run_rpc_command
        and perform error handling based on MCollective issues
        """
        nodes = [self.node]

        log.trace.debug('Running MCO LIBVIRT command {0}'.format(
            self._get_mco_libvirt_command(mco_action, args)))
        results = run_rpc_command(nodes, self.agent, mco_action, args, timeout,
                                  retries=retries)

        if not len(results) == 1:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Expected 1 response, received %s"\
                % (len(results))
            log.trace.error(err_msg)
            raise LibvirtMcoException(err_msg)
        if not results.keys()[0] == self.node:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Response from unexpected sender %s"\
                       % (results.keys()[0])
            log.trace.error(err_msg)
            raise LibvirtMcoException(err_msg)

        if results[self.node]["errors"]:
            error_expected = False
            if expected_errors:
                for error in expected_errors:
                    if error in results[self.node]["errors"]:
                        error_expected = True
                        results[self.node]["data"]["retcode"] = 0

            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: MCO failure... {0} on node {1}".format(
                results[self.node]["errors"], self.node)
            if error_expected:
                log.trace.debug(err_msg)
            else:
                log.trace.error(err_msg)
                raise LibvirtMcoException(err_msg)

        return results[self.node]["data"]

    def restart(self, service_name, start_command=None, stop_command=None):
        mco_action = "restart"

        args = {'service_name': service_name}
        if start_command:
            args['start_command'] = start_command

        if stop_command:
            args['stop_command'] = stop_command

        result = self._call_mco(mco_action, args, timeout=MCO_RESTART_TIMEOUT)
        if result["retcode"]:
            raise LibvirtMcoException(result["err"])

    def node_image_cleanup(self, image_whitelist):
        mco_action = "node_image_cleanup"

        # mco cannot parse empty image_whitelist string
        if not image_whitelist:
            image_whitelist = ' '
        args = {'image_whitelist': image_whitelist}

        result = self._call_mco(mco_action, args, timeout=MCO_RESTART_TIMEOUT)
        if result["out"]:
            log.trace.info('Files deleted from {0}'.format(result["out"]))
        if result["err"]:
            log.trace.info(result["err"])
        if result["retcode"]:
            raise LibvirtMcoException(result["err"])
