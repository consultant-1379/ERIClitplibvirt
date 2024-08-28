import unittest
import mock

from libvirt_plugin.libvirt_mco_client import LibvirtMcoClient
from libvirt_plugin.exception import LibvirtMcoException

class TestLibvirtMcoClient(unittest.TestCase):

    def setUp(self):
        self.csh = LibvirtMcoClient('ms1')

    @mock.patch('libvirt_plugin.libvirt_mco_client.log')
    @mock.patch('libvirt_plugin.libvirt_mco_client.run_rpc_command')
    def test_check_successfully_restart(self, run_rpc_command, log_mock):
        run_rpc_command.return_value = {
            'ms1': {'errors': '',
                    'data': {'retcode': 0, 'err': '', 'out': 'OK'}},
        }
        servicename = 'fmmed'
        start_command = "service fmmed start"
        stop_command = "service fmmed stop"
        self.csh.restart(servicename, start_command, stop_command)
        run_rpc_command.assert_called_once_with(['ms1'],
                                                'libvirt_mco_agent',
                                                'restart',
                                                {'stop_command': 'service fmmed stop',
                                                 'service_name': 'fmmed',
                                                 'start_command': 'service fmmed start'},
                                                360,
                                                retries=1)

    @mock.patch('libvirt_plugin.libvirt_mco_client.log')
    @mock.patch('libvirt_plugin.libvirt_mco_client.run_rpc_command')
    def test_call_mco_error(self, run_rpc_command, log):
        run_rpc_command.return_value = {
            'ms1': {'errors': '',
                    'data': {'retcode': 1, 'err': '', 'out': 'OK'}},
        }
        servicename = 'fmmed'
        start_command = "service fmmed start"
        stop_command = "service fmmed stop"
        self.assertRaises(LibvirtMcoException,
                          self.csh.restart,
                          servicename, start_command, stop_command)
        run_rpc_command.assert_called_once_with(['ms1'],
                                                'libvirt_mco_agent',
                                                'restart',
                                                {'stop_command': 'service fmmed stop',
                                                 'service_name': 'fmmed',
                                                 'start_command': 'service fmmed start'},
                                                360,
                                                retries=1)

    @mock.patch('libvirt_plugin.libvirt_mco_client.log')
    @mock.patch('libvirt_plugin.libvirt_mco_client.run_rpc_command')
    def test_call_mco_success(self, run_rpc_command, log):
        mco_action = 'restart'
        args = {'servicename': 'fmmed',
                'start_command': 'service fmmed start',
                'stop_command': 'service fmmed stop'}
        timeout = 300

        run_rpc_command.return_value = {
            'ms1': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}}
            }
        self.csh._call_mco(mco_action, args, timeout=timeout)
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO LIBVIRT command "mco rpc libvirt_mco_agent restart '
                      'stop_command="service fmmed stop" servicename="fmmed" '
                      'start_command="service fmmed start" -I ms1" ')
            ])

    @mock.patch('libvirt_plugin.libvirt_mco_client.log')
    @mock.patch('libvirt_plugin.libvirt_mco_client.run_rpc_command')
    def test_call_mco_extra_replies(self, run_rpc_command, log):
        mco_action = 'restart'
        args = {'servicename': 'fmmed',
                'start_command': 'service fmmed start',
                'stop_command': 'service fmmed stop'}
        timeout = 300

        run_rpc_command.return_value = {
            'ms1': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}},
            'mn1': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}},
            'mn2': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}}
        }
        self.assertRaises(LibvirtMcoException,
                          self.csh._call_mco, mco_action,
                          args, timeout=timeout)
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO LIBVIRT command "mco rpc libvirt_mco_agent restart '
                      'stop_command="service fmmed stop" servicename="fmmed" '
                      'start_command="service fmmed start" -I ms1" ')
            ])

    @mock.patch('libvirt_plugin.libvirt_mco_client.log')
    @mock.patch('libvirt_plugin.libvirt_mco_client.run_rpc_command')
    def test_call_mco_unexpected_node(self, run_rpc_command, log):
        mco_action = 'restart'
        args = {'servicename': 'fmmed',
                'start_command': 'service fmmed start',
                'stop_command': 'service fmmed stop'}
        timeout = 300

        run_rpc_command.return_value = {
            'mn2': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}}
            }
        self.assertRaises(LibvirtMcoException,
                          self.csh._call_mco, mco_action,
                          args, timeout=timeout)
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO LIBVIRT command "mco rpc libvirt_mco_agent restart '
                      'stop_command="service fmmed stop" servicename="fmmed" '
                      'start_command="service fmmed start" -I ms1" ')
            ])

    @mock.patch('libvirt_plugin.libvirt_mco_client.log')
    @mock.patch('libvirt_plugin.libvirt_mco_client.run_rpc_command')
    def test_call_mco_expected_error(self, run_rpc_command, log):
        mco_action = 'restart'
        args = {'servicename': 'fmmed',
                'start_command': 'service fmmed start',
                'stop_command': 'service fmmed stop'}
        timeout = 300
        expected_errors = ['Expected Error']

        run_rpc_command.return_value = {
            'ms1': {'errors': 'Expected Error',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}}
            }
        self.csh._call_mco(mco_action,
                          args, timeout=timeout,
                          expected_errors=expected_errors)
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO LIBVIRT command "mco rpc libvirt_mco_agent restart '
                      'stop_command="service fmmed stop" servicename="fmmed" '
                      'start_command="service fmmed start" -I ms1" '),
            mock.call('Failure to execute command: "mco rpc libvirt_mco_agent restart '
                      'stop_command="service fmmed stop" servicename="fmmed" '
                      'start_command="service fmmed start" -I ms1" '
                      'Reason: MCO failure... Expected Error on node ms1')
            ])

    @mock.patch('libvirt_plugin.libvirt_mco_client.log')
    @mock.patch('libvirt_plugin.libvirt_mco_client.run_rpc_command')
    def test_call_mco_unexpected_error(self, run_rpc_command, log):
        mco_action = 'restart'
        args = {'servicename': 'fmmed',
                'start_command': 'service fmmed start',
                'stop_command': 'service fmmed stop'}
        timeout = 300

        run_rpc_command.return_value = {
            'ms1': {'errors': 'Unexpected Error',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}}
            }
        self.assertRaises(LibvirtMcoException,
                          self.csh._call_mco, mco_action,
                          args, timeout=timeout)
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO LIBVIRT command "mco rpc libvirt_mco_agent restart '
                      'stop_command="service fmmed stop" servicename="fmmed" '
                      'start_command="service fmmed start" -I ms1" ')
            ])
