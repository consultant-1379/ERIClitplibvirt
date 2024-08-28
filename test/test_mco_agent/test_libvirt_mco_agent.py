import unittest
import mock
import os
import subprocess
import sys
from nose.tools import nottest

sys.path.append('./puppet/mcollective_agents/files')


from libvirt_mco_agent import (LibvirtAgent, RPCAgent, LibvirtAgentException)


class TestRPCAgent(unittest.TestCase):

    def setUp(self):
        self.agent = RPCAgent()

    @mock.patch('libvirt_mco_agent.subprocess')
    def test_rpcagent_run(self, sub_proc):
        sub_proc.Popen = mock.Mock()
        communicate = mock.Mock(return_value=("expected out",
                                              "expected err"))
        process = mock.Mock(returncode=0,
                            communicate=communicate)
        sub_proc.Popen.return_value = process
        code, out, err = self.agent.run("ls")
        self.assertEqual(code, 0)
        self.assertEqual(out, "expected out")
        self.assertEqual(err, "expected err")

    @mock.patch('libvirt_mco_agent.sys')
    @mock.patch('libvirt_mco_agent.json')
    @mock.patch('__builtin__.open')
    def test_rpcagent_action(self, mock_open, mock_json, mock_sys):
        os.environ["MCOLLECTIVE_REQUEST_FILE"] = "/tmp/request"
        os.environ["MCOLLECTIVE_REPLY_FILE"] = "/tmp/reply"

        infile = mock.MagicMock()
        outfile = mock.MagicMock()

        mock_json.load.return_value = {
            "action": "my_action",
            "data": "my_data",
        }

        action_response = "action response"
        self.agent.my_action = mock.Mock(return_value=action_response)

        mock_open.__enter__.side_effect = [infile, outfile]

        self.agent.action()

        mock_open.assert_any_call('/tmp/request', 'r')
        mock_open.assert_any_call('/tmp/reply', 'w')

        infile.assert_called_once()
        outfile.assert_called_once()

        mock_json.load.assert_called_once_with(
            mock_open().__enter__())
        mock_json.dump.assert_called_once_with(
            "action response", mock_open().__enter__())
        mock_open().__exit__.assert_called_with(None, None, None)
        self.assertEqual(2, mock_open().__exit__.call_count)
        mock_sys.assert_has_calls([mock.call.exit(0)])


class TestLibvirtAgent(unittest.TestCase):

    def setUp(self):
        self.api = LibvirtAgent()

    @mock.patch('libvirt_mco_agent.RPCAgent.run')
    def test_api_run_command(self, mock_run):
        mock_run.return_value = 0, "output", ""
        c, o, e = self.api.run_command("ls")
        mock_run.assert_called_once_with("ls", 0)
        self.assertEqual(c, 0)
        self.assertEqual(o, "output")
        self.assertEqual(e, "")

        mock_run.return_value = 1, "", "error"
        self.assertRaises(LibvirtAgentException, self.api.run_command, "ls")

    @mock.patch('libvirt_mco_agent.RPCAgent.run')
    def test_api_run_command_expected_error(self, mock_run):
        std_err = "libvirt: Domain Config error : operation failed: " \
                  "domain 'esmon' already exists with uuid " \
                  "c6a40ed3-c0c2-15ed-3e78-d3a6d3ac807d"
        mock_run.return_value = 1, "output", std_err

        c, o, e = self.api.run_command(
            "ls", rewrite_retcode=True,
             expected_errors=['already exists with uuid'])

        mock_run.assert_called_once_with("ls", 0)
        self.assertEqual(c, 0)
        self.assertEqual(o, "output")
        self.assertEqual(e, std_err)

        mock_run.return_value = 1, "", "error"
        self.assertRaises(LibvirtAgentException, self.api.run_command, "ls")

    @mock.patch('libvirt_mco_agent.RPCAgent.run')
    def test_api_run_command_unexpected_error(self, mock_run):
        std_err = "error"
        mock_run.return_value = 1, "output", std_err

        self.assertRaises(LibvirtAgentException, self.api.run_command,
            "ls", rewrite_retcode=True,
             expected_errors=['unexpected_error'])

    @mock.patch('libvirt_mco_agent.RPCAgent.run')
    def test_api_restart(self, mock_run):
        mock_run.side_effect = [(0, 'stoped', ''),
                                (0, 'service1 started', '')]
        stop_command = '/bin/systemctl stop'
        start_command = '/bin/systemctl start'
        request = {'service_name': 'service1',
                   'stop_command': stop_command,
                   'start_command': start_command}
        response = self.api.restart(request)

        calls = [mock.call(stop_command, 300),
                 mock.call(start_command, 0)]
        mock_run.assert_has_calls(calls, any_order=False)

        expected_response = {'retcode': 0, 'err': '',
                             'out': 'service1 started'}
        self.assertEqual(expected_response, response)

    @mock.patch('libvirt_mco_agent.RPCAgent.run')
    def test_api_restart_timeout(self, mock_run):
        mock_run.side_effect = [
            subprocess.CalledProcessError(-1, ('/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py stop-undefine', 300)),
            (0, 'stoped', ''),
            (0, 'service1 started', '')]
        stop_command = '/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 stop-undefine'
        start_command = '/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 start-define'
        request = {'service_name': 'service1',
                   'stop_command': stop_command,
                   'start_command': start_command}
        response = self.api.restart(request)

        calls = [mock.call('/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 stop-undefine', 300),
                 mock.call('/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 force-stop-undefine', 0),
                 mock.call('/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 start-define', 0)]
        mock_run.assert_has_calls(calls, any_order=False)
        expected_response = {'retcode': 0, 'err': '',
                             'out': 'service1 started'}
        self.assertEqual(expected_response, response)

    @mock.patch('libvirt_mco_agent.RPCAgent.run')
    def test_api_restart_default(self, mock_run):
        mock_run.side_effect = [
            subprocess.CalledProcessError(-1, ('/bin/systemctl stop service1', 300)),
            (0, 'stoped', ''),
            (0, 'service1 started', '')]
        request = {'service_name': 'service1'}
        response = self.api.restart(request)

        calls = [mock.call('/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 stop', 300),
                 mock.call('/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 force-stop-undefine', 0),
                 mock.call('/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py service1 start', 0)]
        mock_run.assert_has_calls(calls, any_order=False)
        expected_response = {'retcode': 0, 'err': '',
                             'out': 'service1 started'}
        self.assertEqual(expected_response, response)

    @mock.patch('shutil.rmtree')
    @mock.patch('os.path.isdir')
    @mock.patch('glob.glob')
    @mock.patch('os.remove')
    def test_node_image_cleanup(self, mock_remove, mock_glob, mock_isdir,
                                                              mock_rmtree):
        mock_isdir.side_effect = [ True, False, False, False, True,
                                   False, False, False, False ]
        mock_glob.side_effect = [['abc', 'xyz', 'a123', 'dir1',
                                  'fmmed-1-1.0.1.qcow2',
                                  'fmmed-1-1.0.1.qcow2.md5',
                                  'fmmed-1-1.0.1.qcow2_checksum.md5',
                                  'fmmed-1-1.0.2.qcow2',
                                  'fmmed-1-1.0.2.qcow2.md5',
                                  'fmmed-1-1.0.2.qcow2_checksum.md5'],
                                 ['.dot']
                                ]
        mock_remove.side_effect = [ None, None,
                                    OSError(2, 'No such file or directory'),
                                    None, None, None, None ]
        mock_rmtree.side_effect = [ None ]


        request = {'image_whitelist':'fmmed-1-1.0.1.qcow2'}

        result = self.api.node_image_cleanup(request)

        hostname = os.uname()[1]
        expected_err = ('On {0} failed to remove file a123. errno=2 : No such '
                                        'file or directory. '.format(hostname))
        expected_out = ('{0} : abc, xyz, dir1, fmmed-1-1.0.2.qcow2, '
                        'fmmed-1-1.0.2.qcow2.md5, '
                        'fmmed-1-1.0.2.qcow2_checksum.md5, '
                        '.dot'.format(hostname))
        self.assertEqual(result['retcode'], 0)
        self.assertEqual(result['err'], expected_err)
        self.assertEqual(result['out'], expected_out)
