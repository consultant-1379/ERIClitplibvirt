#!/bin/env python

"""
Results and Exceptions
0   OK
1   OK, failed. All the data parsed ok, we have a action matching the request
    but the requested action could not be completed.  RPCAborted
2   Unknown action  UnknownRPCAction
3   Missing data    MissingRPCData
4   Invalid data    InvalidRPCData
5   Other error     UnknownRPCError

Request format:
{ "callerid": null,
  "agent": "libvirt_mco_agent",
  "data":{"process_results":true},
  "uniqid":"e8937c54738d5cb09b3ca8d668d821ce",
  "sender":"ms1",
  "action":"pythontest"
}
"""

import sys
import json
import os
import subprocess
import glob
import shutil

from threading import Timer

MCOLLECTIVE_REPLY_FILE = "MCOLLECTIVE_REPLY_FILE"
MCOLLECTIVE_REQUEST_FILE = "MCOLLECTIVE_REQUEST_FILE"

DEFAULT_LIBVIRT_STOP_TIMEOUT = 300
LIBVIRT_ADAPTOR = "/opt/ericsson/nms/litp/lib/litpmnlibvirt/litp_libvirt_adaptor.py"
IMAGE_DIR = '/var/lib/libvirt/images'

OK = 0
RPCAborted = 1
UnknownRPCAction = 2
MissingRPCData = 3
InvalidRPCData = 4
UnknownRPCError = 5


class LibvirtAgentException(Exception):
    pass


class RPCAgent(object):

    def action(self):
        exit_value = OK
        with open(os.environ[MCOLLECTIVE_REQUEST_FILE], 'r') as infile:
            request = json.load(infile)

        action = request["action"]
        method = getattr(self, action, None)
        if callable(method):
            reply = method(request['data'])
        else:
            reply = {}
            exit_value = UnknownRPCAction

        with open(os.environ[MCOLLECTIVE_REPLY_FILE], 'w') as outfile:
            json.dump(reply, outfile)

        sys.exit(exit_value)

    @staticmethod
    def run(command, timeout=0):
        env = dict(os.environ)
        kill = lambda process: process.kill()
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True,
                             env=env)

        if not timeout:
            out, err = p.communicate()
        else:
            timer = Timer(float(timeout), kill, [p])
            try:
                timer.start()
                out, err = p.communicate()
            finally:
                timer.cancel()

        return p.returncode, out.strip(), err.strip()


class LibvirtAgent(RPCAgent):

    def run_command(self, command, expected_errors=None,
                    rewrite_retcode=False, timeout=0):
        expected_errors = expected_errors or []
        c, o, e = self.run(command, timeout)

        if c:
            for expected_error in expected_errors:
                if expected_error in e:
                    if rewrite_retcode:
                        c = 0
                    return c, o, e
            raise LibvirtAgentException(
                "Error running '{0}': Out: '{1}' Err: '{2}'".format(
                    command, o, e))

        return c, o, e

    def restart(self, request):
        service_name = request['service_name']
        default_start_cmd = "{0} {1} start".format(LIBVIRT_ADAPTOR, service_name)
        default_stop_cmd = "{0} {1} stop".format(LIBVIRT_ADAPTOR, service_name)
        start_command = request.get('start_command', default_start_cmd)
        stop_command = request.get('stop_command', default_stop_cmd)

        try:
            self.run_command(stop_command,
                             timeout=DEFAULT_LIBVIRT_STOP_TIMEOUT)

        except subprocess.CalledProcessError, LibvirtAgentException:
            force_stop_cmd = "{0} {1} force-stop-undefine".format(LIBVIRT_ADAPTOR,
                                                         service_name)
            self.run_command(force_stop_cmd)

        r_code, std_out, std_err = self.run_command(
            start_command, rewrite_retcode=True,
            expected_errors=['already exists with uuid'])

        return {"retcode": r_code, "out": std_out, "err": std_err}

    def node_image_cleanup(self, request):
        image_whitelist = request['image_whitelist'].split(',')
        hostname = os.uname()[1]

        keep_files = []
        for image in image_whitelist:
            keep_files.append(image)
            keep_files.append(image + '.md5')
            keep_files.append(image + '_checksum.md5')

        files_deleted = []
        err = ''
        if os.path.isdir(IMAGE_DIR):
            for filename in glob.glob(IMAGE_DIR + '/*') + \
                            glob.glob(IMAGE_DIR + '/.*'):
                if os.path.basename(filename) not in keep_files:
                    try:
                        if os.path.isdir(filename):
                            shutil.rmtree(filename)
                        else:
                            os.remove(filename)
                        files_deleted.append(filename)
                    except OSError, e:
                        err += ('On {0} failed to remove file {1}. errno={2}'
                                ' : {3}. '.format(hostname, filename,
                                                  e.errno, e.strerror))

        if files_deleted:
            out = hostname + ' : ' + ', '.join(files_deleted)
        else:
            out = ''

        return {"retcode": 0, "out": out, "err": err}


if __name__ == '__main__':
    LibvirtAgent().action()
