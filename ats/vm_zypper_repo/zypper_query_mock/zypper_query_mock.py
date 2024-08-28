from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger

import libvirt_plugin.utils

def get_pkgs_mock(repo_name):
    pkgs = set()
    if repo_name == "/var/www/html/3pp/":
        pkgs.update(["pkg1", "pkg2", "pkg3", "pkg4", "VRTSsfmh", "pkg_name1_foo", "EXTRlitprubyrgen_CXP9031337", "EXTRlitplibyaml_CXP9030603", "EXTRlitppassenger_CXP9030924"])

    return pkgs

try:
    setattr(libvirt_plugin.utils, "get_names_of_pkgs_in_repo_by_path", get_pkgs_mock)
except:
    import traceback
    traceback.print_exc()

class ZypperMockPlugin(Plugin):
    pass
