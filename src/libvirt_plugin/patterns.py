"""
All regular expression patterns for the libvirt plugin.
"""
import re

HOSTNAME_RE = re.compile(r"^([a-z])+([a-z0-9\-])*(?<!-)$", re.IGNORECASE)
