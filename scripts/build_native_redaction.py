"""Build the optional accelerator for this Python interpreter and platform."""
import os
import hashlib
import json
import sys
import sysconfig
from pathlib import Path
from setuptools import Extension, setup

root = Path(os.environ.get('NETBOT_NATIVE_SOURCE') or Path(__file__).resolve().parents[1]).resolve()
os.chdir(root)
setup(name='netbotpro-privacy-walk', version='0.1',
      ext_modules=[Extension('core._privacy_walk', ['core/_privacy_walk.c'])])
if '--inplace' in sys.argv:
    source = root/'core/_privacy_walk.c'
    binary = root/'core'/('_privacy_walk' + sysconfig.get_config_var('EXT_SUFFIX'))
    manifest = dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    python_abi=sys.implementation.cache_tag, binary=binary.name)
    (root/'core/native-redaction-build.json').write_text(json.dumps(manifest, indent=2), encoding='ascii')
