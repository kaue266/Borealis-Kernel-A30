#!/usr/bin/env python3
"""Reuse only the fully inspected kernel pair whose sources and bytes match."""
from pathlib import Path
import gzip
import hashlib
import json
import subprocess

package=Path(__file__).resolve().parent.parent
kernel=Path('/home/android/nebula-r24u-android17')
aosp=Path('/home/android/borealisos-android17')
pair=json.loads((package/'validation/kernel/compiled-pair.json').read_text())
assert pair['bpf_backports_linked'] and pair['cpu_dt_fallback_linked']
assert pair['kernel_commit']=='e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563'
assert not pair['installable_package'] and not pair['android17_device_boot_verified']
subprocess.run(['python3',str(package/'tools/capture-kernel-build-source.py'),'--verify'],check=True)
assert pair['source_correspondence']==json.loads((package/'validation/kernel/build-source-start.json').read_text())
def sha(path):
 with path.open('rb') as source:
  return hashlib.file_digest(source,'sha256').hexdigest()
for variant in ('main','kernelsu'):
 expected=pair['artifacts'][variant]
 sources=(package/'kernel-diagnostics'/variant, kernel/'diagnostic-artifacts'/variant,
          kernel/('out-'+variant)/'arch/arm64/boot')
 assert all(sha(base/'Image')==expected['sha256'] for base in sources)
 image=(sources[0]/'Image').read_bytes()
 assert image[56:60]==b'ARM\x64' and len(image)==expected['image_bytes']
 config=gzip.decompress(image[image.index(b'IKCFG_ST')+8:image.index(b'IKCFG_ED')])
 assert config==(kernel/('out-'+variant)/'.config').read_bytes()
 assert config==(sources[0]/'kernel.config').read_bytes()
 assert (b'CONFIG_KSU=y\n' in config)==(variant=='kernelsu')
 for unit,proof in expected['cpu_driver_objects'].items():
  obj=kernel/('out-'+variant)/'drivers/cpufreq'/unit
  assert sha(obj)==proof['object_sha256']
  assert sha(obj.parent/('.'+unit+'.cmd'))==proof['compile_command_sha256']
for base in (package/'project/vendor/borealis/prebuilts/kernel',aosp/'vendor/borealis/prebuilts/kernel'):
 assert sha(base/'Image')==pair['artifacts']['main']['sha256']
 assert (base/'kernel.config').read_bytes()==(package/'kernel-diagnostics/main/kernel.config').read_bytes()
 for name in ('dtb.img','dtbo.img'):
  assert sha(base/name)==pair['artifacts'][name]['sha256']
print('Current inspected kernel pair, root separation, source hashes and ROM prebuilts match; hardware/network unverified.')
