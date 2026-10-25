#!/usr/bin/env python3
"""Export inspected diagnostics into the next build, preserving old artifacts."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
aosp = Path('/home/android/borealisos-android17')
assert subprocess.run(['pgrep', '-x', 'soong_build'], stdout=subprocess.DEVNULL).returncode == 1
pair = json.loads((package / 'validation/kernel/compiled-pair.json').read_text())
assert pair['bpf_backports_linked'] and pair['cpu_dt_fallback_linked'] and not pair['installable_package']
source = kernel / 'diagnostic-artifacts'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert all(sha(source / variant / 'Image') == pair['artifacts'][variant]['sha256']
           for variant in ['main', 'kernelsu'])
# Only files at known kernel artifact paths are replaced; never partitions.
history = package / 'kernel-diagnostics/history'
for variant in ['main', 'kernelsu']:
    old = package / 'kernel-diagnostics' / variant
    if (old / 'Image').is_file():
        archive = history / sha(old / 'Image') / variant
        archive.mkdir(parents=True, exist_ok=True)
        for name in ['Image', 'kernel.config']:
            if (old / name).is_file():
                shutil.copy2(old / name, archive / name)
for item in source.rglob('*'):
    if item.is_file():
        destination = package / 'kernel-diagnostics' / item.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, destination)
for base in [package / 'project/vendor/borealis/prebuilts/kernel', aosp / 'vendor/borealis/prebuilts/kernel']:
    assert base.is_dir()
    for name in ['Image', 'kernel.config', 'dtb.img', 'dtbo.img']:
        origin = source / 'main' / name if name in ['Image', 'kernel.config'] else source / name
        shutil.copy2(origin, base / name)
        assert sha(origin) == sha(base / name)
print('New diagnostic pair exported with matching main-kernel prebuilts; previous Images preserved.')
