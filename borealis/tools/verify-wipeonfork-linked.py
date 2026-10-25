#!/usr/bin/env python3
"""Check source/compiled-object correspondence without claiming device boot."""
import hashlib
import json
import re
from pathlib import Path
import subprocess
import time

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
record_path = package / 'validation/kernel/wipeonfork-backport.json'
record = json.loads(record_path.read_text())
for name, digest in record['after_sha256'].items():
    assert hashlib.sha256((kernel / name).read_bytes()).hexdigest() == digest, name
pair = json.loads((package / 'validation/kernel/compiled-pair.json').read_text())
assert pair['source_correspondence']['backport_patch_sha256']['0006-r24u-wipeonfork.patch'] == record['patch_sha256']
tool = Path('/home/android/nebula-kernel-v1.0/toolchain/bin/llvm-dis')
proof = {}
for variant in ('main', 'kernelsu'):
    out = kernel / ('out-' + variant)
    image = out / 'arch/arm64/boot/Image'
    assert hashlib.sha256(image.read_bytes()).hexdigest() == pair['artifacts'][variant]['sha256']
    config = (out / '.config').read_text()
    assert 'CONFIG_SECURITY_SELINUX=y\n' in config
    assert 'CONFIG_UKSM=y\n' not in config and 'CONFIG_UKSM=m\n' not in config
    object_proof = {}
    for name in ('mm/madvise', 'kernel/fork', 'fs/proc/task_mmu'):
        obj = out / (name + '.o')
        ir = subprocess.check_output([str(tool), str(obj), '-o', '-'], text=True)
        if name == 'fs/proc/task_mmu':
            table = next(line for line in ir.splitlines() if line.startswith('@show_smap_vma_flags.mnemonics ='))
            assert re.findall(r'\[2 x i8\] c"(..)"', table)[23] == 'wf', (variant, name)
        else:
            assert '8388608' in ir, (variant, name, 'Wipe flag absent from object')
        if name == 'mm/madvise':
            assert 'i32 18' in ir and 'i32 19' in ir, 'Advice ABI cases absent'
        command_file = out / (str(Path(name).parent) + '/.' + Path(name).name + '.o.cmd')
        assert name + '.c' in command_file.read_text()
        object_proof[name] = {
            'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
            'compile_command_sha256': hashlib.sha256(command_file.read_bytes()).hexdigest(),
            'wipe_flag_or_diagnostic_mnemonic_in_compiled_ir': True,
        }
    proof[variant] = {'image_sha256': pair['artifacts'][variant]['sha256'],
                      'objects': object_proof, 'selinux_enabled': True}
record.update({'link_verification_timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
               'full_kernel_link_passed': True, 'compiled_correspondence': proof,
               'device_semantics_test_passed': False, 'bootloop_causality_proved': False})
record_path.write_text(json.dumps(record, indent=2)+'\n')
pair['wipeonfork_backport_linked'] = True
pair['wipeonfork_backport_patch_sha256'] = record['patch_sha256']
(package / 'validation/kernel/compiled-pair.json').write_text(json.dumps(pair, indent=2)+'\n')
print(json.dumps({'full_kernel_link_passed': True, 'compiled_variants': list(proof),
                  'device_semantics_test_passed': False, 'bootloop_causality_proved': False}))
