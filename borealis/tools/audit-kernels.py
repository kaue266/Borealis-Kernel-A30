#!/usr/bin/env python3
"""Inspect built kernel bytes and lock diagnostic artifacts; no installer/flash."""
from pathlib import Path
import gzip
import hashlib
import json
import re
import shutil
import subprocess
root=Path('/home/android/nebula-r24u-android17')
package=Path(__file__).resolve().parent.parent
source_record=json.loads((package/'validation/kernel/build-source-start.json').read_text())
subprocess.run(['python3',str(package/'tools/capture-kernel-build-source.py'),'--verify'],check=True)
subprocess.run(['python3',str(package/'tools/check-cpu-dt-fallback.py')],check=True)
cpu_source=json.loads((package/'validation/kernel/cpu-dt-fallback-source-port.json').read_text())
delivery=root/'diagnostic-artifacts';delivery.mkdir(exist_ok=True)
proof=Path(__file__).resolve().parent.parent/'validation/kernel'
results={}
for variant in ('main','kernelsu'):
 out=root/('out-'+variant)
 assert (out/'build-status.txt').read_text().startswith('success')
 image=(out/'arch/arm64/boot/Image').read_bytes()
 assert image[56:60]==b'ARM\x64' and len(image)<37748736
 config=gzip.decompress(image[image.index(b'IKCFG_ST')+8:image.index(b'IKCFG_ED')]).decode()
 assert config==(out/'.config').read_text()
 enabled='CONFIG_KSU=y\n' in config
 assert enabled==(variant=='kernelsu')
 assert 'CONFIG_SECURITY_SELINUX=y\n' in config
 assert 'CONFIG_LTO_CLANG=y\n' in config
 assert 'CONFIG_CGROUP_BPF=y\n' in config
 assert 'CONFIG_MMU=y\n' in config
 assert 'CONFIG_ARM_EXYNOS_ACME=y\n' in config and 'CONFIG_ARM_EXYNOS_UFC=y\n' in config
 cpu_objects={}
 for unit in ('exynos-acme.o','exynos-ufc.o'):
  obj=out/'drivers/cpufreq'/unit
  command=obj.parent/('.'+unit+'.cmd')
  assert obj.stat().st_size>0 and 'clang' in command.read_text()
  cpu_objects[unit]={'object_sha256':hashlib.sha256(obj.read_bytes()).hexdigest(),
                    'compile_command_sha256':hashlib.sha256(command.read_bytes()).hexdigest()}
 symbols=(out/'System.map').read_text()
 for required in ['cg_sockopt_verifier_ops','__cgroup_bpf_run_filter_setsockopt',
                  '__cgroup_bpf_run_filter_getsockopt','bpf_array_lookup_batch',
                  'htab_map_lookup_batch','htab_map_lookup_and_delete_batch',
                  'bpf_sock_is_valid_access','bpf_sock_convert_ctx_access',
                  'bpf_get_socket_cookie_sock_proto','array_map_mmap','bpf_map_mmap',
                  '__cgroup_bpf_run_sock_release','bpf_get_socket_cookie_sock_ctx_proto',
                  'bpf_get_socket_uid_sock_ctx_proto']:
  assert re.search(r'\b'+required+r'(?:\.|\s|$)',symbols), 'Missing linked BPF symbol: '+required
 if variant=='main':
  assert not re.search(r'\bksu_(?:handle|sid|init|core)',symbols)
  assert 'check_nnp_nosuid.ksu_sid' not in symbols
 dest=delivery/variant;dest.mkdir(exist_ok=True)
 shutil.copy2(out/'arch/arm64/boot/Image',dest/'Image')
 shutil.copy2(out/'.config',dest/'kernel.config')
 results[variant]={'root_enabled':enabled,'image_bytes':len(image),
  'sha256':hashlib.sha256(image).hexdigest(),
  'kernel_version':re.search(rb'Linux version [^\x00\n]+',image).group().decode(errors='replace'),
  'security_selinux':True,'clang_lto':True,'cpu_driver_objects':cpu_objects}
for filename,source in [('dtb.img','kernel_zip/aroma/dtb/aosp/enf/9/dtb.img'),('dtbo.img','kernel_zip/dtbo/a30/dtbo.img')]:
 blob=(root/source).read_bytes()
 assert blob[:4]==bytes.fromhex('d7b7ab1e')
 (delivery/filename).write_bytes(blob)
 results[filename]={'sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob),'source':source}
metadata={'kernel_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
 'artifacts':results,'android17_device_boot_verified':False,
 'source_correspondence':source_record,'bpf_backports_linked':True,
 'cpu_dt_fallback_linked':True,'cpu_dt_fallback_source':cpu_source,
 'android17_network_compatibility':'Unverified: version gates, socket storage/helper dependencies and Android 17 runtime remain unresolved',
 'installable_package':False,'scope':'Compiled diagnostics. Not a validated Android 17 kernel release.'}
(proof/'compiled-pair.json').write_text(json.dumps(metadata,indent=2)+'\n')
(delivery/'compiled-pair.json').write_text(json.dumps(metadata,indent=2)+'\n')
print('Both kernel variants inspected; root separation verified. Android 17 boot/network remains unverified.')
