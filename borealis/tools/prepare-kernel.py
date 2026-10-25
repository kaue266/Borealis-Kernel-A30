#!/usr/bin/env python3
"""Narrow R24U sysfs fix. Never modify clocks or thermal/electrical limits."""
from pathlib import Path
import difflib
import subprocess

root=Path('/home/android/nebula-r24u-android17')
assert subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()=='e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563'
relative='drivers/gpu/arm/b_r26p0/platform/exynos/gpu_custom_interface.c'
file=root/relative
before=file.read_text()
start=before.index('static ssize_t show_kernel_sysfs_freq_table(')
end=before.index('\n#ifdef CONFIG_MALI_DVFS',start)
function='''static ssize_t show_kernel_sysfs_freq_table(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret = 0;
	int i, min_level, max_level;
	struct exynos_context *platform;

	if (!pkbdev || !pkbdev->platform_context)
		return -ENODEV;
	platform = (struct exynos_context *)pkbdev->platform_context;
	if (!platform->table || platform->table_size <= 0)
		return -ENODEV;

	min_level = gpu_dvfs_get_level(platform->gpu_min_clock);
	max_level = gpu_dvfs_get_level(platform->gpu_max_clock);
	/* A failed lookup is not a table index or an available frequency. */
	if (min_level < 0 || max_level < 0 ||
	    min_level >= platform->table_size || max_level >= platform->table_size ||
	    min_level < max_level)
		return -EINVAL;

	for (i = min_level; i >= max_level && ret < PAGE_SIZE - 2; i--)
		ret += scnprintf(buf + ret, PAGE_SIZE - ret - 1, "%d ", platform->table[i].clock);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\\n");
	return ret;
}
'''
after=before[:start]+function+before[end:]
file.write_text(after)
output=Path(__file__).resolve().parent.parent/'validation/kernel'
output.mkdir(parents=True,exist_ok=True)
original=subprocess.check_output(['git','-C',str(root),'show',f'HEAD:{relative}'],text=True)
(output/'r24u-gpu-table.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),after.splitlines(True),fromfile='a/'+relative,tofile='b/'+relative)))
print('R24U GPU table bounds checks applied; DVFS and protection limits preserved.')

# R24U calls these hooks unconditionally. CONFIG_KSU=n must link and retain
# ordinary kernel syscall/input behavior, with no dummy root implementation.
calls={
 'fs/open.c':'ksu_handle_faccessat(&dfd, &filename, &mode, NULL);',
 'fs/read_write.c':'ksu_handle_vfs_read(&file, &buf, &count, &pos);',
 'fs/stat.c':'ksu_handle_stat(&dfd, &filename, &flag);',
 'fs/exec.c':'ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);',
 'drivers/input/input.c':'ksu_handle_input_handle_event(&type, &code, &value);',
}
for relative,call in calls.items():
 file=root/relative;text=file.read_text()
 guarded='#ifdef CONFIG_KSU\n\t'+call+'\n#endif'
 if guarded not in text:
  assert text.count('\t'+call)==1
  text=text.replace('\t'+call,guarded,1);file.write_text(text)
 original=subprocess.check_output(['git','-C',str(root),'show',f'HEAD:{relative}'],text=True)
 (output/(relative.replace('/','__')+'.patch')).write_text(''.join(difflib.unified_diff(original.splitlines(True),text.splitlines(True),fromfile='a/'+relative,tofile='b/'+relative)))
print('Five root hook calls gated by CONFIG_KSU; no-root variant uses standard paths.')

relative='security/selinux/hooks.c';file=root/relative;text=file.read_text()
if '// Borealis: KernelSU-only NNP exception.' not in text:
 text=text.replace('\tstatic u32 ksu_sid;\n\tchar *secdata;',
  '#ifdef CONFIG_KSU\n\tstatic u32 ksu_sid;\n\tchar *secdata;\n#endif',1)
 text=text.replace('\tint error;\n\tu32 seclen;\n\n\tif (!nnp',
  '#ifdef CONFIG_KSU\n\tint error;\n\tu32 seclen;\n#endif\n\n\tif (!nnp',1)
 start=text.index('\tif(!ksu_sid){')
 end=text.index('\n\t/*\n\t * The only transitions',start)
 text=text[:start]+'\t// Borealis: KernelSU-only NNP exception.\n#ifdef CONFIG_KSU\n'+text[start:end]+'\n#endif\n'+text[end:]
 file.write_text(text)
original=subprocess.check_output(['git','-C',str(root),'show',f'HEAD:{relative}'],text=True)
(output/'security__selinux__hooks.c.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),text.splitlines(True),fromfile='a/'+relative,tofile='b/'+relative)))
print('KernelSU SELinux exception is also excluded from the main variant.')

# The test phone has CONFIG_EUREKA_CUSTOM_DT_NODES=y but no Eureka GPU
# properties in its active DT. Zero must not replace the standard DT clocks,
# and an absent thermal array must not consume stale stack contents.
relative='drivers/gpu/arm/b_r26p0/platform/exynos/mali_kbase_platform.c'
file=root/relative;text=file.read_text()
if 'static int gpu_valid_custom_clock(' not in text:
 anchor='static int gpu_dvfs_update_config_data_from_dt(struct kbase_device *kbdev)'
 helper='''/* Missing optional Eureka nodes retain the standard device contract. */
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
static int gpu_valid_custom_clock(int standard, int custom)
{
\treturn custom > 0 ? custom : standard;
}
#endif
'''
 assert text.count(anchor)==1
 text=text.replace(anchor,helper+anchor,1)
 text=text.replace('platform->interactive.highspeed_clock = platform->interactive.eureka_gpu_highspeed_clock;',
  'platform->interactive.highspeed_clock = gpu_valid_custom_clock(platform->interactive.highspeed_clock, platform->interactive.eureka_gpu_highspeed_clock);',1)
 text=text.replace('platform->interactive.highspeed_load = platform->interactive.eureka_gpu_highspeed_load;',
  'if (platform->interactive.eureka_gpu_highspeed_load > 0 && platform->interactive.eureka_gpu_highspeed_load <= 100)\n\t\t\tplatform->interactive.highspeed_load = platform->interactive.eureka_gpu_highspeed_load;',1)
 for field in ('gpu_max_clock','gpu_max_clock_limit'):
  old=f'platform->{field} = platform->eureka_gpu_max_clock;'
  assert text.count(old)==1
  text=text.replace(old,f'platform->{field} = gpu_valid_custom_clock(platform->{field}, platform->eureka_gpu_max_clock);',1)
 # Retain the standard throttling table already read immediately above this
 # block if the optional array is missing, truncated or has invalid clocks.
 start=text.index('\tgpu_update_config_data_int_array(np, "eureka_gpu_temp_throttling", of_data_int_array, 6);')
 end=text.index('\n#endif',start)
 text=text[:start]+text[end:]
 start=text.index('\t\tplatform->tmu_lock_clk[0] = platform->eureka_gpu_temp_throttling_0;')
 end=text.index('\n#else',start)
 thermal='''\t\tif (!of_property_read_u32_array(np, "eureka_gpu_temp_throttling",
\t\t\t\tof_data_int_array, TMU_LOCK_CLK_END)) {
\t\t\tfor (i = 0; i < TMU_LOCK_CLK_END; i++)
\t\t\t\tif (of_data_int_array[i] <= 0)
\t\t\t\t\tbreak;
\t\t\tif (i == TMU_LOCK_CLK_END)
\t\t\t\tfor (i = 0; i < TMU_LOCK_CLK_END; i++)
\t\t\t\t\tplatform->tmu_lock_clk[i] = of_data_int_array[i];
\t\t}'''
 text=text[:start]+thermal+text[end:]
 file.write_text(text)
original=subprocess.check_output(['git','-C',str(root),'show',f'HEAD:{relative}'],text=True)
(output/'r24u-gpu-dt-fallback.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),text.splitlines(True),fromfile='a/'+relative,tofile='b/'+relative)))
print('Optional GPU DT clocks fall back to standard nodes; absent thermal overrides preserve protection.')
