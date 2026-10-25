#!/usr/bin/env python3
"""Preserve standard CPU DT limits when optional Eureka properties are absent."""
from pathlib import Path
import difflib
import hashlib
import json

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
report_path = package / 'validation/kernel/cpu-dt-fallback-source-port.json'
assert not report_path.exists(), 'CPU fallback already recorded; do not reapply'
contract = json.loads((package / 'validation/kernel/cpu-eureka-dt-contract.json').read_text())
assert contract['read_only'] and not contract['candidate_device_tested']
names = ['drivers/cpufreq/exynos-acme.c', 'drivers/cpufreq/exynos-ufc.c']
before = {n: (kernel / n).read_text() for n in names}
sha = lambda text: hashlib.sha256(text.encode()).hexdigest()
assert all(sha(before[n]) == contract['candidate_source_sha256'][n] for n in names)

def replace(text, old, new):
    assert text.count(old) == 1, 'Missing/ambiguous CPU anchor: ' + old[:100]
    return text.replace(old, new, 1)

helper = '''/* Optional Eureka values override valid standard values independently.
 * Missing/invalid values retain the existing CAL/device bounds. Never expand
 * the calibrated range while selecting the initial boot/QoS contract.
 */
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
static unsigned int exynos_eureka_dt_freq(struct device_node *dn,
        const char *standard, const char *custom, unsigned int fallback,
        unsigned int minimum, unsigned int maximum)
{
    unsigned int val;

    if (!of_property_read_u32(dn, standard, &val) &&
        val > 0 && val >= minimum && val <= maximum)
        fallback = val;
    if (!of_property_read_u32(dn, custom, &val) &&
        val > 0 && val >= minimum && val <= maximum)
        fallback = val;
    return fallback;
}
#endif
'''
after = {n: replace(text, '#include "exynos-acme.h"', '#include "exynos-acme.h"\n\n' + helper)
         for n, text in before.items()}
name = names[0]
text = after[name]
text = replace(text, 'unsigned int boot_qos, val;\n#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES\n\tunsigned int ekval;\n#endif',
               'unsigned int boot_qos;\n#ifndef CONFIG_EUREKA_CUSTOM_DT_NODES\n\tunsigned int val;\n#endif')
old = '''	if (!of_property_read_u32(dn, "pm_qos-booting", &val)) {
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
		if (!of_property_read_u32(dn, "eureka_pm_qos-booting", &ekval))
			boot_qos = min(boot_qos, ekval);
#else
		boot_qos = min(boot_qos, val);
#endif
	}'''
new = '''#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
	boot_qos = exynos_eureka_dt_freq(dn, "pm_qos-booting",
		"eureka_pm_qos-booting", boot_qos, domain->min_freq, domain->max_freq);
#else
	if (!of_property_read_u32(dn, "pm_qos-booting", &val))
		boot_qos = min(boot_qos, val);
#endif'''
text = replace(text, old, new)
text = replace(text, '\tunsigned int val;\n\tint ret;\n#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES\n\tunsigned int ekval;\n#endif',
               '\tint ret;\n#ifndef CONFIG_EUREKA_CUSTOM_DT_NODES\n\tunsigned int val;\n#endif')
old = '''#ifndef CONFIG_EXYNOS_HOTPLUG_GOVERNOR
	if (!of_property_read_u32(dn, "max-freq", &val)) {
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
		if (!of_property_read_u32(dn, "eureka_max-freq", &ekval))
			domain->max_freq = ekval;
#else
		if (domain->id == 0) {
			domain->max_freq = 1690000;
		} else if (domain->id == 1) {
	                domain->max_freq = 2080000;
		}
#endif
	}
#endif
	if (!of_property_read_u32(dn, "min-freq", &val)) {
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
		if (!of_property_read_u32(dn, "eureka_min-freq", &ekval))
			domain->min_freq = ekval;
#else
		domain->min_freq = val;
#endif
	}'''
new = '''#ifndef CONFIG_EXYNOS_HOTPLUG_GOVERNOR
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
	domain->max_freq = exynos_eureka_dt_freq(dn, "max-freq", "eureka_max-freq",
		domain->max_freq, domain->min_freq, domain->max_freq);
#else
	if (!of_property_read_u32(dn, "max-freq", &val)) {
		if (domain->id == 0)
			domain->max_freq = 1690000;
		else if (domain->id == 1)
			domain->max_freq = 2080000;
	}
#endif
#endif
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
	domain->min_freq = exynos_eureka_dt_freq(dn, "min-freq", "eureka_min-freq",
		domain->min_freq, domain->min_freq, domain->max_freq);
#else
	if (!of_property_read_u32(dn, "min-freq", &val))
		domain->min_freq = val;
#endif'''
text = replace(text, old, new)
anchor = '\t\tdomain->resume_freq = 1560000;\n\t}\n#else'
text = replace(text, anchor, '\t\tdomain->resume_freq = 1560000;\n\t}\n'
               '\tdomain->boot_freq = clamp(domain->boot_freq, domain->min_freq, domain->max_freq);\n'
               '\tdomain->resume_freq = clamp(domain->resume_freq, domain->min_freq, domain->max_freq);\n#else')
after[name] = text
name = names[1]
old = '''	unsigned int val;
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
	unsigned int ekval;
#endif

	if (!of_property_read_u32(dn, "user-default-qos", &val)) {
#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
		if (!of_property_read_u32(dn, "eureka_user-default-qos", &ekval))
			domain->user_default_qos = ekval;
#else
		domain->user_default_qos = val;
#endif
	}'''
new = '''#ifdef CONFIG_EUREKA_CUSTOM_DT_NODES
	domain->user_default_qos = exynos_eureka_dt_freq(dn, "user-default-qos",
		"eureka_user-default-qos", domain->user_default_qos,
		domain->min_freq, domain->max_freq);
#else
	unsigned int val;

	if (!of_property_read_u32(dn, "user-default-qos", &val))
		domain->user_default_qos = val;
#endif'''
after[name] = replace(after[name], old, new)
backup = package / 'validation/kernel/cpu-dt-fallback-before'
patch = []
for name, text in after.items():
    assert not (backup / name).exists()
    patch.extend(difflib.unified_diff(before[name].splitlines(True), text.splitlines(True),
                                    fromfile='a/' + name, tofile='b/' + name))
# Preflight all anchors/hashes before writing either source.
for name, text in after.items():
    saved = backup / name
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_text(before[name])
    (kernel / name).write_text(text)
patch_path = package / 'kernel-patches/r24u-cpu-dt-fallback.patch'
patch_path.write_text(''.join(patch))
record = {'scope': 'CPU DT fallback and independent optional overrides within CAL/domain bounds',
          'before_sha256': {n: sha(text) for n, text in before.items()},
          'changed_files': {n: sha(text) for n, text in after.items()},
          'patch_sha256': sha(patch_path.read_text()),
          'host_tested': False, 'full_kernel_link_passed': False, 'device_tested': False,
          'cold_boot_causality_proved': False, 'thermal_protections_modified': False}
report_path.write_text(json.dumps(record, indent=2) + '\n')
print('CPU parsing fallback installed in sources; tests/full build/runtime remain pending.')
