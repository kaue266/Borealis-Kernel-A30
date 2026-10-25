#!/usr/bin/env python3
"""Test actual CPU selector/boot-QoS/UFC code with mocked DT and QoS calls."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import tempfile

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
names = ['drivers/cpufreq/exynos-acme.c', 'drivers/cpufreq/exynos-ufc.c']
sources = {n: (kernel / n).read_text() for n in names}
old = {n: (package / 'validation/kernel/cpu-dt-fallback-before' / n).read_text() for n in names}

def function(text, name):
    match = re.search(r'^static\s+(?:__init\s+)?(?:unsigned int|int|void)\s+' + name + r'\([^;{}]*?\)\s*\{', text, re.M)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[match.start():end]

helper = function(sources[names[0]], 'exynos_eureka_dt_freq')
assert helper == function(sources[names[1]], 'exynos_eureka_dt_freq')
functions = helper + '\n' + function(sources[names[0]], 'set_boot_qos') + '\n' + function(sources[names[1]], 'parse_ufc_ctrl_info')
regression = function(old[names[0]], 'set_boot_qos') + '\n' + function(old[names[1]], 'parse_ufc_ctrl_info')
contract = json.loads((package / 'validation/kernel/cpu-eureka-dt-contract.json').read_text())
assert contract['read_only'] and not contract['candidate_device_tested']
active_values = [contract['active_dt_properties'][f'cpufreq-ufc/domain@{n}']['user-default-qos']['u32'][0]
                 for n in (0, 1)]

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#define __init
#define USEC_PER_SEC 1000000U
#define min(a,b) ((a)<(b)?(a):(b))
#define clamp(x,a,b) ((x)<(a)?(a):((x)>(b)?(b):(x)))
struct device_node { const char *standard_name,*custom_name;bool has_standard,has_custom;
    unsigned int standard,custom; };
static int of_property_read_u32(struct device_node *n,const char *name,unsigned int *value) {
    if(!strcmp(name,n->standard_name) && n->has_standard) {*value=n->standard;return 0;}
    if(!strcmp(name,n->custom_name) && n->has_custom) {*value=n->custom;return 0;}
    return -1;
}
struct exynos_cpufreq_domain { unsigned int min_freq,max_freq,user_default_qos;int min_qos_req,max_qos_req; };
static unsigned int last_qos[2],last_timeout[2];
static void pm_qos_update_request_timeout(int *req,unsigned int value,unsigned int timeout) {
    assert(*req>=0 && *req<2);last_qos[*req]=value;last_timeout[*req]=timeout;
}
'''
main = r'''
static int cases;
int main(void) {
    struct exynos_cpufreq_domain d={.min_freq=208000,.max_freq=1768000,.min_qos_req=0,.max_qos_req=1};
    const unsigned int values[]={0,1,207999,208000,449000,839000,936000,1352000,1768000,1768001,UINT_MAX};
    for(int standard=0;standard<2;standard++)for(int custom=0;custom<2;custom++)
    for(unsigned int a=0;a<sizeof(values)/sizeof(*values);a++)for(unsigned int b=0;b<sizeof(values)/sizeof(*values);b++) {
        struct device_node n={"standard","custom",standard,custom,values[a],values[b]};
        unsigned int expected=d.max_freq;
        if(standard && values[a]>=d.min_freq && values[a]<=d.max_freq)expected=values[a];
        if(custom && values[b]>=d.min_freq && values[b]<=d.max_freq)expected=values[b];
        assert(exynos_eureka_dt_freq(&n,"standard","custom",d.max_freq,d.min_freq,d.max_freq)==expected);cases++;
        n.standard_name="pm_qos-booting";n.custom_name="eureka_pm_qos-booting";
        set_boot_qos(&d,&n);
        assert(last_qos[0]==expected && last_qos[1]==expected);
        assert(last_timeout[0]==40*USEC_PER_SEC && last_timeout[1]==40*USEC_PER_SEC);cases++;
    }
    for(int domain=0;domain<2;domain++) {
        struct device_node n={"user-default-qos","eureka_user-default-qos",true,false,ACTIVE_QOS(domain),0};
        d.user_default_qos=0;assert(parse_ufc_ctrl_info(&d,&n)==0);
        assert(d.user_default_qos==ACTIVE_QOS(domain));cases++;
    }
    struct device_node only_custom={"pm_qos-booting","eureka_pm_qos-booting",false,true,0,1352000};
    set_boot_qos(&d,&only_custom);assert(last_qos[0]==1352000 && last_qos[1]==1352000);cases++;
    struct device_node no_nodes={"pm_qos-booting","eureka_pm_qos-booting",false,false,0,0};
    set_boot_qos(&d,&no_nodes);assert(last_qos[0]==d.max_freq && last_qos[1]==d.max_freq);cases++;
    printf("{\"cases\":%d,\"passed\":true}\n",cases);return 0;
}
'''
main = main.replace('ACTIVE_QOS(domain)', f'(domain ? {active_values[1]}U : {active_values[0]}U)')
before_main = r'''
int main(void) {
    struct exynos_cpufreq_domain d={.min_freq=208000,.max_freq=1768000,.min_qos_req=0,.max_qos_req=1};
    struct device_node n={"user-default-qos","eureka_user-default-qos",true,false,839000,0};
    parse_ufc_ctrl_info(&d,&n);assert(d.user_default_qos==0);
    n=(struct device_node){"pm_qos-booting","eureka_pm_qos-booting",false,true,0,1352000};
    set_boot_qos(&d,&n);assert(last_qos[0]==1768000);
    n=(struct device_node){"pm_qos-booting","eureka_pm_qos-booting",true,false,936000,0};
    set_boot_qos(&d,&n);assert(last_qos[0]==1768000);
    puts("Three original CPU fallback/override failures reproduced.");return 0;
}
'''
init = function(sources[names[0]], 'init_domain')
assert '"max-freq", "eureka_max-freq"' in init and '"min-freq", "eureka_min-freq"' in init
assert 'clamp(domain->boot_freq, domain->min_freq, domain->max_freq)' in init
assert 'clamp(domain->resume_freq, domain->min_freq, domain->max_freq)' in init
assert init.count('unsigned int ekval;') == 0
with tempfile.TemporaryDirectory(prefix='borealis-cpu-dt-') as temp:
    directory = Path(temp)
    patch = package / 'kernel-patches/r24u-cpu-dt-fallback.patch'
    patch_tree = directory / 'patch-tree'
    for name, text in old.items():
        target = patch_tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=patch_tree, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=patch_tree, check=True)
    assert all((patch_tree / n).read_text() == s for n, s in sources.items())
    source = directory / 'cpu-dt.c'
    source.write_text(prefix + functions + main)
    binary = directory / 'cpu-dt'
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-g', '-DCONFIG_EUREKA_CUSTOM_DT_NODES',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie', str(source), '-o', str(binary)], check=True)
    result = json.loads(subprocess.check_output([str(binary)], text=True))
    previous = directory / 'previous.c'
    previous.write_text(prefix + regression + before_main)
    binary = directory / 'previous'
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-DCONFIG_EUREKA_CUSTOM_DT_NODES',
                    str(previous), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    # The non-custom branch still applies standard QoS values.
    noncustom = directory / 'noncustom.c'
    noncustom.write_text(prefix + functions + before_main.replace('assert(d.user_default_qos==0)', 'assert(d.user_default_qos==839000)')
                        .replace('assert(last_qos[0]==1768000);\n    puts', 'assert(last_qos[0]==936000);\n    puts'))
    binary = directory / 'noncustom'
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-fsanitize=address,undefined', '-no-pie',
                    str(noncustom), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, stdout=subprocess.DEVNULL)
report = {'scope': 'Actual CPU frequency selector/boot-QoS/UFC C with mocked DT/CAL bounds/QoS requests',
          'cases': result['cases'], 'passed': True, 'asan_ubsan': 'passed',
          'original_fallback_failures_reproduced': 3, 'config_disabled_qos_behavior_preserved': True,
          'patch_reconstruction_passed': True,
          'source_sha256': {n: hashlib.sha256(s.encode()).hexdigest() for n, s in sources.items()},
          'init_domain_full_function_executed': False, 'available_opp_selection_tested': False,
          'full_kernel_link_passed': False, 'device_tested': False, 'cold_boot_causality_proved': False}
(package / 'validation/kernel/cpu-dt-fallback-tests.json').write_text(json.dumps(report, indent=2) + '\n')
record_path = package / 'validation/kernel/cpu-dt-fallback-source-port.json'
record = json.loads(record_path.read_text())
assert record['changed_files'] == report['source_sha256']
record.update(host_tested=True, host_cases=result['cases'])
record_path.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(report, indent=2))
