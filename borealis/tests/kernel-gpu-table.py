#!/usr/bin/env python3
"""Exercise the patched kernel function itself, with synthetic platform inputs."""
from pathlib import Path
import subprocess
import tempfile
import json

root=Path('/home/android/nebula-r24u-android17')
source=(root/'drivers/gpu/arm/b_r26p0/platform/exynos/gpu_custom_interface.c').read_text()
start=source.index('static ssize_t show_kernel_sysfs_freq_table(')
end=source.index('\n#ifdef CONFIG_MALI_DVFS',start)
stub=r'''
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#define PAGE_SIZE 64
struct kobject {}; struct kobj_attribute {};
struct row {int clock;};
struct exynos_context {struct row *table; int table_size, gpu_min_clock, gpu_max_clock;};
struct device {void *platform_context;} device;
static struct device *pkbdev=&device;
static int min_level=2, max_level=0;
static int gpu_dvfs_get_level(int clock) {return clock==333 ? min_level : max_level;}
static int scnprintf(char *buffer, size_t size, const char *format,...) {
    va_list ap;va_start(ap,format);int n=vsnprintf(buffer,size,format,ap);va_end(ap);
    return n<0 ? 0 : n>=(int)size ? (int)size-1 : n;
}
'''
test=r'''
int main(void) {
    char buffer[PAGE_SIZE];
    struct row rows[]={{999},{676},{333}};
    struct exynos_context context={rows,3,333,999};device.platform_context=&context;
    assert(show_kernel_sysfs_freq_table(0,0,buffer)==13);
    assert(strcmp(buffer,"333 676 999 \n")==0);
    min_level=-1;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-EINVAL);
    min_level=2;max_level=-1;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-EINVAL);
    max_level=3;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-EINVAL);
    min_level=0;max_level=2;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-EINVAL);
    context.table=0;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-ENODEV);
    context.table=rows;context.table_size=0;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-ENODEV);
    device.platform_context=0;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-ENODEV);
    pkbdev=0;assert(show_kernel_sysfs_freq_table(0,0,buffer)==-ENODEV);
    pkbdev=&device;device.platform_context=&context;
    struct row many[32];for(int i=0;i<32;i++)many[i].clock=2000000000-i;
    context.table=many;context.table_size=32;min_level=31;max_level=0;
    ssize_t count=show_kernel_sysfs_freq_table(0,0,buffer);
    assert(count>0 && count<PAGE_SIZE && buffer[count]=='\0' && buffer[count-1]=='\n');
    puts("PASS: 10 R24U GPU table cases, including invalid lookups and bounded output");
}
'''
with tempfile.TemporaryDirectory(prefix='borealis-gpu-') as folder:
    c=Path(folder)/'test.c'; binary=Path(folder)/'test'
    c.write_text(stub+source[start:end]+test)
    subprocess.run(['gcc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',str(c),'-o',str(binary)],check=True)
    result=subprocess.run([str(binary)],check=True,capture_output=True,text=True)
    print(result.stdout,end='')
output=Path(__file__).resolve().parent.parent/'validation/kernel/gpu-table-test.json'
output.write_text(json.dumps({'cases':10,'result':'passed','sanitizers':['address','undefined'],'scope':'Patched upstream function with synthetic inputs; phone driver not yet tested'},indent=2)+'\n')
