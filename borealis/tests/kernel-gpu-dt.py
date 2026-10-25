"""Test the real narrow DT clock selector against the captured device case."""
from pathlib import Path
import subprocess, tempfile, json
source=Path('/home/android/nebula-r24u-android17/drivers/gpu/arm/b_r26p0/platform/exynos/mali_kbase_platform.c').read_text()
start=source.index('static int gpu_valid_custom_clock(')
end=source.index('\n}',start)+2
test='''
#include <assert.h>
#include <stdio.h>
'''+source[start:end]+'''
int main(void) {
 assert(gpu_valid_custom_clock(845000,0)==845000);
 assert(gpu_valid_custom_clock(845000,-1)==845000);
 assert(gpu_valid_custom_clock(845000,676000)==676000);
 assert(gpu_valid_custom_clock(676000,0)==676000);
 puts("GPU DT fallback passed: absent override retains captured 845 MHz standard limit.");
}
'''
start=source.index('\t\tif (!of_property_read_u32_array(np, "eureka_gpu_temp_throttling",')
end=source.index('\n#else',start)
thermal=source[start:end]
test+='''
#include <string.h>
#define TMU_LOCK_CLK_END 6
static int result;
static int fixture[6];
static int of_property_read_u32_array(void *np, const char *name, int *values, int size) {
 (void)np; (void)name;
 if (result) return result;
 memcpy(values,fixture,size*sizeof(int)); return 0;
}
static void apply_thermal(int *target) {
 void *np=0; int i; int of_data_int_array[6];
 struct {int tmu_lock_clk[6];} data, *platform=&data;
 memcpy(data.tmu_lock_clk,target,sizeof(data.tmu_lock_clk));
'''+thermal+'''
 memcpy(target,data.tmu_lock_clk,sizeof(data.tmu_lock_clk));
}
__attribute__((constructor)) static void test_thermal(void) {
 int standard[]={676000,545000,450000,343000,343000,343000};
 int target[6];
 for (int error=-2;error<0;error++) {
  result=error;memcpy(target,standard,sizeof(target));apply_thermal(target);
  assert(!memcmp(target,standard,sizeof(target)));
 }
 result=0; memset(fixture,0,sizeof(fixture));
 memcpy(target,standard,sizeof(target)); apply_thermal(target);
 assert(!memcmp(target,standard,sizeof(target)));
 memcpy(fixture,standard,sizeof(fixture));fixture[3]=-1;
 apply_thermal(target);assert(!memcmp(target,standard,sizeof(target)));
 memcpy(fixture,standard,sizeof(fixture));fixture[0]=545000;
 apply_thermal(target);assert(!memcmp(target,fixture,sizeof(target)));
 puts("GPU thermal fallback passed: missing/truncated/invalid overrides retain the standard table.");
}
'''
with tempfile.TemporaryDirectory(prefix='borealis-dt-') as folder:
 c=Path(folder)/'test.c';binary=Path(folder)/'test';c.write_text(test)
 subprocess.run(['gcc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
out=Path(__file__).resolve().parent.parent/'validation/kernel/gpu-dt-test.json'
out.write_text(json.dumps({'result':'passed','clock_cases':4,'thermal_cases':5,'scope':'Actual selector and thermal override block; no hardware validation','sanitizers':['address','undefined']},indent=2)+'\n')
