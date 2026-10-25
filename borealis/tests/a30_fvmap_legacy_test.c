/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "a30_fvmap_legacy.h"

static void le16(unsigned char *p, unsigned int value)
{
	p[0] = value; p[1] = value >> 8;
}
static void le32(unsigned char *p, unsigned int value)
{
	for (unsigned int i = 0; i < 4; i++) p[i] = value >> (8 * i);
}
int main(void)
{
	unsigned char map[8192];
	unsigned int cases = 0, rate, volts;
	struct borealis_a30_fvmap_domain domain;
	_Static_assert(sizeof(struct borealis_a30_fvmap_header) == 24, "A30 header ABI");
	_Static_assert(offsetof(struct borealis_a30_fvmap_header, o_ratevolt) == 20, "rate offset");
	/* Every table length, each of the ten native domains, actual 32-bit values.
	 * This catches accidental use of the donor's 4-byte packed voltage format.
	 */
	for (unsigned int count = 1; count <= 255; count++) {
		for (unsigned int index = 0; index < 10; index++) {
			memset(map, 0, sizeof(map));
			map[index * 24] = index;
			map[index * 24 + 1] = count;
			le16(map + index * 24 + 20, 256);
			for (unsigned int i = 0; i < count; i++) {
				le32(map + 256 + i * 8, 1352000 - i * 1000);
				le32(map + 260 + i * 8, 950000 + i * 6250);
				assert(!borealis_a30_fvmap_level_read(map, 8192, index, i, &rate, &volts));
				assert(rate == 1352000 - i * 1000 && volts == 950000 + i * 6250);
				cases++;
			}
			rate = 11; volts = 12;
			assert(borealis_a30_fvmap_level_read(map, 8192, index, count, &rate, &volts));
			assert(rate == 11 && volts == 12); cases++;
		}
	}
	/* Exact end-of-buffer boundary and every truncation of that snapshot. */
	memset(map, 0, sizeof(map)); map[1] = 1;
	le16(map + 20, 8184); le32(map + 8184, 208000); le32(map + 8188, 825000);
	for (unsigned int size = 0; size < 8192; size++) {
		unsigned char *short_map = malloc(size ? size : 1);
		memcpy(short_map, map, size); rate = 11; volts = 12;
		assert(borealis_a30_fvmap_level_read(short_map, size, 0, 0, &rate, &volts));
		assert(rate == 11 && volts == 12); free(short_map); cases++;
	}
	assert(!borealis_a30_fvmap_level_read(map, 8192, 0, 0, &rate, &volts)); cases++;
	assert(rate == 208000 && volts == 825000);
	/* Reserved indices, huge offsets, member ranges and invalid initial level. */
	assert(borealis_a30_fvmap_domain_read(map, 8192, UINT32_MAX, &domain)); cases++;
	assert(borealis_a30_fvmap_domain_read(map, 8192, 10, &domain)); cases++;
	le16(map + 20, 65535); assert(borealis_a30_fvmap_domain_read(map, 8192, 0, &domain)); cases++;
	le16(map + 20, 256); map[2] = 8; le16(map + 18, 8180);
	assert(borealis_a30_fvmap_domain_read(map, 8192, 0, &domain)); cases++;
	le16(map + 18, 300); map[3] = 9;
	assert(borealis_a30_fvmap_domain_read(map, 8192, 0, &domain)); cases++;
	map[3] = 0; map[8] = 1;
	assert(borealis_a30_fvmap_domain_read(map, 8192, 0, &domain)); cases++;
	map[1] = 0; assert(borealis_a30_fvmap_domain_read(map, 8192, 0, &domain) == -2); cases++;
	assert(borealis_a30_fvmap_domain_read(NULL, 8192, 0, &domain)); cases++;
	assert(borealis_a30_fvmap_domain_read(map, 8193, 0, &domain)); cases++;
	/* Adversarial header fuzzing with genuinely short allocations under ASan. */
	uint32_t seed = 17;
	for (unsigned int i = 0; i < 20000; i++) {
		seed = seed * 1664525 + 1013904223;
		unsigned int size = seed % 8193;
		unsigned char *data = malloc(size ? size : 1);
		for (unsigned int j = 0; j < size; j++) {
			seed = seed * 1664525 + 1013904223; data[j] = seed >> 24;
		}
		borealis_a30_fvmap_level_read(data, size, seed % 13, seed >> 24, &rate, &volts);
		free(data); cases++;
	}
	printf("{\"passed\":true,\"cases\":%u,\"hardware_access\":false}\n", cases);
}
