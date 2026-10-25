/* SPDX-License-Identifier: GPL-2.0 */
/* A30 firmware ABI from Samsung's Exynos7885 kernel source.
 * This reader only reads a bounded RAM snapshot. It never writes SRAM/MMIO.
 */
#ifndef BOREALIS_A30_FVMAP_LEGACY_H
#define BOREALIS_A30_FVMAP_LEGACY_H

#define BOREALIS_A30_FVMAP_BYTES 8192U
#define BOREALIS_A30_FVMAP_DOMAINS 10U
#define BOREALIS_A30_FVMAP_HEADER_BYTES 24U

struct borealis_a30_fvmap_header {
	unsigned char dvfs_type, num_of_lv, num_of_members;
	unsigned char num_of_pll, num_of_mux, num_of_div;
	unsigned short gearratio;
	unsigned char init_lv, num_of_gate, reserved[2];
	unsigned short block_addr[3], o_members, o_ratevolt, o_tables;
};

struct borealis_a30_fvmap_domain {
	unsigned int type, levels, ratevolt_offset;
};

static inline unsigned int borealis_a30_fvmap_le16(const unsigned char *p)
{
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static inline unsigned int borealis_a30_fvmap_le32(const unsigned char *p)
{
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
		((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* Return -1 for malformed/truncated data and -2 for an empty domain.
 * Output remains unchanged on failure. Firmware rate units are kHz and
 * voltages are the original 32-bit microvolt values, without scaling.
 */
static inline int borealis_a30_fvmap_domain_read(const unsigned char *map,
	unsigned long bytes, unsigned int index,
	struct borealis_a30_fvmap_domain *output)
{
	struct borealis_a30_fvmap_domain domain;
	const unsigned char *header;
	unsigned int members, member_offset, header_bytes;

	header_bytes = BOREALIS_A30_FVMAP_DOMAINS * BOREALIS_A30_FVMAP_HEADER_BYTES;
	if (!map || !output || index >= BOREALIS_A30_FVMAP_DOMAINS ||
	    bytes < header_bytes || bytes > BOREALIS_A30_FVMAP_BYTES)
		return -1;
	header = map + index * BOREALIS_A30_FVMAP_HEADER_BYTES;
	domain.type = header[0];
	domain.levels = header[1];
	members = header[2];
	member_offset = borealis_a30_fvmap_le16(header + 18);
	domain.ratevolt_offset = borealis_a30_fvmap_le16(header + 20);
	if (!domain.levels)
		return -2;
	if (header[8] >= domain.levels || header[3] > members ||
	    domain.ratevolt_offset < header_bytes ||
	    domain.ratevolt_offset > bytes ||
	    domain.levels > (bytes - domain.ratevolt_offset) / 8)
		return -1;
	if (members && (member_offset < header_bytes || member_offset > bytes ||
	    members > (bytes - member_offset) / 2))
		return -1;
	*output = domain;
	return 0;
}

static inline int borealis_a30_fvmap_level_read(const unsigned char *map,
	unsigned long bytes, unsigned int domain_index, unsigned int level,
	unsigned int *rate_khz, unsigned int *microvolts)
{
	struct borealis_a30_fvmap_domain domain;
	const unsigned char *entry;
	int ret;

	if (!rate_khz || !microvolts)
		return -1;
	ret = borealis_a30_fvmap_domain_read(map, bytes, domain_index, &domain);
	if (ret)
		return ret;
	if (level >= domain.levels)
		return -1;
	entry = map + domain.ratevolt_offset + level * 8;
	*rate_khz = borealis_a30_fvmap_le32(entry);
	*microvolts = borealis_a30_fvmap_le32(entry + 4);
	return 0;
}
#endif
