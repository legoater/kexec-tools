/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2004  Adam Litke (agl@us.ibm.com)
 * Copyright (C) 2004  IBM Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/elf.h>
#include "../../kexec.h"
#include "kexec-ppc64.h"

#include <zlib.h>

#define HEAD_CRC	2
#define EXTRA_FIELD	4
#define ORIG_NAME	8
#define COMMENT		0x10
#define RESERVED	0xe0

static int get_header_len(const char *header)
{
	int len = 10;
	int flags = header[3];

	/* check for gzip header */
	if ((header[0] != 0x1f) || (header[1] != 0x8b) ||
	    (header[2] != Z_DEFLATED) || (flags & RESERVED) != 0) {
		fprintf(stderr, "bad gzip header\n");
		return -1;
	}

	if ((flags & EXTRA_FIELD) != 0)
		len = 12 + header[10] + (header[11] << 8);

	if ((flags & ORIG_NAME) != 0)
		while (header[len++] != 0)
				;
	if ((flags & COMMENT) != 0)
		while (header[len++] != 0)
			;
	if ((flags & HEAD_CRC) != 0)
		len += 2;

	return len;
}

static int gunzip(void *src, int srclen, void *dst, int dstlen)
{
	z_stream strm;
	int hdrlen;
	int len;
	int ret;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;

	hdrlen = get_header_len(src);
	if (hdrlen == -1)
		return -1;

	if (hdrlen >= srclen) {
		fprintf(stderr, "gzip header too large : %d\n", hdrlen);
		return -1;
	}

	ret = inflateInit2(&strm, -MAX_WBITS);
	if (ret != Z_OK) {
		fprintf(stderr, "inflateInit2 failed : %d\n", ret);
		return -1;
	}

	/* skip gzip header */
	strm.total_in = hdrlen;
	strm.next_in = src + hdrlen;
	strm.avail_in = srclen - hdrlen;

	strm.next_out = dst;
	strm.avail_out = dstlen;

	ret = inflate(&strm, Z_FULL_FLUSH);
	if (ret != Z_OK && ret != Z_STREAM_END) {
		fprintf(stderr, "inflate failed: %d %s\n", ret, strm.msg);
		return -1;
	}

	len = strm.next_out - (unsigned char *) dst;

	inflateEnd(&strm);

	return len;
}

int zImage_ppc64_unzip(struct mem_ehdr *ehdr, void **buf, int *len)
{
	struct mem_shdr *shdr;
	void *vmlinuz_addr;
	unsigned long vmlinuz_size;
	unsigned int *vmlinux_sizep;

	void *vmlinux_addr;
	int vmlinux_size;

	shdr = elf_rel_find_section(ehdr, ".kernel:vmlinux.strip");
	if (!shdr)
		return -1;

	vmlinuz_addr = (void *) shdr->sh_data;
	vmlinuz_size = shdr->sh_size;

	 /* The size of the uncompressed file is stored in the last 4
	  * bytes. The vmlinux size should be less than 4G ... */
	vmlinux_sizep = (vmlinuz_addr + vmlinuz_size) - 4;

	fprintf(stderr, "Found vmlinuz at %p, unzipping %d bytes\n",
		vmlinuz_addr, *vmlinux_sizep);
	vmlinux_addr = xmalloc(*vmlinux_sizep);

	vmlinux_size = gunzip(vmlinuz_addr, vmlinuz_size,
			      vmlinux_addr, *vmlinux_sizep);
	if (vmlinux_size != *vmlinux_sizep) {
		fprintf(stderr, "gunzip failed : only got %d of %d bytes.\n",
				vmlinux_size, *vmlinux_sizep);
		return -1;
	}

	*buf = vmlinux_addr;
	*len = vmlinux_size;
	return 0;
}
