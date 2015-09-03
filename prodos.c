/*
 * ProDOS file system reading utility
 * Copyright 2005 Kim Vandry <vandry@TZoNE.ORG>
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License , or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * This is a tool for reading files off ProDOS file systems (for the
 * Apple II). It should be able to deal with all types of files
 * including extended files with resource forks.
 *
 * I wanted to back up some of my old Apple II files. Trying to
 * transfer a whole hard drive's worth of data to another computer
 * from the Apple IIgs using zmodem over a serial port wasn't turning
 * out to be very effective, so I plugged the hard drive into
 * another machine and took a raw image snapshot. Then I needed to
 * be able to interpret the ProDOS file system on a Linux or
 * Solaris machine or something of that sort. I didn't build any
 * write capacity into this tool because I don't need it and it
 * would be a lot more work.
 *
 * How to use it:
 *
 * The source code should be very portable. The only thing it depends
 * on that might not be available everywhere is mmap. If you replace
 * mmap with a stub that always fails it should work fine since it
 * has a fallback mode. Compile with -Wall -Wno-parentheses
 *
 * Give it the name of a file containing a disk image using the
 * -i option. It can be a floppy image or a hard disk device,
 * or, more typically, a floppy or hard disk image.
 *
 * If it is a hard disk or hard disk image, there will be a partition
 * table at the start. The tool is able to read the partition table.
 * Use the -p option to select which partition you want to access by
 * number. Use the syntax "prodos -i image partitions" to list the
 * available partitions.
 *
 * The other commands are self explanatory.
 *
 * About the tar feature:
 *
 * The tar subcommand lets you translate the ProDOS filesystem or a
 * part of the ProDOS filesystem to a tar archive. That means you
 * can do something like this:
 *
 * prodos -i disk.image -p 2 tar | tar xf -
 *
 * and you will end up with a copy of the files on your native
 * filesystem.
 *
 * This process is lossy. The Apple II file type is mostly lost, the
 * aux_type is lost, the creation time is lost, some of the access
 * permissions are lost, and most importantly, the resource fork is
 * lost. A possible improvement would be to generate metainformation
 * in the tar archive (say, in the format recognized by CAP or by
 * netatalk).
 *
 * Oh, and by the way, it's rather faster than any of my Apples are
 * (duh)
 *
 * --kv Wed Mar 23 18:28:38 EST 2005
 *
 * Usage: prodos -i image [-p partition_number] command [args]
 * commands: ls [pathname]    short filename listing
 *           dir [pathname]   long filename listing
 *           cat pathname     dump data fork
 *           rcat pathname    dump resource fork
 *           volume           show volume information
 *           partitions       show partition table
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#define __USE_UNIX98
#include <unistd.h>

#define BLOCKSIZE 512

struct diskimage {
	char type;
	struct diskimage *subimage;
	unsigned int start;
	int fd;
	unsigned int length;
	void *base;
};

struct partition_map {
	struct diskimage *im;
	unsigned int blocksize;
	unsigned int map_count;
	unsigned int start_block;
	unsigned int block_count;
	unsigned int data_start;
	unsigned int data_count;
};

struct prodos_fs {
	struct diskimage *im;
	unsigned int curdir_block;
	unsigned char *curdir;
	unsigned char *volname;
	unsigned char *superblock;
};

struct prodos_dir {
	struct prodos_fs *fs;
	int curblocknum;
	unsigned char *curblock;
	unsigned char *dirname;
	int entries_per_block;
	int entry_length;
	int cur_entry_num;
	int error;
};

#define PRODOS_FI_STAT_PRESENT 1
#define PRODOS_FI_EXTENDED_PRESENT 2
struct prodos_file_info {
	int flags;
	unsigned int storage_type;
	unsigned int data_storage_type;
	unsigned int resource_storage_type;
	char filename[16];
	char raw_filename[16];
	unsigned int file_type;
	unsigned int key_pointer;
	unsigned int data_key_pointer;
	unsigned int resource_key_pointer;
	unsigned int nblocks;
	unsigned int data_nblocks;
	unsigned int resource_nblocks;
	unsigned int length;
	unsigned int data_length;
	unsigned int resource_length;
	unsigned int creation;
	unsigned int modification;
	unsigned int version;
	unsigned int min_version;
	unsigned int access;
	unsigned int aux_type;
	unsigned int header_pointer;
};

struct prodos_file {
	struct prodos_fs *fs;
	int storage_type;
	unsigned char *keyblock;
	int data_block_n;
	unsigned char *datablock;
	int index_block_n;
	unsigned char *index_block;
	int cursor;
	int length;
};

struct tarblock {
	int count;
	unsigned char data[10240];
};

struct diskimage *diskimage_fromfile(char *file)
{
struct diskimage *new;
struct stat sbuf;

	if (!(new = malloc(sizeof(*new)))) {
		perror("malloc");
		return NULL;
	}
	if ((new->fd = open(file, O_RDONLY)) < 0) {
		fprintf(stderr, "diskimage_fromfile: open %s: %s\n", file, strerror(errno));
		free(new);
		return NULL;
	}
	if (fstat(new->fd, &sbuf) < 0) {
		fprintf(stderr, "diskimage_fromfile: fstat %s: %s\n", file, strerror(errno));
		close(new->fd);
		free(new);
		return NULL;
	}
	if (sbuf.st_size > 0) {
		if (sbuf.st_size & 511) {
			fprintf(stderr, "diskimage_fromfile: warning: partial block discarded at the end of %s\n", file);
		}
		new->length = sbuf.st_size >> 9;
	} else {
		fprintf(stderr, "diskimage_fromfile: %s: must have non zero size\n", file);
		close(new->fd);
		free(new);
		return NULL;
	}

	new->start = 0;
	new->base = mmap(NULL, new->length << 9, PROT_READ, MAP_SHARED, new->fd, 0);

	if (new->base == MAP_FAILED) {
		new->type = 'f';
	} else {
		close(new->fd);
		new->type = 'm';
	}

	return new;
}

void diskimage_close(struct diskimage *d)
{
	if (d->type == 'f') {
		close(d->fd);
	} else if (d->type == 'm') {
		munmap(d->base, d->length << 9);
	}
	free(d);
}

void *diskimage_block(struct diskimage *d, int block)
{
void *result;
int i, fill;

	if ((block < 0) || (block > d->length)) {
		fprintf(stderr, "diskimage_block: block %d out of range\n", block);
		return NULL;
	}
	if (d->type == 'm') {
		return d->base + (block << 9);
	} else if (d->type == 'f') {
		if (!(result = malloc(BLOCKSIZE))) {
			perror("malloc");
			return NULL;
		}
		fill = 0;
		while (fill < 512) {
			i = pread(d->fd, result + fill, BLOCKSIZE - fill, (block << 9) + fill);
			if (i <= 0) {
				fprintf(stderr, "diskimage_block: read block %d: %s\n", block,
					(i < 0) ? strerror(errno) : "EOF");
				free(result);
				return NULL;
			}
			fill += i;
		}
		return result;
	} else if (d->type == 's') {
		return diskimage_block(d->subimage, block + d->start);
	} else {
		fprintf(stderr, "diskimage_block: unknown type of diak image\n");
		return NULL;
	}
}

void diskimage_freeblock(struct diskimage *d, void *b)
{
	if (d->type == 'f') {
		free(b);
	} else if (d->type == 's') {
		return diskimage_freeblock(d->subimage, b);
	}
}

struct diskimage *diskimage_makesub(struct diskimage *d, int start, int length)
{
struct diskimage *new;

	if ((start + length) > (d->length)) {
		fprintf(stderr, "diskimage_makesub: attempt to make a subimage bigger than the parent\n"
			"parent has %d blocks; child attempt at block %d for %d blocks\n",
			d->length, start, length);
		return NULL;
	}
	if (!(new = malloc(sizeof(*new)))) {
		perror("malloc");
		return NULL;
	}
	new->type = 's';
	new->start = start;
	new->length = length;
	new->subimage = d;
	return new;
}

struct prodos_fs *prodos_openfs(struct diskimage *d)
{
unsigned char *superblock;
struct prodos_fs *new;
int i, invalid_warned;

	if (!(superblock = diskimage_block(d, 2))) return NULL;

	if (superblock[0] != 0) goto notfound;
	if (superblock[1] != 0) goto notfound;
	if ((superblock[4] & 0xf0) != 0xf0) goto notfound;
	if (superblock[33] != 0) goto notfound;
	if (superblock[35] != 39) goto notfound;
	if (superblock[36] != 13) goto notfound;

	if (!(new = malloc(sizeof(*new)))) {
		perror("malloc");
		return NULL;
	}

	memset(new, 0, sizeof(*new));
	
	new->im = d;
	if (!(new->volname = malloc((superblock[4] & 15) + 2))) {
		perror("malloc");
		free(new);
		return NULL;
	}

	new->curdir_block = 2;

	new->volname[0] = '/';
	invalid_warned = 0;
	for (i = 0; i < (superblock[4] & 15); i++) {
		if ((superblock[i+5] == 0) || (superblock[i+5] == '/')) {
			if (!invalid_warned) {
				fprintf(stderr, "prodos_openfs: invalid characters in volume name\n");
				invalid_warned = 1;
			}
			new->volname[i+1] = '.';
		} else {
			new->volname[i+1] = superblock[i+5];
		}
	}
	new->volname[i+1] = 0;

	if (!(new->curdir = malloc(2))) {
		perror("malloc");
		free(new->volname);
		free(new);
		return NULL;
	}
	new->curdir[0] = '/';
	new->curdir[1] = 0;

	new->superblock = superblock;

	return new;

notfound:
	fprintf(stderr, "prodos_openfs: no ProDOS filesystem superblock found at block 2\n");
	return NULL;
}

void prodos_closefs(struct prodos_fs *f)
{
	free(f->curdir);
	free(f->volname);
	diskimage_freeblock(f->im, f->superblock);
	free(f);
}

struct prodos_dir *prodos_opendir_atblock(struct prodos_fs *f, int keyblock)
{
struct prodos_dir *new;
int invalid_warned, i;

	new = malloc(sizeof(*new));
	new->fs = f;
	if (!(new->curblock = diskimage_block(f->im, keyblock))) {
		free(new);
		return NULL;
	}

	if ((new->curblock[4] & 0xe0) != 0xe0) {
		fprintf(stderr, "prodos_opendir_atblock: subdirectory at block %d is corrupt\n", keyblock);
		diskimage_freeblock(f->im, new->curblock);
		free(new);
		return NULL;
	}

	new->entries_per_block = new->curblock[36];
	new->entry_length = new->curblock[35];
	new->cur_entry_num = 1;
	new->error = 0;
	new->curblocknum = keyblock;

	if (!(new->dirname = malloc((new->curblock[4] & 15) + 1))) {
		perror("malloc");
		diskimage_freeblock(f->im, new->curblock);
		free(new);
		return NULL;
	}

	invalid_warned = 0;
	for (i = 0; i < (new->curblock[4] & 15); i++) {
		if ((new->curblock[i+5] == 0) || (new->curblock[i+5] == '/')) {
			if (!invalid_warned) {
				fprintf(stderr, "prodos_opendir: invalid characters in directory name\n");
				invalid_warned = 1;
			}
			new->dirname[i] = '.';
		} else {
			new->dirname[i] = new->curblock[i+5];
		}
	}
	new->dirname[i] = 0;

	return new;
}

int prodos_readdir(struct prodos_dir *d, struct prodos_file_info *sbuf)
{
int newblock;
int base, i, mask;

	if (d->error) return -1;
	for (;;) {
		if (d->cur_entry_num >= d->entries_per_block) {
			/* next block */
			if ((d->curblock[2] == 0) && (d->curblock[3] == 0))
				/* no more! */
				return 0;

			newblock = d->curblock[2] | (d->curblock[3] << 8);
			if (newblock == d->curblocknum) {
				fprintf(stderr, "prodos_readdir: directory is corrupt at block %d, loops back to itself\n", newblock);
				return 0;
			}

			diskimage_freeblock(d->fs->im, d->curblock);
			if (d->curblock = diskimage_block(d->fs->im, newblock)) {
				d->cur_entry_num = 0;
				d->curblocknum = newblock;
			} else {
				d->error = 1;
				return -1;
			}
		}
		base = 4 + (d->cur_entry_num * d->entry_length);

		if ((d->curblock[base] & 0xf0) == 0) {
			/* unoccupied slot */
			d->cur_entry_num++;
			continue;
		}

		sbuf->flags = PRODOS_FI_STAT_PRESENT;

		sbuf->storage_type = (d->curblock[base] & 0xf0) >> 4;
		memcpy(sbuf->filename, d->curblock + base + 1, d->curblock[base] & 15);
		memcpy(sbuf->raw_filename, d->curblock + base + 1, d->curblock[base] & 15);
		sbuf->filename[d->curblock[base] & 15] = 0;
		sbuf->raw_filename[d->curblock[base] & 15] = 0;
		sbuf->file_type = d->curblock[base+16];
		sbuf->key_pointer = d->curblock[base+17] | (d->curblock[base+18] << 8);
		sbuf->nblocks = d->curblock[base+19] | (d->curblock[base+20] << 8);
		sbuf->length = d->curblock[base+21] | (d->curblock[base+22] << 8) |
			(d->curblock[base+23] << 16);
		sbuf->creation = d->curblock[base+24] | (d->curblock[base+25] << 8) |
			(d->curblock[base+26] << 16) | (d->curblock[base+27] << 24);
		sbuf->version = d->curblock[base+28];
		sbuf->min_version = d->curblock[base+29];
		sbuf->access = d->curblock[base+30];
		sbuf->aux_type = d->curblock[base+31] | (d->curblock[base+32] << 8);
		sbuf->modification = d->curblock[base+33] | (d->curblock[base+34] << 8) |
			(d->curblock[base+35] << 16) | (d->curblock[base+36] << 24);
		sbuf->header_pointer = d->curblock[base+37] | (d->curblock[base+38] << 8);

		d->cur_entry_num++;

		if (sbuf->min_version > 0x80) {
			i = 0;
			mask = (sbuf->min_version << 8) | sbuf->version;
			for (i = 0; i < d->curblock[base] & 15; i++) {
				if (mask & 0x4000) {
					if ((sbuf->filename[i] >= 'A') && (sbuf->filename[i] <= 'Z')) {
						sbuf->filename[i] -= 'A'-'a';
					}
				}
				mask <<= 1;
			}
		}

		return 1;
	}
}

void prodos_closedir(struct prodos_dir *d)
{
	if (d->curblock)
		diskimage_freeblock(d->fs->im, d->curblock);
	free(d->dirname);
	free(d);
}

int prodos_resolvepath2(struct prodos_fs *f, char *path, int curblock, struct prodos_file_info *sbuf)
{
char *slash;
struct prodos_dir *d;
struct prodos_file_info psbuf;
int i;

	slash = strchr(path, '/');

	if (!(d = prodos_opendir_atblock(f, curblock)))
		return EIO;

	while ((i = prodos_readdir(d, &psbuf)) == 1) {
		if (slash ? ((strlen(psbuf.filename) == (slash - path)) &&
			(!strncasecmp(psbuf.filename, path, slash - path))) :
			(!strcasecmp(psbuf.filename, path)))
				/* found the file */
				break;
	}
	prodos_closedir(d);
	if (i == -1) return EIO;
	if (i == 0) return ENOENT;

	if (slash && (psbuf.storage_type != 13)) return ENOTDIR;

	if (slash) {
		while (slash[0] == '/') slash++;
	}

	if (slash && slash[0]) {
		return prodos_resolvepath2(f, slash, psbuf.key_pointer, sbuf);
	}

	memcpy(sbuf, &psbuf, sizeof(*sbuf));
	return 0;
}

int prodos_stat_fromdirkey(struct prodos_fs *f, int keyblock, struct prodos_file_info *sbuf)
{
unsigned char *block;

	if (!(block = diskimage_block(f->im, keyblock)))
		return -1;

	sbuf->flags = PRODOS_FI_STAT_PRESENT;

	sbuf->storage_type = 13;
	memcpy(sbuf->filename, block + 5, block[4] & 15);
	memcpy(sbuf->raw_filename, block + 5, block[4] & 15);
	sbuf->filename[block[4] & 15] = 0;
	sbuf->raw_filename[block[4] & 15] = 0;
	sbuf->file_type = 15;
	sbuf->key_pointer = keyblock;
	sbuf->nblocks = 0;
	sbuf->length = 0;
	sbuf->creation = block[28] | (block[29] << 8) |
		(block[30] << 16) | (block[31] << 24);
	sbuf->version = block[32];
	sbuf->min_version = block[33];
	sbuf->access = block[34];
	sbuf->aux_type = 0;
	sbuf->modification = 0;
	sbuf->header_pointer = 0;

	diskimage_freeblock(f->im, block);

	return 0;
}

int prodos_stat(struct prodos_fs *f, char *path, struct prodos_file_info *sbuf)
{
int useblock;

	if (path[0] == '/') {
		while (path[0] == '/') path++;
		useblock = 2;
	} else {
		useblock = f->curdir_block;
	}

	if (path[0] == 0) {
		/* this directory */
		return prodos_stat_fromdirkey(f, useblock, sbuf);
	}

	return prodos_resolvepath2(f, path, useblock, sbuf);
}

int prodos_extended_stat(struct prodos_fs *f, struct prodos_file_info *sbuf)
{
unsigned char *keyblock;

	if (sbuf->flags & PRODOS_FI_EXTENDED_PRESENT) return 0;
	if (sbuf->storage_type != 5) return 0;

	if (!(keyblock = diskimage_block(f->im, sbuf->key_pointer))) {
		return -1;
	}

	sbuf->data_storage_type = keyblock[0];
	sbuf->resource_storage_type = keyblock[256];

	sbuf->data_key_pointer = keyblock[1] | (keyblock[2] << 8);
	sbuf->resource_key_pointer = keyblock[257] | (keyblock[258] << 8);

	sbuf->data_nblocks = keyblock[3] | (keyblock[4] << 8);
	sbuf->resource_nblocks = keyblock[259] | (keyblock[260] << 8);

	sbuf->data_length = keyblock[5] | (keyblock[6] << 8) | (keyblock[7] << 16);
	sbuf->resource_length = keyblock[261] | (keyblock[262] << 8) | (keyblock[263] << 16);

	sbuf->flags |= PRODOS_FI_EXTENDED_PRESENT;

	diskimage_freeblock(f->im, keyblock);

	return 0;
}

struct prodos_dir *prodos_opendir(struct prodos_fs *f, char *path)
{
int err;
struct prodos_file_info sbuf;

	err = prodos_stat(f, path, &sbuf);
	if ((err == 0) && (sbuf.storage_type != 13)) err = ENOTDIR;
	;if (err) {
		fprintf(stderr, "prodos_opendir: %s\n", strerror(err));
		return NULL;
	}
	return prodos_opendir_atblock(f, sbuf.key_pointer);
}

void prodos_close(struct prodos_file *f)
{
	diskimage_freeblock(f->fs->im, f->keyblock);
	free(f);
}

struct prodos_file *prodos_open_statbuf(struct prodos_fs *f, struct prodos_file_info *sbuf, int rfork)
{
struct prodos_file *new;

	if (sbuf->storage_type == 13) {
		fprintf(stderr, "prodos_open: cannot open a directory\n");
		return NULL;
	}

	if ((sbuf->storage_type != 1) &&
		(sbuf->storage_type != 2) &&
		(sbuf->storage_type != 5) &&
		(sbuf->storage_type != 3)) {
			fprintf(stderr, "prodos_open: unsupported storage type %d\n", sbuf->storage_type);
			return NULL;
	}

	if (sbuf->storage_type == 5) {
		if (prodos_extended_stat(f, sbuf) < 0) {
			fprintf(stderr, "prodos_open: cannot read key block\n");
			return NULL;
		}
	} else if (rfork) {
		fprintf(stderr, "prodos_open: does not have a resource fork\n");
		return NULL;
	}

	if (!(new = malloc(sizeof(*new)))) {
		perror("malloc");
		return NULL;
	}

	if (sbuf->storage_type == 5) {
		new->storage_type = rfork ? sbuf->resource_storage_type : sbuf->data_storage_type;
		new->length = rfork ? sbuf->resource_length : sbuf->data_length;

		new->keyblock = diskimage_block(f->im, rfork ? sbuf->resource_key_pointer : sbuf->data_key_pointer);
	} else {
		new->storage_type = sbuf->storage_type;
		new->length = sbuf->length;

		new->keyblock = diskimage_block(f->im, sbuf->key_pointer);
	}

	if (!(new->keyblock)) {
		fprintf(stderr, "prodos_open: cannot read key block\n");
		free(new);
		return NULL;
	}

	new->cursor = 0;
	new->data_block_n = new->index_block_n = -1;
	new->fs = f;

	return new;
}

struct prodos_file *prodos_open(struct prodos_fs *f, char *path, int rfork)
{
int err;
struct prodos_file_info sbuf;

	err = prodos_stat(f, path, &sbuf);
	if (err) {
		fprintf(stderr, "prodos_open: %s: %s\n", path, strerror(err));
		return NULL;
	}
	return prodos_open_statbuf(f, &sbuf, rfork);
}

int prodos_read(struct prodos_file *f, char *buf, int count)
{
int fill = 0;
int realcount;
int needblock;
int i;

	while (count) {
		if (f->cursor >= f->length) break;
		if (f->storage_type == 1) {
			realcount = count;
			if ((count + f->cursor) > f->length)
				realcount = f->length - f->cursor;
			if (f->cursor < 512) {
				if ((f->cursor + realcount) > 512) {
					/* tail sparse - zeros afterwards */
					memcpy(buf + fill, f->keyblock + f->cursor, 512 - f->cursor);
					memset(buf + fill + 512 - f->cursor, 0,
						realcount - 512 - f->cursor);
				} else {
					memcpy(buf + fill, f->keyblock + f->cursor, realcount);
				}
			}
			fill += realcount;
			f->cursor += realcount;
			count = 0;
		} else if (f->storage_type == 2) {
			/* which block is needed for the current position? */
			i = f->cursor >> 9;
			if ((i > 255) || (f->length > 131072)) {
				/* tail sparse - we are reading regions beyond the storage
				   catacity for sapling files */
				needblock = 0;
			} else {
				needblock = f->keyblock[i] | (f->keyblock[i | 256] << 8);
			}

			if ((needblock > 0) && (needblock != f->data_block_n)) {
				if (f->data_block_n != -1) {
					diskimage_freeblock(f->fs->im, f->datablock);
				}
				f->data_block_n = -1;
				if (!(f->datablock = diskimage_block(f->fs->im, needblock))) {
					if (fill) break;
					errno = EIO;
					return -1;
				}
				f->data_block_n = needblock;
			}

			realcount = 512 - (f->cursor & 511);
			if (realcount > count) realcount = count;
			if ((f->cursor + realcount) > f->length) realcount = f->length - f->cursor;

			if (needblock == 0) {
				/* sparse */
				memset(buf + fill, 0, realcount);
			} else {
				memcpy(buf + fill, f->datablock + (f->cursor & 511), realcount);
			}

			fill += realcount;
			count -= realcount;
			f->cursor += realcount;
		} else if (f->storage_type == 3) {
			/* which index block is needed for the current position? */
			i = f->cursor >> 17;
			if ((i > 127) || (f->length > 16777216)) {
				/* can files be sparse beyond 16M? don't think so */
				fprintf(stderr, "prodos_read: size assertion failed for tree file\n");
				return fill ? fill : -1;
			}
			needblock = f->keyblock[i] | (f->keyblock[i | 256] << 8);

			if ((needblock > 0) && (needblock != f->index_block_n)) {
				if (f->index_block_n != -1) {
					diskimage_freeblock(f->fs->im, f->index_block);
				}
				f->index_block_n = -1;
				if (!(f->index_block = diskimage_block(f->fs->im, needblock))) {
					if (fill) break;
					errno = EIO;
					return -1;
				}
				f->index_block_n = needblock;
			}

			if (needblock) {
				/* which data block is needed for the current position? */
				i = (f->cursor >> 9) & 255;
				needblock = f->index_block[i] | (f->index_block[i | 256] << 8);

				if ((needblock > 0) && (needblock != f->data_block_n)) {
					if (f->data_block_n != -1) {
						diskimage_freeblock(f->fs->im, f->datablock);
					}
					f->data_block_n = -1;
					if (!(f->datablock = diskimage_block(f->fs->im, needblock))) {
						if (fill) break;
						errno = EIO;
						return -1;
					}
					f->data_block_n = needblock;
				}
			} /* else sparse */

			realcount = 512 - (f->cursor & 511);
			if (realcount > count) realcount = count;
			if ((f->cursor + realcount) > f->length) realcount = f->length - f->cursor;

			if (needblock == 0) {
				memset(buf + fill, 0, realcount);
			} else {
				memcpy(buf + fill, f->datablock + (f->cursor & 511), realcount);
			}

			fill += realcount;
			count -= realcount;
			f->cursor += realcount;
		}
	}
	return fill;
}

void prodos_pretty_time(char *s, unsigned int tm)
{
	if (tm == 0) {
		strcpy(s, "<NO DATE>");
		return;
	}
#ifdef FAITHFUL_BUT_Y2K_UNFRIENDLY
	sprintf(s, "%2d-%s-%02d %2d:%02d",
		tm & 31,
		"m00\0JAN\0FEB\0MAR\0APR\0MAY\0JUN\0JUL\0AUG\0SEP\0OCT\0NOV\0DEC\0m13\0m14\0m15" +
			(((tm & 511) >> 3) & 0x3c),
		((tm & 65535) >> 9) % 100,
		(tm >> 24) & 255,
		(tm >> 16) & 255);
#else
	/* The year is a 7 bit field. We know that years 1900 through 1999
	   are encoded as (year)-1900. How are years 2000 through 2027
	   encoded? The sensible thing is to follow the same rule. I'm
	   not sure this is what the Apple would do, but, well, my ProDOS
	   authoritztive documentation was published in 1987 and I don't
	   think Y2K was anticipated. */
	sprintf(s, "%2d%s%04d %2d:%02d",
		tm & 31,
		"m00\0jan\0feb\0mar\0apr\0may\0jun\0jul\0aug\0sep\0oct\0nov\0dec\0m13\0m14\0m15" +
			(((tm & 511) >> 3) & 0x3c),
		((tm & 65535) >> 9) + 1900,
		(tm >> 24) & 255,
		(tm >> 16) & 255);

#endif
	/* do not show time if the time is zero. */
	if ((tm & 0xffff0000) == 0) s[9] = 0;
}

void prodos_pretty_header(FILE *fp, struct prodos_dir *dir)
{
	if (dir) fprintf(fp, "\n%s\n", dir->dirname);
	fprintf(fp, "\n NAME           TYPE  BLOCKS  MODIFIED         CREATED          ENDFILE SUBTYPE\n\n");
}

void prodos_pretty_dir(FILE *fp, struct prodos_file_info *sbuf)
{
char lock;
char type[4];
char auxtype[16];
char cre_t[20];
char mod_t[20];

	lock = ' ';
	if ((sbuf->access & 0xc3) != 0xc3) lock = '*';

	if (sbuf->file_type == 1) strcpy(type, "BAD");
	else if (sbuf->file_type == 4) strcpy(type, "TXT");
	else if (sbuf->file_type == 6) strcpy(type, "BIN");
	else if (sbuf->file_type == 15) strcpy(type, "DIR");
	else if (sbuf->file_type == 0xb0) strcpy(type, "SRC");
	else if (sbuf->file_type == 0xb1) strcpy(type, "OBJ");
	else if (sbuf->file_type == 0xb3) strcpy(type, "S16");
	else if (sbuf->file_type == 0xb5) strcpy(type, "EXE");
	else if (sbuf->file_type == 0xe0) strcpy(type, "SHK");
	else if (sbuf->file_type == 0xfc) strcpy(type, "BAS");
	else if (sbuf->file_type == 0xff) strcpy(type, "SYS");
	else sprintf(type, "$%02x", sbuf->file_type);

	if (sbuf->file_type == 4) {
		sprintf(auxtype, "R=%5d", sbuf->aux_type);
	} else if (sbuf->file_type == 6) {
		if (sbuf->aux_type)
			sprintf(auxtype, "A=$%04x", sbuf->aux_type);
		else	auxtype[0] = 0;
	} else {
		auxtype[0] = 0;
	}

	prodos_pretty_time(mod_t, sbuf->modification);
	prodos_pretty_time(cre_t, sbuf->creation);

	fprintf(fp, "%c%-15s %s  %6d  %-15s  %-15s %8d %s\n",
		lock, sbuf->filename, type,
		sbuf->nblocks, mod_t, cre_t,
		sbuf->length, auxtype);
}

struct partition_map *partition_map_fromimage(struct diskimage *im)
{
struct partition_map *new;
unsigned char *block;
int blocksize, offset;

	if (!(block = diskimage_block(im, 0))) return NULL;
	if ((block[0] != 0x45) || (block[1] != 0x52)) {
		diskimage_freeblock(im, block);
		goto notfound;
	}
	blocksize = (block[2] << 8) | block[3];

	diskimage_freeblock(im, block);

	/* read the first entry */

	if (!(block = diskimage_block(im, blocksize/512))) return NULL;
	offset = blocksize % 512;
	if ((block[offset] != 0x50) || (block[offset+1] != 0x4d)) {
		diskimage_freeblock(im, block);
		goto notfound;
	}
	if (memcmp(block + offset + 48,
		"Apple_Partition_Map\0\0\0\0\0\0\0\0\0\0\0\0\0", 32)) {
			diskimage_freeblock(im, block);
			goto notfound;
	}

	/* looks valid */

	if (!(new = malloc(sizeof(*new)))) {
		diskimage_freeblock(im, block);
		return NULL;
	}

	new->im = im;
	new->blocksize = blocksize;
	new->map_count = (block[offset + 4] << 24) | (block[offset + 5] << 16) |
		(block[offset + 6] << 8) | block[offset + 7];
	new->start_block = (block[offset + 8] << 24) | (block[offset + 9] << 16) |
		(block[offset + 10] << 8) | block[offset + 11];
	new->block_count = (block[offset + 12] << 24) | (block[offset + 13] << 16) |
		(block[offset + 14] << 8) | block[offset + 15];
	new->data_start = (block[offset + 80] << 24) | (block[offset + 81] << 16) |
		(block[offset + 82] << 8) | block[offset + 83];
	new->data_count = (block[offset + 84] << 24) | (block[offset + 85] << 16) |
		(block[offset + 86] << 8) | block[offset + 87];

	diskimage_freeblock(im, block);
	return new;

notfound:
	fprintf(stderr, "partition_map_fromimage: image does not contain a partition map\n");
	return NULL;
}

void partition_map_print(struct partition_map *pm, FILE *fp)
{
int i;
int offset;
unsigned char *block;
char name[33];
char type[33];
int length;
int base;

	fprintf(fp, "map block size=%d\n", pm->blocksize);
	fprintf(fp, "   #:                 type name                 length   base     ( size )\n");
	for (i = 0; i < pm->map_count; i++) {
		if (!(block = diskimage_block(pm->im, (i+1)*(pm->blocksize)/512))) {
			fprintf(stderr, "partition_map_print: cannot read block %d\n",
				(i+1)*(pm->blocksize)/512);
			continue;
		}
		offset = ((i+1)*(pm->blocksize)) % 512;

		memcpy(name, block + offset + 16, 32);
		name[32] = 0;
		memcpy(type, block + offset + 48, 32);
		type[32] = 0;

		base = (block[offset + 8] << 24) | (block[offset + 9] << 16) |
			(block[offset + 10] << 8) | block[offset + 11];
		length = (block[offset + 12] << 24) | (block[offset + 13] << 16) |
			(block[offset + 14] << 8) | block[offset + 15];

		fprintf(fp, "%4d: %20s %-19s %7d @ %d\n", i+1, type, name, length, base);

		diskimage_freeblock(pm->im, block);
	}
}

struct diskimage *partition_map_getpartition(struct partition_map *pm, int partnum)
{
unsigned char *block;
int length, abs_length;
int base, abs_base;
int offset;

	if ((partnum < 1) || (partnum > (pm->map_count))) {
		fprintf(stderr, "partition_map_getpartition: partition number %d out of range\n", partnum);
		return NULL;
	}

	if (!(block = diskimage_block(pm->im, partnum*(pm->blocksize)/512))) {
		fprintf(stderr, "partition_map_getpartition: cannot read block %d\n",
			partnum*(pm->blocksize)/512);
		return NULL;
	}
	offset = (partnum*(pm->blocksize)) % 512;

	base = (block[offset + 8] << 24) | (block[offset + 9] << 16) |
		(block[offset + 10] << 8) | block[offset + 11];
	length = (block[offset + 12] << 24) | (block[offset + 13] << 16) |
		(block[offset + 14] << 8) | block[offset + 15];

	/* blocksize for diskimage is 512; blocksize of the units we have
	   here is variable (though normally it's 512) */
	abs_base = base * (pm->blocksize)/512;
	abs_length = length * (pm->blocksize)/512;

	if (((base * (pm->blocksize)) % 512) || ((length * (pm->blocksize)) % 512)) {
		fprintf(stderr, "partition_map_getpartition: partition blocksizes are not compatible (software limitation)\n");
		return NULL;
	}

	return diskimage_makesub(pm->im, abs_base, abs_length);
}

void usage(char *a0)
{
	fprintf(stderr,
		"Usage: %s -i image [-p partition_number] command [args]\n"
		"commands: ls [pathname]    short filename listing\n"
		"          dir [pathname]   long filename listing\n"
		"          cat pathname     dump data fork\n"
		"          rcat pathname    dump resource fork\n"
		"          volume           show volume information\n"
		"          partitions       show partition table\n",
		a0);
}

time_t apple_to_unix_time(unsigned int appletime)
{
struct tm tmb;
time_t result;

	if (appletime == 0) return 0;
	tmb.tm_sec = 0;
	tmb.tm_min = (appletime >> 16) & 255;
	tmb.tm_hour = (appletime >> 24) & 255;
	tmb.tm_mday = appletime & 31;
	tmb.tm_mon = ((appletime & 511) >> 5) - 1;
	tmb.tm_year = (appletime & 65535) >> 9;
	tmb.tm_isdst = -1; /* guess */

	result = mktime(&tmb);
	if ((result == -1) && (tmb.tm_year < 69)) {
		/* if the year is very low (less than 1969) then maybe
		   we cannot represent it anyway; maybe we can guess
		   that it is off by 100 years and maybe represent it
		   and maybe it will even be correct due to having
		   unwittingly compensated for Y2K problems */
		tmb.tm_year += 100;
		result = mktime(&tmb);
	}
	if (result == -1) {
		return 0;
	} else {
		return result;
	}
}

int tar_dumpblock(struct tarblock *tbb)
{
int i, offset;

	offset = 0;
	while (offset < 10240) {
		i = write(1, tbb->data + offset, 10240 - offset);
		if (i <= 0) return i;
		offset += i;
	}
	memset(tbb, 0, sizeof(*tbb));
	return 10240;
}

int tar_writeblock(unsigned char *block, struct tarblock *tbb)
{
	memcpy(tbb->data + (tbb->count * 512), block, 512);
	tbb->count++;
	if (tbb->count == 20) return tar_dumpblock(tbb);
	return 0;
}

int maketar2(struct prodos_fs *fs, struct prodos_file_info *sbuf, char *ext_name, struct tarblock *tbb)
{
unsigned char tarblock[512];
unsigned char datablock[512];
int ext_namelen;
int mode, i, sum;
unsigned int length;
struct prodos_dir *dir;
struct prodos_file *pfile;
int non_fatal_error = 0;

	memset(tarblock, 0, 512);
	ext_namelen = strlen(ext_name);
	if (sbuf->storage_type == 13) {
		if (ext_namelen == 0) {
			strcpy(ext_name, "./");
			ext_namelen = 2;
		} else {
			if (ext_name[ext_namelen-1] != '/') {
				ext_name[ext_namelen++] = '/';
				ext_name[ext_namelen] = 0;
			}
		}
	}

	if (ext_namelen > 255) {
		fprintf(stderr, "maketar: pathname too long, skipping %s\n", ext_name);
		return -2;
	}
	if (ext_namelen > 100) {
		memcpy(tarblock + 345, ext_name, ext_namelen-100);
		memcpy(tarblock, ext_name, 100);
	} else {
		memcpy(tarblock, ext_name, ext_namelen);
	}

	mode = 0;
	if (sbuf->access & 1) mode |= 0444; /* read enable */
	if (sbuf->access & 2) mode |= 0222; /* write enable */
	/* ignore delete and rename enable */
	if ((sbuf->storage_type == 13) &&
		(sbuf->access & 1)) mode |= 0111; /* search for directories */
	if ((sbuf->file_type == 0xb3) || (sbuf->file_type == 0xff) ||
		(sbuf->file_type == 0xb5)) {
			mode |= 0111; /* executable file types */
	}

	if (sbuf->storage_type == 5) {
		if (prodos_extended_stat(fs, sbuf) < 0) {
			fprintf(stderr, "maketar: prodos_extended_stat %s failed, skipping\n", ext_name);
			return -2;
		}
		length = sbuf->data_length;
	} else {
		length = sbuf->length;
	}

	sprintf(tarblock+100, "%07o", mode);
	sprintf(tarblock+108, "%07o", 0 /* uid */);
	sprintf(tarblock+116, "%07o", 0 /* gid */);
	sprintf(tarblock+124, "%011o", (sbuf->storage_type == 13) ? 0 : length);
	sprintf(tarblock+136, "%011lo", 
		apple_to_unix_time(sbuf->modification ? sbuf->modification : sbuf->creation));
	memcpy(tarblock+148, "        ", 8); /* checksum */

	if (sbuf->storage_type == 13) tarblock[156] = '5'; /* directory type */
	else tarblock[156] = '0';

	memcpy(tarblock+257, "ustar  ", 8); /* magic */

	/* username goes at 265, groupname goes at 297, both are length 32 */

	sprintf(tarblock+329, "%07o", 0 /* device major */);
	sprintf(tarblock+337, "%07o", 0 /* device minor */);

	/* calculate the checksum */
	for (i = sum = 0; i < 512; i++) sum += tarblock[i];
	/* and stick it in */
	sprintf(tarblock+148, "%07o", sum);

	if (sbuf->storage_type == 13) {
		if (tar_writeblock(tarblock, tbb) < 0) {
			fprintf(stderr, "maketar: error writing tar header block: %s\n", strerror(errno));
			return -1;
		}

		if (dir = prodos_opendir_atblock(fs, sbuf->key_pointer)) {
			while (prodos_readdir(dir, sbuf) == 1) {
				strcpy(ext_name + ext_namelen, sbuf->filename);
				if ((i = maketar2(fs, sbuf, ext_name, tbb)) == -1) {
					prodos_closedir(dir);
					return -1;
				}
				if (i == -2) non_fatal_error = 1;
				ext_name[ext_namelen] = 0;
			}
			prodos_closedir(dir);
		} else {
			fprintf(stderr, "maketar: prodos_opendir %s failed, skipping\n", ext_name);
			return -2;
		}
	} else {
		/* dump file contents */

		if (!(pfile = prodos_open_statbuf(fs, sbuf, 0))) {
			fprintf(stderr, "maketar: prodos_open %s failed, skipping\n", ext_name);
			return -2;
		}

		/* try reding the file once through first. This is so that in case we
		   have trouble reading it, we can safely skip before its tar header has
		   been output */
		for (;;) {
			if ((i = prodos_read(pfile, datablock, 512)) < 0) {
				fprintf(stderr, "maketar: prodos_read %s: %s, skipping\n", ext_name, strerror(errno));
				prodos_close(pfile);
				return -2;
			}
			if (i <= 0) break;
		}
		prodos_close(pfile);

		/* now that we know we can read it, dump its header */
		if (tar_writeblock(tarblock, tbb) < 0) {
			fprintf(stderr, "maketar: error writing tar header block: %s\n", strerror(errno));
			prodos_close(pfile);
			return -1;
		}

		if (!(pfile = prodos_open_statbuf(fs, sbuf, 0))) {
			fprintf(stderr, "maketar: prodos_open %s failed\n", ext_name);
			return -1;
		}

		for (;;) {
			memset(tarblock, 0, 512);
			if ((i = prodos_read(pfile, tarblock, 512)) < 0) {
				fprintf(stderr, "maketar: prodos_read %s: %s\n", ext_name, strerror(errno));
				prodos_close(pfile);
				return -1;
			}
			if (i <= 0) break;

			if (tar_writeblock(tarblock, tbb) < 0) {
				fprintf(stderr, "maketar: error writing tar data block: %s\n", strerror(errno));
				prodos_close(pfile);
				return -1;
			}
		}
		prodos_close(pfile);
	}

	return non_fatal_error ? -2 : 0;
}

int maketar(struct prodos_fs *fs, char *path)
{
int err, err2;
struct prodos_file_info sbuf;
char ext_name[300]; /* must be big enough to overflow by one maximum filename length plus one or two */
struct tarblock tarbigblock;

	if ((err = prodos_stat(fs, path, &sbuf)) != 0) {
		fprintf(stderr, "maketar: prodos_stat %s failed: %s\n", path, strerror(err));
		return -1;
	}

	sprintf(ext_name, "%s/", sbuf.filename);

	memset(&tarbigblock, 0, sizeof(tarbigblock));

	err = maketar2(fs, &sbuf, ext_name, &tarbigblock);

	if (tarbigblock.count) {
		err2 = tar_dumpblock(&tarbigblock);
		if (err >= 0) return err2;
	}
	return err;
}

int main(int argc, char **argv)
{
struct diskimage *rawf, *part1;
struct prodos_fs *fs;
struct prodos_dir *dir;
struct prodos_file *pfile;
struct prodos_file_info sbuf;
struct partition_map *pm;
int i, j;
int partno = 0;
int errexit = 0;
char *image_name = NULL;

	while ((i = getopt(argc, argv, "i:p:")) != EOF) {
		switch (i) {
			case 'i':
				image_name = optarg;
				break;
			case 'p':
				partno = atoi(optarg);
				if (!partno) {
					fprintf(stderr, "%s: -p argument must be >= 1\n", argv[0]);
					usage(argv[0]);
					return 1;
				}
				break;
		}
	}
	if (!image_name) {
		fprintf(stderr, "%s: -i (image filename) required\n", argv[0]);
		usage(argv[0]);
		return 1;
	}

	rawf = diskimage_fromfile(image_name);
	if (!rawf) return 2;

	/* special case the partitions command here, it is the only one
	   that does not require successfully opening the filesystem */
	if ((argc >= optind) && (!strcmp(argv[optind], "partitions"))) {
		pm = partition_map_fromimage(rawf);
		if (!pm) return 2;
		partition_map_print(pm, stdout);
		return 0;
	}

	if (partno) {
		pm = partition_map_fromimage(rawf);
		if (!pm) return 2;

		part1 = partition_map_getpartition(pm, partno);
		if (!part1) return 2;
	} else {
		/* treat it as a floppy image or something that has the
		   filesystem straight on it */
		part1 = rawf;
	}
	if (fs = prodos_openfs(part1)) {
		if (argc > 1) {
			if (!strcmp(argv[optind], "ls")) {
				i = prodos_stat(fs, (argc > (optind+1)) ? argv[optind+1] : "", &sbuf);
				if ((i == 0) && (sbuf.storage_type == 13)) {
					if (dir = prodos_opendir(fs, (argc > (optind+1)) ? argv[optind+1] : "")) {
						while ((i = prodos_readdir(dir, &sbuf)) == 1) {
							fprintf(stdout, "%s\n", sbuf.filename);
						}
						prodos_closedir(dir);
					} else {
						errexit = 2;
					}
				} else if (i == 0) {
					fprintf(stdout, "%s\n", (argc > (optind+1)) ? argv[optind+1] : ".");
				} else {
					fprintf(stderr, "%s: %s\n", (argc > (optind+1)) ? argv[optind+1] : "", strerror(i));
					errexit = 1;
				}
			} else if (!strcmp(argv[optind], "dir")) {
				i = prodos_stat(fs, (argc > (optind+1)) ? argv[optind+1] : "", &sbuf);
				if ((i == 0) && (sbuf.storage_type == 13)) {
					if (dir = prodos_opendir(fs, (argc > (optind+1)) ? argv[optind+1] : "")) {
						prodos_pretty_header(stdout, dir);
						while ((i = prodos_readdir(dir, &sbuf)) == 1) {
							prodos_pretty_dir(stdout, &sbuf);
						}
						prodos_closedir(dir);
						fprintf(stdout, "\n");
					} else {
						errexit = 2;
					}
				} else if (i == 0) {
					prodos_pretty_header(stdout, NULL);
					prodos_pretty_dir(stdout, &sbuf);
					fprintf(stdout, "\n");
				} else {
					fprintf(stderr, "%s: %s\n", (argc > (optind+1)) ? argv[optind+1] : "", strerror(i));
					errexit = 1;
				}
			} else if (!strcmp(argv[optind], "volume")) {
				fprintf(stdout, "volume name is %s\n", fs->volname);
			} else if (!strcmp(argv[optind], "tar")) {
				if (maketar(fs, (argc > (optind+1)) ? argv[optind+1] : "") < 0) errexit = 2;
			} else if ((!strcmp(argv[optind], "cat")) || (!strcmp(argv[optind], "rcat"))) {
				if (argc > (optind+1)) {
					if (pfile = prodos_open(fs, argv[optind+1], (argv[optind][0] == 'r') ? 1 : 0)) {
						char buf[4096];

						while ((i = prodos_read(pfile, buf, sizeof(buf))) > 0) {
							j = write(1, buf, i);
							if (j != i) {
								fprintf(stderr, "%s: write error", argv[0]);
								errexit = 3;
							}
						}
						if (i < 0) {	
							fprintf(stderr, "%s: prodos_read %s: %s\n", argv[0], argv[2], strerror(errno));
							errexit = 2;
						}
						prodos_close(pfile);
					} else {
						errexit = 2;
					}
				} else {
					fprintf(stderr, "Usage: %s cat pathname\n", argv[0]);
				}
			} else {
				usage(argv[0]);
				errexit = 1;
			}
		}
		prodos_closefs(fs);
	} else {
		errexit = 2;
	}
	diskimage_close(part1);
	if (part1 != rawf) diskimage_close(rawf);
	return errexit;
}
