// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#define _GNU_SOURCE
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/lsn.h"
#include "../common/common.h"
#include "../utilities/list.h"
#include "device_structures.h"
#include "djb2.h"
#include "mem_structures.h"
#include "region_log.h"
#include "volume_manager.h"

#include <assert.h>
#include <fcntl.h>
#include <log.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>
#include <uthash.h>

/*from this address any node can see the entire volume*/
uint64_t MAPPED = 0;
int FD = -1;

/*<new_persistent_design>*/
#define MEM_LOG_WORD_SIZE_IN_BITS 8
#define MEM_MAX_VOLUME_NAME_SIZE 256

static struct volume_map_entry *volume_map = NULL;
struct klist *volume_list = NULL;
struct volume_map_entry {
	char volume_name[MEM_MAX_VOLUME_NAME_SIZE];
	struct volume_descriptor *volume_desc;
	uint64_t hash_key;
	UT_hash_handle hh;
};
/*</new_persistent_design>*/

off64_t mount_volume(char *volume_name, int64_t start, int64_t unused_size)
{
	(void)unused_size;
	off64_t device_size = 0;

	static pthread_mutex_t VOLUME_LOCK = PTHREAD_MUTEX_INITIALIZER;
	MUTEX_LOCK(&VOLUME_LOCK);

#if !ALLOW_RAW_VOLUMES
	if (strlen(volume_name) >= 5 && strncmp(volume_name, "/dev/", 5) == 0) {
		log_fatal("Volume is a raw device %s current version does not support it!", volume_name);
		BUG_ON();
	}
#endif

	if (MAPPED == 0) {
		log_debug("Opening Volume %s", volume_name);
		/* open the device */
		FD = open(volume_name, O_RDWR | O_DIRECT | O_DSYNC);
		if (FD < 0) {
			log_fatal("Failed to open %s", volume_name);
			perror("Reason:\n");
			BUG_ON();
		}

		device_size = lseek64(FD, 0, SEEK_END);
		log_debug("Found device of %ld bytes", device_size);
		if (device_size == -1) {
			log_fatal("failed to determine volume size exiting...");
			perror("ioctl");
			BUG_ON();
		}

		if (device_size < MIN_VOLUME_SIZE) {
			log_fatal("Sorry minimum supported volume size is %ld GB actual size %ld GB",
				  MIN_VOLUME_SIZE / (1024 * 1024 * 1024), device_size / (1024 * 1024 * 1024));
			BUG_ON();
		}

		log_debug("Creating virtual address space offset %lld size %ld\n", (long long)start, device_size);
		/*mmap the device*/

		char *addr_space = NULL;

		addr_space = mmap(NULL, device_size, PROT_READ, MAP_SHARED, FD, start);

		if (addr_space == MAP_FAILED) {
			log_fatal("MMAP for device %s reason follows", volume_name);
			perror("Reason for mmap");
			BUG_ON();
		}

		MAPPED = (uint64_t)addr_space;
		madvise((void *)MAPPED, device_size, MADV_RANDOM);

		if (MAPPED % sysconf(_SC_PAGE_SIZE) != 0) {
			log_fatal("Mapped address not aligned correctly mapped: %llu", (long long unsigned)MAPPED);
			BUG_ON();
		}
	}

	MUTEX_UNLOCK(&VOLUME_LOCK);
	return device_size;
}

static uint8_t init_db_superblock(struct pr_db_superblock *db_superblock, const char *db_name, uint32_t db_name_size,
				  uint32_t db_id)
{
	if (db_name_size > MAX_DB_NAME_SIZE)
		return 0;
	memset(db_superblock, 0x00, sizeof(struct pr_db_superblock));
	memcpy(db_superblock->db_name, db_name, db_name_size);
	db_superblock->db_name_size = db_name_size;
	db_superblock->id = db_id; //in the array
	db_superblock->valid = 1;
	reset_lsn(&db_superblock->last_lsn);
	return 1;
}

#if 0
static void print_allocation_type(enum rul_op_type type)
{
	switch (type) {
	case REGL_ALLOCATE:
		log_info("REGL_ALLOCATE");
		break;
	case REGL_LOG_ALLOCATE:
		log_info("REGL_LOG_ALLOCATE");
		break;
	case REGL_FREE:
		log_info("REGL_FREE");
		break;
	case REGL_LOG_FREE:
		log_info("REGL_LOG_FREE");
		break;
	case REGL_COMMIT:
		log_info("REGL_COMMIT");
		break;
	default:
		log_fatal("Corrupted operation type %d", type);
		BUG_ON();
	}
}
#endif

static void apply_db_allocations_to_allocator_bitmap(struct volume_descriptor *volume_desc, const uint8_t *mem_bitmap,
						     int mem_bitmap_size)
{
	/* 0 --> in use
   * 1  --> free
   */
	char *volume_allocator_bitmap = (char *)volume_desc->mem_volume_bitmap;
	int volume_allocator_size = volume_desc->mem_volume_bitmap_size * sizeof(uint64_t);

	if (volume_allocator_size != mem_bitmap_size) {
		log_fatal("Bitmaps of allocator and db differ in size");
		assert(0);
		BUG_ON();
	}

	for (int byte = 0; byte < volume_allocator_size; ++byte) {
		for (uint8_t bit_id = 0; bit_id < 8; ++bit_id) {
			uint8_t db_bit_value = GET_BIT(mem_bitmap[byte], bit_id);
			if (!db_bit_value) {
				/*Check if there is conflict. If yes we have corruption since two dbs claim space as theirs*/
				uint8_t allocator_bit_value = GET_BIT(volume_allocator_bitmap[byte], bit_id);
				if (!allocator_bit_value) {
					log_fatal("Corruption multiple DBs claim ownership of the same segment !");
					BUG_ON();
				}
				CLEAR_BIT(&volume_allocator_bitmap[byte], bit_id);
			}
		}
	}
}

void replay_db_allocation_log(struct volume_descriptor *volume_desc, struct pr_db_superblock *superblock)
{
	uint32_t mem_bitmap_size = volume_desc->mem_volume_bitmap_size * sizeof(uint64_t);
	uint8_t *mem_bitmap = malloc(mem_bitmap_size);

	/*DBs view of the volume initally everything as don't know not mine*/
	memset(mem_bitmap, 0xFF, mem_bitmap_size);
	struct pr_region_allocation_log *allocation_log = &superblock->allocation_log;
	(void)allocation_log;
	/* log_info("Allocation log of DB: %s head %lu tail %lu size %lu", superblock->db_name, */
	/* 	 allocation_log->head_dev_offt, allocation_log->tail_dev_offt, allocation_log->size); */

	struct regl_cursor *log_cursor = regl_cursor_init(volume_desc, superblock);
	struct regl_log_entry *log_entry;

	while ((log_entry = regl_cursor_get_next(log_cursor))) {
		uint64_t bit_distance = log_entry->dev_offt / SEGMENT_SIZE;
		uint64_t byte_id = bit_distance / 8;
		uint8_t bit_id = bit_distance % 8;
		/*print_allocation_type(log_entry->op_type);*/

		switch (log_entry->op_type) {
		case REGL_LARGE_LOG_ALLOCATE:
		case REGL_MEDIUM_LOG_ALLOCATE:
		case REGL_SMALL_LOG_ALLOCATE:
		case REGL_ALLOCATE_SST:
		case REGL_ALLOCATE:
			//log_info("Marking dev_offt: %llu as RESERVED txn_id: %llu", log_entry->dev_offt,
			//	 log_entry->txn_id);
			CLEAR_BIT(&mem_bitmap[byte_id], bit_id);
			break;

		case REGL_LOG_FREE:
		case REGL_FREE:
		case REGL_FREE_SST:
			//log_info("Marking dev_offt: %llu as FREE txn_id: %llu", log_entry->dev_offt, log_entry->txn_id);
			SET_BIT(&mem_bitmap[byte_id], bit_id);
			break;
		case BLOB_GARBAGE_BYTES:
			break;
		default:
			log_fatal("Unknown/Corrupted entry in allocation log try type is: %d", log_entry->op_type);
			log_fatal("Head off = %lu Tail = %lu cur = %lu chunk_id %u entry %u segment id %lu",
				  allocation_log->head_dev_offt, allocation_log->tail_dev_offt,
				  ABSOLUTE_ADDRESS(log_cursor->segment), log_cursor->curr_chunk_id,
				  log_cursor->curr_entry_in_chunk, log_cursor->segment->segment_id);
			BUG_ON();
		}
	}

	regl_close_cursor(log_cursor);
	apply_db_allocations_to_allocator_bitmap(volume_desc, mem_bitmap, mem_bitmap_size);
	free(mem_bitmap);
}

static void recover_allocator_bitmap(struct volume_descriptor *volume_desc)
{
	/*Iterate and replay all dbs allocation log info*/
	uint32_t max_regions = volume_desc->vol_superblock.max_regions_num;

	for (uint32_t i = 0; i < max_regions; ++i) {
		if (volume_desc->pr_regions->db[i].valid) {
			log_debug("Replaying allocation log for DB: %s", volume_desc->pr_regions->db[i].db_name);
			replay_db_allocation_log(volume_desc, &volume_desc->pr_regions->db[i]);
		}
	}
}

struct pr_db_superblock *get_db_superblock(struct volume_descriptor *volume_desc, const char *db_name,
					   uint32_t db_name_size, uint8_t allocate, uint8_t *new_db)
{
	*new_db = 0;
	MUTEX_LOCK(&volume_desc->db_array_lock);
	struct pr_db_superblock *db = NULL;
	int next_free_db_id = -1;
	//search superblock array in the start of the volume
	for (uint32_t i = 0; i < volume_desc->pr_regions->size; ++i) {
		if (!volume_desc->pr_regions->db[i].valid) {
			if (-1 == next_free_db_id)
				next_free_db_id = i;
			continue;
		}

		if (volume_desc->pr_regions->db[i].db_name_size == db_name_size) {
			if (memcmp(volume_desc->pr_regions->db[i].db_name, db_name, db_name_size) == 0) {
				/* DB Found*/
				log_debug("Found region %s at index %u of the region superblock array",
					  volume_desc->pr_regions->db[i].db_name, i);
				db = &volume_desc->pr_regions->db[i];
				goto exit;
			}
		}
	}

	if (allocate) {
		if (next_free_db_id >= 0) {
			*new_db = 1;
			init_db_superblock(&volume_desc->pr_regions->db[next_free_db_id], db_name, db_name_size,
					   next_free_db_id);
			db = &volume_desc->pr_regions->db[next_free_db_id];
			goto exit;
		}
		log_warn("No more space for new regions!");
	}
	db = NULL;
exit:
	MUTEX_UNLOCK(&volume_desc->db_array_lock);
	return db;
}

static struct mem_bitmap_word mem_bitmap_get_curr_word(const struct volume_descriptor *volume_desc)
{
	return volume_desc->curr_word;
}

static void mem_bitmap_reset_pos(struct volume_descriptor *volume_desc)
{
	volume_desc->curr_word.word_id = 0;
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_addr = volume_desc->mem_volume_bitmap;
}

static struct mem_bitmap_word mem_bitmap_get_next_word(struct volume_descriptor *volume_desc)
{
	struct mem_bitmap_word ret = { .word_id = -1, .word_addr = NULL };

	if (++volume_desc->curr_word.word_id >= volume_desc->mem_volume_bitmap_size) {
		// sorry end of bitmap
		return ret;
	}
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_addr = &volume_desc->mem_volume_bitmap[volume_desc->curr_word.word_id];
	return mem_bitmap_get_curr_word(volume_desc);
}

static uint32_t mem_bitmap_check_first_n_bits_free(struct mem_bitmap_word *b_word, uint32_t length_bits,
						   uint32_t suffix_bits)
{
	uint64_t mask = 0xFFFFFFFFFFFFFFFF;
	int actual_bits;
	if (length_bits - suffix_bits > MEM_WORD_SIZE_IN_BITS) {
		actual_bits = MEM_WORD_SIZE_IN_BITS;
	} else {
		actual_bits = length_bits - suffix_bits;
		uint32_t diff = MEM_WORD_SIZE_IN_BITS - actual_bits;
		if (diff < MEM_WORD_SIZE_IN_BITS)
			mask = mask >> diff;
		else {
			log_fatal("Wrong sliding number!");
			BUG_ON();
		}
	}
	if (mask == (mask & *b_word->word_addr)) {
		b_word->start_bit = 0;
		b_word->end_bit = actual_bits;
		// log_info("Found First %u bits of word %d in buddy %d", actual_bits,
		// b_word->word_id,
		//	 b_word->buddy_pair);
		return actual_bits;
	}
	// log_info("Not Found First %u bits of word %d in buddy %d", actual_bits,
	// b_word->word_id,
	//	 b_word->buddy_pair);
	return 0;
}

static uint32_t mem_bitmap_find_suffix(struct mem_bitmap_word *b_word, const uint64_t *rounds, int num_rounds)
{
	uint64_t mask = 0x8000000000000000;
	uint32_t size_bits = 0;
	int L = num_rounds;
	uint64_t b = 1;
	// log_info("Suffix search: num rounds are %d", num_rounds);
	do {
		if (mask & (rounds[L] << size_bits)) {
			size_bits += (b << L);
			// log_info("Suffix now is %u L = %d rounds %llu", size_bits, L,
			// rounds[L]);
		}
		--L;
	} while (L >= 0);

	if (size_bits) {
		b_word->start_bit = MEM_WORD_SIZE_IN_BITS - size_bits;
		b_word->end_bit = MEM_WORD_SIZE_IN_BITS;
		// log_info("Suffix search size found is %u", size_bits);
		return size_bits;
	}
	// log_info("Sorry no suffix found");
	return 0;
}

static uint32_t mem_bitmap_find_nbits_in_word(struct mem_bitmap_word *b_word, uint64_t *round, uint32_t *num_rounds,
					      uint32_t length_bits)
{
	uint32_t actual_bits;
	if (length_bits > MEM_WORD_SIZE_IN_BITS)
		actual_bits = MEM_WORD_SIZE_IN_BITS;
	else
		actual_bits = length_bits;

	// log_info("Checking if word %u contains bits %u", b_word->word_id,
	// actual_bits);

	uint32_t m_rounds;
	// calculare upper integral part of log2
	double r = log2(actual_bits);
	m_rounds = (uint64_t)r;
	// check if we have decimal points
	if (floor(r) != r)
		++m_rounds;
	assert(m_rounds + 1 < *num_rounds);
	*num_rounds = m_rounds;
	// log_info("Num rounds are %u", *num_rounds);
	int shift_size = 1;

	// Our guard

	round[0] = *b_word->word_addr;
	// log_info("Round [0] bitmap is %llu",round[0]);
	for (uint32_t i = 0; i < *num_rounds; ++i) {
		if (i == 0)
			shift_size = 1;
		else if (i == *num_rounds - 1)
			shift_size = actual_bits - (shift_size * 2);
		else
			shift_size *= 2;
		// log_info("Shift size %u", shift_size);
		uint64_t c = round[i] << shift_size;
		round[i + 1] = round[i] & c;
	}

	// did we find size or WORD_SIZE bits?
	if (round[*num_rounds] != 0) {
		b_word->end_bit = ffsl(round[*num_rounds]);
		b_word->start_bit = b_word->end_bit - actual_bits;
		// log_info("Yes it does! end bit is %u round is %llu", b_word->end_bit,
		// round[*num_rounds]);

		return actual_bits;
	}
	return 0;
}

static void mem_bitmap_mark_reserved(struct mem_bitmap_word *b_word)
{
	uint8_t *word_byte = (uint8_t *)b_word->word_addr;
	for (uint32_t bit = b_word->start_bit; bit < b_word->end_bit; ++bit) {
		uint32_t i = bit / 8;
		uint32_t j = bit % 8;
		CLEAR_BIT(&word_byte[i], j);
	}

	return;
}

static uint64_t mem_bitmap_translate_word_to_offt(struct volume_descriptor *volume_desc,
						  const struct mem_bitmap_word *b)
{
	(void)volume_desc;

	if (!b) {
		log_fatal("Null word!");
		assert(0);
		BUG_ON();
	}

	// log_info("Word is %u start bit %u end bit %u", b->word_id, b->start_bit,
	// b->end_bit);
	uint64_t bytes_per_word = MEM_WORD_SIZE_IN_BITS * SEGMENT_SIZE * 1UL;
	uint64_t dev_offt = (bytes_per_word * b->word_id) + (b->start_bit * SEGMENT_SIZE);
	// dev_offt += volume_desc->my_superblock.volume_metadata_size;
	// log_info("Now is Dev offt = %llu volume_metadata_size %llu", dev_offt,
	//	 volume_desc->my_superblock.volume_metadata_size);
	return dev_offt;
}

uint64_t mem_allocate(struct volume_descriptor *volume_desc, uint64_t num_bytes)
{
	uint64_t base_addr = 0;
	MUTEX_LOCK(&volume_desc->bitmap_lock);
	// assert(num_bytes == SEGMENT_SIZE);
	if (num_bytes == 0) {
		base_addr = 0;
		assert(0);
		goto exit;
	}
	if (num_bytes % SEGMENT_SIZE != 0) {
		log_warn("Allocation size: %lu not a multiple of SEGMENT_SIZE: %lu", num_bytes, SEGMENT_SIZE);
		base_addr = 0;
		goto exit;
	}

	uint64_t length_bits = num_bytes / SEGMENT_SIZE;

	struct mem_bitmap_word *b_words = NULL;
	/*how many words will i need?*/
	uint32_t alloc_size;

	if (length_bits == 1)
		alloc_size = sizeof(struct mem_bitmap_word);
	else if (length_bits > 1 && length_bits < 64)
		alloc_size = sizeof(struct mem_bitmap_word) * 2;
	else
		alloc_size = ((length_bits / MEM_WORD_SIZE_IN_BITS) * sizeof(struct mem_bitmap_word)) +
			     (2 * sizeof(struct mem_bitmap_word));

	b_words = (struct mem_bitmap_word *)malloc(alloc_size);

	if (b_words == NULL) {
		log_fatal("Malloc failed out of memory");
		BUG_ON();
	}

	int32_t wrap_around = 0;
	int idx = -1;
	struct mem_bitmap_word b_word = mem_bitmap_get_curr_word(volume_desc);
	uint64_t suffix_bits = 0;

	while (suffix_bits < length_bits) {
		if (b_word.word_addr == NULL) {
			// reached end of bitmap
			if (wrap_around == MAX_ALLOCATION_TRIES) {
				log_warn("Volume %s out of space allocation request size was "
					 "%lu max_tries %d\n",
					 volume_desc->volume_name, num_bytes, MAX_ALLOCATION_TRIES);
				mem_bitmap_reset_pos(volume_desc);
				free(b_words);
				BUG_ON();
			}

			++wrap_around;
			if (volume_desc->max_suffix < suffix_bits) /*update max_suffix */
				volume_desc->max_suffix = suffix_bits;

			suffix_bits = 0; /*contiguous bytes just broke :-( */
			idx = -1; /*reset _counters*/
			// reset bitmap pos
			log_warn("\n*****\nEnd Of Bitmap, wrap around\n*****\n");
			mem_bitmap_reset_pos(volume_desc);
			b_word = mem_bitmap_get_curr_word(volume_desc);
			continue;
		} else if (*b_word.word_addr == 0) {
			/*update max_suffix*/
			if (volume_desc->max_suffix < suffix_bits)
				volume_desc->max_suffix = suffix_bits;
			// contiguous bytes just broke :-(
			suffix_bits = 0;
			// reset _counters
			idx = -1;
			b_word = mem_bitmap_get_next_word(volume_desc);
			continue;
		}

		// Are the first bits of word free
		uint32_t bits_found = mem_bitmap_check_first_n_bits_free(&b_word, length_bits, suffix_bits);

		if (bits_found) {
			b_words[++idx] = b_word;
			suffix_bits += bits_found;
			if (suffix_bits == length_bits)
				break; // we are done here

			b_word = mem_bitmap_get_next_word(volume_desc);
			continue;
		}

		// First high bits not 1
		idx = -1;
		uint64_t rounds[MEM_LOG_WORD_SIZE_IN_BITS * 2];
		uint32_t round_size = MEM_LOG_WORD_SIZE_IN_BITS * 2;
		bits_found = mem_bitmap_find_nbits_in_word(&b_word, rounds, &round_size, length_bits);
		// log_info("Bits found %u length_bits %u start bit %u end bit %u",
		// bits_found, length_bits, 	 b_word.start_bit, b_word.end_bit);

		if (bits_found == length_bits) {
			b_words[++idx] = b_word;
			break;
		}

		bits_found = mem_bitmap_find_suffix(&b_word, rounds, round_size);
		if (bits_found > 0) {
			b_words[++idx] = b_word;
			suffix_bits += bits_found;
		}
		b_word = mem_bitmap_get_next_word(volume_desc);
	}
	// mark the bitmap now, we have surely found something
	for (int i = 0; i <= idx; i++)
		mem_bitmap_mark_reserved(&b_words[i]);

	if (idx != -1) {
		base_addr = mem_bitmap_translate_word_to_offt(volume_desc, b_words);
		free(b_words);
	}
exit:
	MUTEX_UNLOCK(&volume_desc->bitmap_lock);
	return base_addr;
}

void mem_free_segment(struct volume_descriptor *volume_desc, uint64_t dev_offt)
{
	MUTEX_LOCK(&volume_desc->bitmap_lock);
	// distance of addr from bitmap end
	uint64_t distance_in_bits = dev_offt / SEGMENT_SIZE;
	struct mem_bitmap_word w;
	w.word_id = distance_in_bits / MEM_WORD_SIZE_IN_BITS;
	uint32_t bit_in_word = distance_in_bits % MEM_WORD_SIZE_IN_BITS;

	w.word_addr = &volume_desc->mem_volume_bitmap[w.word_id];
	uint8_t *word_byte = (uint8_t *)w.word_addr;
	int m_idx = bit_in_word / 8;
	int m_bit = bit_in_word % 8;
	SET_BIT(&word_byte[m_idx], m_bit);
	MUTEX_UNLOCK(&volume_desc->bitmap_lock);
}

void read_dev_offt_into_buffer(char *buffer, const uint32_t start, const uint32_t size, const off_t dev_offt,
			       const int fd, const char *error_message)
{
	(void)error_message;
	ssize_t bytes_read = start;

	while (bytes_read < size) {
		ssize_t bytes = pread(fd, &buffer[bytes_read], size - bytes_read, dev_offt + bytes_read);
		if (bytes == -1) {
			log_fatal("Failed to read, %s ,error code", error_message);
			perror("Error");
			assert(0);
			BUG_ON();
		}
		bytes_read += bytes;
	}
}

/**
 * Prints volume's superblock info
 */
static void mem_print_volume_info(struct superblock *superblock, char *volume_name)
{
	(void)superblock;
	(void)volume_name;
	log_debug("<Volume %s info>", volume_name);
	log_debug("Volume size in GB: %lu", superblock->volume_size / GB(1));
	log_debug("Able to host up to %u regions useful space in GB: %lu", superblock->max_regions_num,
		  (superblock->volume_size - (superblock->volume_metadata_size + superblock->unmappedSpace)) / GB(1));
	log_debug("Unmapped space %lu", superblock->unmappedSpace);
}

/**
 * Reads from device volume's region superblocks and keeps it in an in memory
 * array
 */
void mem_init_superblock_array(struct volume_descriptor *volume_desc)
{
	int ret = posix_memalign((void **)&volume_desc->pr_regions, ALIGNMENT_SIZE,
				 sizeof(struct pr_superblock_array) + (volume_desc->vol_superblock.max_regions_num *
								       sizeof(struct pr_db_superblock)));

	if (ret) {
		log_fatal("Failed to allocate regions array!");
		BUG_ON();
	}

	volume_desc->pr_regions->size = volume_desc->vol_superblock.max_regions_num;
	off64_t dev_offt = sizeof(struct superblock);
	uint32_t size = volume_desc->vol_superblock.max_regions_num * sizeof(struct pr_db_superblock);
	read_dev_offt_into_buffer((char *)volume_desc->pr_regions->db, 0, size, dev_offt, volume_desc->vol_fd,
				  "Failed to read volume's region superblocks");

	log_debug("Restored %s region superblocks in memory", volume_desc->volume_name);
}

/**
 * Recovers from the device all the info about this volume
 */
static volume_descriptor *mem_init_volume(char *volume_name)
{
	struct volume_descriptor *volume_desc = NULL;
	if (posix_memalign((void **)&volume_desc, ALIGNMENT_SIZE, sizeof(struct volume_descriptor))) {
		log_fatal("posix memalign failed");
		BUG_ON();
	}
	memset(volume_desc, 0x00, sizeof(struct volume_descriptor));

	volume_desc->volume_name = calloc(1, strlen(volume_name) + 1);
	if (!volume_desc->volume_name) {
		log_fatal("calloc failed");
		BUG_ON();
	}
	memcpy(volume_desc->volume_name, volume_name, strlen(volume_name));

	volume_desc->vol_fd = open(volume_name, O_RDWR | O_DIRECT | O_DSYNC);

	if (volume_desc->vol_fd < 0) {
		log_fatal("Failed to open %s", volume_name);
		perror("Reason:\n");
		BUG_ON();
	}
	// read volume superblock (accouning info into memory)
	char error_message[MAX_ERROR_MESSAGE_SIZE];
	snprintf(error_message, MAX_ERROR_MESSAGE_SIZE, "Failed to read volume's %s superblock", volume_name);
	read_dev_offt_into_buffer((char *)&volume_desc->vol_superblock, 0, sizeof(struct superblock), 0,
				  volume_desc->vol_fd, error_message);

	off64_t device_size = lseek64(volume_desc->vol_fd, 0, SEEK_END);
	if (device_size == -1) {
		log_fatal("failed to determine volume size exiting...");
		perror("ioctl");
		BUG_ON();
	}
	if ((uint64_t)device_size !=
	    volume_desc->vol_superblock.volume_size + volume_desc->vol_superblock.unmappedSpace) {
		log_fatal("Volume sizes do not match! Found %ld expected %ld", device_size,
			  volume_desc->vol_superblock.volume_size);
		BUG_ON();
	}

	if (volume_desc->vol_superblock.magic_number != FINE_STRUCTURE_CONSTANT) {
		log_fatal("Volume seems not to have been initialized!");
		BUG_ON();
	}
	volume_desc->mem_volume_bitmap_size = volume_desc->vol_superblock.bitmap_size_in_words;
	mem_print_volume_info(&volume_desc->vol_superblock, volume_name);
	/*Now allocate the in memory bitmap*/
	volume_desc->mem_volume_bitmap = malloc(volume_desc->mem_volume_bitmap_size * sizeof(uint64_t));
	/*set everything to 1 aka free aka don't know*/
	memset(volume_desc->mem_volume_bitmap, 0xFF, volume_desc->mem_volume_bitmap_size * sizeof(uint64_t));
	mem_init_superblock_array(volume_desc);

	volume_desc->curr_word.word_addr = volume_desc->mem_volume_bitmap;
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_id = 0;

	/*Mark as allocated volume's metadata*/
	uint32_t n_segments = volume_desc->vol_superblock.volume_metadata_size / SEGMENT_SIZE;
	uint64_t dev_offt = 0;

	for (uint32_t i = 0; i < n_segments; ++i)
		dev_offt = mem_allocate(volume_desc, SEGMENT_SIZE);
	/**
   * Last bits of bitmap are usually padded in order for the bitmap size to be
   * a multiple of 4 KB. As a results last bits of the bitmap may point to void
   * space. So we mark them as "reserved" so the allocator does not bother them.
   **/
	uint64_t registry_size_in_bits =
		(volume_desc->vol_superblock.volume_size - volume_desc->vol_superblock.unmappedSpace) / SEGMENT_SIZE;
	uint32_t bits_in_page = 4096 * 8;
	uint32_t unmapped_bits = 0;

	if (registry_size_in_bits % bits_in_page) {
		unmapped_bits = (bits_in_page - (registry_size_in_bits % bits_in_page));
		registry_size_in_bits += unmapped_bits;
	}

	if (registry_size_in_bits % bits_in_page) {
		log_fatal("ownership registry must be a multiple of 4 KB its value %lu", registry_size_in_bits);
		BUG_ON();
	}
	log_debug("Unmapped bits %u registry_size_in_bits %lu", unmapped_bits, registry_size_in_bits);
	char *registry_buffer = (char *)volume_desc->mem_volume_bitmap;
	for (uint64_t i = registry_size_in_bits - 1; i >= registry_size_in_bits - unmapped_bits; --i) {
		uint64_t idx = i / 8;
		uint8_t *byte = (uint8_t *)&registry_buffer[idx];
		CLEAR_BIT(byte, (i % 8));
	}

	if (dev_offt + SEGMENT_SIZE != volume_desc->vol_superblock.volume_metadata_size) {
		log_fatal("Faulty marking of volume's metadata as reserved");
		assert(0);
		BUG_ON();
	}
	log_debug("Recovering ownership registry... XXX TODO XXX");

	volume_desc->open_databases = klist_init();
	return volume_desc;
}
/**
 * Retrieves or creates if not present the volume_descriptor for a volume_name.
 */
struct volume_descriptor *mem_get_volume_desc(char *volume_name)
{
	static pthread_mutex_t volume_map_lock = PTHREAD_MUTEX_INITIALIZER;
	MUTEX_LOCK(&volume_map_lock);
	struct volume_map_entry *volume = NULL;
	uint64_t hash_key = djb2_hash((unsigned char *)volume_name, strlen(volume_name));

	HASH_FIND_PTR(volume_map, &hash_key, volume);
	if (volume)
		goto exit;

	log_debug("Volume %s not open creating/initializing new volume ...", volume_name);
	volume = calloc(1, sizeof(struct volume_map_entry));

	if (!volume) {
		log_fatal("calloc failed");
		BUG_ON();
	}

	volume->volume_desc = mem_init_volume(volume_name);

	if (strlen(volume_name) >= MEM_MAX_VOLUME_NAME_SIZE) {
		log_fatal("Volume name too large!");
		BUG_ON();
	}

	memcpy(volume->volume_name, volume_name, strlen(volume_name));
	volume->hash_key = djb2_hash((unsigned char *)volume_name, strlen(volume_name));
	volume->volume_desc->size = mount_volume(volume_name, 0, 0);

	volume->volume_desc->db_superblock_lock =
		calloc(volume->volume_desc->vol_superblock.max_regions_num, sizeof(pthread_mutex_t));

	for (uint32_t i = 0; i < volume->volume_desc->vol_superblock.max_regions_num; ++i)
		MUTEX_INIT(&volume->volume_desc->db_superblock_lock[i], NULL);

	recover_allocator_bitmap(volume->volume_desc);
	HASH_ADD_PTR(volume_map, hash_key, volume);

exit:
	MUTEX_UNLOCK(&volume_map_lock);
	return volume->volume_desc;
}
