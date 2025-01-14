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
#ifndef KV_PAIRS_H
#define KV_PAIRS_H
#include "../include/parallax/structures.h"
#include <stdbool.h>
#include <stdint.h>
enum KV_type { KV_FORMAT = 1, KV_PREFIX };
#define KV_META_MAX_PREV_SIZE (2 << 12)

#define KV_SEP2_MAX_SIZE (sizeof(struct kv_splice_meta) + sizeof(int16_t) + sizeof(uint64_t) + MAX_KEY_SIZE)

struct kv_splice_meta {
	uint16_t kv_format : 1;
	uint16_t tombstone : 1;
	uint16_t kv_cat : 2;
	uint16_t unreserved : 12;
} __attribute__((packed));

struct kv_splice {
	struct kv_splice_meta meta;
#if TEBIS_FORMAT
	int16_t key_size;
	int32_t value_size;
	int8_t tail_for_sizes;
#else
	int16_t key_size;
	int32_t value_size;
#endif
	char data[];
} __attribute__((packed));

struct kv_seperation_splice2 {
	// uint64_t value_offt;
	struct kv_splice_meta meta;
#if TEBIS_FORMAT
	int16_t key_size;
	uint64_t value_offt; //oops
#else
	int16_t key_size;
	uint64_t value_offt;
#endif
	char key[];
} __attribute__((packed));

struct kv_splice_base {
	enum kv_category kv_cat;
	enum KV_type kv_type;
	union {
		struct kv_splice *kv_splice;
		struct kv_seperation_splice2 *kv_sep2;
	};
	bool is_tombstone;
};

enum kv_category kv_meta_get_cat(const struct kv_splice_meta *meta);
bool kv_meta_set_cat(struct kv_splice_meta *meta, enum kv_category cat);
bool kv_meta_is_tombstone(const struct kv_splice_meta *meta);
bool kv_meta_set_tombstone(struct kv_splice_meta *meta, bool val);
bool kv_meta_is_kv_format(const struct kv_splice_meta *meta);
bool kv_meta_set_kv_format(struct kv_splice_meta *meta, bool val);

bool kv_meta_set_prev_kv_size(struct kv_splice_meta *meta, uint16_t size);
uint16_t kv_meta_get_prev_kv_size(const struct kv_splice_meta *meta);
/**
 * @brief Returns a pointer to the key
 * @param kv_sep2 pointer to the splice
 * @return pointer to the key
 */
char *kv_sep2_get_key(struct kv_seperation_splice2 *kv_sep2);

/**
 * @brief Returns the size of the key for kv seperation splices
 * @param kv_sep2 pointer to the seperation splice
 * @returns the size of the key (without its metadata)
 */
int32_t kv_sep2_get_key_size(const struct kv_seperation_splice2 *kv_sep2);

/**
 * @brief Returns the offset in the device where the splice has been stored. In
 * the device the kv pair is stored in kv_splice format.
 * @param kv_sep2 pointer to the splice object
 * @returns the offset in the file/device where the splice is stored.
 */
uint64_t kv_sep2_get_value_offt(const struct kv_seperation_splice2 *kv_sep2);

/**
 * @brief Sets the offset to the specified value_offt
 * @param kv_sep2 pinter to the splice object
 * @param value_offt the new offset to be set
 */
void kv_sep2_set_value_offt(struct kv_seperation_splice2 *kv_sep2, uint64_t value_offt);

/**
 * @brief Returns the total size of the splice which includes also the size of its metadata.
 * @param kv_sep2 pointer to the splice object
 * @return the size of the splice
 */
int32_t kv_sep2_get_total_size(const struct kv_seperation_splice2 *kv_sep2);

/**
 * @brief Serializes into dest buffer the splice object.
 * @param splice pointer to the splice object
 * @param dest pointer to the buffer
 * @param dest_size sizeo of the buffer
 * @returns true on success or false in failure because the buffer does not
 * have adequate space.
 */
bool kv_sep2_serialize(const struct kv_seperation_splice2 *splice, char *dest, int32_t dest_size);

/**
 * @brief Constructs a kv_sep2 object. Internally it allocates memory and constructs the object.
 * @param key_size the size of the key in bytes.
 * @param key pointer to the key buffer
 * @param value_offt the offset in the file/device where the kv pair has been stored.
 * @returns reference to the newly created object otherwise NULL on failure
 */
struct kv_seperation_splice2 *kv_sep2_alloc_and_create(int32_t key_size, const char *key, uint64_t value_offt);

/**
 * @brief Constructs a splice and stores it in the buf buffer.
 * @param key_size the size of the key
 * @param key pointer to the key object
 * @param value_offt the offset in the device where the kv pair has been stored
 * @param buf the destination buffer which is used to store the object
 * @param buf_size the size of the buffer.
 * @returns reference to the kv_sep2 object or NULL in case of a failure
 */
struct kv_seperation_splice2 *kv_sep2_create(int32_t key_size, const char *key, uint64_t value_offt, char *buf,
					     uint32_t buf_size);

/**
 * @brief Calculates the storage space needed to encode a key of size key_size
 * into a kv_sep object.
 * @param key_size the sizeo of the key that we want to encode as a kv_sep
 * object.
 * @returns the storage size needed
 */
uint32_t kv_sep2_calculate_size(int32_t key_size);

void kv_splice_serialize(const struct kv_splice *splice, char *dest);

struct kv_splice *kv_splice_create(int32_t key_size, const char *key, int32_t value_size, const char *value);

/**
 * @brief Calculates the size in bytes of the given kv_splice.
 * @param kv_pair pointer to the kv_splice object
 * @returns the size of the splice in bytes
 */
uint32_t kv_splice_get_size(struct kv_splice *kv_pair);

/**
 * @brief Creates a splice using as memory space the given buffer.
 * @param key_size the size of the key
 * @param key pointer to the key object
 * @param value_size the size of the value
 * @param value pointer to the value object
 * @return pointer to the kv_splice object or NULL if the buffer space is not enough
 *
 */
struct kv_splice *kv_splice_create2(int32_t key_size, const char *key, int32_t value_size, const char *value,
				    char *buffer, int32_t buffer_len);
/**
 * Calculates key_size given a splice formated key
 * @param kv_pair key a KV_FORMATED key
 * @return key size
 */
int32_t kv_splice_get_key_size(const struct kv_splice *kv_pair);
/**
 * Returns the value_size given a splice formated key
 * @param kv_pair a spliced (KV_FORMATED) kv ptr
 */
int32_t kv_splice_get_value_size(const struct kv_splice *kv_pair);
/**
 * Calculates the value_size  + metadata given a splice formated key
 * @param kv_pair a spliced (KV_FORMATED) kv ptr
 */
int32_t kv_splice_get_value_size_with_metadata(const struct kv_splice *kv_pair);
/**
 * Calculates sizeof(splice.value_size) + sizeof(splice.key_size)
 */
int32_t kv_splice_get_metadata_size(void);
/**
 * Calculates the key value pair size (with its metadata) for KV_FORMAT
 * @param kv_pair a spliced (KV_FORMATED) kv ptr
 */
int32_t kv_splice_get_kv_size(const struct kv_splice *kv_pair);
/**
 * Returns the size of the tails (size_tail/payload_tail)
 */
int32_t kv_splice_get_tail_size(void);
/**
 * Sets the key size given a splice formated kv
 * @param kv_pair a spliced (KV_FORMATED) kv ptr, where key_size will be set
 * @param key_size the new size to be set
 */
void kv_splice_set_key_size(struct kv_splice *kv_pair, int32_t key_size);

/**
  * Copies the key buffer to the kv pair
  * @param kv_pair: a KV_FORMAT kv_pair
  * @param key: pointer to the key buffer
  * @param key_size: size of the key buffer
  */
void kv_splice_set_key(struct kv_splice *kv_pair, const char *key, int32_t key_size);

/**
 * Sets the value size given a splice formated kv
 * @param kv_pair a spliced (KV_FORMATED) kv ptr, where value_size will be set
 * @param value_size the new size to be set
 */
void kv_splice_set_value_size(struct kv_splice *kv_pair, int32_t value_size);

/**
  * Copies the value buffer to the kv pair
  * @param kv_pair a KV_FORMAT kv_pair
  * @param value pointer to the value buffer
  * @param value_size size of the value buffer
  */
void kv_splice_set_value(struct kv_splice *kv_pair, const char *value, int32_t value_size);

void set_sizes_tail(struct kv_splice *kv_pair, uint8_t tail);
void set_payload_tail(struct kv_splice *kv_pair, uint8_t tail);

/**
 * Calculates the starting offset of the key part of a given splice kv
 * @param kv_pair a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 */
char *kv_splice_get_key_offset_in_kv(struct kv_splice *kv_pair);
/**
 * Calculates the starting offset of the value part of a given splice kv
 * @param kv_pair a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 * @param key_size: the key size of this kv
 */
char *kv_splice_get_value_offset_in_kv(struct kv_splice *kv_pair, int32_t key_size);

/**
  * @brief Examines a KV pair to see if it is a delete marker
  */
bool kv_splice_is_tombstone_kv_pair(const struct kv_splice *kv_pair);

/**
 * @brief Characterizes a splice as a tombstone.
 * @param kv_pair pointer to splice object
 */
void kv_splice_set_tombstone(struct kv_splice *kv_pair);

/**
 * @brief characterizes a kv_pair as a non tombstone.
 * @param kv_pair pointer to splice object
 */
void kv_splice_set_non_tombstone(struct kv_splice *kv_pair);

/**
 * @brief serializes the key part of a kv_splice to a key_splice
 * @param buf pointer to the buffer where the key_splice will be stored
 * @param kv_pair pointer to the kv_splice object
 */
void kv_splice_serialize_to_key_splice(const char *buf, struct kv_splice *kv_pair);

/**
 * @brief Returns the size (data+metadata) of the minimum size of a kv pair in
 * Parallax
 */
uint32_t kv_splice_get_min_possible_kv_size(void);

uint32_t kv_splice_calculate_size(int32_t key_size, int32_t value_size);

/**
 * @brief Compares the keys of two splices
 * @param sp1 pointer to splice 1
 * @param sp2 pointer to splice 2
 * @returns 0 if the keys of the splices are equal greater than zero if sp1 >
 * sp2 otherwise < 0.
 */
int kv_splice_base_compare(struct kv_splice_base *sp1, struct kv_splice_base *sp2);

/**
 * @brief Returns the size of the kv splice
 * @param splice pointer to the splice object
 * @returns the size of the splice in bytes
 */
int32_t kv_splice_base_get_size(struct kv_splice_base *splice);
/**
 * @brief Returns the key size of the splice
 * @param splice pointer to the splice object
 * @returns the size of the object
 */
int32_t kv_splice_base_get_key_size(struct kv_splice_base *splice);
int32_t kv_splice_base_get_value_size(struct kv_splice_base *splice);

/**
 * @brief Calculates the size of the splice
 * @param splice pointer to the splice object
 */
int32_t kv_splice_base_calculate_size(struct kv_splice_base *splice);

/**
 * @brief Returns a reference to the start of the underlying (kv_sep2 or
 * kv_splice) object starts.
 * @param splice pointer to the splice object
 */
char *kv_splice_base_get_reference(struct kv_splice_base *splice);

/**
 * @brief Returns the start of the key buffer of the splice
 * @param splice pointer to the splice object
 */
char *kv_splice_base_get_key_buf(struct kv_splice_base *splice);
void kv_splice_base_serialize(const struct kv_splice_base *splice_base, char *dest, int32_t dest_size);

#endif // KV_PAIRS_H
