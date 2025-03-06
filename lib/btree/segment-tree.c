#include "st.h"
#include <assert.h>
#include <inttypes.h>
#include <log.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef NDEBUG
#define ASSERT(condition, message)           \
	do {                                 \
		assert(condition &&message); \
	} while (0)
#else

#define ASSERT(condition, message)

#endif

enum node_type { INDEX_NODE = 0, LEAF_NODE };

#define TOTAL_SEGMENT_NODE_SIZE (4096)

struct segment_tree {
	enum node_type node_type;
	uint8_t buffer[];
};

struct slot_array {
	uint16_t slot_array_boundary;
	uint16_t slots_num;
	uint16_t slots[];
};

struct key {
	uint8_t size;
	uint8_t data[];
};

struct children {
	struct segment_tree *left_node;
	struct segment_tree *right_node;
};

struct exact_bsearch_value {
	int8_t match;
	uint16_t slot;
	union {
		struct segment_tree *next_node;
		void *guard;
	};
};

#define BUFFER_SIZE (TOTAL_SEGMENT_NODE_SIZE - offsetof(struct segment_tree, buffer))

int compare_keys(struct key *str1, struct key *str2)
{
	ASSERT(str1->size > 0, "str1 size = 0");
	ASSERT(str2->size > 0, "str2 size = 0");

	uint8_t min_data_len = str1->size < str2->size ? str1->size : str2->size;
	int result = memcmp(str1->data, str2->data, min_data_len);
	return 0 == result ? str1->size - str2->size : result;
}

range_tree initialize_range_tree(void)
{
	struct segment_tree *tree = calloc(1, TOTAL_SEGMENT_NODE_SIZE);
	if (!tree)
		return NULL;

	tree->node_type = LEAF_NODE;

	return tree;
}

struct segment_tree *get_new_segment_leaf(void)
{
	struct segment_tree *leaf_node = calloc(1, TOTAL_SEGMENT_NODE_SIZE);
	if (!leaf_node) {
		ASSERT(0, "Malloc failed");
		return NULL;
	}

	leaf_node->node_type = LEAF_NODE;
	return leaf_node;
}

struct segment_tree *get_new_segment_index(void)
{
	struct segment_tree *leaf_node = calloc(1, TOTAL_SEGMENT_NODE_SIZE);
	if (!leaf_node) {
		ASSERT(0, "Malloc failed");
		return NULL;
	}

	leaf_node->node_type = INDEX_NODE;
	return leaf_node;
}

void split_leaf(struct segment_tree *index_node, struct segment_tree *leaf_node)
{
	ASSERT(leaf_node->node_type == LEAF_NODE, "Got an index node in split leaf");
	struct segment_tree *left_leaf = get_new_segment_leaf();
	struct segment_tree *right_leaf = get_new_segment_leaf();
	struct slot_array *parent_leaf_slot_array = (struct slot_array *)leaf_node->buffer;

	// Split the leaf into two parts
	for (uint16_t i = 0; i < parent_leaf_slot_array->slots_num / 2; ++i) {
		struct key *current_leaf_key = get_key_from_slot(leaf_node, i);
		void *value = get_value_from_slot(leaf_node, i);
		add_new_entry_in_leaf(left_leaf, current_leaf_key, value, i);
	}

	uint16_t j = 0;
	for (uint16_t i = parent_leaf_slot_array->slots_num / 2; i < parent_leaf_slot_array->slots_num; ++i, ++j) {
		struct key *current_leaf_key = get_key_from_slot(leaf_node, i);
		void *value = get_value_from_slot(leaf_node, i);
		add_new_entry_in_leaf(right_leaf, current_leaf_key, value, j);
	}

	index_node = leaf_node;
	reset_node_metadata(index_node);
	index_node->node_type = INDEX_NODE;

	// Get the pivot key from right_leaf[0]
	struct key *pivot_key = get_key_from_slot(right_leaf, 0);
	int16_t slot = binary_search_node(index_node, pivot_key);
	add_new_entry_in_index(index_node, pivot_key, slot, left_leaf, right_leaf);
}

void split_index(struct segment_tree *index_node)
{
	ASSERT(index_node->node_type == INDEX_NODE, "Got a leaf node in split index");
	struct segment_tree *left_node = get_new_segment_leaf();
	struct segment_tree *right_node = get_new_segment_leaf();
	struct slot_array *parent_node_slot_array = (struct slot_array *)index_node->buffer;

	// Split the leaf into two parts
	for (uint16_t i = 0; i < parent_node_slot_array->slots_num / 2; ++i) {
		struct key *current_index_key = get_key_from_slot(index_node, i);
		struct children *children = get_value_from_slot(index_node, i);
		add_new_entry_in_index(left_node, current_index_key, i, children->left_node, children->right_node);
	}

	uint16_t j = 0;
	for (uint16_t i = parent_node_slot_array->slots_num / 2; i < parent_node_slot_array->slots_num; ++i, ++j) {
		struct key *current_index_key = get_key_from_slot(index_node, i);
		struct children *children = get_value_from_slot(index_node, i);
		add_new_entry_in_index(right_node, current_index_key, j, children->left_node, children->right_node);
	}

	// Get the pivot key from right_leaf[0]
	struct key *pivot_key = get_key_from_slot(right_node, 0);
	int16_t slot = binary_search_node(index_node, pivot_key);
	add_new_entry_in_index(index_node, pivot_key, slot, left_node, right_node);
}

struct segment_tree *find_leaf(struct segment_tree *index_node, struct key *key, void *value)
{
	struct segment_tree *prev_node = NULL;
	struct segment_tree *current_node = index_node;
	uint16_t range_index_size = calculate_serialized_range_size_in_index(key);
	uint16_t range_leaf_size = calculate_serialized_range_size_in_leaf(key, value);

	while (current_node->node_type == INDEX_NODE) {
		if (is_node_full(current_node, range_index_size)) {
			split_index(current_node);
		}

		struct exact_bsearch_value bsearch_status = exact_binary_search_node(current_node, key);
		prev_node = current_node;
		current_node = bsearch_status.next_node;
	}

	while (is_node_full(current_node, range_leaf_size)) {
		split_leaf(prev_node, current_node);
		struct exact_bsearch_value bsearch_status = exact_binary_search_node(current_node, key);
		prev_node = current_node;
		current_node = bsearch_status.next_node;
	}
	return current_node;
}

struct key *get_key_from_slot(struct segment_tree *node, uint16_t slot_idx)
{
	struct slot_array *slot_array = (struct slot_array *)node->buffer;
	return (struct key *)&node->buffer[slot_array->slots[slot_idx]];
}

void *get_value_from_slot(struct segment_tree *node, uint16_t slot_idx)
{
	struct slot_array *slot_array = (struct slot_array *)node->buffer;
	struct key *key = (struct key *)&node->buffer[slot_array->slots[slot_idx]];
	return &key->data[key->size];
}

int16_t binary_search_node(struct segment_tree *node, struct key *key)
{
	// TODO check if I need int16_t or uint16_t as ret value of the func.
	struct slot_array *slot_array = (struct slot_array *)node->buffer;
	int compare_key = 0;
	int16_t start_idx = 0;
	int16_t middle_idx = 0;
	int16_t end_idx = slot_array->slots_num - 1;

	while (start_idx <= end_idx) {
		middle_idx = (start_idx + end_idx) / 2;
		struct key *current_key = get_key_from_slot(node, middle_idx);

		compare_key = compare_keys(key, current_key);

		if (compare_key > 0) {
			start_idx = middle_idx + 1;
		} else {
			end_idx = middle_idx - 1;
		}
	}

	return compare_key > 0 ? middle_idx + 1 : middle_idx;
}

struct segment_tree *choose_next_node(struct children *children, int comparison)
{
	if (comparison < 0) {
		return children->left_node;
	}

	return children->right_node;
}

struct exact_bsearch_value exact_binary_search_node(struct segment_tree *node, struct key *key)
{
	// TODO check if I need int16_t or uint16_t as ret value of the func.
	struct exact_bsearch_value return_value = { 0, -1, { NULL } };

	struct slot_array *slot_array = (struct slot_array *)node->buffer;
	int compare_key = 0;
	int16_t start_idx = 0;
	int16_t middle_idx = 0;
	int16_t end_idx = slot_array->slots_num - 1;

	while (start_idx <= end_idx) {
		middle_idx = (start_idx + end_idx) / 2;
		struct key *current_key = get_key_from_slot(node, middle_idx);

		compare_key = compare_keys(key, current_key);

		if (compare_key > 0) {
			start_idx = middle_idx + 1;
		} else if (compare_key < 0) {
			end_idx = middle_idx - 1;
		} else {
			return_value.slot = middle_idx;
			return_value.match = 0;
			if (node->node_type == INDEX_NODE) {
				return_value.next_node = choose_next_node(get_value_from_slot(node, middle_idx), 0);
			}
			return return_value;
		}
	}

	return_value.slot = middle_idx; // compare_key > 0 ? middle_idx + 1 : middle_idx;
	return_value.match = compare_keys(key, get_key_from_slot(node, return_value.slot));
	if (node->node_type == INDEX_NODE) {
		return_value.next_node =
			choose_next_node(get_value_from_slot(node, return_value.slot), return_value.match);
	}
	return return_value;
}

uint16_t calculate_serialized_range_size_in_leaf(struct key *key, void *value)
{
	return key->size + sizeof(key->size) + sizeof(value);
}

uint16_t calculate_serialized_range_size_in_index(struct key *key)
{
	return key->size + sizeof(key->size) + sizeof(struct segment_stree *) * 2;
}

void reset_node_metadata(struct segment_tree *node)
{
	struct slot_array *slot_array = (struct slot_array *)node->buffer;
	slot_array->slot_array_boundary = 0;
	slot_array->slots_num = 0;
}

uint8_t is_node_full(struct segment_tree *node, uint16_t new_range_size)
{
	struct slot_array *slot_array = (struct slot_array *)node->buffer;
	uint8_t *right_border = &node->buffer[BUFFER_SIZE - (slot_array->slot_array_boundary + new_range_size)];
	uint8_t *left_border =
		&node->buffer[sizeof(struct slot_array) + sizeof(uint16_t) * (slot_array->slots_num + 1)];
	return !(right_border > left_border);
}

struct key *find_new_key_position_in_node(struct segment_tree *leaf_node, uint16_t new_data_size)
{
	struct slot_array *slot_array = (struct slot_array *)leaf_node->buffer;
	return (struct key *)&leaf_node->buffer[BUFFER_SIZE - slot_array->slot_array_boundary - new_data_size];
}

void create_space_for_insert_in_buffer(struct segment_tree *leaf_node, uint16_t slot)
{
	struct slot_array *slot_array = (struct slot_array *)leaf_node->buffer;
	memmove(&slot_array->slots[slot + 1], &slot_array->slots[slot],
		sizeof(uint16_t) * (slot_array->slots_num - slot));
}

void add_new_entry_in_leaf(struct segment_tree *leaf_node, struct key *key, void *value, uint16_t slot)
{
	create_space_for_insert_in_buffer(leaf_node, slot);

	struct slot_array *slot_array = (struct slot_array *)leaf_node->buffer;
	uint16_t serialized_sum = calculate_serialized_range_size_in_leaf(key, value);
	struct key *new_key = find_new_key_position_in_node(leaf_node, serialized_sum);

	memcpy(new_key, key, sizeof(key->size) + key->size);
	memcpy(&new_key->data[new_key->size], value, sizeof(void *));
	slot_array->slot_array_boundary += serialized_sum;
	slot_array->slots[slot] = BUFFER_SIZE - slot_array->slot_array_boundary;
	++slot_array->slots_num;
}

void add_new_entry_in_index(struct segment_tree *index_node, struct key *key, uint16_t slot,
			    struct segment_tree *left_leaf, struct segment_tree *right_leaf)
{
	create_space_for_insert_in_buffer(index_node, slot);

	struct slot_array *slot_array = (struct slot_array *)index_node->buffer;
	uint16_t serialized_sum = calculate_serialized_range_size_in_index(key);
	struct key *new_key = find_new_key_position_in_node(index_node, serialized_sum);

	memcpy(new_key, key, sizeof(key->size) + key->size);
	struct children *children = (struct children *)&new_key->data[new_key->size];
	children->left_node = left_leaf;
	children->right_node = right_leaf;
	slot_array->slot_array_boundary += serialized_sum;
	slot_array->slots[slot] = BUFFER_SIZE - slot_array->slot_array_boundary;
	++slot_array->slots_num;
}

void print_leaf(struct segment_tree *leaf_node)
{
	struct slot_array *slot_array = (struct slot_array *)leaf_node->buffer;
	log_info("Slots num: %" PRIu16, slot_array->slots_num);
	for (int i = 0; i < slot_array->slots_num; ++i) {
		/* struct key *key_range = (struct key *)&leaf_node->buffer[slot_array->slots[i]]; */
		/* log_info("Offset %" PRIu16 ": Key Size %" PRIu8 ": Key %.*s", slot_array->slots[i], key_range->size, */
		/* 	 key_range->size, key_range->data); */
	}
}

void insert_key_in_leaf(struct segment_tree *leaf_node, struct key *key, void *value)
{
	ASSERT(leaf_node->node_type == LEAF_NODE, "Insert in leaf received INDEX node");
	struct slot_array *slot_array = (struct slot_array *)leaf_node->buffer;
	if (slot_array->slots_num == 0) {
		add_new_entry_in_leaf(leaf_node, key, value, 0);
		return;
	}

	// TODO Check if i move bsearch before the if check, if the code still works.
	int16_t slot = binary_search_node(leaf_node, key);
	add_new_entry_in_leaf(leaf_node, key, value, slot);
}

void insert_key(range_tree tree, struct key *key, void *value)
{
	ASSERT(key, "Got null key");
	struct segment_tree *leaf = tree;

	leaf = find_leaf(tree, key, value);

	ASSERT(leaf->node_type == LEAF_NODE, "Got index node while expecting a leaf");
	ASSERT(is_node_full(leaf, calculate_serialized_range_size_in_leaf(key, value)) == 0,
	       "Got a leaf that needs split before insert.");
	insert_key_in_leaf(leaf, key, value);
}

void remove_entry_from_leaf(struct segment_tree *leaf_node, uint16_t slot)
{
	struct slot_array *slot_array = (struct slot_array *)leaf_node->buffer;

	memmove(&slot_array->slots[slot], &slot_array->slots[slot + 1], slot_array->slots_num - (slot + 1));
	--slot_array->slots_num;
}

void delete_key_in_leaf(struct segment_tree *leaf_node, struct key *key)
{
	ASSERT(leaf_node->node_type == LEAF_NODE, "Insert in leaf received INDEX node");
	struct slot_array *slot_array = (struct slot_array *)leaf_node->buffer;
	if (slot_array->slots_num == 0) {
		return;
	}

	int16_t slot = binary_search_node(leaf_node, key);
	remove_entry_from_leaf(leaf_node, slot);
}

void delete_key(range_tree tree, struct key *key)
{
	ASSERT(key, "Got null key");
	struct segment_tree *leaf = tree;

	leaf = find_leaf(tree, key, NULL);

	ASSERT(leaf->node_type == LEAF_NODE, "Got index node while expecting a leaf");
	delete_key_in_leaf(leaf, key);
}

void create_key(struct key *key, char *string)
{
	int len = strlen(string);
	key->size = len;
	memcpy(key->data, string, key->size);
}

void inorder_traversal(struct segment_tree *node)
{
	if (node->node_type == LEAF_NODE) {
		print_leaf(node);
		return;
	}

	struct slot_array *slot_array = (struct slot_array *)node->buffer;

	for (uint16_t i = 0; i < slot_array->slots_num; i++) {
		struct children *children = get_value_from_slot(node, i);

		inorder_traversal(children->left_node);
		inorder_traversal(children->right_node);
	}
}

void free_tree(struct segment_tree *root_node)
{
	if (root_node->node_type == LEAF_NODE) {
		free(root_node);
		return;
	}

	struct slot_array *slot_array = (struct slot_array *)root_node->buffer;
	for (uint16_t i = 0; i < slot_array->slots_num; i++) {
		struct children *children = get_value_from_slot(root_node, i);

		free_tree(children->left_node);
		free_tree(children->right_node);
	}
	free(root_node);
}

//int main(void)
//{
//	char buffer[8192];
//	char value_buffer[8192];
//	char large_string[257];
//	struct key *key;
//	range_tree tree = initialize_range_tree();
//	key = (struct key *)buffer;
//
//	void *value = (void *)value_buffer;
//	create_key((struct key *)value, "lets go");
//	create_key(key, "ef");
//	insert_key(tree, key, value);
//	delete_key(tree, key);
//	delete_key(tree, key);
//	create_key(key, "bb");
//	insert_key(tree, key, value);
//
//	create_key(key, "a");
//	insert_key(tree, key, value);
//
//	create_key(key, "no");
//	insert_key(tree, key, value);
//
//	create_key(key, "ik");
//	insert_key(tree, key, value);
//
//	create_key(key, "aa");
//	insert_key(tree, key, value);
//
//	create_key(key, "aaa");
//	insert_key(tree, key, value);
//
//	create_key(key, "aaaa");
//	insert_key(tree, key, value);
//
//	char c = 'a';
//	for (int i = 0; i < 26; i++) {
//		memset(large_string, c, 255);
//		large_string[256] = '\0';
//		create_key(key, large_string);
//		insert_key(tree, key, value);
//		/* print_leaf(tree); */
//		c++;
//	}
//
//	char b = 'a';
//	for (int j = 0; j < 26; j++) {
//		c = 'a';
//		for (int i = 0; i < 26; i++) {
//			memset(large_string, c, 255);
//			large_string[256] = '\0';
//			large_string[1] = b;
//			create_key(key, large_string);
//			insert_key(tree, key, value);
//			c++;
//		}
//		b++;
//	}
//
//	inorder_traversal(tree);
//	free_tree(tree);
//
//	return 0;
//}
