#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <mba/bitset.h>
#include <log.h>
#include "static_leaf.h"
#include "conf.h"

static void retrieve_static_leaf_structures(const struct bt_static_leaf_node *leaf, struct bt_static_leaf_structs *src,
					    level_descriptor *level)
{
	char *leaf_base_address = (char *)leaf;
	src->bitmap = (struct bt_leaf_entry_bitmap *)(leaf_base_address + level->leaf_offsets.bitmap_offset);
	src->slot_array = (bt_leaf_slot_array *)(leaf_base_address + level->leaf_offsets.slot_array_offset);
	src->kv_entries = (bt_leaf_entry *)(leaf_base_address + level->leaf_offsets.kv_entries_offset);
}

static uint32_t get_bitmap_size(level_descriptor *level)
{
	return sizeof(struct bt_leaf_entry_bitmap) * level->leaf_offsets.bitmap_entries;
}

static uint32_t get_slot_array_size(level_descriptor *level)
{
	return sizeof(bt_leaf_slot_array) * level->leaf_offsets.slot_array_entries;
}

static uint32_t get_kv_entries_size(level_descriptor *level)
{
	return sizeof(bt_leaf_entry) * level->leaf_offsets.kv_entries_offset;
}

void init_static_leaf_metadata(struct bt_static_leaf_node *leaf, level_descriptor *level)
{
	struct bt_static_leaf_structs src;
	retrieve_static_leaf_structures(leaf, &src, level);
	memset(src.bitmap, 0, get_bitmap_size(level));
	memset(src.slot_array, 0, get_slot_array_size(level));
	memset(src.kv_entries, 0, get_kv_entries_size(level));
}

struct bsearch_result binary_search_static_leaf(struct bt_static_leaf_node const *leaf, level_descriptor *level,
						struct splice *key_buf)
{
	struct bt_static_leaf_structs src;
	char *leaf_key_prefix, *leaf_key_buf;
	struct bsearch_result result = { 0, INSERT };
	int32_t start = 0, middle = 0, end = leaf->header.numberOfEntriesInNode - 1;
	const int32_t numberOfEntriesInNode = leaf->header.numberOfEntriesInNode;
	const int32_t kv_entries = level->leaf_offsets.kv_entries;
	uint32_t pos;
	int ret, ret_case;
	retrieve_static_leaf_structures(leaf, &src, level);

	while (numberOfEntriesInNode > 0) {
		middle = (start + end) / 2;

		if (numberOfEntriesInNode > kv_entries || middle < 0 || middle >= numberOfEntriesInNode) {
			result.status = ERROR;
			return result;
		}

		pos = src.slot_array[middle].index;
		leaf_key_prefix = src.kv_entries[pos].prefix;
		ret = prefix_compare(leaf_key_prefix, key_buf->data, PREFIX_SIZE);
		ret_case = ret < 0 ? LESS_THAN_ZERO : ret > 0 ? GREATER_THAN_ZERO : EQUAL_TO_ZERO;

		if (ret_case == EQUAL_TO_ZERO) {
			leaf_key_buf = REAL_ADDRESS(src.kv_entries[pos].pointer);
			ret = _tucana_key_cmp(leaf_key_buf, key_buf, KV_FORMAT, KV_FORMAT);

			if (ret == 0) {
				result.middle = middle;
				result.status = FOUND;
				return result;
			}

			ret_case = ret < 0 ? LESS_THAN_ZERO : GREATER_THAN_ZERO;
		}

		switch (ret_case) {
		case LESS_THAN_ZERO:
			start = middle + 1;
			if (start > end) {
				middle++;
				result.middle = middle;
				result.status = INSERT;
				return result;
			}
			continue;
		case GREATER_THAN_ZERO:
			end = middle - 1;
			if (start > end) {
				result.middle = middle;
				result.status = INSERT;
				return result;
			}
			continue;
		}
	}

	return result;
}

void *find_key_in_static_leaf(const struct bt_static_leaf_node *leaf, level_descriptor *level, void *key,
			      uint32_t key_size)
{
	struct bt_static_leaf_structs src;
	struct bsearch_result result;
	void *ret = NULL;
	char buf[128];
	struct splice *key_buf = (struct splice *)buf;

	assert(buf != NULL);
	assert((key_size + sizeof(uint32_t)) <= 128);
	SERIALIZE_KEY(buf, key, key_size);
	retrieve_static_leaf_structures(leaf, &src, level);

	result = binary_search_static_leaf(leaf, level, key_buf);
	switch (result.status) {
	case FOUND:
		return (void *)src.kv_entries[src.slot_array[result.middle].index].pointer;
	default:
		log_info("Key not found %s", key_buf->data);
	}

	return ret;
}

void shift_slot_array(struct bt_static_leaf_node *leaf, uint32_t middle, level_descriptor *level)
{
	struct bt_static_leaf_structs src;
	const size_t num_items = leaf->header.numberOfEntriesInNode - middle;
	retrieve_static_leaf_structures(leaf, &src, level);

	if (num_items == 0)
		return;

	memmove(&src.slot_array[middle + 1], &src.slot_array[middle], num_items * sizeof(bt_leaf_slot_array));
}

struct bt_rebalance_result split_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req)
{
	struct bt_static_leaf_structs leaf_src, right_leaf_src;
	struct bt_rebalance_result rep;
	struct bt_static_leaf_node *leaf_copy;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[leaf->header.level_id];
	volume_descriptor *volume_desc = req->metadata.handle->volume_desc;
	uint64_t i, j = 0;

	retrieve_static_leaf_structures(leaf, &leaf_src, level);
	/*cow check*/
	if (leaf->header.epoch <= volume_desc->dev_catalogue->epoch) {
		leaf_copy = seg_get_static_leaf_node(volume_desc, level, COW_FOR_LEAF);
		memcpy(leaf_copy, leaf, level->leaf_size);
		leaf_copy->header.epoch = volume_desc->mem_catalogue->epoch;
		leaf = leaf_copy;
	}

	rep.left_slchild = leaf;

	/*Fix Right leaf metadata*/
	rep.right_slchild = seg_get_static_leaf_node(volume_desc, level, LEAF_SPLIT);
	init_static_leaf_metadata(rep.right_slchild, level);
	retrieve_static_leaf_structures(rep.right_slchild, &right_leaf_src, level);
	rep.middle_key_buf = REAL_ADDRESS(
		leaf_src.kv_entries[leaf_src.slot_array[leaf->header.numberOfEntriesInNode / 2].index].pointer);

	/*Copy pointers + prefixes*/
	for (i = leaf->header.numberOfEntriesInNode / 2 + (leaf->header.numberOfEntriesInNode % 2);
	     i < leaf->header.numberOfEntriesInNode; ++i, ++j) {
		right_leaf_src.slot_array[j].index = j;
		right_leaf_src.kv_entries[j] = leaf_src.kv_entries[leaf_src.slot_array[i].index];
		bitset_set(right_leaf_src.bitmap, j);
	}

	rep.right_lchild->header.numberOfEntriesInNode =
		(leaf->header.numberOfEntriesInNode / 2) + (leaf->header.numberOfEntriesInNode % 2);
	rep.right_lchild->header.type = leafNode;

	/* Fix Left leaf metadata */
	for (i = leaf->header.numberOfEntriesInNode / 2 + (leaf->header.numberOfEntriesInNode % 2);
	     i < leaf->header.numberOfEntriesInNode; ++i)
		bitset_unset(leaf_src.bitmap, leaf_src.slot_array[i].index);
	rep.left_lchild->header.height = leaf->header.height;
	rep.left_lchild->header.numberOfEntriesInNode = leaf->header.numberOfEntriesInNode / 2;

	if (leaf->header.type == leafRootNode) {
		rep.left_lchild->header.type = leafNode;
		rep.stat = LEAF_ROOT_NODE_SPLITTED;
	} else
		rep.stat = INDEX_NODE_SPLITTED;

	return rep;
}

void underflow_borrow_from_left_static_leaf_neighbor(struct bt_static_leaf_node *curr, struct bt_static_leaf_node *left,
						     level_descriptor *level, bt_delete_request *req)
{
	struct bt_static_leaf_structs curr_leaf_src, left_leaf_src;
	struct siblings_index_entries neighbor_metadata = { .left_entry = NULL, .right_entry = NULL };
	struct bt_leaf_entry_bitmap *bitmap_end;
	void *key_addr;
	int curr_leaf_kventry_pos = -1, left_leaf_kventry_pos = -1;

	retrieve_static_leaf_structures(curr, &curr_leaf_src, level);
	retrieve_static_leaf_structures(left, &left_leaf_src, level);
	bitmap_end = curr_leaf_src.bitmap + level->leaf_offsets.bitmap_entries;
	memmove(&curr_leaf_src.slot_array[1], &curr_leaf_src.slot_array[0],
		sizeof(struct bt_leaf_slot_array) * curr->header.numberOfEntriesInNode);
	curr_leaf_kventry_pos = bitset_find_first(curr_leaf_src.bitmap, bitmap_end, 0);
	assert(curr_leaf_kventry_pos >= 0);
	bitset_set(curr_leaf_src.bitmap, curr_leaf_kventry_pos);

	/* Move the leftmost KV pair */
	curr_leaf_src.slot_array[0].index = curr_leaf_kventry_pos;
	left_leaf_kventry_pos = left_leaf_src.slot_array[left->header.numberOfEntriesInNode - 1].index;
	curr_leaf_src.kv_entries[curr_leaf_kventry_pos] = left_leaf_src.kv_entries[left_leaf_kventry_pos];
	bitset_unset(left_leaf_src.bitmap, left_leaf_kventry_pos);
	++curr->header.numberOfEntriesInNode;
	--left->header.numberOfEntriesInNode;

	/* NOTE in this case we don't have to move anything as it is the last KV pair. */
	key_addr = REAL_ADDRESS(curr_leaf_src.kv_entries[curr_leaf_kventry_pos].pointer);
	_index_node_binary_search_posret(req->parent, req->key_buf, KV_FORMAT, &neighbor_metadata);

	assert(neighbor_metadata.left_entry);

	/* A pivot change should happen in the parent index node */
	__update_index_pivot_in_place(req->metadata.handle, (node_header *)req->parent,
				      &neighbor_metadata.left_entry->pivot, key_addr, req->metadata.level_id);
}
/* struct bt_static_leaf_node *curr, struct bt_static_leaf_node *left,level_descriptor *level, bt_delete_request *req */
void underflow_borrow_from_right_static_leaf_neighbor(struct bt_static_leaf_node *curr,
						      struct bt_static_leaf_node *right, level_descriptor *level,
						      bt_delete_request *req)
{
	struct bt_static_leaf_structs curr_leaf_src, right_leaf_src;
	struct siblings_index_entries neighbor_metadata = { .left_entry = NULL, .right_entry = NULL };
	struct bt_leaf_entry_bitmap *bitmap_end;
	node_header *parent = (node_header *)req->parent;
	void *key_addr;
	int curr_leaf_kventry_pos = -1, right_leaf_kventry_pos = -1;

	retrieve_static_leaf_structures(curr, &curr_leaf_src, level);
	retrieve_static_leaf_structures(right, &right_leaf_src, level);
	bitmap_end = curr_leaf_src.bitmap + level->leaf_offsets.bitmap_entries;

	curr_leaf_kventry_pos = bitset_find_first(curr_leaf_src.bitmap, bitmap_end, 0);
	assert(curr_leaf_kventry_pos >= 0);
	bitset_set(curr_leaf_src.bitmap, curr_leaf_kventry_pos);

	/* First steal the kv pointer + prefix */
	right_leaf_kventry_pos = right_leaf_src.slot_array[0].index;
	bitset_unset(right_leaf_src.bitmap, right_leaf_kventry_pos);
	curr_leaf_src.slot_array[curr->header.numberOfEntriesInNode].index = curr_leaf_kventry_pos;
	curr_leaf_src.kv_entries[curr_leaf_kventry_pos] = right_leaf_src.kv_entries[right_leaf_kventry_pos];
	++curr->header.numberOfEntriesInNode;

	/* Fix the slot array of the right neighbor */
	--right->header.numberOfEntriesInNode;

	key_addr = REAL_ADDRESS(right_leaf_src.kv_entries[right_leaf_src.slot_array[0].index].pointer);
	assert(parent->type != leafNode);

	_index_node_binary_search_posret(req->parent, req->key_buf, KV_FORMAT, &neighbor_metadata);

	if (neighbor_metadata.right_entry == NULL) {
		log_fatal("We are the rightmost node so we cannot borrow from the right leaf");
		assert(0);
	}

	/* Fix the pivot in the parent node */
	__update_index_pivot_in_place(req->metadata.handle, parent, (&neighbor_metadata.right_entry->pivot), key_addr,
				      req->metadata.level_id);
}

/* struct bt_static_leaf_node *curr, struct bt_static_leaf_node *right,
					  level_descriptor *level, bt_delete_request *req*/
void merge_with_right_static_leaf_neighbor(struct bt_static_leaf_node *curr, struct bt_static_leaf_node *right,
					   level_descriptor *level, bt_delete_request *req)
{
	struct bt_static_leaf_structs curr_leaf_src, right_leaf_src;
	struct siblings_index_entries parent_metadata = {
		.left_entry = NULL, .right_entry = NULL, .left_pos = 0, .right_pos = 0
	};
	struct bt_leaf_entry_bitmap *bitmap_end;
	index_node *parent = req->parent;
	uint64_t i, j;
	int curr_leaf_kventry_pos = -1, right_leaf_kventry_pos = -1;

	retrieve_static_leaf_structures(curr, &curr_leaf_src, level);
	retrieve_static_leaf_structures(right, &right_leaf_src, level);
	bitmap_end = curr_leaf_src.bitmap + level->leaf_offsets.bitmap_entries;

	for (i = curr->header.numberOfEntriesInNode, j = 0; j < right->header.numberOfEntriesInNode; ++i, ++j) {
		curr_leaf_kventry_pos = bitset_find_first(curr_leaf_src.bitmap, bitmap_end, 0);
		assert(curr_leaf_kventry_pos >= 0);
		bitset_set(curr_leaf_src.bitmap, curr_leaf_kventry_pos);
		right_leaf_kventry_pos = right_leaf_src.slot_array[j].index;
		curr_leaf_src.slot_array[i].index = curr_leaf_kventry_pos;
		curr_leaf_src.kv_entries[curr_leaf_kventry_pos] = right_leaf_src.kv_entries[right_leaf_kventry_pos];
	}

	curr->header.numberOfEntriesInNode += right->header.numberOfEntriesInNode;

	_index_node_binary_search_posret(parent, req->key_buf, KV_FORMAT, &parent_metadata);

	assert(right == (struct bt_static_leaf_node *)REAL_ADDRESS(parent->p[parent_metadata.right_pos + 1].left[0]));

	if (parent->header.numberOfEntriesInNode == 1) {
		if (parent->header.type == rootNode) {
			curr->header.type = leafRootNode;
			curr->header.height = 0;
			req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.active_tree] =
				(node_header *)curr;
			return;
		}
		assert(0);
	}

	parent->p[parent_metadata.right_pos].pivot = parent->p[parent_metadata.right_pos + 1].pivot;

	memmove(&parent->p[parent_metadata.right_pos + 1], &parent->p[parent_metadata.right_pos + 2],
		(sizeof(index_entry) * (parent->header.numberOfEntriesInNode - (parent_metadata.right_pos + 2))) +
			sizeof(uint64_t));

	--parent->header.numberOfEntriesInNode;

	//In this case we do not have to change anything to the right neighbor
	//nor to change the pivots in our parent.Reclaim the node space here.
}

void merge_with_left_static_leaf_neighbor(struct bt_static_leaf_node *curr, struct bt_static_leaf_node *left,
					  level_descriptor *level, bt_delete_request *req)
{
	struct bt_static_leaf_structs curr_leaf_src, left_leaf_src;
	struct siblings_index_entries parent_metadata = {
		.left_entry = NULL, .right_entry = NULL, .left_pos = 0, .right_pos = 0
	};
	struct bt_leaf_entry_bitmap *bitmap_end;
	index_node *parent = req->parent;
	uint64_t i, j;
	int curr_kventry_pos = -1, left_kventry_pos = -1;
	retrieve_static_leaf_structures(curr, &curr_leaf_src, level);
	retrieve_static_leaf_structures(left, &left_leaf_src, level);
	bitmap_end = curr_leaf_src.bitmap + level->leaf_offsets.bitmap_entries;

	/* First shift the kv pointers + prefixes to make space
	   for the kv pointers + prefixes of the left leaf */
	memmove(&curr_leaf_src.slot_array[left->header.numberOfEntriesInNode], &curr_leaf_src.slot_array[0],
		sizeof(bt_leaf_slot_array) * curr->header.numberOfEntriesInNode);

	/* copy the kv pointers + prefixes from the left leaf */
	for (i = 0; i < left->header.numberOfEntriesInNode; ++i) {
		curr_kventry_pos = bitset_find_first(curr_leaf_src.bitmap, bitmap_end, 0);
		assert(curr_kventry_pos >= 0);
		bitset_set(curr_leaf_src.bitmap, curr_kventry_pos);
		curr_leaf_src.slot_array[i].index = curr_kventry_pos;
		left_kventry_pos = left_leaf_src.slot_array[i].index;
		curr_leaf_src.kv_entries[curr_kventry_pos] = left_leaf_src.kv_entries[left_kventry_pos];
	}

	/* Shift every index entry of the parent to the left
	   to remove the left leaf node from the index*/
	curr->header.numberOfEntriesInNode += left->header.numberOfEntriesInNode;
	_index_node_binary_search_posret(parent, req->key_buf, KV_FORMAT, &parent_metadata);

	if (parent->header.numberOfEntriesInNode == 1) {
		if (parent->header.type == rootNode) {
			curr->header.type = leafRootNode;
			req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.active_tree] =
				(node_header *)curr;
			return;
		}
		assert(0);
	}

	memmove(&parent->p[parent_metadata.left_pos], &parent->p[parent_metadata.left_pos + 1],
		(sizeof(index_entry) * (parent->header.numberOfEntriesInNode - (parent_metadata.left_pos + 1))) +
			sizeof(uint64_t));

	--parent->header.numberOfEntriesInNode;
	/* Free the left leaf node */
}

void delete_key_value_from_static_leaf(struct bt_static_leaf_node *leaf, level_descriptor *level, uint32_t pos)
{
	struct bt_static_leaf_structs leaf_src;
	retrieve_static_leaf_structures(leaf, &leaf_src, level);
	bitset_unset(leaf_src.bitmap, pos);

	if (pos > 0 && pos < (leaf->header.numberOfEntriesInNode - 1)) {
		memmove(&leaf_src.slot_array[pos], &leaf_src.slot_array[pos + 1],
			(leaf->header.numberOfEntriesInNode - (pos + 1)) * sizeof(struct bt_leaf_slot_array));
	} else if (pos == (leaf->header.numberOfEntriesInNode - 1)) {
		/* Key is in the last position of the leaf */
	} else if (pos == 0) {
		/* Key in the first position of the leaf */
		memmove(&leaf_src.slot_array[0], &leaf_src.slot_array[1],
			(leaf->header.numberOfEntriesInNode - 1) * sizeof(struct bt_leaf_slot_array));
	} else {
		log_debug("Error unknown case to delete a KV pair position = %d", pos);
		assert(0);
		exit(EXIT_FAILURE);
	}
}

void validate_static_leaf(uint64_t num_entries, struct bt_leaf_entry_bitmap *bitmap_base,
			  struct bt_leaf_entry_bitmap *bitmap_end)
{
	iter_t iter;
	uint64_t count_set_bits = 0;
	bitset_iterate(&iter);

	while (1)
		switch (bitset_next(bitmap_base, bitmap_end, &iter)) {
		case 1:
			++count_set_bits;
			continue;
		case 0:
			continue;
		case -1:
			return;
		}

	assert(num_entries == count_set_bits);
}

int8_t insert_in_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req, level_descriptor *level)
{
	struct bt_static_leaf_structs src;
	struct splice *key = req->key_value_buf;
	struct bt_leaf_entry_bitmap *bitmap_end;
	struct bsearch_result bsearch;
	int kventry_slot = -1;

	if (unlikely(leaf->header.numberOfEntriesInNode == 0)) {
		init_static_leaf_metadata(leaf, level);
	}

	retrieve_static_leaf_structures(leaf, &src, level);
	bitmap_end = src.bitmap + level->leaf_offsets.bitmap_entries;
	bsearch = binary_search_static_leaf(leaf, level, key);

	switch (bsearch.status) {
	case INSERT:
		shift_slot_array(leaf, bsearch.middle, level);
		kventry_slot = bitset_find_first(src.bitmap, bitmap_end, 0);
		assert(kventry_slot >= 0);
		bitset_set(src.bitmap, kventry_slot);
		src.slot_array[bsearch.middle].index = kventry_slot;
		src.kv_entries[kventry_slot].pointer = ABSOLUTE_ADDRESS(req->key_value_buf);
		memcpy(src.kv_entries[kventry_slot].prefix, key->data, MIN(key->size, PREFIX_SIZE));
		++leaf->header.numberOfEntriesInNode;
		break;
	case FOUND:
		src.kv_entries[src.slot_array[bsearch.middle].index].pointer = ABSOLUTE_ADDRESS(req->key_value_buf);
		memcpy(src.kv_entries[src.slot_array[bsearch.middle].index].prefix, key->data,
		       MIN(key->size, PREFIX_SIZE));
		++leaf->header.fragmentation;
		break;
	default:
		log_info("ERROR");
		exit(EXIT_FAILURE);
	}

	validate_static_leaf(leaf->header.numberOfEntriesInNode, src.bitmap, bitmap_end);

	return 1;
}