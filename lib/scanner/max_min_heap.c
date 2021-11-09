/*
        File:   minHeap.c
        Desc:   Program showing various operations on a binary min heap
        Author: Robin Thomas <robinthomas2591@gmail.com>
        Edited by Giorgos Saloustros (gesalous@ics.forth.gr) 21/07/2017
*/

#include <stdlib.h>
#include <assert.h>
#include <log.h>
#include "max_min_heap.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../../utilities/dups_list.h"

#define LCHILD(x) ((2 * x) + 1)
#define RCHILD(x) ((2 * x) + 2)
#define PARENT(x) ((x - 1) / 2)

static int sh_cmp_max_heap_nodes(struct sh_max_heap *hp, struct sh_max_heap_node *nd_1, struct sh_max_heap_node *nd_2);

/*Allocate a max heap using dynamic memory and zero initialize it */
struct sh_max_heap *sh_alloc_max_heap(void)
{
	struct sh_max_heap *new_heap = calloc(1, sizeof(struct sh_max_heap));
	if (!new_heap) {
		log_fatal("Calloc failed");
		exit(EXIT_FAILURE);
	}
	new_heap->dups = init_dups_list();
	return new_heap;
}

/*
 * Function to initialize the max heap
 */
void sh_init_max_heap(struct sh_max_heap *heap, int active_tree)
{
	heap->heap_size = 0;
	heap->dups = init_dups_list();
	(void)active_tree;
	heap->active_tree = -1;
}

/*Destroy a max heap that was allocated using dynamic memory */
void sh_destroy_max_heap(struct sh_max_heap *heap)
{
	free_dups_list(&heap->dups);
	free(heap);
}

/*
    Heapify function is used to make sure that the heap property is never
   violated
    In case of deletion of a heap_node, or creating a max heap from an array,
   heap property
    may be violated. In such cases, heapify function can be called to make sure
   that
    heap property is never violated
*/
static inline void heapify_max(struct sh_max_heap *hp, int i)
{
	int biggest = i;
	if (LCHILD(i) < hp->heap_size && sh_cmp_max_heap_nodes(hp, &hp->elem[LCHILD(i)], &hp->elem[i]) > 0)
		biggest = LCHILD(i);
	if (RCHILD(i) < hp->heap_size && sh_cmp_max_heap_nodes(hp, &hp->elem[RCHILD(i)], &hp->elem[biggest]) > 0)
		biggest = RCHILD(i);

	if (biggest != i) {
		// swap(&(hp->elem[i]), &(hp->elem[smallest]))
		struct sh_max_heap_node temp = hp->elem[i];
		hp->elem[i] = hp->elem[biggest];
		hp->elem[biggest] = temp;
		heapify_max(hp, biggest);
	}
}

static void push_back_duplicate_kv(struct sh_max_heap *heap, struct sh_max_heap_node *hp_node)
{
	if (hp_node->cat == BIG_INLOG) {
		struct bt_leaf_entry *keyvalue = hp_node->KV;
		uint64_t segment_offset =
			ABSOLUTE_ADDRESS(keyvalue->pointer) - (ABSOLUTE_ADDRESS(keyvalue->pointer) % SEGMENT_SIZE);
		char *kv = (char *)keyvalue->pointer;
		uint32_t key_size = *(uint32_t *)kv;
		assert(key_size < MAX_KEY_SIZE);
		uint32_t value_size = *(uint32_t *)(kv + sizeof(uint32_t) + key_size);
		struct dups_node *node = find_element(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset));

		if (node)
			node->kv_size += key_size + value_size + (sizeof(uint32_t) * 2);
		else
			append_node(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset),
				    key_size + value_size + (sizeof(uint32_t) * 2));
	}
}

static int sh_cmp_max_heap_nodes(struct sh_max_heap *hp, struct sh_max_heap_node *nd_1, struct sh_max_heap_node *nd_2)
{
	int64_t ret;

	struct bt_kv_log_address L1 = { .addr = NULL, .in_tail = 0, .tail_id = UINT8_MAX };
	struct bt_leaf_entry my_b1 = { .prefix = { 0 }, .pointer = 0 };
	char *old_pointer_nd1 = NULL;
	struct bt_kv_log_address L2 = { .addr = NULL, .in_tail = 0, .tail_id = UINT8_MAX };
	struct bt_leaf_entry my_b2 = { .prefix = { 0 }, .pointer = 0 };
	char *old_pointer_nd2 = NULL;

	switch (nd_1->cat) {
	case BIG_INLOG:
		if (!nd_1->level_id) {
			struct bt_leaf_entry *b1 = (struct bt_leaf_entry *)nd_1->KV;
			L1 = bt_get_kv_log_address(&nd_1->db_desc->big_log, ABSOLUTE_ADDRESS(b1->pointer));
			if (L1.in_tail) {
				my_b1 = *b1;
				my_b1.pointer = (uint64_t)L1.addr;
				old_pointer_nd1 = nd_1->KV;
				nd_1->KV = &my_b1;
			}
		}
		break;
#if MEDIUM_LOG_UNSORTED
	case MEDIUM_INLOG:
		if (!nd_1->level_id) {
			struct bt_leaf_entry *b1 = (struct bt_leaf_entry *)nd_1->KV;
			L1 = bt_get_kv_log_address(&nd_1->db_desc->medium_log, ABSOLUTE_ADDRESS(b1->pointer));
			if (L1.in_tail) {
				my_b1 = *b1;
				my_b1.pointer = (uint64_t)L1.addr;
				old_pointer_nd1 = nd_1->KV;
				nd_1->KV = &my_b1;
			}
		}
		break;
#endif
	default:
		break;
	}
	switch (nd_2->cat) {
	case BIG_INLOG:
		if (!nd_2->level_id) {
			struct bt_leaf_entry *b2 = (struct bt_leaf_entry *)nd_2->KV;
			L2 = bt_get_kv_log_address(&nd_2->db_desc->big_log, ABSOLUTE_ADDRESS(b2->pointer));
			if (L2.in_tail) {
				my_b2 = *b2;
				my_b2.pointer = (uint64_t)L2.addr;
				old_pointer_nd2 = nd_2->KV;
				nd_2->KV = &my_b2;
			}
		}
		break;
#if MEDIUM_LOG_UNSORTED
	case MEDIUM_INLOG:
		if (!nd_2->level_id) {
			struct bt_leaf_entry *b2 = (struct bt_leaf_entry *)nd_2->KV;
			L2 = bt_get_kv_log_address(&nd_2->db_desc->medium_log, ABSOLUTE_ADDRESS(b2->pointer));
			if (L2.in_tail) {
				my_b2 = *b2;
				my_b2.pointer = (uint64_t)L2.addr;
				old_pointer_nd2 = nd_2->KV;
				nd_2->KV = &my_b2;
			}
		}
		break;
#endif
	default:
		break;
	}

	ret = key_cmp(nd_1->KV, nd_2->KV, nd_1->type, nd_2->type);

	if (L1.in_tail) {
		switch (nd_1->cat) {
		case BIG_INLOG:
			bt_done_with_value_log_address(&nd_1->db_desc->big_log, &L1);
			break;
#if MEDIUM_LOG_UNSORTED
		case MEDIUM_INLOG:
			bt_done_with_value_log_address(&nd_1->db_desc->medium_log, &L1);
			break;
#endif
		default:
			log_fatal("Wrong category/faulty state cat = %d", nd_1->cat);
			assert(0);
			exit(EXIT_FAILURE);
		}
		nd_1->KV = old_pointer_nd1;
	}

	if (L2.in_tail) {
		switch (nd_2->cat) {
		case BIG_INLOG:
			bt_done_with_value_log_address(&nd_2->db_desc->big_log, &L2);
			break;
#if MEDIUM_LOG_UNSORTED
		case MEDIUM_INLOG:
			bt_done_with_value_log_address(&nd_2->db_desc->medium_log, &L2);
			break;
#endif
			break;
		default:
			log_fatal("Wrong category/faulty state");
			exit(EXIT_FAILURE);
		}
		nd_2->KV = old_pointer_nd2;
	}

	if (ret == 0) {
		/* duplicate detected smallest level_id wins, needs more thinking */
		if (nd_1->level_id == hp->active_tree) {
			nd_2->duplicate = 1;
			push_back_duplicate_kv(hp, nd_2);
			return 1;
		} else if (nd_2->level_id == hp->active_tree) {
			nd_1->duplicate = 1;
			push_back_duplicate_kv(hp, nd_1);
			return -1;
		}
		if (nd_1->level_id < nd_2->level_id) {
			nd_2->duplicate = 1;
			push_back_duplicate_kv(hp, nd_2);
			return 1;
		} else if (nd_1->level_id > nd_2->level_id) {
			nd_1->duplicate = 1;
			push_back_duplicate_kv(hp, nd_1);
			return -1;
		} else {
			log_fatal("Cannot resolve tie active tree = %d nd_1 level_id = %d nd_2 "
				  "level_id = %d",
				  hp->active_tree, nd_1->level_id, nd_2->level_id);
			exit(EXIT_FAILURE);
		}
	}
	return ret;
}

/*
    Function to insert a heap_node into the max heap, by allocating space for
   that heap_node in the
    heap and also making sure that the heap property and shape propety are never
   violated.
*/
void sh_insert_max_heap_node(struct sh_max_heap *hp, struct sh_max_heap_node *nd)
{
	int i;

	nd->duplicate = 0;
	if (hp->heap_size > HEAP_SIZE) {
		log_fatal("max max heap out of space resize heap accordingly");
		exit(EXIT_FAILURE);
	}

	i = hp->heap_size++;
	while (i && sh_cmp_max_heap_nodes(hp, nd, &(hp->elem[PARENT(i)])) > 0) {
		hp->elem[i] = hp->elem[PARENT(i)];
		// hp->elem[i].data = hp->elem[PARENT(i)].data;
		// hp->elem[i].level_id = hp->elem[PARENT(i)].level_id;
		// hp->elem[i].duplicate = hp->elem[PARENT(i)].duplicate;
		i = PARENT(i);
	}

	hp->elem[i] = *nd;
}

enum sh_max_heap_status sh_remove_max(struct sh_max_heap *hp, struct sh_max_heap_node *heap_node)
{
	if (hp->heap_size) {
		*heap_node = hp->elem[0];
		//log_info("key is %s",heap_node->data+4);

		if (hp->heap_size == 1) { // fast path
			hp->heap_size = 0;
		} else {
			hp->elem[0] = hp->elem[--hp->heap_size];
			heapify_max(hp, 0);
		}
		return GOT_MAX_HEAP;
	} else
		return EMPTY_MAX_HEAP;
}