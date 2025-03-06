#ifndef ST_H_
#define ST_H_
#include <stdint.h>

struct segment_tree *get_new_segment_leaf(void);
struct key *get_key_from_slot(struct segment_tree *node, uint16_t slot_idx);
void *get_value_from_slot(struct segment_tree *node, uint16_t slot_idx);
void add_new_entry_in_leaf(struct segment_tree *leaf_node, struct key *start, void *value, uint16_t slot);
void reset_node_metadata(struct segment_tree *node);
int16_t binary_search_node(struct segment_tree *node, struct key *start);
void add_new_entry_in_index(struct segment_tree *index_node, struct key *start, uint16_t slot,
			    struct segment_tree *left_leaf, struct segment_tree *right_leaf);
struct exact_bsearch_value exact_binary_search_node(struct segment_tree *node, struct key *start);
uint8_t is_node_full(struct segment_tree *node, uint16_t new_range_size);
struct exact_bsearch_value exact_binary_search_node(struct segment_tree *node, struct key *start);
uint16_t calculate_serialized_range_size_in_leaf(struct key *start, void *value);
uint16_t calculate_serialized_range_size_in_index(struct key *start);
typedef struct segment_tree *range_tree;
#endif // ST_H_
