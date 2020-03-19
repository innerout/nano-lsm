#include "btree.h"

/*functions for index nodes*/
index_node *seg_get_index_node(volume_descriptor *volume_desc, level_descriptor *level_desc, char reason);

index_node *seg_get_index_node_header(volume_descriptor *volume_desc, level_descriptor *level_desc, char reason);

IN_log_header *seg_get_IN_log_block(volume_descriptor *volume_desc, level_descriptor *level_desc, char reason);

void seg_free_index_node_header(volume_descriptor *volume_desc, level_descriptor *level_desc, node_header *);

void seg_free_index_node(volume_descriptor *volume_desc, level_descriptor *level_desc, index_node *inode);

/*function for leaf nodes*/
leaf_node *seg_get_leaf_node(volume_descriptor *volume_desc, level_descriptor *level_desc, char reason);

leaf_node *seg_get_leaf_node_header(volume_descriptor *volume_desc, level_descriptor *level_desc, char reason);

void seg_free_leaf_node(volume_descriptor *volume_desc, level_descriptor *level_desc, leaf_node *leaf);

/*log related*/
segment_header *seg_get_raw_log_segment(volume_descriptor *volume_desc);
void free_raw_segment(volume_descriptor *volume_desc, segment_header *segment);

void *get_space_for_system(volume_descriptor *volume_desc, uint32_t size);

void seg_free_level(db_handle *handle, uint8_t level_id, uint8_t tree_id);
