#ifndef PERSISTENT_OPERATIONS_H_
#define PERSISTENT_OPERATIONS_H_

#include "../btree/btree.h"
#include <stdint.h>
/**
 * Returns number of garbage entries detected during the recovery of the redo undo log.
 */
uint32_t get_garbage_entries(void);

/**
 * Returns garbage bytes detected during the recovery of the redo undo log.
 */
uint32_t get_garbage_bytes(void);

/**
 * Triggers the counting for blobs garbage bytes when recovering redo_undo_log.
 */
void enable_validation_garbage_bytes(void);

/**
 * Disables the counting for blobs garbage bytes when recovering redo_undo_log.
 */
void disable_validation_garbage_bytes(void);

/**
 * Persists L0 key value pairs in storage making it recoverable.
 * in L0 during a compaction operation from L0 to L1. As a result, valid tree_id
 * values are from 0 to NUM_TREES_PER_LEVEL-1.
 * @param db_desc is the descriptor of the db
 * @param tree_id The id of the tree in L0. Parallax performs double buffering
 */
void pr_flush_L0(struct db_descriptor *db_desc, uint8_t tree_id);

void pr_flush_log_tail(struct db_descriptor *db_desc, struct log_descriptor *log_desc);

void pr_read_db_superblock(struct db_descriptor *db_desc);

void pr_flush_db_superblock(struct db_descriptor *db_desc);

void pr_lock_db_superblock(struct db_descriptor *db_desc);

void pr_unlock_db_superblock(struct db_descriptor *db_desc);

/**
 * Persists the results of a compaction from Li to Li+1 where i >= 1.
 * @param db_desc the descriptor of the database @param level_id the id of
 * level i+1
 * @param tree_id
 */
void pr_flush_compaction(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id);

void recover_L0(struct db_descriptor *db_desc);
#endif // PERSISTENT_OPERATIONS_H_
