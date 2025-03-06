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
#include "compaction_daemon.h"
#include "../../allocator/device_structures.h"
#include "../../allocator/log_structures.h"
#include "../../allocator/persistent_operations.h"
#include "../../allocator/region_log.h"
#include "../../common/common.h"
#include "../../parallax_callbacks/parallax_callbacks.h"
#include "../btree.h"
#include "../conf.h"
#include "compaction_worker.h"
#include "device_level.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <pthread.h>
#include <semaphore.h>
#include <spin_loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// IWYU pragma: no_forward_declare index_node

struct compaction_daemon {
	pthread_mutex_t barrier_lock;
	pthread_cond_t barrier;
	sem_t compaction_daemon_interrupts;
	db_handle *db_handle;
	int next_L0_tree_to_compact;
	bool do_not_issue_L0_compactions;
};

struct compaction_daemon *compactiond_create(struct db_handle *handle, bool do_not_issue_L0_compactions)
{
	struct compaction_daemon *daemon = calloc(1UL, sizeof(struct compaction_daemon));
	daemon->db_handle = handle;
	daemon->do_not_issue_L0_compactions = do_not_issue_L0_compactions;
	daemon->next_L0_tree_to_compact = 0;
	pthread_mutex_init(&daemon->barrier_lock, NULL);
	sem_init(&daemon->compaction_daemon_interrupts, 0, 0);
	pthread_cond_init(&daemon->barrier, NULL);
	return daemon;
}

static struct compaction_request *compactiond_compact_L0(struct compaction_daemon *daemon, uint8_t L0_tree_id,
							 uint8_t L1_tree_id)
{
	struct LSM_tree_descriptor *tree_descriptor = NULL;
	assert(tree_descriptor);
	struct L0_descriptor *level_0 = &tree_descriptor->L0;
	struct device_level *level_1 = tree_descriptor->dev_levels[1];

	for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
		if (level_0->tree_status[i] == BT_COMPACTION_IN_PROGRESS) {
			log_trace("Not compacting L0 due to %u being compacted", i);
			return NULL;
		}
	}
	L0_tree_id = level_0->active_tree;
	if (level_0->tree_status[L0_tree_id] != BT_NO_COMPACTION) {
		log_trace("Not compacting L0 due to %u being compacted", L0_tree_id);
		return NULL;
	}

	if (level_0->level_size[L0_tree_id] < level_0->max_level_size) {
		log_trace("Level 0 is not yet full %u", L0_tree_id);
		return NULL;
	}

	if (level_is_compacting(level_1)) {
		log_trace("Not compacting L0 Level 1 is compacting");
		return NULL;
	}

	if (level_has_overflow(level_1, L1_tree_id)) {
		log_trace("Level 1 is full cannot compact L0");
		return NULL;
	}

	bt_set_db_status(daemon->db_handle->db_desc, level_0, BT_COMPACTION_IN_PROGRESS, 0, L0_tree_id);
	level_set_comp_in_progress(level_1);

	/*start a compaction*/
	return compaction_create_req(daemon->db_handle->db_desc, &daemon->db_handle->db_options, UINT64_MAX, UINT64_MAX,
				     0, L0_tree_id, 1, 1);
}

static void *compactiond_run(void *args)
{
	struct compaction_daemon *daemon = (struct compaction_daemon *)args;
	assert(daemon);
	struct db_handle *handle = daemon->db_handle;
	struct db_descriptor *db_desc = handle->db_desc;
	struct compaction_request *comp_req = NULL;
	pthread_setname_np(pthread_self(), "compactiond");
	// TODO(gxanth): Think about how the compaction daemon will find out about new compactions
	struct LSM_tree_descriptor *tree_descriptor = NULL;
	while (1) {
		if (!tree_descriptor)
			continue;
	start:
		sleep(1);
		// if a level is being compacted continue
		for (uint8_t level_id = 1; level_id < MAX_LEVELS; ++level_id) {
			if (level_is_compacting(tree_descriptor->dev_levels[level_id])) {
				goto start;
			}
		}
		// check if L0 is compacting
		for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
			if (tree_descriptor->L0.tree_status[i] == BT_COMPACTION_IN_PROGRESS) {
				goto start;
			}
		}
		// if all level0 trees are empty wakeup clients
		bool L0_is_empty = true;
		for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
			if (tree_descriptor->L0.level_size[i] > 0) {
				L0_is_empty = false;
				break;
			}
		}

		if (L0_is_empty && !db_desc->split_in_action && db_desc->writes_enabled) {
			MUTEX_LOCK(&daemon->barrier_lock);
			if (pthread_cond_broadcast(&daemon->barrier) != 0) {
				log_fatal("Failed to wake up stopped clients");
				BUG_ON();
			}
			MUTEX_UNLOCK(&daemon->barrier_lock);
		}
		// sem_wait(&daemon->compaction_daemon_interrupts);
		if (db_desc->db_state == DB_TERMINATE_COMPACTION_DAEMON) {
			log_warn("Compaction daemon instructed to exit because DB %s is closing, "
				 "Bye bye!...",
				 db_desc->db_superblock->db_name);
			db_desc->db_state = DB_IS_CLOSING;
			return NULL;
		}

		comp_req = compactiond_compact_L0(daemon, daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL, 0);
		if (comp_req)
			++daemon->next_L0_tree_to_compact;

		int active_tree = tree_descriptor->L0.active_tree;
		if (tree_descriptor->L0.tree_status[active_tree] == BT_COMPACTION_IN_PROGRESS) {
			uint8_t next_active_tree = active_tree < NUM_TREES_PER_LEVEL - 1 ? active_tree + 1 : 0;
			if (tree_descriptor->L0.tree_status[next_active_tree] == BT_NO_COMPACTION) {
				/*Acquire guard lock and wait writers to finish*/
				if (RWLOCK_WRLOCK(&tree_descriptor->L0.guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}
				spin_loop(&(tree_descriptor->L0.active_operations), 0);
				/*fill L0 recovery log  info*/
				db_desc->small_log_start_segment_dev_offt = db_desc->small_log.tail_dev_offt;
				log_debug("Setting db_desc->small_log_start_segment_dev_offt to %lu",
					  db_desc->small_log.tail_dev_offt);
				db_desc->small_log_start_offt_in_segment = db_desc->small_log.size % SEGMENT_SIZE;

				/*fill big log recovery  info*/
				db_desc->big_log_start_segment_dev_offt = db_desc->big_log.tail_dev_offt;
				db_desc->big_log_start_offt_in_segment = db_desc->big_log.size % SEGMENT_SIZE;
				/*done now atomically change active tree*/

				tree_descriptor->L0.active_tree = next_active_tree;
				tree_descriptor->L0.scanner_epoch += 1;
				tree_descriptor->L0.epoch[active_tree] = tree_descriptor->L0.scanner_epoch;
				log_debug("Next active tree %u for L0 of DB: %s", next_active_tree,
					  db_desc->db_superblock->db_name);
				/*Acquire a new transaction id for the next_active_tree*/
				tree_descriptor->L0.allocation_txn_id[next_active_tree] = regl_start_txn(db_desc);
				/*Release guard lock*/
				if (RWLOCK_UNLOCK(&tree_descriptor->L0.guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}

				MUTEX_LOCK(&daemon->barrier_lock);
				if (pthread_cond_broadcast(&daemon->barrier) != 0) {
					log_fatal("Failed to wake up stopped clients");
					BUG_ON();
				}
				MUTEX_UNLOCK(&daemon->barrier_lock);
			}
		}

		if (comp_req) {
			/*Start a compaction from L0 to L1. Flush L0 prior to compaction from L0 to L1*/
			log_debug("Flushing L0 for region:%s tree:[0][%u]", db_desc->db_superblock->db_name,
				  compaction_get_src_tree(comp_req));
			pr_flush_L0(db_desc, &tree_descriptor->L0, compaction_get_src_tree(comp_req));
			compaction_set_dst_tree(comp_req, 1);
			assert(tree_descriptor->L0.root[compaction_get_src_tree(comp_req)] != NULL);

			parallax_callbacks_t par_callbacks = db_desc->parallax_callbacks;
			if (are_parallax_callbacks_set(par_callbacks) &&
			    handle->db_options.options[PRIMARY_MODE].value) {
				struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
				void *context = parallax_get_context(par_callbacks);
				if (par_cb.build_index_L0_compaction_started_cb)
					par_cb.build_index_L0_compaction_started_cb(context);
			}

			if (pthread_create(&tree_descriptor->L0.compaction_thread[compaction_get_src_tree(comp_req)],
					   NULL, compaction, comp_req) != 0) {
				log_fatal("Failed to start compaction");
				BUG_ON();
			}
			comp_req = NULL;
			goto start;
		}

		bool split_LSM = true;
		for (uint8_t level_id = 1; level_id < MAX_LEVELS; ++level_id) {
			bool level_compacting = level_is_compacting(tree_descriptor->dev_levels[level_id]);
			bool level_overflow = level_has_overflow(tree_descriptor->dev_levels[level_id], 0);
			if (level_id == MAX_LEVELS - 1) {
				level_overflow = last_level_has_overflow(tree_descriptor->dev_levels[level_id], 0,
									 tree_descriptor->dev_levels[level_id - 1]);
			}

			if (level_compacting || !level_overflow) {
				split_LSM = false;
				break;
			}
		}
		// finally check if L0 is full
		if (tree_descriptor->L0.level_size[daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL] <
		    tree_descriptor->L0.max_level_size) {
			split_LSM = false;
		}
		for (uint8_t i = 0; i < NUM_TREES_PER_LEVEL; i++) {
			if (tree_descriptor->L0.tree_status[i] == BT_COMPACTION_IN_PROGRESS) {
				split_LSM = false;
				break;
			}
		}
		active_tree = tree_descriptor->L0.active_tree;
		if (split_LSM) {
			//print level sizes
			log_trace(
				"L0 size %lu",
				tree_descriptor->L0.level_size[daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL]);
			for (uint8_t i = 1; i < MAX_LEVELS; i++) {
				log_trace("Level %u size: %lu", i, level_get_size(tree_descriptor->dev_levels[i], 0));
			}
			log_trace("Splitting LSM tree for L0 tree id %u",
				  daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL);
			uint8_t next_L0_tree = active_tree; //daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL;
			struct compaction_request *split_comp_req =
				compaction_create_req(db_desc, &handle->db_options, UINT64_MAX, UINT64_MAX, 0,
						      next_L0_tree, MAX_LEVELS - 1, 1);

			assert(tree_descriptor->L0.tree_status[next_L0_tree] == BT_NO_COMPACTION);
			/*Acquire guard lock and wait writers to finish*/
			if (RWLOCK_WRLOCK(&tree_descriptor->L0.guard_of_level.rx_lock)) {
				log_fatal("Failed to acquire guard lock");
				BUG_ON();
			}
			spin_loop(&(tree_descriptor->L0.active_operations), 0);
			db_desc->writes_enabled = false;
			db_desc->split_in_action = true;
			bt_set_db_status(daemon->db_handle->db_desc, &tree_descriptor->L0, BT_COMPACTION_IN_PROGRESS, 0,
					 next_L0_tree);
			if (RWLOCK_UNLOCK(&tree_descriptor->L0.guard_of_level.rx_lock)) {
				log_fatal("Failed to release guard lock");
				BUG_ON();
			}
			for (uint8_t level_id = 1; level_id < MAX_LEVELS; ++level_id) {
				assert(level_is_compacting(tree_descriptor->dev_levels[level_id]) == false);
				level_set_comp_in_progress(tree_descriptor->dev_levels[level_id]);
			}
			compaction_set_dst_tree(split_comp_req, 1);
			++daemon->next_L0_tree_to_compact;
			level_start_comp_thread(tree_descriptor->dev_levels[MAX_LEVELS - 1], compaction,
						split_comp_req);
			goto start;
		}

		// rest of levels
		for (uint8_t level_id = 1; level_id < MAX_LEVELS - 1; ++level_id) {
			struct device_level *src_level = tree_descriptor->dev_levels[level_id];
			struct device_level *dst_level = tree_descriptor->dev_levels[level_id + 1];

			if (false == level_has_overflow(src_level, 0)) {
				log_trace("src level is not full %d", level_id);
				continue;
			}
			if (true == level_has_overflow(dst_level, 0)) {
				log_trace("Dest level is full %d", level_id + 1);
				continue;
			}
			if (level_is_compacting(src_level)) {
				log_trace("src level is compacting %d", level_id);
				continue;
			}
			if (level_is_compacting(dst_level)) {
				log_trace("dst level is compacting %d", level_id + 1);
				continue;
			}
			log_trace("Compacting level %d to %d", level_id, level_id + 1);
			level_set_comp_in_progress(tree_descriptor->dev_levels[level_id]);
			level_set_comp_in_progress(tree_descriptor->dev_levels[level_id + 1]);

			//compaction request will get a txn in its constructor
			struct compaction_request *comp_req_p = compaction_create_req(
				db_desc, &handle->db_options, UINT64_MAX, UINT64_MAX, level_id, 0, level_id + 1, 1);
			level_start_comp_thread(tree_descriptor->dev_levels[compaction_get_dst_level(comp_req_p)],
						compaction, comp_req_p);
			break;
		}
	}
}

bool compactiond_start(struct compaction_daemon *daemon, pthread_t *context)
{
	assert(daemon && context);
	if (pthread_create(context, NULL, compactiond_run, daemon) != 0) {
		log_fatal("Failed to start compaction_daemon for db %s", daemon->db_handle->db_options.db_name);
		BUG_ON();
	}
	return true;
}

void compactiond_wait(struct compaction_daemon *daemon)
{
	MUTEX_LOCK(&daemon->barrier_lock);

	if (pthread_cond_wait(&daemon->barrier, &daemon->barrier_lock) != 0) {
		log_fatal("failed to throttle");
		BUG_ON();
	}
	MUTEX_UNLOCK(&daemon->barrier_lock);
}

void compactiond_notify_all(struct compaction_daemon *daemon)
{
	assert(daemon);
	MUTEX_LOCK(&daemon->barrier_lock);
	if (pthread_cond_broadcast(&daemon->barrier) != 0) {
		log_fatal("Failed to wake up stopped clients");
		BUG_ON();
	}
	MUTEX_UNLOCK(&daemon->barrier_lock);
}

void compactiond_interrupt(struct compaction_daemon *daemon)
{
	assert(daemon);
	sem_post(&daemon->compaction_daemon_interrupts);
}

void compactiond_close(struct compaction_daemon *daemon)
{
	assert(daemon);
	if (pthread_cond_destroy(&daemon->barrier) != 0) {
		log_fatal("Failed to destroy condition variable");
		perror("pthread_cond_destroy() error");
		BUG_ON();
	}
	free(daemon);
}

// cppcheck-suppress unusedFunction
void compactiond_force_L0_compaction(struct compaction_daemon *daemon, struct L0_descriptor *L0)
{
	assert(daemon);
	struct L0_descriptor *level_0 = L0;
	int tree_id = daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL;
	level_0->level_size[tree_id] = level_0->max_level_size;
	compactiond_interrupt(daemon);
}
