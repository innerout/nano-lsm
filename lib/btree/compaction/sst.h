#ifndef SST_H
#define SST_H
#include "../btree.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct sst;
struct sst_meta;
struct kv_splice_base;

/**
 *@brief Creates an SST object.
 *@param size size in B of the SST
 *@param txn_id transaction id acquired from redo log of Parallax
 *@param handle database handle this SST belongs to
 *@param level_id id of the level that this SST belongs to
  *@return a pointer to the SST object
*/
struct sst *sst_create(uint32_t size, uint64_t txn_id, db_handle *handle, uint32_t level_id, bool enable_bfs);

/**
 *@brief Appends a kv pair in an SST (assumes that splices arrive in sorted order)
 *@param sst pointer to the sst object
 *@param splice pointer to the splice object
 *@return true on success or false if the SST is out of space (time for a new SST)
*/
bool sst_append_KV_pair(struct sst *sst, struct kv_splice_base *splice);

/**
 *@brief Finalizes and writes the SST to the device.
 *@param sst pointer to the SST object
 *@return true on sucess false on failure
*/
bool sst_flush(struct sst *sst);

/**
 *@brief Releases all memory resources associated with the SST
 *@param sst pointer to the SST object
 *@return true on success false on failure
*/
bool sst_close(struct sst *sst);
//sst meta staff follow

/**
 * @brief Restores the metadata of an sst into memory.
 * @param handle descriptor of the database
 * @param dev_offt offset on the file/device where the SST is
 * @return a pointer to the sst_meta on success NULL on failure
 */
struct sst_meta *sst_meta_restore_from_dev_offt(struct db_handle *handle, uint64_t dev_offt);

/**
  * @brief sst_meta contains all metadata information of an SST. The idea in Parallax
  * is that it creates an SST object, appends splices, flushes it, gets then a reference
  * to the sst_meta object. This contain all information needed for all future read
  * operations.
  * @param sst SST object
  * @return returns a referece to the SST metadata or NULL on failure
*/
struct sst_meta *sst_get_meta(const struct sst *sst);

/**
  * @brief Returns the device offset where the first leaf (or data block)
  * of the SST is.
  * @param sst pointer to the SST object
  * @return a device offset or 0 on failure
*/
uint64_t sst_meta_get_first_leaf_offt(const struct sst_meta *sst);

/**
  * @brief Return a pointer to the first guard.
  * @param sst pointer to the sst_meta object
  * @return a pointer to the first guard or NULL on failure
*/
struct key_splice *sst_meta_get_first_guard(struct sst_meta *sst);

/**
  * @brief Return a pointer to the last guard.
  * @param sst pointer to the sst_meta object
  * @return a pointer to the first guard or NULL on failure
*/
struct key_splice *sst_meta_get_last_guard(struct sst_meta *sst);

/**
  * @brief Returns the device offset where the SST is stored
  * in the device.
  * @param sst pointer to the sst_meta object
  * @return device offset or 0 on failure.
*/
uint64_t sst_meta_get_dev_offt(const struct sst_meta *sst);

/**
  * @brief Returns the id of the level this SST belongs to.
  * @param sst pointer to the sst_meta object
  * @return the id of the level
*/
uint32_t sst_meta_get_level_id(const struct sst_meta *sst);

/**
 *@brief Returns the offset of the root index block of this SST.
 *@param sst pointer to the sst_meta object
 *@return the device offset on success or 0 on failure.
*/
uint64_t sst_meta_get_root_offt(const struct sst_meta *sst);

/**
 *@brief Returns the relative offset with the SST where its first
 * leaf (or data block) is.
 *@param sst pointer to the sst_meta object
 *@return the relative offset or 0 on failure
*/
uint32_t sst_meta_get_first_leaf_relative_offt(const struct sst_meta *sst);

/**
 *@brief Calculates the relative offset of the next leaf (or data block) in the SST.
 *@param offt is an in out variable. Initially it should contain a leaf offset. The
 *function given this information calculates where the next leaf offset is.
 *@param sst_buffer buffer where the SST is stored.
 *@return on success it returns true and off is set with the corresponding offset.
 * Otherwise it returns false (no more data blocks in the SST)
*/
bool sst_meta_get_next_relative_leaf_offt(struct sst_meta *sst_meta, uint32_t *offt);

bool sst_key_exists(const struct sst_meta *sst, struct key_splice *key_splice);

struct sst_meta *sst_meta_recover(uint64_t dev_offt);

bool sst_meta_destroy(struct sst_meta *meta);

uint32_t sst_meta_get_size(void);

#endif
