// Copyright [2022] [FORTH-ICS]
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

#ifndef PARALLAX_H
#define PARALLAX_H
#ifdef __cplusplus
extern "C" {
#endif
#include "structures.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * Calls the device formatting function of Parallax to initialize the volume's metadata. It does the same job as kv_format.parallax.
 * @param device_name Raw device or file to XFS filesystem. e.g /dev/sdc or $HOME/test.dat
 * @param max_regions_num Maximum regions that will be needed in this deployment it should always be > 1.
 * @return The error message.
 * @retval NULL Function successfully executed. NON-NULL The reason the function failed.
 */
char *par_format(char *device_name, uint32_t max_regions_num) __attribute__((warn_unused_result));

/**
 * Opens a DB based on the options provided.
 * @param db_options User DB options to configure the DB's behavior.
 * @param error_message The reason the call failed.
 * @return Returns a par_handle to perform operations in the DB.
 * @retval NULL The function failed check @p error_message to find the reason it failed. NON-NULL The function ran successfully.
 */
par_handle par_open(par_db_options *db_options, const char **error_message);

/**
 * @brief Return the name of the parallax db
 * @param handle the db handle
 * @param error_message In case of an error it contains the failure reason
 * @return A pointer to a C string containing the db name otherwise NULL
 */
char *par_get_db_name(par_handle handle, const char **error_message);

/**
 * Closes the DB referenced by handle. Syncs data to the file or device before exiting.
 * @param handle Handle returned by \ref par_open.
 * @return Error message in case of failure.
 */

const char *par_close(par_handle handle) __attribute__((warn_unused_result));
/*This will be removed before merging the public api*/
typedef enum par_ret_code {
	PAR_SUCCESS = 0,
	PAR_FAILURE,
	PAR_KEY_NOT_FOUND,
	PAR_GET_NOT_ENOUGH_BUFFER_SPACE
} par_ret_code;

/**
 * Returns the category of the KV based on its key-value size and the operation to perform.
 * @param key_size
 * @param value_size
 * @param operation Operation to execute valid operation insertOp, deleteOp.
 * @param error_message Contains error message if call fails.
 * @return On success return the KV category.
 */
enum kv_category get_kv_category(int32_t key_size, int32_t value_size, request_type operation,
				 const char **error_message);

/**
 * Inserts the key in the DB if it does not exist else this becomes an update internally.
 * @param handle DB handle provided by par_open.
 * @param key_value KV to insert.
 * @param error_message Contains error message if call fails.
 */
struct par_put_metadata par_put(par_handle handle, struct par_key_value *key_value, const char **error_message);

/**
 * Inserts a serialized key value pair by using the buffer provided by the user.
 * @param handle DB handle provided by par_open.
 * @param serialized_key_value is a buffer containing the serialized key value
 * pair. The format of the key value pair is | key_size | key | value_size |
 * value | where {key,value}_size is uint32_t.
 * @param append_to_log True to append to log and False not to append. In case
 * the key-value belongs to the big category it will always be appended to the
 * log.
 * @param error_message Contains error message if call fails.
 * @param abort_on_compaction If set to true the calling thread aborts the
 * operation if it cannot be served due to a pending L0->L1 compaction. If set
 * to false it blocks until L0 is available.
 */
struct par_put_metadata par_put_serialized(par_handle handle, char *serialized_key_value, const char **error_message,
					   bool append_to_log, bool abort_on_compaction);

/**
 * Takes as input a key and searches for it. If the key exists in the DB, then
 * it allocates the value if it is NULL and the client is responsible to release
 * the memory. Otherwise it copies the data to the existing data buffer provided
 * by the value pointer.
 * @param handle DB handle provided by par_open.
 * @param key to be searched.
 * @param value buffer to be filled uppon get success.
 * @param error_message Contains error message if call fails.
 */
void par_get(par_handle handle, struct par_key *key, struct par_value *value, const char **error_message);

/**
 * Takes as input a key and searches for it. If the key exists in the DB, then
 * it allocates the value if it is NULL and the client is responsible to release
 * the memory. Otherwise it copies the data to the existing data buffer provided
 * by the value pointer.
 * @param handle DB handle provided by par_open.
 * @param key_serialized key to be searched.
 * @param value buffer to be filled uppon get success.
 * @param error_message Contains error message if call fails.
 */
void par_get_serialized(par_handle handle, char *key_serialized, struct par_value *value, const char **error_message);

/**
 * Searches for a key and returns if the key exists in the DB.
 */
par_ret_code par_exists(par_handle handle, struct par_key *key);

/**
 * Only for Tebis-Parallax use
 * Takes an in-memory buffer and flushes it to the appropriate log
 * The buffer size must be equal to Parallax's segment size. Also, the buffer must be padded with 0 indicating
 * the "not used" space at the end of a buffer.
 * The DB must be opend in replica mode
 * @param handle: DB handle provided by par_open
 * @param buf: the in-memory buffer to be flushed
 * @param buf_size: the in-memory buffer size
 * @param IO_size: the size of the IO which is the closest ALIGNMENT_SIZE multiple of buf_size
 * @param log_cat: the category of the log to flush into
 */
uint64_t par_flush_segment_in_log(par_handle handle, char *buf, int32_t buf_size, uint32_t IO_size,
				  enum log_category log_cat);
/**
 * Flushes Parallax superblock
 * in order for buffer to be persisted, the buffers must be flushed (par_flush_segment_in_log)
 * @param handle: DB handle proviced by par_open
 */
void par_flush_superblock(par_handle handle);

/**
 * Only for Tebis-Parallax use
 * Every compaction is associated with a transaction ID in Parallax
 * The function initializes a new transaction ID for the upcoming transaction, for the specified level_id & tree_id
 * @param handle: DB handle provided by par_open */
uint64_t par_init_compaction_id(par_handle handle);

/**
 * Deletes an existing key in the DB.
 */
void par_delete(par_handle handle, struct par_key *key, const char **error_message);

/**
 * scanner API. At the current state scanner supports snapshot isolation. The lifetime of a scanner start with
 * a call to par_init_scanner and ends with par_close_scanner. Currently, to provide snapshot isolation during
 * an active scanner no updates or insers can be performed in the DB. We will add other types of scanner with
 * relaxed semantics for higher concurrency soon
 */
par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode, const char **error_message);
void par_close_scanner(par_scanner sc);

/**
 * Advances the scanner iterator to the next key-value.
 */
//TODO Describe return values of this function
int par_get_next(par_scanner sc);

/**
 * Checks the scanner if the current key-value is valid else we reached the end of database.
 */
//TODO Describe return values of this function
int par_is_valid(par_scanner sc);

/**
 * Takes a scanner and returns the current key size + key in the iterator.
 */
struct par_key par_get_key(par_scanner sc);

/**
 * Takes a scanner and returns the current value size + value in the iterator.
 */
struct par_value par_get_value(par_scanner sc);

/**
 * Syncs data to the file or device.
 */
par_ret_code par_sync(par_handle handle);

/**
 * Create, populate and return a buffer containing the default db_options values from option.yml file. Callers can modify the buffer at will.
 * @retval Array with NUM_OF_OPTIONS sizeo of struct options_desc
 */
struct par_options_desc *par_get_default_options(void);

/**
* @brief Returns the maximum KV pair size that Parallax is configured to store
* @return number of bytes of the maximum KV pair size
*/
uint32_t par_get_max_kv_pair_size(void);
#ifdef __cplusplus
}
#endif
#endif // PARALLAX_H
