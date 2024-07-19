set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(LIB_SERVER "${PROJECT_NAME}_server")

set(SERVER_SOURCE_FILES
    ../lib/allocator/allocator.c
    ../lib/allocator/log_structures.c
    ../lib/allocator/kv_format.c
    ../lib/allocator/region_log.c
    ../lib/allocator/persistent_operations.c
    ../lib/allocator/djb2.c
    ../lib/btree/btree.c
    ../lib/btree/index_node.c
    ../lib/btree/compaction/compaction_daemon.c
    ../lib/btree/compaction/compaction_worker.c
    ../lib/btree/compaction/bloom_filter.c
    ../lib/btree/dynamic_leaf.c
    ../lib/btree/compaction/device_level.c
    ../lib/btree/compaction/dev_leaf.c
    ../lib/btree/compaction/fractal_leaf.c
    ../lib/btree/compaction/fractal_index.c
    ../lib/btree/compaction/dev_index.c
    ../lib/btree/compaction/sst.c
    ../lib/btree/compaction/threadpool.c
    ../lib/btree/gc.c
    ../lib/btree/medium_log_LRU_cache.c
    ../lib/btree/segment_allocator.c
    ../lib/btree/set_options.c
    ../lib/btree/kv_pairs.c
    ../lib/btree/key_splice.c
    ../lib/btree/lsn.c
    ../lib/common/common.c
    ../lib/scanner/min_max_heap.c
    ../lib/scanner/scanner.c
    ../lib/scanner/L0_scanner.c
    ../lib/scanner/stack.c
    ../lib/parallax_callbacks/parallax_callbacks.c
    ../lib/api/parallax_client_lib.c
    server/arg_parser.c
    server/server_handle.c
    par_net/par_net_put.c
    par_net/par_net_open.c
    par_net/par_net_delete.c
    par_net/par_net_get.c)

list(APPEND SERVER_SOURCE_FILES
     "$CACHE{parallax_SOURCE_DIR}/utilities/spin_loop.c")
list(APPEND SERVER_SOURCE_FILES "$CACHE{parallax_SOURCE_DIR}/utilities/list.c")
list(APPEND SERVER_SOURCE_FILES
     "$CACHE{parallax_SOURCE_DIR}/utilities/dups_list.c")

add_library(${LIB_SERVER} ${SERVER_SOURCE_FILES})

set_target_properties(
  ${LIB_SERVER}
  PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_INSTALL_LIBDIR}"
             LIBRARY_OUTPUT_DIRECTORY "${CMAKE_INSTALL_LIBDIR}"
             PUBLIC_HEADER
             "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include/parallax/parallax.h")

target_link_libraries(${LIB_SERVER} ${DEPENDENCIES})
target_include_directories(${LIB_SERVER}
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include/")
target_include_directories(${LIB_SERVER}
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../lib/")
