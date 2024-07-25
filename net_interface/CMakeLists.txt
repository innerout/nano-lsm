set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(NET_LIB "${PROJECT_NAME}_net_lib")

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(NET_LIB_SOURCE_FILES
    par_net/par_net_put.c
    par_net/par_net_open.c
    par_net/par_net_delete.c
    par_net/par_net_get.c
    par_net/par_net_close.c
    ../lib/api/parallax_client_lib.c
    ../lib/btree/key_splice.c
    ../lib/btree/set_options.c
    ../lib/common/common.c)

add_library(${NET_LIB} SHARED ${NET_LIB_SOURCE_FILES})

set_target_properties(${NET_LIB} PROPERTIES 
    PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include/parallax/parallax.h")

target_include_directories(${NET_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include")

target_link_libraries(${NET_LIB} log yaml)

install(
  TARGETS ${NET_LIB}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
