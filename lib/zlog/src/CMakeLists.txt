aux_source_directory(. SRCS)

add_library(zlog STATIC ${SRCS})
target_link_libraries(zlog pthread)
target_include_directories(zlog PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
