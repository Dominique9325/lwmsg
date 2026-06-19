cmake_minimum_required(VERSION 3.14)
project(lwmsg C)

set(CMAKE_C_STANDARD 11)
find_package(json-c REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

add_subdirectory(lib/zlog/src)

set(COMMON_LIBS json-c::json-c OpenSSL::SSL OpenSSL::Crypto)
set(SERVER_LIBS ${COMMON_LIBS} SQLite::SQLite3 zlog)


add_executable(lwmsg-server server/server.c
        server/servcfg.c
        server/servcfg.h
        server/thrdctx.c
        server/thrdctx.h
        server/servctrl.c
        server/servctrl.h
        common/netwrap.c
        common/netwrap.h
        server/clhandle.c
        server/clhandle.h
        server/htable.c
        server/htable.h
        server/misc.c
        server/misc.h
        common/lwmp.c
        common/lwmp.h
        server/registration.c
        server/registration.h
        server/cltimerheap.c
        server/cltimerheap.h
        common/xalloc.c
        common/xalloc.h
        server/ipblock.c
        server/ipblock.h
        common/util.c
        common/util.h
        server/worker.c
        server/worker.h)
add_executable(lwmsg-client client/client.c
        common/netwrap.c
        common/netwrap.h
        common/lwmp.c
        common/lwmp.h
        common/xalloc.c
        common/xalloc.h
        common/util.c
        common/util.h)

target_include_directories(lwmsg-server PRIVATE server common)
target_include_directories(lwmsg-client PRIVATE client common)

target_link_libraries(lwmsg-server ${SERVER_LIBS})
target_link_libraries(lwmsg-client ${COMMON_LIBS})
