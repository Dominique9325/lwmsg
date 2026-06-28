cmake_minimum_required(VERSION 3.14)
project(lwmsg C)

set(CMAKE_C_STANDARD 11)

set(SANITIZE "" CACHE STRING "Sanitizers: a -fsanitize list (e.g. 'address,undefined' or 'thread'), or ON for address,undefined. Empty/OFF = off.")
if(SANITIZE)
    if(SANITIZE MATCHES "^(ON|TRUE|YES|Y|1)$")
        set(SANITIZE_FLAGS "address,undefined")
    else()
        set(SANITIZE_FLAGS "${SANITIZE}")
    endif()
    add_compile_options(-fsanitize=${SANITIZE_FLAGS} -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${SANITIZE_FLAGS})
    message(STATUS "Sanitizers enabled: ${SANITIZE_FLAGS}")
endif()

find_package(json-c REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

find_library(READLINE_LIB readline REQUIRED)
find_path(READLINE_INCLUDE_DIR readline/readline.h REQUIRED)

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
        common/misc.c
        common/misc.h
        common/lwmp.c
        common/lwmp.h
        common/cmdparse.c
        common/cmdparse.h
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
        server/worker.h
        server/thrdmsg_mpscq.c
        server/thrdmsg_mpscq.h
        server/dbops.c
        server/dbops.h)
add_executable(lwmsg-client client/client.c
        client/client.h
        client/clnet.c
        client/clnet.h
        client/clcmd.c
        client/clcmd.h
        client/clrecv.c
        client/clrecv.h
        client/clio.c
        client/clio.h
        common/netwrap.c
        common/netwrap.h
        common/lwmp.c
        common/lwmp.h
        common/cmdparse.c
        common/cmdparse.h
        common/xalloc.c
        common/xalloc.h
        common/util.c
        common/util.h)

target_include_directories(lwmsg-server PRIVATE server common)
target_include_directories(lwmsg-client PRIVATE client common ${READLINE_INCLUDE_DIR})

target_compile_definitions(lwmsg-server PRIVATE LWMSG_SERVER)

target_link_libraries(lwmsg-server ${SERVER_LIBS})
target_link_libraries(lwmsg-client ${COMMON_LIBS} ${READLINE_LIB})
