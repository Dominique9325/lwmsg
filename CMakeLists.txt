cmake_minimum_required(VERSION 3.5)
project(lwmsg C)

set(CMAKE_C_STANDARD 11)
set(LIBS json-c::json-c OpenSSL::SSL OpenSSL::Crypto)


add_executable(lwmsg-server server/server.c
        server/servcfg.c
        server/servcfg.h
        server/thrdctx.c
        server/thrdctx.h
        server/servctrl.c
        server/servctrl.h
        common/netwrap.c
        common/netwrap.h)
add_executable(lwmsg-client client/client.c
        common/netwrap.c
        common/netwrap.h)

target_include_directories(lwmsg-server PRIVATE server)
target_include_directories(lwmsg-client PRIVATE client)

find_package(json-c REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(lwmsg-server ${LIBS})
target_link_libraries(lwmsg-client ${LIBS})
