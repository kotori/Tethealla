set (HEADER_FILES ${PROJECT_SOURCE_DIR}/src/login_server/pso_crypt.h )

add_executable(ship_server ship_server.c ${HEADER_FILES})

target_include_directories (ship_server PUBLIC
			    "${CMAKE_CURRENT_SOURCE_DIR}"
                            "${PROJECT_SOURCE_DIR}"
                           )

