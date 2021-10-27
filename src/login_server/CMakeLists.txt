if (NO_SQL)
  list (APPEND EXTRA_LIBS ssl crypto)
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/login_server")
else ()
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
  find_package(MySQL)

  list (APPEND EXTRA_LIBS ssl crypto ${MYSQL_LIBRARY})
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/login_server")
endif()

add_executable (login_server login_server.c)

target_include_directories (login_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR})

target_link_libraries (login_server PUBLIC ${EXTRA_LIBS})
