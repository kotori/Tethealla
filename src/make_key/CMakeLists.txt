if (NO_SQL)
  list (APPEND EXTRA_LIBS ssl crypto)
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/make_key")
else ()
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
  find_package(MySQL)

  list (APPEND EXTRA_LIBS ssl crypto ${MYSQL_LIBRARY})
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/make_key")
endif()

add_executable (make_key make_key.c)

target_include_directories (make_key PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${EXTRA_INCLUDES})

target_link_libraries (make_key PUBLIC ${EXTRA_LIBS})
