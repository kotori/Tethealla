if (NO_SQL)
  list (APPEND EXTRA_LIBS ssl crypto)
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/char_export")
else ()
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
  find_package(MySQL)

  list (APPEND EXTRA_LIBS ssl crypto ${MYSQL_LIBRARY})
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/char_export")
endif()

add_executable (char_export char_export.c)

target_include_directories (char_export PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries (char_export PUBLIC ${EXTRA_LIBS})
