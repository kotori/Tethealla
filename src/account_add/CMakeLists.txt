if (NO_SQL)
  list (APPEND EXTRA_LIBS ssl crypto)
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/account_add")
else ()
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
  find_package(MySQL)

  list (APPEND EXTRA_LIBS ssl crypto ${MYSQL_LIBRARY})
  list (APPEND EXTRA_INCLUDES "${PROJECT_SOURCE_DIR}/src/account_add")
endif()

add_executable (account_add account_add.c)

target_include_directories (account_add PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries (account_add PUBLIC ${EXTRA_LIBS})
