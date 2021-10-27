add_executable (convert_unitxt convert_unitxt.c)

target_include_directories (convert_unitxt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR})
#target_include_directories (convert_unitxt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
