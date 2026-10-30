add_executable(quokka_unit_tests unit_tests.cpp)
target_link_libraries(quokka_unit_tests PRIVATE quokka_core)
add_test(NAME unit COMMAND quokka_unit_tests)

add_executable(quokka_rogue_client rogue_client.cpp)
target_link_libraries(quokka_rogue_client PRIVATE quokka_core)

# Злой узел: тот же код с хуками атаки (QUOKKA_TEST_HOOKS). В обычную сборку они не попадают.
list(TRANSFORM QUOKKA_CORE_SOURCES PREPEND "${CMAKE_SOURCE_DIR}/" OUTPUT_VARIABLE QUOKKA_EVIL_SOURCES)
add_executable(quokka_evil ${CMAKE_SOURCE_DIR}/src/main.cpp ${QUOKKA_EVIL_SOURCES})
target_compile_definitions(quokka_evil PRIVATE QUOKKA_TEST_HOOKS)
target_include_directories(quokka_evil PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/core)
target_link_libraries(quokka_evil PRIVATE Boost::headers Threads::Threads OpenSSL::Crypto msquic::msquic)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME e2e COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/e2e.py
             $<TARGET_FILE:Quokka> $<TARGET_FILE:quokka_rogue_client> $<TARGET_FILE:quokka_evil>)
    set_tests_properties(e2e PROPERTIES TIMEOUT 600)
endif()
