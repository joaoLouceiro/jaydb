add_executable(tests tests.cpp)

# Catch2WithMain provides it's own main function, which deals with command line arguments on its own
target_link_libraries(tests PRIVATE jaydb::libjaydb Catch2::Catch2WithMain)

add_subdirectory("targets")

