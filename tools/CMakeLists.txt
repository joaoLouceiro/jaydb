add_executable(jaydb jaydb.cpp)
target_link_libraries(
    jaydb PRIVATE jaydb::libjaydb
    PkgConfig::libedit
    fmt::fmt
)

include(GNUInstallDirs)
install(
    TARGETS jaydb
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
