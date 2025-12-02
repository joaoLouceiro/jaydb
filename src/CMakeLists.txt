# Create a target called libjdb with a single source file, libjdb.cpp
add_library(libjdb process.cpp pipe.cpp registers.cpp breakpoint_site.cpp)
# create a namespaced library target, which can result in more understandable errors
add_library(jdb::libjdb ALIAS libjdb)

# By default, Linux creates libraries called "lib<target name>".
# In our case, that would create a library called "liblibjdb".
# To avoid this, we specify that we want the OUTPUT_NAME of our
# target to be called "jdb"
set_target_properties(
    libjdb
    PROPERTIES OUTPUT_NAME jdb
)

# specify that the target should be compiled to C++ 17
target_compile_features(libjdb PUBLIC cxx_std_17)

# specify the directories for libjdb
# jdb/src/include is set to PRIVATE
# jdb/include is set to PUBLIC
target_include_directories(
    libjdb
    # these are called "generator expressions". They generate information specific to the current build
    PRIVATE $<INSTALL_INTERFACE:include>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

# This module (GNUInstallDirs) contains variables that specify common instalation directories
include(GNUInstallDirs)
install(TARGETS libjdb
    EXPORT jdb-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# This installs the public headers
install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Saves the export information to a file
install(
    EXPORT jdb-targets
    FILE jdb_config.cmake
    NAMESPACE jdb::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jdb
)
