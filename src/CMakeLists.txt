# Create a target called libjaydb with a single source file, libjaydb.cpp
add_library(libjaydb process.cpp pipe.cpp registers.cpp breakpoint_site.cpp)
# create a namespaced library target, which can result in more understandable errors
add_library(jaydb::libjaydb ALIAS libjaydb)

# By default, Linux creates libraries called "lib<target name>".
# In our case, that would create a library called "liblibjaydb".
# To avoid this, we specify that we want the OUTPUT_NAME of our
# target to be called "jaydb"
set_target_properties(
    libjaydb
    PROPERTIES OUTPUT_NAME jaydb
)

# specify that the target should be compiled to C++ 17
target_compile_features(libjaydb PUBLIC cxx_std_17)

# specify the directories for libjaydb
# jaydb/src/include is set to PRIVATE
# jaydb/include is set to PUBLIC
target_include_directories(
    libjaydb
    # these are called "generator expressions". They generate information specific to the current build
    PRIVATE $<INSTALL_INTERFACE:include>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

# This module (GNUInstallDirs) contains variables that specify common instalation directories
include(GNUInstallDirs)
install(TARGETS libjaydb
    EXPORT jaydb-targets
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
    EXPORT jaydb-targets
    FILE jaydb_config.cmake
    NAMESPACE jaydb::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jaydb
)
