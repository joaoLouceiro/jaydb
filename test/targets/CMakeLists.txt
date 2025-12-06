function(add_test_cpp_target name)
    add_executable(${name} "${name}.cpp")
    target_compile_options(${name} PRIVATE -g -O0 -pie)
    add_dependencies(tests ${name})
endfunction()

function(add_test_asm_target name)
    add_executable(${name} "${name}.s")
    target_compile_options(${name} PRIVATE -pie)
    add_dependencies(tests ${name})
endfunction()


add_test_cpp_target(run_endlessly run_endlessly.cpp)
add_test_cpp_target(end_immediately end_immediately.cpp)
add_test_cpp_target(hello_jdb hello_jdb.cpp)

add_test_asm_target(reg_write reg_write.s)
add_test_asm_target(reg_read reg_read.s)
