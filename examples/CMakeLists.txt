# Example broker binaries (POSIX).
foreach(example tcp_broker)
    add_executable(${example} ${example}.cpp)
    target_link_libraries(${example} PRIVATE minimosq::minimosq minimosq_build_flags)
endforeach()
