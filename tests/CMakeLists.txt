# Each test source file is a standalone binary registered with CTest.
function(minimosq_add_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE minimosq::minimosq minimosq_build_flags)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

minimosq_add_test(test_harness)
minimosq_add_test(test_core)
minimosq_add_test(test_protocol_io)
minimosq_add_test(test_frame)
minimosq_add_test(test_packets)
minimosq_add_test(test_topic)
minimosq_add_test(test_broker_connect)
minimosq_add_test(test_broker_pubsub)
minimosq_add_test(test_broker_qos)

# The transport tests exercise real sockets/pipes and are POSIX-only.
if(UNIX)
    minimosq_add_test(test_transport_tcp)
    minimosq_add_test(test_transport_uds)
    minimosq_add_test(test_transport_pipe)
endif()
