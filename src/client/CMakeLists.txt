add_executable(client client.cpp)
target_compile_features(client PRIVATE cxx_std_20)
target_link_libraries(client)
