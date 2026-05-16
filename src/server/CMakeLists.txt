add_executable(server server.cpp)
target_compile_features(server PRIVATE cxx_std_20)
target_link_libraries(server sqlite3 OpenSSL::SSL OpenSSL::Crypto pthread)
