add_executable(crypto crypto.cpp)
target_compile_features(crypto PRIVATE cxx_std_20)
target_link_libraries(crypto OpenSSL::SSL OpenSSL::Crypto)
