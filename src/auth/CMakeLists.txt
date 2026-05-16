add_executable(auth auth.cpp)
target_compile_features(auth PRIVATE cxx_std_20)
target_link_libraries(auth OpenSSL::SSL OpenSSL::Crypto)
