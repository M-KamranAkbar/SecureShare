set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

add_executable(gui main.cpp)
target_compile_features(gui PRIVATE cxx_std_20)
target_link_libraries(gui Qt6::Core Qt6::Widgets Qt6::Network OpenSSL::SSL OpenSSL::Crypto)
