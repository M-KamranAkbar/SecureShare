add_executable(storage storage.cpp)
target_compile_features(storage PRIVATE cxx_std_20)
target_link_libraries(storage sqlite3)
