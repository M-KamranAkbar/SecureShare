# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "")
  file(REMOVE_RECURSE
  "src/gui/CMakeFiles/gui_autogen.dir/AutogenUsed.txt"
  "src/gui/CMakeFiles/gui_autogen.dir/ParseCache.txt"
  "src/gui/gui_autogen"
  )
endif()
