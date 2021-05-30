# CMakeLists.txt --- CMake project settings
#    ex) cmake -G "Visual Studio 9 2008" .
#    ex) cmake -DCMAKE_BUILD_TYPE=Release -G "MinGW Makefiles" .
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 3.0)

# project name and language
project(debaka CXX)

# debaka.exe
add_executable(debaka debaka.cpp)
target_link_libraries(debaka kernel32 user32)
