# this one is important
SET(CMAKE_SYSTEM_NAME Linux)

# specify the cross compiler
SET(CMAKE_C_COMPILER   /opt/toolchains/x86_64-pc-linux-gnu/usr/bin/gcc)
SET(CMAKE_CXX_COMPILER /opt/toolchains/x86_64-pc-linux-gnu/usr/bin/g++)

# where is the target environment
SET(CMAKE_FIND_ROOT_PATH  /opt/toolchains/x86_64-pc-linux-gnu)

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)

# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

