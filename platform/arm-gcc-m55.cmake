set(CMAKE_SYSTEM_NAME Generic)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
# CMAKE_SIZE_UTIL is not a 'real' CMake variable but is sometimes
# used by convention in embedded toolchain files.
set(CMAKE_SIZE_UTIL arm-none-eabi-size)

set(CMAKE_C_FLAGS "-mthumb -mcpu=cortex-m55 -Os")
set(CMAKE_EXE_LINKER_FLAGS "--specs=nosys.specs")
