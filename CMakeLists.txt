cmake_minimum_required(VERSION 3.10)
project(BPF_snoops)

# Define output directory
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/.output")
file(MAKE_DIRECTORY ${OUTPUT_DIR})

option(CROSS_COMPILE "Cross-compile using a specific toolchain" OFF)
if(CROSS_COMPILE)
	set(CLANG ${CROSS_COMPILE}-clang)
	set(CLANGXX ${CROSS_COMPILE}-clang++)
else()
	# This still may require update-alternatives --config c++
	find_program(CLANG clang)
	find_program(CLANGXX clang++)
endif()

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	message(FATAL_ERROR "C++ compiler must be Clang (clang++)")
endif()

# Check for mandatory libs (including llvm C++ ones)
find_library(LIBCXX_LIB c++)
find_library(LIBCXXABI_LIB c++abi)
find_library(LIBELF_LIB elf)
find_library(LIBZ_LIB z)

if(NOT LIBCXX_LIB)
	message(FATAL_ERROR "libc++-dev is missing")
endif()
if(NOT LIBCXXABI_LIB)
	message(FATAL_ERROR "libc++abi-dev is midding")
endif()
if(NOT LIBELF_LIB)
	message(FATAL_ERROR "libelf1 libelf-dev are missing")
endif()
if(NOT LIBZ_LIB)
	message(FATAL_ERROR "zlib1g-dev is missing")
endif()

# For debugging purposes (logs commands into compile_commands.json)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include directories (used by add_executable)
include_directories(${OUTPUT_DIR} ${CMAKE_SOURCE_DIR}/libbpf/include/uapi ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/blazesym/capi/include)
# include_directories are not passed to add_custom_command
set(CUSTOM_INCLUDES -I${OUTPUT_DIR} -I${CMAKE_SOURCE_DIR}/libbpf/include/uapi -I${CMAKE_SOURCE_DIR}/include -I${CMAKE_SOURCE_DIR}/blazesym/capi/include)

# Compilation flags
set(CMAKE_C_FLAGS "-Wall -O2")
# Force llvm C++ lib
set(CMAKE_CXX_FLAGS "-Wall -O2 -std=c++20 -stdlib=libc++")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lrt -ldl -lpthread -lm")

# Used for -target bpf compilation
set(ARCH "x86" CACHE STRING "Target architecture")

include(ExternalProject)
ExternalProject_Add(libbpf
	PREFIX libbpf
	SOURCE_DIR ${CMAKE_SOURCE_DIR}/libbpf/src
	CONFIGURE_COMMAND ""
	BUILD_COMMAND make BUILD_STATIC_ONLY=1 OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf INCLUDEDIR= LIBDIR= UAPIDIR= install install_uapi_headers
	BUILD_IN_SOURCE TRUE
	INSTALL_COMMAND ""
	STEP_TARGETS build
)

ExternalProject_Add(bpftool
	PREFIX bpftool
	SOURCE_DIR ${CMAKE_SOURCE_DIR}/bpftool/src
	CONFIGURE_COMMAND ""
	BUILD_COMMAND make bootstrap
	OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
	BUILD_IN_SOURCE TRUE
	INSTALL_COMMAND ""
	STEP_TARGETS build
)

ExternalProject_Add(blazesym
	PREFIX blazesym
	SOURCE_DIR ${CMAKE_SOURCE_DIR}/blazesym
	CONFIGURE_COMMAND ""
	BUILD_COMMAND cargo build --package=blazesym-c --release
	BUILD_IN_SOURCE TRUE
	INSTALL_COMMAND ""
	STEP_TARGETS build
)

# BPF programs
set(BPF_PROGRAMS memsnoop.bpf.o fdsnoop.bpf.o)
foreach(BPF_PROGRAM ${BPF_PROGRAMS})
	string(REPLACE ".bpf.o" "" PROGRAM_NAME ${BPF_PROGRAM})
	add_custom_command(
		OUTPUT ${OUTPUT_DIR}/${BPF_PROGRAM}
		COMMAND ${CLANG} ${CUSTOM_INCLUDES} -g -target bpf -D__TARGET_ARCH_${ARCH} --sysroot=${SYSROOT_PATH} -c ${CMAKE_SOURCE_DIR}/${PROGRAM_NAME}.bpf.c -o ${OUTPUT_DIR}/${PROGRAM_NAME}.tmp.bpf.o
		COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool gen object ${OUTPUT_DIR}/${PROGRAM_NAME}.bpf.o ${OUTPUT_DIR}/${PROGRAM_NAME}.tmp.bpf.o
		DEPENDS libbpf-build bpftool-build
		COMMENT "Compiling and generating BPF object for ${PROGRAM_NAME}"
	)
	add_custom_target(${BPF_PROGRAM}_target ALL DEPENDS ${OUTPUT_DIR}/${BPF_PROGRAM})
endforeach()

# Generate BPF skeletons
foreach(BPF_PROGRAM ${BPF_PROGRAMS})
	string(REPLACE ".bpf.o" "" PROGRAM_NAME ${BPF_PROGRAM})
	add_custom_command(
		OUTPUT ${OUTPUT_DIR}/${PROGRAM_NAME}.skel.h
		COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool gen skeleton ${OUTPUT_DIR}/${BPF_PROGRAM} > ${OUTPUT_DIR}/${PROGRAM_NAME}.skel.h
		DEPENDS ${OUTPUT_DIR}/${BPF_PROGRAM}
		COMMENT "Generating BPF skeleton for ${PROGRAM_NAME}"
	)
	add_custom_target(${PROGRAM_NAME}_skel_target ALL DEPENDS ${OUTPUT_DIR}/${PROGRAM_NAME}.skel.h)
endforeach()

# User-space applications
set(APPS memsnoop fdsnoop)
foreach(APP ${APPS})
	add_executable(${APP} ${CMAKE_SOURCE_DIR}/${APP}.cpp ${OUTPUT_DIR}/${APP}.skel.h ${CMAKE_SOURCE_DIR}/libsnoop.cpp)
	target_link_libraries(${APP} PRIVATE ${CMAKE_SOURCE_DIR}/blazesym/target/release/libblazesym_c.a ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a -lelf -lz -lc++ -lc++abi)
	add_dependencies(${APP} blazesym-build bpftool-build libbpf-build ${APP}_skel_target)
endforeach()

# Clean target
add_custom_target(clean_all
	COMMAND ${CMAKE_COMMAND} -E remove_directory ${OUTPUT_DIR}
	COMMENT "Cleaning up"
)
