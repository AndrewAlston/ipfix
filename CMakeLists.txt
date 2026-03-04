cmake_minimum_required(VERSION 4.1.2)
find_package(Doxygen REQUIRED dot)
project(ipfix C)

set(CMAKE_GENERATOR Ninja)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DRTE_FORCE_INTRINSICS -g3 -O3 -Wno-reserved-identifier")
set(DOXYGEN_PROJECT_NAME "Packet statistics collection documentation")
set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/docs)
set(DOXYGEN_GENERATE_HTML YES)
set(DOXYGEN_RECURSIVE YES)
set(DOXYGEN_EXTRACT_ALL YES)
set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
set(DOXYGEN_GENERATE_HTMLHELP YES)
set(DOXYGEN_CALL_GRAPH YES)
set(DOXYGEN_GENERATE_LATEX YES)
set(DOXYGEN_USE_PDFLATEX YES)
set(DOXYGEN_PDF_HYPERLINKS YES)
set(DOXYGEN_EXTRACT_STATIC YES)
set(DOXYGEN_ENABLE_PREPROCESSING YES)
set(DOXYGEN_EXAMPLE_PATH ${CMAKE_BINARY_DIR})
set(DOXYGEN_EXCLUDE_PATTERNS */examples/* */cmake-build-debug/* */docs/* */Testing/* */testcode/*)
set(DOXYGEN_INCLUDE_PATTERNS */functions/*)
set(DOXYGEN_PREDEFINED SOURCE_ADDRESS)
set(DOXYGEN_UML_LOOK YES)
set(DOXYGEN_UML_LIMIT_NUM_FIELDS 50)
set(DOXYGEN_HIDE_UNDOC_RELATIONS NO)
include_directories(.)

doxygen_add_docs(docs ALL COMMENT "Generating Doxygen Documentation")
add_dependencies(docs ipfix)

add_executable(ipfix
        socket.c
        socket.h
        main.c
        main.c
        ipfix_types.h
)
