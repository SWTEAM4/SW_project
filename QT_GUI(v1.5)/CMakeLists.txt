cmake_minimum_required(VERSION 3.16)

# vcpkg toolchain 파일 설정 (Qt Creator에서도 인식되도록)
# VCPKG_ROOT 환경 변수를 먼저 확인하고, 없으면 기본 경로 사용
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
elseif(EXISTS "C:/Users/sihwa/source/repos/vcpkg/scripts/buildsystems/vcpkg.cmake" 
       AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/Users/sihwa/source/repos/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
endif()

project(FileCryptoGUI VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Qt 찾기
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

# OpenSSL 찾기 (vcpkg를 통해)
find_package(OpenSSL REQUIRED)

# Qt 자동 처리 활성화 (UI, MOC, RCC)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# C 소스 파일들 (CLI용 main 제외)
set(C_SOURCES
    cli.c
    aes_ctr.c
    sha512.c
    hmac_sha512.c
    kdf.c
    platform_utils.c
    error_utils.c
    file_path_utils.c
    password_utils.c
    random_utils.c
    key_derivation.c
)

# Qt GUI 소스
set(QT_SOURCES
    main.cpp
    mainwindow.cpp
    cryptoworker.cpp
)

# Qt 헤더 파일
set(QT_HEADERS
    mainwindow.h
    cryptoworker.h
)

# UI 파일
set(UI_FILES
    mainwindow.ui
)

# 실행 파일 생성
add_executable(FileCryptoGUI
    ${QT_SOURCES}
    ${C_SOURCES}
    ${QT_HEADERS}
    ${UI_FILES}
)

# C 파일들을 C로 컴파일하도록 설정
set_source_files_properties(${C_SOURCES} PROPERTIES LANGUAGE C)

# Qt 모듈 사용
target_link_libraries(FileCryptoGUI
    Qt6::Core
    Qt6::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows에서 콘솔 창 숨기기 (GUI 전용)
if(WIN32)
    set_target_properties(FileCryptoGUI PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
endif()

# 플랫폼별 정의
if(WIN32)
    target_compile_definitions(FileCryptoGUI PRIVATE PLATFORM_WINDOWS USE_OPENSSL)
elseif(APPLE)
    target_compile_definitions(FileCryptoGUI PRIVATE PLATFORM_MAC)
elseif(UNIX)
    target_compile_definitions(FileCryptoGUI PRIVATE PLATFORM_LINUX)
endif()

# GUI 빌드임을 표시 (CLI main 함수 제외)
target_compile_definitions(FileCryptoGUI PRIVATE BUILD_GUI)

# include 디렉토리 설정
target_include_directories(FileCryptoGUI PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

