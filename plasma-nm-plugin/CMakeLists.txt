cmake_minimum_required(VERSION 3.22...4.2)
project(plasmanetworkmanagement_openvpnssoui VERSION 0.3.1)

# Required for CMake 4.x + Qt6 compatibility
set(QT_DEFAULT_MAJOR_VERSION 6)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
include(KDEInstallDirs)
include(KDECMakeSettings)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets DBus)
find_package(KF6CoreAddons REQUIRED)
find_package(KF6I18n REQUIRED)
find_package(KF6KIO REQUIRED)
find_package(KF6NetworkManagerQt REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NM REQUIRED IMPORTED_TARGET libnm>=1.4.0)

add_library(plasmanetworkmanagement_openvpnssoui MODULE
    openvpnsso.cpp
    openvpnsso.h
    openvpnssowidget.cpp
    openvpnssowidget.h
    openvpnssoauth.cpp
    openvpnssoauth.h
)

# The .ui file will be processed by AUTOUIC automatically

target_include_directories(plasmanetworkmanagement_openvpnssoui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link against plasma-nm editor library (installed by plasma-nm package)
find_library(PLASMANM_EDITOR_LIB plasmanm_editor REQUIRED)

target_link_libraries(plasmanetworkmanagement_openvpnssoui
    ${PLASMANM_EDITOR_LIB}
    Qt6::Core
    Qt6::Widgets
    Qt6::DBus
    KF6::CoreAddons
    KF6::I18n
    KF6::KIOWidgets
    KF6::NetworkManagerQt
    PkgConfig::NM
)

# Suppress warnings about missing export header (we define the macro ourselves)
target_compile_definitions(plasmanetworkmanagement_openvpnssoui PRIVATE
    PLASMANM_EDITOR_EXPORT=
)

install(TARGETS plasmanetworkmanagement_openvpnssoui
    DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/network/vpn
)
