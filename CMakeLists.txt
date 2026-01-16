cmake_minimum_required(VERSION 3.16)
project(UdpCatcher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt5 COMPONENTS Core Gui Widgets Network REQUIRED)

set(PCAPPP_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/libs/include")
set(PCAPPP_LIB_DIR "${PROJECT_SOURCE_DIR}/libs/lib")

    # 2.2 ПРЯМАЯ ПРОВЕРКА СУЩЕСТВОВАНИЯ ФАЙЛОВ (без вызова brew)
    # Ищем заголовочный файл (например, PcapLiveDevice.h внутри подкаталога)
find_path(PCAPPP_INCLUDE_SEARCH_PATH
    NAMES pcapplusplus/PcapLiveDevice.h
    PATHS "${PCAPPP_INCLUDE_DIR}"
    NO_DEFAULT_PATH
)
   # Ищем хотя бы одну ключевую библиотеку
find_library(PCAPPP_LIB_PCAP
    NAMES Pcap++ libPcap++
    PATHS "${PCAPPP_LIB_DIR}"
    NO_DEFAULT_PATH
)
add_library(PcapPlusPlus::PcapPlusPlus INTERFACE IMPORTED GLOBAL)
target_include_directories(PcapPlusPlus::PcapPlusPlus INTERFACE ${PCAPPP_INCLUDE_DIR})

target_link_libraries(PcapPlusPlus::PcapPlusPlus INTERFACE
    ${PCAPPP_LIB_DIR}/libPcap++.a
    ${PCAPPP_LIB_DIR}/libPacket++.a
    ${PCAPPP_LIB_DIR}/libCommon++.a
    pcap    
    pthread 
    dl      
    m       
)

set(PCAPPP_TARGET PcapPlusPlus::PcapPlusPlus)


# 3. Создаем исполняемый файл проекта
add_executable(${PROJECT_NAME}
    main.cpp
    mainwindow.cpp
    packetcapture.cpp
    packetplayer.cpp 
)

# 4. Подключаем заголовки самого проекта
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# 5. Линковка всех зависимостей
target_link_libraries(${PROJECT_NAME}
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Network
    ${PCAPPP_TARGET}
)