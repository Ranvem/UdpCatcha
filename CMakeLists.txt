cmake_minimum_required(VERSION 3.16)
project(UdpCatcher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# 1. Поиск Qt5
find_package(Qt5 COMPONENTS Core Gui Widgets Network REQUIRED)

# 2. НАДЁЖНАЯ НАСТРОЙКА PcapPlusPlus (с приоритетом pkg-config)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    # Пробуем найти с именем 'PcapPlusPlus' (с большой буквы, как в файле .pc)
    pkg_check_modules(PCAPPP_PKGCONFIG QUIET IMPORTED_TARGET PcapPlusPlus)
endif()

if(TARGET PkgConfig::PCAPPP_PKGCONFIG)
    # СЛУЧАЙ 1: Успешно нашли через pkg-config
    message(STATUS "PcapPlusPlus найден через pkg-config.")
    set(PCAPPP_TARGET PkgConfig::PCAPPP_PKGCONFIG)

else()
    # СЛУЧАЙ 2: Ручная настройка по ПРОВЕРЕННОМУ пути
    message(STATUS "Использую ручную настройку PcapPlusPlus через проверенный путь Homebrew.")

    # ЖЁСТКО ЗАДАЁМ ПРОВЕРЕННЫЙ ПУТЬ (вы его подтвердили ранее)
    set(BREW_PCAPPP_PREFIX "/home/linuxbrew/.linuxbrew/opt/pcapplusplus")
    message(STATUS "Путь к библиотеке: ${BREW_PCAPPP_PREFIX}")

    # 2.1 Определяем подпути
    set(PCAPPP_INCLUDE_DIR "${BREW_PCAPPP_PREFIX}/include")
    set(PCAPPP_LIB_DIR "${BREW_PCAPPP_PREFIX}/lib")

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

    if(NOT PCAPPP_INCLUDE_SEARCH_PATH)
        message(FATAL_ERROR "Заголовки PcapPlusPlus не найдены в ${PCAPPP_INCLUDE_DIR}. Запустите в терминале: ls -la ${PCAPPP_INCLUDE_DIR}/")
    endif()
    if(NOT PCAPPP_LIB_PCAP)
        message(FATAL_ERROR "Библиотеки PcapPlusPlus не найдены в ${PCAPPP_LIB_DIR}. Запустите в терминале: ls -la ${PCAPPP_LIB_DIR}/")
    endif()

    message(STATUS "Заголовки найдены в: ${PCAPPP_INCLUDE_SEARCH_PATH}")
    message(STATUS "Библиотеки найдены в: ${PCAPPP_LIB_DIR}")

    # 2.3 Создаем интерфейсную цель вручную
    add_library(PcapPlusPlus::PcapPlusPlus INTERFACE IMPORTED GLOBAL)

    # Подключаем найденные заголовки
    target_include_directories(PcapPlusPlus::PcapPlusPlus INTERFACE ${PCAPPP_INCLUDE_SEARCH_PATH})

    # Линкуем ВСЕ необходимые статические библиотеки PcapPlusPlus и их зависимости
    # ИЗМЕНЁННЫЙ ПОРЯДОК: сначала Pcap++, затем Packet++, затем Common++
    target_link_libraries(PcapPlusPlus::PcapPlusPlus INTERFACE
        ${PCAPPP_LIB_DIR}/libPcap++.a
        ${PCAPPP_LIB_DIR}/libPacket++.a
        ${PCAPPP_LIB_DIR}/libCommon++.a
        pcap    # libpcap
        pthread # pthread
        dl      # libdl
        m       # libm
    )

    set(PCAPPP_TARGET PcapPlusPlus::PcapPlusPlus)
    message(STATUS "PcapPlusPlus настроен вручную.")
endif()

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