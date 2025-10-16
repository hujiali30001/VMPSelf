# Placeholder CMake configuration for Python backend

add_custom_target(server-requirements
    COMMAND ${CMAKE_COMMAND} -E echo "Install Python deps from server/requirements.txt"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
