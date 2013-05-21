#==============================================================================#
#                                                                              #
#  Copyright (c) 2010 maidsafe.net limited                                     #
#  All rights reserved.                                                        #
#                                                                              #
#  Redistribution and use in source and binary forms, with or without          #
#  modification, are permitted provided that the following conditions are met: #
#                                                                              #
#      * Redistributions of source code must retain the above copyright        #
#        notice, this list of conditions and the following disclaimer.         #
#      * Redistributions in binary form must reproduce the above copyright     #
#        notice, this list of conditions and the following disclaimer in the   #
#        documentation and/or other materials provided with the distribution.  #
#      * Neither the name of the maidsafe.net limited nor the names of its     #
#        contributors may be used to endorse or promote products derived from  #
#        this software without specific prior written permission.              #
#                                                                              #
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" #
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  #
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE  #
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    #
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     #
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     #
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  #
#  POSSIBILITY OF SUCH DAMAGE.                                                 #
#                                                                              #
#==============================================================================#
#                                                                              #
#  Written by maidsafe.net team                                                #
#  Patch https://gist.github.com/a4c52f036fc61c24abac supplied by Marenz       #
#                                                                              #
#==============================================================================#
#                                                                              #
#  Uses built in CMake module FindBoost to locate boost libs and headers.      #
#  Searches for all Boost libraries listed in settable variable                #
#  REQUIRED_BOOST_COMPONENTS.  The Boost version will be set to the highest    #
#  found between 1.40 and 1.99 inclusive.                                      #
#                                                                              #
#  Settable variables to aid with finding Boost are:                           #
#    BOOST_LIB_DIR, BOOST_INC_DIR and BOOST_ROOT_DIR                           #
#                                                                              #
#  Variables set and cached by FindBoost module include:                       #
#    Boost_INCLUDE_DIR, Boost_LIBRARY_DIRS, Boost_LIBRARIES and                #
#    Boost_${COMPONENT}_LIBRARY_RELEASE (e.g. Boost_FILESYSTEM_LIBRARY_RELEASE)#
#  (See documentation of FindBoost for further info.)                          #
#                                                                              #
#==============================================================================#


SET(COPY_OF_LIST REQUIRED_BOOST_COMPONENTS)
FOREACH(COMPONENT ${REQUIRED_BOOST_COMPONENTS})
  LIST(LENGTH ${COPY_OF_LIST} LEN)
  MATH(EXPR LEN ${LEN}-1)
  LIST(FIND ${COPY_OF_LIST} ${COMPONENT} POSITION)
  IF(${POSITION} EQUAL 0)
    SET(REQUIRED_BOOST_LIST \"${COMPONENT}\")
  ELSEIF(${POSITION} EQUAL LEN)
    SET(REQUIRED_BOOST_LIST "${REQUIRED_BOOST_LIST} and \"${COMPONENT}\"")
  ELSE()
    SET(REQUIRED_BOOST_LIST "${REQUIRED_BOOST_LIST}, \"${COMPONENT}\"")
  ENDIF()
  STRING(TOUPPER ${COMPONENT} COMP)
  UNSET(Boost_${COMP}_FOUND CACHE)
ENDFOREACH()
FOREACH(VER_NUM RANGE 46 99)
  SET(Boost_ADDITIONAL_VERSIONS ${Boost_ADDITIONAL_VERSIONS} "1.${VER_NUM}" "1.${VER_NUM}.0")
  SET(BOOST_TRY_VERSIONS ${BOOST_TRY_VERSIONS} "boost-1_${VER_NUM}")
ENDFOREACH()
UNSET(Boost_INCLUDE_DIR CACHE)
UNSET(Boost_LIBRARY_DIRS CACHE)
UNSET(TRY_BOOST_INC_DIR CACHE)

IF(BOOST_LIB_DIR)
  SET(BOOST_LIBRARYDIR ${BOOST_LIB_DIR} CACHE PATH "Path to Boost libraries directory" FORCE)
ELSEIF(UNIX)
  SET(BOOST_LIBRARYDIR /usr/local/lib)
ENDIF()

IF(BOOST_INC_DIR)
  SET(BOOST_INCLUDEDIR ${BOOST_INC_DIR} CACHE PATH "Path to Boost include directory" FORCE)
ELSEIF(UNIX)
  SET(BOOST_INCLUDEDIR /usr/local/include)
ELSE()
  LIST(REVERSE BOOST_TRY_VERSIONS)
  FOREACH(TRY_VERSION ${BOOST_TRY_VERSIONS})
    FOREACH(INC_OPTION ${INCLUDE_DIR})
      FIND_FILE(TRY_BOOST_INC_DIR ${TRY_VERSION} ${INC_OPTION})
      IF(TRY_BOOST_INC_DIR)
        SET(BOOST_INCLUDEDIR ${TRY_BOOST_INC_DIR})
        BREAK()
      ENDIF()
    ENDFOREACH()
    IF(TRY_BOOST_INC_DIR)
      BREAK()
    ENDIF()
  ENDFOREACH()
ENDIF()

IF(BOOST_ROOT_DIR)
  SET(BOOST_ROOT ${BOOST_ROOT_DIR} CACHE PATH "Path to Boost root directory" FORCE)
ELSE()
  SET(BOOST_ROOT /usr/local)
ENDIF()
SET(Boost_USE_STATIC_LIBS ON)
SET(Boost_USE_MULTITHREADED ON)
SET(Boost_USE_STATIC_RUNTIME ON)
SET(Boost_NO_SYSTEM_PATHS ON)
SET(BOOST_LIB_DIAGNOSTIC OFF)
#ADD_DEFINITIONS(-DBOOST_ALL_DYN_LINK)

FIND_PACKAGE(Boost 1.47 COMPONENTS ${REQUIRED_BOOST_COMPONENTS})
IF(NOT Boost_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find Boost libraries.\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}Required Boost libraries are ${REQUIRED_BOOST_LIST}.\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download Boost libraries at http://www.boost.org\n\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If the required Boost libraries are already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DBOOST_LIB_DIR=<Path to Boost library directory> and/or\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DBOOST_INC_DIR=<Path to Boost include directory> and/or\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DBOOST_ROOT_DIR=<Path to Boost root directory>\n\n")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()
FOREACH(COMPONENT ${REQUIRED_BOOST_COMPONENTS})
  STRING(TOUPPER ${COMPONENT} COMP)
  IF(NOT Boost_${COMP}_FOUND)
    IF(DEFINED Boost_LIB_VERSION)
      SET(ERROR_VERSION "version ${Boost_LIB_VERSION} ")
    ENDIF()
    SET(ERROR_MESSAGE "\nFound Boost headers at ${Boost_INCLUDE_DIR} but could not find ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Boost \"${COMPONENT}\" library.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Required Boost libraries are ${REQUIRED_BOOST_LIST}.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download Boost libraries at http://www.boost.org\n\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If the required Boost libraries are already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DBOOST_LIB_DIR=<Path to Boost library directory> and/or\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DBOOST_INC_DIR=<Path to Boost include directory> and/or\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DBOOST_ROOT_DIR=<Path to Boost root directory>\n\n")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
ENDFOREACH()

INCLUDE_DIRECTORIES(AFTER SYSTEM ${Boost_INCLUDE_DIR})
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Boost_INCLUDE_DIR})

IF(WIN32)
  FILE(GLOB RELEASE_LIBS "${Boost_LIBRARY_DIRS}/*s-1_*")
  FILE(GLOB DEBUG_LIBS "${Boost_LIBRARY_DIRS}/*sgd-1_*")
ELSE()
  FILE(GLOB RELEASE_LIBS "${Boost_LIBRARY_DIRS}/*boost*.a")
  SET(DEBUG_LIBS ${RELEASE_LIBS})
ENDIF()

SET(EXPORT_BOOST)
FOREACH(RELEASE_LIB ${RELEASE_LIBS})
  IF(WIN32)
    STRING(REGEX MATCH "boost_[a-z][^-]+" LIB_NAME ${RELEASE_LIB})
  ELSE()
    STRING(REGEX MATCH "boost_[a-z_0-9]+[^.]" LIB_NAME ${RELEASE_LIB})
  ENDIF()
  SET(EXPORT_BOOST "${EXPORT_BOOST}ADD_LIBRARY(${LIB_NAME} STATIC IMPORTED)\n")
  SET(EXPORT_BOOST "${EXPORT_BOOST}SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES\n")
  SET(EXPORT_BOOST "${EXPORT_BOOST}                        IMPORTED_CONFIGURATIONS \"RELEASE;DEBUG\"\n")
  SET(EXPORT_BOOST "${EXPORT_BOOST}                        IMPORTED_LOCATION_RELEASE \"${RELEASE_LIB}\")\n")
ENDFOREACH()
FOREACH(DEBUG_LIB ${DEBUG_LIBS})
  IF(WIN32)
    STRING(REGEX MATCH "boost_[a-z][^-]+" LIB_NAME ${DEBUG_LIB})
  ELSE()
    STRING(REGEX MATCH "boost_[a-z_0-9]+[^.]" LIB_NAME ${DEBUG_LIB})
  ENDIF()
  STRING(REGEX MATCH "ADD_LIBRARY[\(]${LIB_NAME} STATIC" FOUND_LIB ${EXPORT_BOOST})
  IF(FOUND_LIB)
    SET(EXPORT_BOOST "${EXPORT_BOOST}SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES\n")
    SET(EXPORT_BOOST "${EXPORT_BOOST}                        IMPORTED_LOCATION_DEBUG \"${DEBUG_LIB}\")\n")
  ENDIF()
ENDFOREACH()
