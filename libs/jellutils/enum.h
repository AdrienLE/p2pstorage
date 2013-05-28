#pragma once

#include <boost/preprocessor/seq/for_each.hpp>
#include <string>

#define _ENUM_REALLY_MAKE_STRING_(x) #x
#define _ENUM_MACRO1_(r, data, elem) elem,
#define _ENUM_MACRO1_STRING_(r, data, elem)    case elem: return _ENUM_REALLY_MAKE_STRING_(elem);
#define _ENUM_MACRO1_ENUM_(r, data, elem)      if (_ENUM_REALLY_MAKE_STRING_(elem) == eStrEl) return elem;


#define MAKE_ENUM(eName, SEQ) \
    enum eName { BOOST_PP_SEQ_FOR_EACH(_ENUM_MACRO1_, , SEQ) \
    last_##eName##_enum}; \
    const int eName##Count = BOOST_PP_SEQ_SIZE(SEQ); \
    static std::string eName##2String(const enum eName eel) \
    { \
        switch (eel) \
        { \
        BOOST_PP_SEQ_FOR_EACH(_ENUM_MACRO1_STRING_, , SEQ) \
        default: return "Unknown enumerator value."; \
        }; \
    }; \
    static enum eName eName##2Enum(const std::string eStrEl) \
    { \
        BOOST_PP_SEQ_FOR_EACH(_ENUM_MACRO1_ENUM_, , SEQ) \
        return (enum eName)0; \
    };


#define _ENUM_NAME_(Tuple)                 BOOST_PP_TUPLE_ELEM(2, 0, Tuple)
#define _ENUM_VALUE_(Tuple)                BOOST_PP_TUPLE_ELEM(2, 1, Tuple)
#define _ENUM_MACRO2_(r, data, elem)           _ENUM_NAME_(elem) _ENUM_VALUE_(elem),
#define _ENUM_MACRO2_STRING_(r, data, elem)    case _ENUM_NAME_(elem): return BOOST_PP_STRINGIZE(_ENUM_NAME_(elem));

#define MAKE_SPARSE_ENUM(eName, SEQ) \
    enum eName { \
    BOOST_PP_SEQ_FOR_EACH(_ENUM_MACRO2_, _, SEQ) \
    last_##eName##_enum }; \
    const int eName##Count = BOOST_PP_SEQ_SIZE(SEQ); \
    static std::string eName##2String(const enum eName eel) \
    { \
        switch (eel) \
        { \
        BOOST_PP_SEQ_FOR_EACH(_ENUM_MACRO2_STRING_, _, SEQ) \
        default: return "Unknown enumerator value."; \
        }; \
    };  

