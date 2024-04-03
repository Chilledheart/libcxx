//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// WARNING: This test was generated by generate_feature_test_macro_components.py
// and should not be edited manually.
//
// clang-format off

// <ranges>

// Test the feature test macros defined by <ranges>

/*  Constant                                                Value
    __cpp_lib_default_template_type_for_algorithm_values    202403L [C++26]
    __cpp_lib_ranges                                        202207L [C++20]
    __cpp_lib_ranges_as_const                               202207L [C++23]
    __cpp_lib_ranges_as_rvalue                              202207L [C++23]
    __cpp_lib_ranges_chunk                                  202202L [C++23]
    __cpp_lib_ranges_chunk_by                               202202L [C++23]
    __cpp_lib_ranges_concat                                 202403L [C++26]
    __cpp_lib_ranges_join_with                              202202L [C++23]
    __cpp_lib_ranges_repeat                                 202207L [C++23]
    __cpp_lib_ranges_slide                                  202202L [C++23]
    __cpp_lib_ranges_to_container                           202202L [C++23]
    __cpp_lib_ranges_zip                                    202110L [C++23]
*/

#include <ranges>
#include "test_macros.h"

#if TEST_STD_VER < 14

# ifdef __cpp_lib_default_template_type_for_algorithm_values
#   error "__cpp_lib_default_template_type_for_algorithm_values should not be defined before c++26"
# endif

# ifdef __cpp_lib_ranges
#   error "__cpp_lib_ranges should not be defined before c++20"
# endif

# ifdef __cpp_lib_ranges_as_const
#   error "__cpp_lib_ranges_as_const should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_as_rvalue
#   error "__cpp_lib_ranges_as_rvalue should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk
#   error "__cpp_lib_ranges_chunk should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk_by
#   error "__cpp_lib_ranges_chunk_by should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_concat
#   error "__cpp_lib_ranges_concat should not be defined before c++26"
# endif

# ifdef __cpp_lib_ranges_join_with
#   error "__cpp_lib_ranges_join_with should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_repeat
#   error "__cpp_lib_ranges_repeat should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_slide
#   error "__cpp_lib_ranges_slide should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_to_container
#   error "__cpp_lib_ranges_to_container should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_zip
#   error "__cpp_lib_ranges_zip should not be defined before c++23"
# endif

#elif TEST_STD_VER == 14

# ifdef __cpp_lib_default_template_type_for_algorithm_values
#   error "__cpp_lib_default_template_type_for_algorithm_values should not be defined before c++26"
# endif

# ifdef __cpp_lib_ranges
#   error "__cpp_lib_ranges should not be defined before c++20"
# endif

# ifdef __cpp_lib_ranges_as_const
#   error "__cpp_lib_ranges_as_const should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_as_rvalue
#   error "__cpp_lib_ranges_as_rvalue should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk
#   error "__cpp_lib_ranges_chunk should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk_by
#   error "__cpp_lib_ranges_chunk_by should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_concat
#   error "__cpp_lib_ranges_concat should not be defined before c++26"
# endif

# ifdef __cpp_lib_ranges_join_with
#   error "__cpp_lib_ranges_join_with should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_repeat
#   error "__cpp_lib_ranges_repeat should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_slide
#   error "__cpp_lib_ranges_slide should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_to_container
#   error "__cpp_lib_ranges_to_container should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_zip
#   error "__cpp_lib_ranges_zip should not be defined before c++23"
# endif

#elif TEST_STD_VER == 17

# ifdef __cpp_lib_default_template_type_for_algorithm_values
#   error "__cpp_lib_default_template_type_for_algorithm_values should not be defined before c++26"
# endif

# ifdef __cpp_lib_ranges
#   error "__cpp_lib_ranges should not be defined before c++20"
# endif

# ifdef __cpp_lib_ranges_as_const
#   error "__cpp_lib_ranges_as_const should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_as_rvalue
#   error "__cpp_lib_ranges_as_rvalue should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk
#   error "__cpp_lib_ranges_chunk should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk_by
#   error "__cpp_lib_ranges_chunk_by should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_concat
#   error "__cpp_lib_ranges_concat should not be defined before c++26"
# endif

# ifdef __cpp_lib_ranges_join_with
#   error "__cpp_lib_ranges_join_with should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_repeat
#   error "__cpp_lib_ranges_repeat should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_slide
#   error "__cpp_lib_ranges_slide should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_to_container
#   error "__cpp_lib_ranges_to_container should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_zip
#   error "__cpp_lib_ranges_zip should not be defined before c++23"
# endif

#elif TEST_STD_VER == 20

# ifdef __cpp_lib_default_template_type_for_algorithm_values
#   error "__cpp_lib_default_template_type_for_algorithm_values should not be defined before c++26"
# endif

# ifndef __cpp_lib_ranges
#   error "__cpp_lib_ranges should be defined in c++20"
# endif
# if __cpp_lib_ranges != 202207L
#   error "__cpp_lib_ranges should have the value 202207L in c++20"
# endif

# ifdef __cpp_lib_ranges_as_const
#   error "__cpp_lib_ranges_as_const should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_as_rvalue
#   error "__cpp_lib_ranges_as_rvalue should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk
#   error "__cpp_lib_ranges_chunk should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_chunk_by
#   error "__cpp_lib_ranges_chunk_by should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_concat
#   error "__cpp_lib_ranges_concat should not be defined before c++26"
# endif

# ifdef __cpp_lib_ranges_join_with
#   error "__cpp_lib_ranges_join_with should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_repeat
#   error "__cpp_lib_ranges_repeat should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_slide
#   error "__cpp_lib_ranges_slide should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_to_container
#   error "__cpp_lib_ranges_to_container should not be defined before c++23"
# endif

# ifdef __cpp_lib_ranges_zip
#   error "__cpp_lib_ranges_zip should not be defined before c++23"
# endif

#elif TEST_STD_VER == 23

# ifdef __cpp_lib_default_template_type_for_algorithm_values
#   error "__cpp_lib_default_template_type_for_algorithm_values should not be defined before c++26"
# endif

# ifndef __cpp_lib_ranges
#   error "__cpp_lib_ranges should be defined in c++23"
# endif
# if __cpp_lib_ranges != 202207L
#   error "__cpp_lib_ranges should have the value 202207L in c++23"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_as_const
#     error "__cpp_lib_ranges_as_const should be defined in c++23"
#   endif
#   if __cpp_lib_ranges_as_const != 202207L
#     error "__cpp_lib_ranges_as_const should have the value 202207L in c++23"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_as_const
#     error "__cpp_lib_ranges_as_const should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_as_rvalue
#   error "__cpp_lib_ranges_as_rvalue should be defined in c++23"
# endif
# if __cpp_lib_ranges_as_rvalue != 202207L
#   error "__cpp_lib_ranges_as_rvalue should have the value 202207L in c++23"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_chunk
#     error "__cpp_lib_ranges_chunk should be defined in c++23"
#   endif
#   if __cpp_lib_ranges_chunk != 202202L
#     error "__cpp_lib_ranges_chunk should have the value 202202L in c++23"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_chunk
#     error "__cpp_lib_ranges_chunk should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_chunk_by
#   error "__cpp_lib_ranges_chunk_by should be defined in c++23"
# endif
# if __cpp_lib_ranges_chunk_by != 202202L
#   error "__cpp_lib_ranges_chunk_by should have the value 202202L in c++23"
# endif

# ifdef __cpp_lib_ranges_concat
#   error "__cpp_lib_ranges_concat should not be defined before c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_join_with
#     error "__cpp_lib_ranges_join_with should be defined in c++23"
#   endif
#   if __cpp_lib_ranges_join_with != 202202L
#     error "__cpp_lib_ranges_join_with should have the value 202202L in c++23"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_join_with
#     error "__cpp_lib_ranges_join_with should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_repeat
#   error "__cpp_lib_ranges_repeat should be defined in c++23"
# endif
# if __cpp_lib_ranges_repeat != 202207L
#   error "__cpp_lib_ranges_repeat should have the value 202207L in c++23"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_slide
#     error "__cpp_lib_ranges_slide should be defined in c++23"
#   endif
#   if __cpp_lib_ranges_slide != 202202L
#     error "__cpp_lib_ranges_slide should have the value 202202L in c++23"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_slide
#     error "__cpp_lib_ranges_slide should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_to_container
#   error "__cpp_lib_ranges_to_container should be defined in c++23"
# endif
# if __cpp_lib_ranges_to_container != 202202L
#   error "__cpp_lib_ranges_to_container should have the value 202202L in c++23"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_zip
#     error "__cpp_lib_ranges_zip should be defined in c++23"
#   endif
#   if __cpp_lib_ranges_zip != 202110L
#     error "__cpp_lib_ranges_zip should have the value 202110L in c++23"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_zip
#     error "__cpp_lib_ranges_zip should not be defined because it is unimplemented in libc++!"
#   endif
# endif

#elif TEST_STD_VER > 23

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_default_template_type_for_algorithm_values
#     error "__cpp_lib_default_template_type_for_algorithm_values should be defined in c++26"
#   endif
#   if __cpp_lib_default_template_type_for_algorithm_values != 202403L
#     error "__cpp_lib_default_template_type_for_algorithm_values should have the value 202403L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_default_template_type_for_algorithm_values
#     error "__cpp_lib_default_template_type_for_algorithm_values should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges
#   error "__cpp_lib_ranges should be defined in c++26"
# endif
# if __cpp_lib_ranges != 202207L
#   error "__cpp_lib_ranges should have the value 202207L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_as_const
#     error "__cpp_lib_ranges_as_const should be defined in c++26"
#   endif
#   if __cpp_lib_ranges_as_const != 202207L
#     error "__cpp_lib_ranges_as_const should have the value 202207L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_as_const
#     error "__cpp_lib_ranges_as_const should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_as_rvalue
#   error "__cpp_lib_ranges_as_rvalue should be defined in c++26"
# endif
# if __cpp_lib_ranges_as_rvalue != 202207L
#   error "__cpp_lib_ranges_as_rvalue should have the value 202207L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_chunk
#     error "__cpp_lib_ranges_chunk should be defined in c++26"
#   endif
#   if __cpp_lib_ranges_chunk != 202202L
#     error "__cpp_lib_ranges_chunk should have the value 202202L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_chunk
#     error "__cpp_lib_ranges_chunk should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_chunk_by
#   error "__cpp_lib_ranges_chunk_by should be defined in c++26"
# endif
# if __cpp_lib_ranges_chunk_by != 202202L
#   error "__cpp_lib_ranges_chunk_by should have the value 202202L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_concat
#     error "__cpp_lib_ranges_concat should be defined in c++26"
#   endif
#   if __cpp_lib_ranges_concat != 202403L
#     error "__cpp_lib_ranges_concat should have the value 202403L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_concat
#     error "__cpp_lib_ranges_concat should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_join_with
#     error "__cpp_lib_ranges_join_with should be defined in c++26"
#   endif
#   if __cpp_lib_ranges_join_with != 202202L
#     error "__cpp_lib_ranges_join_with should have the value 202202L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_join_with
#     error "__cpp_lib_ranges_join_with should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_repeat
#   error "__cpp_lib_ranges_repeat should be defined in c++26"
# endif
# if __cpp_lib_ranges_repeat != 202207L
#   error "__cpp_lib_ranges_repeat should have the value 202207L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_slide
#     error "__cpp_lib_ranges_slide should be defined in c++26"
#   endif
#   if __cpp_lib_ranges_slide != 202202L
#     error "__cpp_lib_ranges_slide should have the value 202202L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_slide
#     error "__cpp_lib_ranges_slide should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_ranges_to_container
#   error "__cpp_lib_ranges_to_container should be defined in c++26"
# endif
# if __cpp_lib_ranges_to_container != 202202L
#   error "__cpp_lib_ranges_to_container should have the value 202202L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_ranges_zip
#     error "__cpp_lib_ranges_zip should be defined in c++26"
#   endif
#   if __cpp_lib_ranges_zip != 202110L
#     error "__cpp_lib_ranges_zip should have the value 202110L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_ranges_zip
#     error "__cpp_lib_ranges_zip should not be defined because it is unimplemented in libc++!"
#   endif
# endif

#endif // TEST_STD_VER > 23

