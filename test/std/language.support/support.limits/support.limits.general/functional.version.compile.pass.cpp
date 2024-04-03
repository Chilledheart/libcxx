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

// <functional>

// Test the feature test macros defined by <functional>

/*  Constant                           Value
    __cpp_lib_bind_back                202202L [C++23]
                                       202306L [C++26]
    __cpp_lib_bind_front               201907L [C++20]
                                       202306L [C++26]
    __cpp_lib_boyer_moore_searcher     201603L [C++17]
    __cpp_lib_constexpr_functional     201907L [C++20]
    __cpp_lib_copyable_function        202306L [C++26]
    __cpp_lib_function_ref             202306L [C++26]
    __cpp_lib_invoke                   201411L [C++17]
    __cpp_lib_invoke_r                 202106L [C++23]
    __cpp_lib_move_only_function       202110L [C++23]
    __cpp_lib_not_fn                   201603L [C++17]
    __cpp_lib_ranges                   202207L [C++20]
    __cpp_lib_reference_wrapper        202403L [C++26]
    __cpp_lib_result_of_sfinae         201210L [C++14]
    __cpp_lib_transparent_operators    201210L [C++14]
                                       201510L [C++17]
    __cpp_lib_unwrap_ref               201811L [C++20]
*/

#include <functional>
#include "test_macros.h"

#if TEST_STD_VER < 14

# ifdef __cpp_lib_bind_back
#   error "__cpp_lib_bind_back should not be defined before c++23"
# endif

# ifdef __cpp_lib_bind_front
#   error "__cpp_lib_bind_front should not be defined before c++20"
# endif

# ifdef __cpp_lib_boyer_moore_searcher
#   error "__cpp_lib_boyer_moore_searcher should not be defined before c++17"
# endif

# ifdef __cpp_lib_constexpr_functional
#   error "__cpp_lib_constexpr_functional should not be defined before c++20"
# endif

# ifdef __cpp_lib_copyable_function
#   error "__cpp_lib_copyable_function should not be defined before c++26"
# endif

# ifdef __cpp_lib_function_ref
#   error "__cpp_lib_function_ref should not be defined before c++26"
# endif

# ifdef __cpp_lib_invoke
#   error "__cpp_lib_invoke should not be defined before c++17"
# endif

# ifdef __cpp_lib_invoke_r
#   error "__cpp_lib_invoke_r should not be defined before c++23"
# endif

# ifdef __cpp_lib_move_only_function
#   error "__cpp_lib_move_only_function should not be defined before c++23"
# endif

# ifdef __cpp_lib_not_fn
#   error "__cpp_lib_not_fn should not be defined before c++17"
# endif

# ifdef __cpp_lib_ranges
#   error "__cpp_lib_ranges should not be defined before c++20"
# endif

# ifdef __cpp_lib_reference_wrapper
#   error "__cpp_lib_reference_wrapper should not be defined before c++26"
# endif

# ifdef __cpp_lib_result_of_sfinae
#   error "__cpp_lib_result_of_sfinae should not be defined before c++14"
# endif

# ifdef __cpp_lib_transparent_operators
#   error "__cpp_lib_transparent_operators should not be defined before c++14"
# endif

# ifdef __cpp_lib_unwrap_ref
#   error "__cpp_lib_unwrap_ref should not be defined before c++20"
# endif

#elif TEST_STD_VER == 14

# ifdef __cpp_lib_bind_back
#   error "__cpp_lib_bind_back should not be defined before c++23"
# endif

# ifdef __cpp_lib_bind_front
#   error "__cpp_lib_bind_front should not be defined before c++20"
# endif

# ifdef __cpp_lib_boyer_moore_searcher
#   error "__cpp_lib_boyer_moore_searcher should not be defined before c++17"
# endif

# ifdef __cpp_lib_constexpr_functional
#   error "__cpp_lib_constexpr_functional should not be defined before c++20"
# endif

# ifdef __cpp_lib_copyable_function
#   error "__cpp_lib_copyable_function should not be defined before c++26"
# endif

# ifdef __cpp_lib_function_ref
#   error "__cpp_lib_function_ref should not be defined before c++26"
# endif

# ifdef __cpp_lib_invoke
#   error "__cpp_lib_invoke should not be defined before c++17"
# endif

# ifdef __cpp_lib_invoke_r
#   error "__cpp_lib_invoke_r should not be defined before c++23"
# endif

# ifdef __cpp_lib_move_only_function
#   error "__cpp_lib_move_only_function should not be defined before c++23"
# endif

# ifdef __cpp_lib_not_fn
#   error "__cpp_lib_not_fn should not be defined before c++17"
# endif

# ifdef __cpp_lib_ranges
#   error "__cpp_lib_ranges should not be defined before c++20"
# endif

# ifdef __cpp_lib_reference_wrapper
#   error "__cpp_lib_reference_wrapper should not be defined before c++26"
# endif

# ifndef __cpp_lib_result_of_sfinae
#   error "__cpp_lib_result_of_sfinae should be defined in c++14"
# endif
# if __cpp_lib_result_of_sfinae != 201210L
#   error "__cpp_lib_result_of_sfinae should have the value 201210L in c++14"
# endif

# ifndef __cpp_lib_transparent_operators
#   error "__cpp_lib_transparent_operators should be defined in c++14"
# endif
# if __cpp_lib_transparent_operators != 201210L
#   error "__cpp_lib_transparent_operators should have the value 201210L in c++14"
# endif

# ifdef __cpp_lib_unwrap_ref
#   error "__cpp_lib_unwrap_ref should not be defined before c++20"
# endif

#elif TEST_STD_VER == 17

# ifdef __cpp_lib_bind_back
#   error "__cpp_lib_bind_back should not be defined before c++23"
# endif

# ifdef __cpp_lib_bind_front
#   error "__cpp_lib_bind_front should not be defined before c++20"
# endif

# ifndef __cpp_lib_boyer_moore_searcher
#   error "__cpp_lib_boyer_moore_searcher should be defined in c++17"
# endif
# if __cpp_lib_boyer_moore_searcher != 201603L
#   error "__cpp_lib_boyer_moore_searcher should have the value 201603L in c++17"
# endif

# ifdef __cpp_lib_constexpr_functional
#   error "__cpp_lib_constexpr_functional should not be defined before c++20"
# endif

# ifdef __cpp_lib_copyable_function
#   error "__cpp_lib_copyable_function should not be defined before c++26"
# endif

# ifdef __cpp_lib_function_ref
#   error "__cpp_lib_function_ref should not be defined before c++26"
# endif

# ifndef __cpp_lib_invoke
#   error "__cpp_lib_invoke should be defined in c++17"
# endif
# if __cpp_lib_invoke != 201411L
#   error "__cpp_lib_invoke should have the value 201411L in c++17"
# endif

# ifdef __cpp_lib_invoke_r
#   error "__cpp_lib_invoke_r should not be defined before c++23"
# endif

# ifdef __cpp_lib_move_only_function
#   error "__cpp_lib_move_only_function should not be defined before c++23"
# endif

# ifndef __cpp_lib_not_fn
#   error "__cpp_lib_not_fn should be defined in c++17"
# endif
# if __cpp_lib_not_fn != 201603L
#   error "__cpp_lib_not_fn should have the value 201603L in c++17"
# endif

# ifdef __cpp_lib_ranges
#   error "__cpp_lib_ranges should not be defined before c++20"
# endif

# ifdef __cpp_lib_reference_wrapper
#   error "__cpp_lib_reference_wrapper should not be defined before c++26"
# endif

# ifndef __cpp_lib_result_of_sfinae
#   error "__cpp_lib_result_of_sfinae should be defined in c++17"
# endif
# if __cpp_lib_result_of_sfinae != 201210L
#   error "__cpp_lib_result_of_sfinae should have the value 201210L in c++17"
# endif

# ifndef __cpp_lib_transparent_operators
#   error "__cpp_lib_transparent_operators should be defined in c++17"
# endif
# if __cpp_lib_transparent_operators != 201510L
#   error "__cpp_lib_transparent_operators should have the value 201510L in c++17"
# endif

# ifdef __cpp_lib_unwrap_ref
#   error "__cpp_lib_unwrap_ref should not be defined before c++20"
# endif

#elif TEST_STD_VER == 20

# ifdef __cpp_lib_bind_back
#   error "__cpp_lib_bind_back should not be defined before c++23"
# endif

# ifndef __cpp_lib_bind_front
#   error "__cpp_lib_bind_front should be defined in c++20"
# endif
# if __cpp_lib_bind_front != 201907L
#   error "__cpp_lib_bind_front should have the value 201907L in c++20"
# endif

# ifndef __cpp_lib_boyer_moore_searcher
#   error "__cpp_lib_boyer_moore_searcher should be defined in c++20"
# endif
# if __cpp_lib_boyer_moore_searcher != 201603L
#   error "__cpp_lib_boyer_moore_searcher should have the value 201603L in c++20"
# endif

# ifndef __cpp_lib_constexpr_functional
#   error "__cpp_lib_constexpr_functional should be defined in c++20"
# endif
# if __cpp_lib_constexpr_functional != 201907L
#   error "__cpp_lib_constexpr_functional should have the value 201907L in c++20"
# endif

# ifdef __cpp_lib_copyable_function
#   error "__cpp_lib_copyable_function should not be defined before c++26"
# endif

# ifdef __cpp_lib_function_ref
#   error "__cpp_lib_function_ref should not be defined before c++26"
# endif

# ifndef __cpp_lib_invoke
#   error "__cpp_lib_invoke should be defined in c++20"
# endif
# if __cpp_lib_invoke != 201411L
#   error "__cpp_lib_invoke should have the value 201411L in c++20"
# endif

# ifdef __cpp_lib_invoke_r
#   error "__cpp_lib_invoke_r should not be defined before c++23"
# endif

# ifdef __cpp_lib_move_only_function
#   error "__cpp_lib_move_only_function should not be defined before c++23"
# endif

# ifndef __cpp_lib_not_fn
#   error "__cpp_lib_not_fn should be defined in c++20"
# endif
# if __cpp_lib_not_fn != 201603L
#   error "__cpp_lib_not_fn should have the value 201603L in c++20"
# endif

# ifndef __cpp_lib_ranges
#   error "__cpp_lib_ranges should be defined in c++20"
# endif
# if __cpp_lib_ranges != 202207L
#   error "__cpp_lib_ranges should have the value 202207L in c++20"
# endif

# ifdef __cpp_lib_reference_wrapper
#   error "__cpp_lib_reference_wrapper should not be defined before c++26"
# endif

# ifndef __cpp_lib_result_of_sfinae
#   error "__cpp_lib_result_of_sfinae should be defined in c++20"
# endif
# if __cpp_lib_result_of_sfinae != 201210L
#   error "__cpp_lib_result_of_sfinae should have the value 201210L in c++20"
# endif

# ifndef __cpp_lib_transparent_operators
#   error "__cpp_lib_transparent_operators should be defined in c++20"
# endif
# if __cpp_lib_transparent_operators != 201510L
#   error "__cpp_lib_transparent_operators should have the value 201510L in c++20"
# endif

# ifndef __cpp_lib_unwrap_ref
#   error "__cpp_lib_unwrap_ref should be defined in c++20"
# endif
# if __cpp_lib_unwrap_ref != 201811L
#   error "__cpp_lib_unwrap_ref should have the value 201811L in c++20"
# endif

#elif TEST_STD_VER == 23

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_bind_back
#     error "__cpp_lib_bind_back should be defined in c++23"
#   endif
#   if __cpp_lib_bind_back != 202202L
#     error "__cpp_lib_bind_back should have the value 202202L in c++23"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_bind_back
#     error "__cpp_lib_bind_back should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_bind_front
#   error "__cpp_lib_bind_front should be defined in c++23"
# endif
# if __cpp_lib_bind_front != 201907L
#   error "__cpp_lib_bind_front should have the value 201907L in c++23"
# endif

# ifndef __cpp_lib_boyer_moore_searcher
#   error "__cpp_lib_boyer_moore_searcher should be defined in c++23"
# endif
# if __cpp_lib_boyer_moore_searcher != 201603L
#   error "__cpp_lib_boyer_moore_searcher should have the value 201603L in c++23"
# endif

# ifndef __cpp_lib_constexpr_functional
#   error "__cpp_lib_constexpr_functional should be defined in c++23"
# endif
# if __cpp_lib_constexpr_functional != 201907L
#   error "__cpp_lib_constexpr_functional should have the value 201907L in c++23"
# endif

# ifdef __cpp_lib_copyable_function
#   error "__cpp_lib_copyable_function should not be defined before c++26"
# endif

# ifdef __cpp_lib_function_ref
#   error "__cpp_lib_function_ref should not be defined before c++26"
# endif

# ifndef __cpp_lib_invoke
#   error "__cpp_lib_invoke should be defined in c++23"
# endif
# if __cpp_lib_invoke != 201411L
#   error "__cpp_lib_invoke should have the value 201411L in c++23"
# endif

# ifndef __cpp_lib_invoke_r
#   error "__cpp_lib_invoke_r should be defined in c++23"
# endif
# if __cpp_lib_invoke_r != 202106L
#   error "__cpp_lib_invoke_r should have the value 202106L in c++23"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_move_only_function
#     error "__cpp_lib_move_only_function should be defined in c++23"
#   endif
#   if __cpp_lib_move_only_function != 202110L
#     error "__cpp_lib_move_only_function should have the value 202110L in c++23"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_move_only_function
#     error "__cpp_lib_move_only_function should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_not_fn
#   error "__cpp_lib_not_fn should be defined in c++23"
# endif
# if __cpp_lib_not_fn != 201603L
#   error "__cpp_lib_not_fn should have the value 201603L in c++23"
# endif

# ifndef __cpp_lib_ranges
#   error "__cpp_lib_ranges should be defined in c++23"
# endif
# if __cpp_lib_ranges != 202207L
#   error "__cpp_lib_ranges should have the value 202207L in c++23"
# endif

# ifdef __cpp_lib_reference_wrapper
#   error "__cpp_lib_reference_wrapper should not be defined before c++26"
# endif

# ifndef __cpp_lib_result_of_sfinae
#   error "__cpp_lib_result_of_sfinae should be defined in c++23"
# endif
# if __cpp_lib_result_of_sfinae != 201210L
#   error "__cpp_lib_result_of_sfinae should have the value 201210L in c++23"
# endif

# ifndef __cpp_lib_transparent_operators
#   error "__cpp_lib_transparent_operators should be defined in c++23"
# endif
# if __cpp_lib_transparent_operators != 201510L
#   error "__cpp_lib_transparent_operators should have the value 201510L in c++23"
# endif

# ifndef __cpp_lib_unwrap_ref
#   error "__cpp_lib_unwrap_ref should be defined in c++23"
# endif
# if __cpp_lib_unwrap_ref != 201811L
#   error "__cpp_lib_unwrap_ref should have the value 201811L in c++23"
# endif

#elif TEST_STD_VER > 23

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_bind_back
#     error "__cpp_lib_bind_back should be defined in c++26"
#   endif
#   if __cpp_lib_bind_back != 202306L
#     error "__cpp_lib_bind_back should have the value 202306L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_bind_back
#     error "__cpp_lib_bind_back should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_bind_front
#   error "__cpp_lib_bind_front should be defined in c++26"
# endif
# if __cpp_lib_bind_front != 202306L
#   error "__cpp_lib_bind_front should have the value 202306L in c++26"
# endif

# ifndef __cpp_lib_boyer_moore_searcher
#   error "__cpp_lib_boyer_moore_searcher should be defined in c++26"
# endif
# if __cpp_lib_boyer_moore_searcher != 201603L
#   error "__cpp_lib_boyer_moore_searcher should have the value 201603L in c++26"
# endif

# ifndef __cpp_lib_constexpr_functional
#   error "__cpp_lib_constexpr_functional should be defined in c++26"
# endif
# if __cpp_lib_constexpr_functional != 201907L
#   error "__cpp_lib_constexpr_functional should have the value 201907L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_copyable_function
#     error "__cpp_lib_copyable_function should be defined in c++26"
#   endif
#   if __cpp_lib_copyable_function != 202306L
#     error "__cpp_lib_copyable_function should have the value 202306L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_copyable_function
#     error "__cpp_lib_copyable_function should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_function_ref
#     error "__cpp_lib_function_ref should be defined in c++26"
#   endif
#   if __cpp_lib_function_ref != 202306L
#     error "__cpp_lib_function_ref should have the value 202306L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_function_ref
#     error "__cpp_lib_function_ref should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_invoke
#   error "__cpp_lib_invoke should be defined in c++26"
# endif
# if __cpp_lib_invoke != 201411L
#   error "__cpp_lib_invoke should have the value 201411L in c++26"
# endif

# ifndef __cpp_lib_invoke_r
#   error "__cpp_lib_invoke_r should be defined in c++26"
# endif
# if __cpp_lib_invoke_r != 202106L
#   error "__cpp_lib_invoke_r should have the value 202106L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_move_only_function
#     error "__cpp_lib_move_only_function should be defined in c++26"
#   endif
#   if __cpp_lib_move_only_function != 202110L
#     error "__cpp_lib_move_only_function should have the value 202110L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_move_only_function
#     error "__cpp_lib_move_only_function should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_not_fn
#   error "__cpp_lib_not_fn should be defined in c++26"
# endif
# if __cpp_lib_not_fn != 201603L
#   error "__cpp_lib_not_fn should have the value 201603L in c++26"
# endif

# ifndef __cpp_lib_ranges
#   error "__cpp_lib_ranges should be defined in c++26"
# endif
# if __cpp_lib_ranges != 202207L
#   error "__cpp_lib_ranges should have the value 202207L in c++26"
# endif

# if !defined(_LIBCPP_VERSION)
#   ifndef __cpp_lib_reference_wrapper
#     error "__cpp_lib_reference_wrapper should be defined in c++26"
#   endif
#   if __cpp_lib_reference_wrapper != 202403L
#     error "__cpp_lib_reference_wrapper should have the value 202403L in c++26"
#   endif
# else // _LIBCPP_VERSION
#   ifdef __cpp_lib_reference_wrapper
#     error "__cpp_lib_reference_wrapper should not be defined because it is unimplemented in libc++!"
#   endif
# endif

# ifndef __cpp_lib_result_of_sfinae
#   error "__cpp_lib_result_of_sfinae should be defined in c++26"
# endif
# if __cpp_lib_result_of_sfinae != 201210L
#   error "__cpp_lib_result_of_sfinae should have the value 201210L in c++26"
# endif

# ifndef __cpp_lib_transparent_operators
#   error "__cpp_lib_transparent_operators should be defined in c++26"
# endif
# if __cpp_lib_transparent_operators != 201510L
#   error "__cpp_lib_transparent_operators should have the value 201510L in c++26"
# endif

# ifndef __cpp_lib_unwrap_ref
#   error "__cpp_lib_unwrap_ref should be defined in c++26"
# endif
# if __cpp_lib_unwrap_ref != 201811L
#   error "__cpp_lib_unwrap_ref should have the value 201811L in c++26"
# endif

#endif // TEST_STD_VER > 23

