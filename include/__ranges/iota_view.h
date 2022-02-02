// -*- C++ -*-
//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef _LIBCPP___RANGES_IOTA_VIEW_H
#define _LIBCPP___RANGES_IOTA_VIEW_H

#include <__compare/three_way_comparable.h>
#include <__concepts/arithmetic.h>
#include <__concepts/constructible.h>
#include <__concepts/convertible_to.h>
#include <__concepts/copyable.h>
#include <__concepts/equality_comparable.h>
#include <__concepts/invocable.h>
#include <__concepts/same_as.h>
#include <__concepts/semiregular.h>
#include <__concepts/totally_ordered.h>
#include <__config>
#include <__debug>
#include <__functional/ranges_operations.h>
#include <__iterator/concepts.h>
#include <__iterator/incrementable_traits.h>
#include <__iterator/iterator_traits.h>
#include <__iterator/unreachable_sentinel.h>
#include <__ranges/copyable_box.h>
#include <__ranges/enable_borrowed_range.h>
#include <__ranges/view_interface.h>
#include <__utility/forward.h>
#include <__utility/move.h>
#include <type_traits>

#if !defined(_LIBCPP_HAS_NO_PRAGMA_SYSTEM_HEADER)
#  pragma GCC system_header
#endif

_LIBCPP_BEGIN_NAMESPACE_STD

#if !defined(_LIBCPP_HAS_NO_CONCEPTS)

namespace ranges {
  template<class _Int>
  struct __get_wider_signed {
    static auto __call() {
           if constexpr (sizeof(_Int) < sizeof(short)) return type_identity<short>{};
      else if constexpr (sizeof(_Int) < sizeof(int))   return type_identity<int>{};
      else if constexpr (sizeof(_Int) < sizeof(long))  return type_identity<long>{};
      else                                             return type_identity<long long>{};

      static_assert(sizeof(_Int) <= sizeof(long long),
        "Found integer-like type that is bigger than largest integer like type.");
    }

    using type = typename decltype(__call())::type;
  };

  template<class _Start>
  using _IotaDiffT = typename _If<
      (!integral<_Start> || sizeof(iter_difference_t<_Start>) > sizeof(_Start)),
      type_identity<iter_difference_t<_Start>>,
      __get_wider_signed<_Start>
    >::type;

  template<class _Iter>
  concept __decrementable = incrementable<_Iter> && requires(_Iter __i) {
    { --__i } -> same_as<_Iter&>;
    { __i-- } -> same_as<_Iter>;
  };

  template<class _Iter>
  concept __advanceable =
    __decrementable<_Iter> && totally_ordered<_Iter> &&
    requires(_Iter __i, const _Iter __j, const _IotaDiffT<_Iter> __n) {
      { __i += __n } -> same_as<_Iter&>;
      { __i -= __n } -> same_as<_Iter&>;
      _Iter(__j + __n);
      _Iter(__n + __j);
      _Iter(__j - __n);
      { __j - __j } -> convertible_to<_IotaDiffT<_Iter>>;
    };

  template<class>
  struct __iota_iterator_category {};

  template<incrementable _Tp>
  struct __iota_iterator_category<_Tp> {
    using iterator_category = input_iterator_tag;
  };

  template<weakly_incrementable _Start, semiregular _Bound = unreachable_sentinel_t>
    requires __weakly_equality_comparable_with<_Start, _Bound> && copyable<_Start>
  class iota_view : public view_interface<iota_view<_Start, _Bound>> {
    struct __iterator : public __iota_iterator_category<_Start> {
      friend class iota_view;

      using iterator_concept =
        _If<__advanceable<_Start>,   random_access_iterator_tag,
        _If<__decrementable<_Start>, bidirectional_iterator_tag,
        _If<incrementable<_Start>,   forward_iterator_tag,
        /*Else*/                     input_iterator_tag>>>;

      using value_type = _Start;
      using difference_type = _IotaDiffT<_Start>;

      _Start __value_ = _Start();

      _LIBCPP_HIDE_FROM_ABI
      __iterator() requires default_initializable<_Start> = default;

      _LIBCPP_HIDE_FROM_ABI
      constexpr explicit __iterator(_Start __value) : __value_(_VSTD::move(__value)) {}

      _LIBCPP_HIDE_FROM_ABI
      constexpr _Start operator*() const noexcept(is_nothrow_copy_constructible_v<_Start>) {
        return __value_;
      }

      _LIBCPP_HIDE_FROM_ABI
      constexpr __iterator& operator++() {
        ++__value_;
        return *this;
      }

      _LIBCPP_HIDE_FROM_ABI
      constexpr void operator++(int) { ++*this; }

      _LIBCPP_HIDE_FROM_ABI
      constexpr __iterator operator++(int) requires incrementable<_Start> {
        auto __tmp = *this;
        ++*this;
        return __tmp;
      }

      _LIBCPP_HIDE_FROM_ABI
      constexpr __iterator& operator--() requires __decrementable<_Start> {
        --__value_;
        return *this;
      }

      _LIBCPP_HIDE_FROM_ABI
      constexpr __iterator  operator--(int) requires __decrementable<_Start> {
        auto __tmp = *this;
        --*this;
        return __tmp;
      }

      _LIBCPP_HIDE_FROM_ABI
      constexpr __iterator& operator+=(difference_type __n)
        requires __advanceable<_Start>
      {
        if constexpr (__integer_like<_Start> && !__signed_integer_like<_Start>) {
          if (__n >= difference_type(0)) {
            __value_ += static_cast<_Start>(__n);
          } else {
            __value_ -= static_cast<_Start>(-__n);
          }
        } else {
          __value_ += __n;
        }
        return *this;
      }

      _LIBCPP_HIDE_FROM_ABI
      constexpr __iterator& operator-=(difference_type __n)
        requires __advanceable<_Start>
      {
        if constexpr (__integer_like<_Start> && !__signed_integer_like<_Start>) {
          if (__n >= difference_type(0)) {
            __value_ -= static_cast<_Start>(__n);
          } else {
            __value_ += static_cast<_Start>(-__n);
          }
        } else {
          __value_ -= __n;
        }
        return *this;
      }

      _LIBCPP_HIDE_FROM_ABI
      constexpr _Start operator[](difference_type __n) const
        requires __advanceable<_Start>
      {
        return _Start(__value_ + __n);
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr bool operator==(const __iterator& __x, const __iterator& __y)
        requires equality_comparable<_Start>
      {
        return __x.__value_ == __y.__value_;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr bool operator<(const __iterator& __x, const __iterator& __y)
        requires totally_ordered<_Start>
      {
        return __x.__value_ < __y.__value_;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr bool operator>(const __iterator& __x, const __iterator& __y)
        requires totally_ordered<_Start>
      {
        return __y < __x;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr bool operator<=(const __iterator& __x, const __iterator& __y)
        requires totally_ordered<_Start>
      {
        return !(__y < __x);
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr bool operator>=(const __iterator& __x, const __iterator& __y)
        requires totally_ordered<_Start>
      {
        return !(__x < __y);
      }

      friend constexpr auto operator<=>(const __iterator& __x, const __iterator& __y)
        requires totally_ordered<_Start> && three_way_comparable<_Start>
      {
        return __x.__value_ <=> __y.__value_;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr __iterator operator+(__iterator __i, difference_type __n)
        requires __advanceable<_Start>
      {
        __i += __n;
        return __i;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr __iterator operator+(difference_type __n, __iterator __i)
        requires __advanceable<_Start>
      {
        return __i + __n;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr __iterator operator-(__iterator __i, difference_type __n)
        requires __advanceable<_Start>
      {
        __i -= __n;
        return __i;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr difference_type operator-(const __iterator& __x, const __iterator& __y)
        requires __advanceable<_Start>
      {
        if constexpr (__integer_like<_Start>) {
          if constexpr (__signed_integer_like<_Start>) {
            return difference_type(difference_type(__x.__value_) - difference_type(__y.__value_));
          }
          if (__y.__value_ > __x.__value_) {
            return difference_type(-difference_type(__y.__value_ - __x.__value_));
          }
          return difference_type(__x.__value_ - __y.__value_);
        }
        return __x.__value_ - __y.__value_;
      }
    };

    struct __sentinel {
      friend class iota_view;

    private:
      _Bound __bound_ = _Bound();

    public:
      _LIBCPP_HIDE_FROM_ABI
      __sentinel() = default;
      constexpr explicit __sentinel(_Bound __bound) : __bound_(_VSTD::move(__bound)) {}

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr bool operator==(const __iterator& __x, const __sentinel& __y) {
        return __x.__value_ == __y.__bound_;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr iter_difference_t<_Start> operator-(const __iterator& __x, const __sentinel& __y)
        requires sized_sentinel_for<_Bound, _Start>
      {
        return __x.__value_ - __y.__bound_;
      }

      _LIBCPP_HIDE_FROM_ABI
      friend constexpr iter_difference_t<_Start> operator-(const __sentinel& __x, const __iterator& __y)
        requires sized_sentinel_for<_Bound, _Start>
      {
        return -(__y - __x);
      }
    };

    _Start __value_ = _Start();
    _Bound __bound_ = _Bound();

  public:
    _LIBCPP_HIDE_FROM_ABI
    iota_view() requires default_initializable<_Start> = default;

    _LIBCPP_HIDE_FROM_ABI
    constexpr explicit iota_view(_Start __value) : __value_(_VSTD::move(__value)) { }

    _LIBCPP_HIDE_FROM_ABI
    constexpr iota_view(type_identity_t<_Start> __value, type_identity_t<_Bound> __bound)
      : __value_(_VSTD::move(__value)), __bound_(_VSTD::move(__bound)) {
      // Validate the precondition if possible.
      if constexpr (totally_ordered_with<_Start, _Bound>) {
        _LIBCPP_ASSERT(ranges::less_equal()(__value_, __bound_),
                       "Precondition violated: value is greater than bound.");
      }
    }

    _LIBCPP_HIDE_FROM_ABI
    constexpr iota_view(__iterator __first, __iterator __last)
      requires same_as<_Start, _Bound>
      : iota_view(_VSTD::move(__first.__value_), _VSTD::move(__last.__value_)) {}

    _LIBCPP_HIDE_FROM_ABI
    constexpr iota_view(__iterator __first, _Bound __last)
      requires same_as<_Bound, unreachable_sentinel_t>
      : iota_view(_VSTD::move(__first.__value_), _VSTD::move(__last)) {}

    _LIBCPP_HIDE_FROM_ABI
    constexpr iota_view(__iterator __first, __sentinel __last)
      requires (!same_as<_Start, _Bound> && !same_as<_Start, unreachable_sentinel_t>)
      : iota_view(_VSTD::move(__first.__value_), _VSTD::move(__last.__bound_)) {}

    _LIBCPP_HIDE_FROM_ABI
    constexpr __iterator begin() const { return __iterator{__value_}; }

    _LIBCPP_HIDE_FROM_ABI
    constexpr auto end() const {
      if constexpr (same_as<_Bound, unreachable_sentinel_t>)
        return unreachable_sentinel;
      else
        return __sentinel{__bound_};
    }

    _LIBCPP_HIDE_FROM_ABI
    constexpr __iterator end() const requires same_as<_Start, _Bound> {
      return __iterator{__bound_};
    }

    _LIBCPP_HIDE_FROM_ABI
    constexpr auto size() const
      requires (same_as<_Start, _Bound> && __advanceable<_Start>) ||
               (integral<_Start> && integral<_Bound>) ||
               sized_sentinel_for<_Bound, _Start>
    {
      if constexpr (__integer_like<_Start> && __integer_like<_Bound>) {
        if (__value_ < 0) {
          if (__bound_ < 0) {
            return _VSTD::__to_unsigned_like(-__value_) - _VSTD::__to_unsigned_like(-__bound_);
          }
          return _VSTD::__to_unsigned_like(__bound_) + _VSTD::__to_unsigned_like(-__value_);
        }
        return _VSTD::__to_unsigned_like(__bound_) - _VSTD::__to_unsigned_like(__value_);
      }
      return _VSTD::__to_unsigned_like(__bound_ - __value_);
    }
  };

  template<class _Start, class _Bound>
    requires (!__integer_like<_Start> || !__integer_like<_Bound> ||
              (__signed_integer_like<_Start> == __signed_integer_like<_Bound>))
  iota_view(_Start, _Bound) -> iota_view<_Start, _Bound>;

  template<class _Start, class _Bound>
  inline constexpr bool enable_borrowed_range<iota_view<_Start, _Bound>> = true;

namespace views {
namespace __iota {
  struct __fn {
    template<class _Start>
    _LIBCPP_HIDE_FROM_ABI
    constexpr auto operator()(_Start&& __start) const
      noexcept(noexcept(ranges::iota_view(_VSTD::forward<_Start>(__start))))
      -> decltype(      ranges::iota_view(_VSTD::forward<_Start>(__start)))
      { return          ranges::iota_view(_VSTD::forward<_Start>(__start)); }

    template<class _Start, class _Bound>
    _LIBCPP_HIDE_FROM_ABI
    constexpr auto operator()(_Start&& __start, _Bound&& __bound) const
      noexcept(noexcept(ranges::iota_view(_VSTD::forward<_Start>(__start), _VSTD::forward<_Bound>(__bound))))
      -> decltype(      ranges::iota_view(_VSTD::forward<_Start>(__start), _VSTD::forward<_Bound>(__bound)))
      { return          ranges::iota_view(_VSTD::forward<_Start>(__start), _VSTD::forward<_Bound>(__bound)); }
  };
} // namespace __iota

inline namespace __cpo {
  inline constexpr auto iota = __iota::__fn{};
} // namespace __cpo
} // namespace views
} // namespace ranges

#endif // !defined(_LIBCPP_HAS_NO_CONCEPTS)

_LIBCPP_END_NAMESPACE_STD

#endif // _LIBCPP___RANGES_IOTA_VIEW_H
