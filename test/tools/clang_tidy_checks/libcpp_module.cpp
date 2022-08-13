//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang-tidy/ClangTidyModule.h"
#include "clang-tidy/ClangTidyModuleRegistry.h"
#include "robust_against_adl.hpp"

namespace {
class LibcxxTestModule : public clang::tidy::ClangTidyModule {
public:
  void addCheckFactories(clang::tidy::ClangTidyCheckFactories& check_factories) override {
    check_factories.registerCheck<libcpp::robust_against_adl_check>("libcpp-robust-against-adl");
  }
};
} // namespace

clang::tidy::ClangTidyModuleRegistry::Add<LibcxxTestModule> libcpp_module{
    "libcpp-module", "Adds libc++-specific checks."};
