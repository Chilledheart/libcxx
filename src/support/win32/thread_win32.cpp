//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <__thread/support/windows.h>
#include <chrono>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <process.h>
#include <windows.h>

#if defined(_LIBCPP_HAS_THREAD_API_WIN32)

_LIBCPP_BEGIN_NAMESPACE_STD

#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA
static_assert(sizeof(__libcpp_mutex_t) == sizeof(SRWLOCK), "");
static_assert(alignof(__libcpp_mutex_t) == alignof(SRWLOCK), "");
#  else
static_assert(sizeof(__libcpp_mutex_t) == sizeof(CRITICAL_SECTION), "");
static_assert(alignof(__libcpp_mutex_t) == alignof(CRITICAL_SECTION), "");
#  endif
static_assert(sizeof(__libcpp_recursive_mutex_t) == sizeof(CRITICAL_SECTION), "");
static_assert(alignof(__libcpp_recursive_mutex_t) == alignof(CRITICAL_SECTION), "");

#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA
static_assert(sizeof(__libcpp_condvar_t) == sizeof(CONDITION_VARIABLE), "");
static_assert(alignof(__libcpp_condvar_t) == alignof(CONDITION_VARIABLE), "");
#  else
typedef struct {
  int nwaiters_blocked;
  int nwaiters_gone;
  int nwaiters_to_unblock;
  int reserved;
  HANDLE sem_block_queue;
  HANDLE sem_block_lock;
  CRITICAL_SECTION mtx_unblock_lock;
} __libcpp_condvar_do_t;
static_assert(sizeof(__libcpp_condvar_t) == sizeof(__libcpp_condvar_do_t), "");
static_assert(alignof(__libcpp_condvar_t) == alignof(__libcpp_condvar_do_t), "");
#    define _LIBCPP_SEMAPHORE_MAX (::std::numeric_limits<long>::max())
#  endif

#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA
static_assert(sizeof(__libcpp_exec_once_flag) == sizeof(INIT_ONCE), "");
static_assert(alignof(__libcpp_exec_once_flag) == alignof(INIT_ONCE), "");
#  else
static_assert(sizeof(__libcpp_exec_once_flag) >= sizeof(LONG), "");
static_assert(alignof(__libcpp_exec_once_flag) >= alignof(LONG), "");
#  endif

static_assert(sizeof(__libcpp_thread_id) == sizeof(DWORD), "");
static_assert(alignof(__libcpp_thread_id) == alignof(DWORD), "");

static_assert(sizeof(__libcpp_thread_t) == sizeof(HANDLE), "");
static_assert(alignof(__libcpp_thread_t) == alignof(HANDLE), "");

static_assert(sizeof(__libcpp_tls_key) == sizeof(DWORD), "");
static_assert(alignof(__libcpp_tls_key) == alignof(DWORD), "");

// Mutex
int __libcpp_recursive_mutex_init(__libcpp_recursive_mutex_t* __m) {
  InitializeCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

int __libcpp_recursive_mutex_lock(__libcpp_recursive_mutex_t* __m) {
  EnterCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

bool __libcpp_recursive_mutex_trylock(__libcpp_recursive_mutex_t* __m) {
  return TryEnterCriticalSection((LPCRITICAL_SECTION)__m) != 0;
}

int __libcpp_recursive_mutex_unlock(__libcpp_recursive_mutex_t* __m) {
  LeaveCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

int __libcpp_recursive_mutex_destroy(__libcpp_recursive_mutex_t* __m) {
  DeleteCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

#  if _WIN32_WINNT >= _WIN32_WINNT_WIN7

int __libcpp_mutex_init(__libcpp_mutex_t* __m) {
  *__m = _LIBCPP_MUTEX_INITIALIZER;
  return 0;
}

int __libcpp_mutex_lock(__libcpp_mutex_t* __m) {
  AcquireSRWLockExclusive((PSRWLOCK)__m);
  return 0;
}

bool __libcpp_mutex_trylock(__libcpp_mutex_t* __m) { return TryAcquireSRWLockExclusive((PSRWLOCK)__m) != 0; }

int __libcpp_mutex_unlock(__libcpp_mutex_t* __m) {
  ReleaseSRWLockExclusive((PSRWLOCK)__m);
  return 0;
}

int __libcpp_mutex_destroy(__libcpp_mutex_t* __m) {
  static_cast<void>(__m);
  return 0;
}

#  else // _WIN32_WINNT >= _WIN32_WINNT_WIN7

int __libcpp_mutex_init(__libcpp_mutex_t* __m) {
  InitializeCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

int __libcpp_mutex_lock(__libcpp_mutex_t* __m) {
  EnterCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

bool __libcpp_mutex_trylock(__libcpp_mutex_t* __m) { return TryEnterCriticalSection((LPCRITICAL_SECTION)__m) != 0; }

int __libcpp_mutex_unlock(__libcpp_mutex_t* __m) {
  LeaveCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

int __libcpp_mutex_destroy(__libcpp_mutex_t* __m) {
  DeleteCriticalSection((LPCRITICAL_SECTION)__m);
  return 0;
}

#  endif // _WIN32_WINNT >= _WIN32_WINNT_WIN7

// Condition Variable

#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA

int __libcpp_condvar_init(__libcpp_condvar_t* __cv) {
  *__cv = _LIBCPP_CONDVAR_INITIALIZER;
  return 0;
}

int __libcpp_condvar_signal(__libcpp_condvar_t* __cv) {
  WakeConditionVariable((PCONDITION_VARIABLE)__cv);
  return 0;
}

int __libcpp_condvar_broadcast(__libcpp_condvar_t* __cv) {
  WakeAllConditionVariable((PCONDITION_VARIABLE)__cv);
  return 0;
}

int __libcpp_condvar_wait(__libcpp_condvar_t* __cv, __libcpp_mutex_t* __m) {
  SleepConditionVariableSRW((PCONDITION_VARIABLE)__cv, (PSRWLOCK)__m, INFINITE, 0);
  return 0;
}

int __libcpp_condvar_timedwait(__libcpp_condvar_t* __cv, __libcpp_mutex_t* __m, __libcpp_timespec_t* __ts) {
  using namespace std::chrono;

  auto duration   = seconds(__ts->tv_sec) + nanoseconds(__ts->tv_nsec);
  auto abstime    = system_clock::time_point(duration_cast<system_clock::duration>(duration));
  auto timeout_ms = duration_cast<milliseconds>(abstime - system_clock::now());

  if (!SleepConditionVariableSRW(
          (PCONDITION_VARIABLE)__cv, (PSRWLOCK)__m, timeout_ms.count() > 0 ? timeout_ms.count() : 0, 0)) {
    auto __ec = GetLastError();
    return __ec == ERROR_TIMEOUT ? ETIMEDOUT : __ec;
  }
  return 0;
}

int __libcpp_condvar_destroy(__libcpp_condvar_t* __cv) {
  static_cast<void>(__cv);
  return 0;
}

#  else // _WIN32_WINNT >= _WIN32_WINNT_VISTA

/*
Note:
  The implementation of condition variable is ported from Boost.Interprocess
  See https://www.boost.org/doc/libs/1_53_0/boost/interprocess/sync/windows/condition.hpp
*/

static inline _LIBCPP_HIDE_FROM_ABI void __libcpp_condvar_do_signal(__libcpp_condvar_do_t* __cond, bool __broadcast) {
  int nsignal = 0;

  EnterCriticalSection(&__cond->mtx_unblock_lock);
  if (__cond->nwaiters_to_unblock != 0) {
    if (__cond->nwaiters_blocked == 0) {
      LeaveCriticalSection(&__cond->mtx_unblock_lock);
      return;
    }
    if (__broadcast) {
      __cond->nwaiters_to_unblock += nsignal = __cond->nwaiters_blocked;
      __cond->nwaiters_blocked               = 0;
    } else {
      nsignal = 1;
      __cond->nwaiters_to_unblock++;
      __cond->nwaiters_blocked--;
    }
  } else if (__cond->nwaiters_blocked > __cond->nwaiters_gone) {
    WaitForSingleObject(__cond->sem_block_lock, INFINITE);
    if (__cond->nwaiters_gone != 0) {
      __cond->nwaiters_blocked -= __cond->nwaiters_gone;
      __cond->nwaiters_gone = 0;
    }
    if (__broadcast) {
      nsignal = __cond->nwaiters_to_unblock = __cond->nwaiters_blocked;
      __cond->nwaiters_blocked              = 0;
    } else {
      nsignal = __cond->nwaiters_to_unblock = 1;
      __cond->nwaiters_blocked--;
    }
  }
  LeaveCriticalSection(&__cond->mtx_unblock_lock);

  if (0 < nsignal)
    ReleaseSemaphore(__cond->sem_block_queue, nsignal, nullptr);
}

static inline _LIBCPP_HIDE_FROM_ABI int
__libcpp_condvar_do_wait(__libcpp_condvar_do_t* __cond, __libcpp_mutex_t* __m, __libcpp_timespec_t* __ts) {
  using namespace std::chrono;

  DWORD timeout_ms = INFINITE;
  if (__ts) {
    auto duration = seconds(__ts->tv_sec) + nanoseconds(__ts->tv_nsec);
    auto abstime  = system_clock::time_point(duration_cast<system_clock::duration>(duration));
    timeout_ms    = duration_cast<milliseconds>(abstime - system_clock::now()).count();
  }

  int nleft          = 0;
  int nnwaiters_gone = 0;
  int timeout        = 0;
  DWORD w;

  WaitForSingleObject(__cond->sem_block_lock, INFINITE);
  __cond->nwaiters_blocked++;
  ReleaseSemaphore(__cond->sem_block_lock, 1, nullptr);

  __libcpp_mutex_unlock(__m);

  w       = WaitForSingleObject(__cond->sem_block_queue, timeout_ms);
  timeout = (w == WAIT_TIMEOUT);

  EnterCriticalSection(&__cond->mtx_unblock_lock);
  if ((nleft = __cond->nwaiters_to_unblock) != 0) {
    if (timeout) {
      if (__cond->nwaiters_blocked != 0) {
        __cond->nwaiters_blocked--;
      } else {
        __cond->nwaiters_gone++;
      }
    }
    if (--__cond->nwaiters_to_unblock == 0) {
      if (__cond->nwaiters_blocked != 0) {
        ReleaseSemaphore(__cond->sem_block_lock, 1, nullptr);
        nleft = 0;
      } else if ((nnwaiters_gone = __cond->nwaiters_gone) != 0) {
        __cond->nwaiters_gone = 0;
      }
    }
  } else if (++__cond->nwaiters_gone == INT_MAX / 2) {
    WaitForSingleObject(__cond->sem_block_lock, INFINITE);
    __cond->nwaiters_blocked -= __cond->nwaiters_gone;
    ReleaseSemaphore(__cond->sem_block_lock, 1, nullptr);
    __cond->nwaiters_gone = 0;
  }
  LeaveCriticalSection(&__cond->mtx_unblock_lock);

  if (nleft == 1) {
    while (nnwaiters_gone--)
      WaitForSingleObject(__cond->sem_block_queue, INFINITE);
    ReleaseSemaphore(__cond->sem_block_lock, 1, nullptr);
  }

  __libcpp_mutex_lock(__m);
  return timeout ? /* busy */ ETIMEDOUT : 0;
}

int __libcpp_condvar_init(__libcpp_condvar_t* __cv) {
  auto __cond                 = reinterpret_cast<__libcpp_condvar_do_t*>(__cv);
  __cond->nwaiters_blocked    = 0;
  __cond->nwaiters_gone       = 0;
  __cond->nwaiters_to_unblock = 0;
  __cond->reserved            = 0;
  __cond->sem_block_queue     = CreateSemaphore(nullptr, 0, _LIBCPP_SEMAPHORE_MAX, nullptr);
  __cond->sem_block_lock      = CreateSemaphore(nullptr, 1, 1, nullptr);
  InitializeCriticalSection(&__cond->mtx_unblock_lock);
  return 0;
}

int __libcpp_condvar_signal(__libcpp_condvar_t* __cv) {
  auto __do_cv = reinterpret_cast<__libcpp_condvar_do_t*>(__cv);
  __libcpp_condvar_do_signal(__do_cv, false);
  return 0;
}

int __libcpp_condvar_broadcast(__libcpp_condvar_t* __cv) {
  auto __do_cv = reinterpret_cast<__libcpp_condvar_do_t*>(__cv);
  __libcpp_condvar_do_signal(__do_cv, true);
  return 0;
}

int __libcpp_condvar_wait(__libcpp_condvar_t* __cv, __libcpp_mutex_t* __m) {
  auto __do_cv = reinterpret_cast<__libcpp_condvar_do_t*>(__cv);
  return __libcpp_condvar_do_wait(__do_cv, __m, nullptr);
}

int __libcpp_condvar_timedwait(__libcpp_condvar_t* __cv, __libcpp_mutex_t* __m, __libcpp_timespec_t* __ts) {
  auto __do_cv = reinterpret_cast<__libcpp_condvar_do_t*>(__cv);
  return __libcpp_condvar_do_wait(__do_cv, __m, __ts);
}

int __libcpp_condvar_destroy(__libcpp_condvar_t* __cv) {
  auto __cond = reinterpret_cast<__libcpp_condvar_do_t*>(__cv);
  CloseHandle(__cond->sem_block_queue);
  CloseHandle(__cond->sem_block_lock);
  DeleteCriticalSection(&__cond->mtx_unblock_lock);
  return 0;
}

#  endif // _WIN32_WINNT >= _WIN32_WINNT_VISTA

// Execute Once
int __libcpp_execute_once(__libcpp_exec_once_flag* __flag, void* arg, void (*__init_routine)(void));

#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA

struct __libcpp_init_once_execute_context {
  void* arg;
  void (*init_routine)(void*);
};

static _LIBCPP_HIDE_FROM_ABI BOOL CALLBACK
__libcpp_init_once_execute_once_thunk(PINIT_ONCE __init_once, PVOID __parameter, PVOID* __context) {
  static_cast<void>(__init_once);
  static_cast<void>(__context);

  auto __ctx = reinterpret_cast<__libcpp_init_once_execute_context*>(__parameter);
  __ctx->init_routine(__ctx->arg);

  return TRUE;
}

int __libcpp_execute_once(__libcpp_exec_once_flag* __flag, void* arg, void (*init_routine)(void*)) {
  static_assert(sizeof(__libcpp_exec_once_flag) == sizeof(INIT_ONCE), "invalid size");
  __libcpp_init_once_execute_context __ctx;
  __ctx.arg          = arg;
  __ctx.init_routine = init_routine;
  if (!InitOnceExecuteOnce((PINIT_ONCE)__flag, __libcpp_init_once_execute_once_thunk, &__ctx, nullptr))
    return GetLastError();
  return 0;
}

#  else // _WIN32_WINNT >= _WIN32_WINNT_VISTA

int __libcpp_execute_once(__libcpp_exec_once_flag* __flag, void* arg, void (*__init_routine)(void*)) {
  /* This assumes that reading *once has acquire semantics. This should be true
   * on x86 and x86-64, where we expect Windows to run. */
#    if !defined(_M_IX86) && !defined(_M_X64) && !defined(_M_ARM64)
#      error "Windows once code may not work on other platforms." \
       "You can use InitOnceBeginInitialize on >=Vista"
#    endif

  volatile LONG* __once = reinterpret_cast<volatile LONG*>(__flag);

  static_assert(sizeof(*__flag) >= sizeof(*__once), "exec_once_flag must contains at least a LONG variable");

  if (*__once == 1) {
    return 0;
  }

  for (;;) {
    switch (InterlockedCompareExchange(__once, 2, 0)) {
    case 0:
      /* The value was zero so we are the first thread to call once
       * on it. */
      __init_routine(arg);
      /* Write one to indicate that initialisation is complete. */
      InterlockedExchange(__once, 1);
      return 0;

    case 1:
      /* Another thread completed initialisation between our fast-path check
       * and |InterlockedCompareExchange|. */
      return 0;

    case 2:
      /* Another thread is running the initialisation. Switch to it then try
       * again. */
      SwitchToThread();
      break;

    default:
      abort();
    }
  }
  return 0;
}

#  endif // _WIN32_WINNT >= _WIN32_WINNT_VISTA

int __libcpp_execute_once(__libcpp_exec_once_flag* __flag, void (*init_routine)()) {
  return __libcpp_execute_once(__flag, nullptr, reinterpret_cast<void (*)(void*)>(init_routine));
}

// Thread ID
bool __libcpp_thread_id_equal(__libcpp_thread_id __lhs, __libcpp_thread_id __rhs) { return __lhs == __rhs; }

bool __libcpp_thread_id_less(__libcpp_thread_id __lhs, __libcpp_thread_id __rhs) { return __lhs < __rhs; }

// Thread
struct __libcpp_beginthreadex_thunk_data {
  void* (*__func)(void*);
  void* __arg;
};

#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA

static inline _LIBCPP_HIDE_FROM_ABI unsigned WINAPI __libcpp_beginthreadex_thunk(void* __raw_data) {
  auto* __data = static_cast<__libcpp_beginthreadex_thunk_data*>(__raw_data);
  auto* __func = __data->__func;
  void* __arg  = __data->__arg;
  delete __data;
  return static_cast<unsigned>(reinterpret_cast<uintptr_t>(__func(__arg)));
}

#  else // _WIN32_WINNT >= _WIN32_WINNT_VISTA

static inline _LIBCPP_HIDE_FROM_ABI void __libcpp_tls_tss_dor_invoke();

static inline _LIBCPP_HIDE_FROM_ABI unsigned WINAPI __libcpp_beginthreadex_thunk(void* __raw_data) {
  auto* __data = static_cast<__libcpp_beginthreadex_thunk_data*>(__raw_data);
  auto* __func = __data->__func;
  void* __arg  = __data->__arg;
  delete __data;
  int ret;
  ret = static_cast<unsigned>(reinterpret_cast<uintptr_t>(__func(__arg)));
  __libcpp_tls_tss_dor_invoke();
  return ret;
}

#  endif // _WIN32_WINNT >= _WIN32_WINNT_VISTA

bool __libcpp_thread_isnull(const __libcpp_thread_t* __t) { return *__t == 0; }

int __libcpp_thread_create(__libcpp_thread_t* __t, __libcpp_thread_id* __t_id, void* (*__func)(void*), void* __arg) {
  auto* __data   = new __libcpp_beginthreadex_thunk_data;
  __data->__func = __func;
  __data->__arg  = __arg;

  unsigned __id;

  *__t = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, __libcpp_beginthreadex_thunk, __data, 0, &__id));

  *__t_id = __id;

  if (*__t)
    return 0;
  return GetLastError();
}

__libcpp_thread_id __libcpp_thread_get_current_id() { return GetCurrentThreadId(); }

int __libcpp_thread_join(__libcpp_thread_t* __t) {
  if (WaitForSingleObjectEx(*__t, INFINITE, FALSE) == WAIT_FAILED)
    return GetLastError();
  if (!CloseHandle(*__t))
    return GetLastError();
  return 0;
}

int __libcpp_thread_detach(__libcpp_thread_t* __t) {
  if (!CloseHandle(*__t))
    return GetLastError();
  return 0;
}

void __libcpp_thread_yield() { SwitchToThread(); }

void __libcpp_thread_sleep_for(const chrono::nanoseconds& __ns) {
  // round-up to the nearest millisecond
  chrono::milliseconds __ms = chrono::ceil<chrono::milliseconds>(__ns);
  // FIXME(compnerd) this should be an alertable sleep (WFSO or SleepEx)
  Sleep(__ms.count());
}

// Thread Local Storage
#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA
int __libcpp_tls_create(__libcpp_tls_key* __key, void(_LIBCPP_TLS_DESTRUCTOR_CC* __at_exit)(void*)) {
  DWORD index = FlsAlloc(__at_exit);
  if (index == FLS_OUT_OF_INDEXES)
    return GetLastError();
  *__key = index;
  return 0;
}

void* __libcpp_tls_get(__libcpp_tls_key __key) { return FlsGetValue(__key); }

int __libcpp_tls_set(__libcpp_tls_key __key, void* __p) {
  if (!FlsSetValue(__key, __p))
    return GetLastError();
  return 0;
}

#  else // _WIN32_WINNT >= _WIN32_WINNT_VISTA

// https://devblogs.microsoft.com/oldnewthing/20160613-00/?p=93655
// see also TLS_MINIMUM_AVAILABLE
#    define EMULATED_THREADS_TSS_DTOR_SLOTNUM 1024

typedef void (*_LIBCPP_TLS_DESTRUCTOR_CC __libcpp_tls_dtor_t)(void*);

static struct __libcpp_tls_tss_dor_entry {
  __libcpp_tls_key key;
  __libcpp_tls_dtor_t dtor;
} __libcpp_tls_tss_dor_tbl[EMULATED_THREADS_TSS_DTOR_SLOTNUM];

static inline _LIBCPP_HIDE_FROM_ABI int __libcpp_tls_tss_dor_register(__libcpp_tls_key key, __libcpp_tls_dtor_t dtor) {
  int i;
  for (i = 0; i < EMULATED_THREADS_TSS_DTOR_SLOTNUM; i++) {
    if (!__libcpp_tls_tss_dor_tbl[i].dtor)
      break;
  }
  if (i == EMULATED_THREADS_TSS_DTOR_SLOTNUM)
    return 1;
  __libcpp_tls_tss_dor_tbl[i].key  = key;
  __libcpp_tls_tss_dor_tbl[i].dtor = dtor;
  return 0;
}

static inline _LIBCPP_HIDE_FROM_ABI void __libcpp_tls_tss_dor_invoke() {
  int i;
  for (i = 0; i < EMULATED_THREADS_TSS_DTOR_SLOTNUM; i++) {
    if (__libcpp_tls_tss_dor_tbl[i].dtor) {
      void* val = __libcpp_tls_get(__libcpp_tls_tss_dor_tbl[i].key);
      if (val)
        (__libcpp_tls_tss_dor_tbl[i].dtor)(val);
    }
  }
}

int __libcpp_tls_create(__libcpp_tls_key* __key, void(_LIBCPP_TLS_DESTRUCTOR_CC* __at_exit)(void*)) {
  DWORD index = TlsAlloc();
  if (index == TLS_OUT_OF_INDEXES)
    return GetLastError();
  if (__libcpp_tls_tss_dor_register(index, __at_exit)) {
    TlsFree(index);
    return ERROR_INVALID_BLOCK;
  }
  *__key = index;
  return 0;
}

void* __libcpp_tls_get(__libcpp_tls_key __key) { return TlsGetValue(__key); }

int __libcpp_tls_set(__libcpp_tls_key __key, void* __p) {
  if (!TlsSetValue(__key, __p))
    return GetLastError();
  return 0;
}

#  endif // _WIN32_WINNT >= _WIN32_WINNT_VISTA

_LIBCPP_END_NAMESPACE_STD

#endif // _LIBCPP_HAS_THREAD_API_WIN32
