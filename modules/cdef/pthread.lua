local ffi = require("ffi")

if ffi.arch == "x86" then
ffi.cdef[[
typedef union
{
  char __size[4];
  long int __align;
} pthread_mutexattr_t;

typedef struct __pthread_internal_slist
{
  struct __pthread_internal_slist *__next;
} __pthread_slist_t;

typedef union
{
  struct __pthread_mutex_s
  {
    int __lock;
    unsigned int __count;
    int __owner;


    int __kind;
    unsigned int __nusers;
    __extension__ union
    {
      int __spins;
      __pthread_slist_t __list;
    };
  } __data;
  char __size[24];
  long int __align;
} pthread_mutex_t;

typedef union
{
  struct
  {
    int __lock;
    unsigned int __nr_readers;
    unsigned int __readers_wakeup;
    unsigned int __writer_wakeup;
    unsigned int __nr_readers_queued;
    unsigned int __nr_writers_queued;


    unsigned char __flags;
    unsigned char __shared;
    unsigned char __pad1;
    unsigned char __pad2;
    int __writer;
  } __data;
  char __size[32];
  long int __align;
} pthread_rwlock_t;

typedef union
{
  char __size[8];
  long int __align;
} pthread_rwlockattr_t;

extern int pthread_mutex_init (pthread_mutex_t *__mutex, pthread_mutexattr_t *__mutexattr);
extern int pthread_mutex_destroy (pthread_mutex_t *__mutex);
extern int pthread_mutex_trylock (pthread_mutex_t *__mutex);
extern int pthread_mutex_lock (pthread_mutex_t *__mutex);
extern int pthread_mutex_unlock (pthread_mutex_t *__mutex);
extern int pthread_mutexattr_init (pthread_mutexattr_t *__attr);
extern int pthread_mutexattr_destroy (pthread_mutexattr_t *__attr);
extern int pthread_mutexattr_setpshared (pthread_mutexattr_t *__attr, int __pshared);

extern int pthread_rwlock_init (pthread_rwlock_t * __rwlock, pthread_rwlockattr_t * __attr);
extern int pthread_rwlock_destroy (pthread_rwlock_t *__rwlock);
extern int pthread_rwlock_rdlock (pthread_rwlock_t *__rwlock);
extern int pthread_rwlock_tryrdlock (pthread_rwlock_t *__rwlock);
extern int pthread_rwlock_wrlock (pthread_rwlock_t *__rwlock);
extern int pthread_rwlock_trywrlock (pthread_rwlock_t *__rwlock);
extern int pthread_rwlock_unlock (pthread_rwlock_t *__rwlock);
extern int pthread_rwlockattr_init (pthread_rwlockattr_t *__attr);
extern int pthread_rwlockattr_destroy (pthread_rwlockattr_t *__attr);
extern int pthread_rwlockattr_setpshared (pthread_rwlockattr_t *__attr, int __pshared);

static const int PTHREAD_PROCESS_SHARED = 1;
]]
else
error("arch not support: " .. ffi.arch)
end
