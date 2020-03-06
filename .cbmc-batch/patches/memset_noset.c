/* Modified version of CBMC's string.c where memset doesn't set anything.
   Temporary hack until the normal CBMC implementation's bugs are fixed. */

/* FUNCTION: memset */

#ifndef __CPROVER_STRING_H_INCLUDED
#    include <string.h>
#    define __CPROVER_STRING_H_INCLUDED
#endif

#undef memset

void *memset(void *s, int c, size_t n) {
__CPROVER_HIDE:;
#ifdef __CPROVER_STRING_ABSTRACTION
    __CPROVER_precondition(__CPROVER_buffer_size(s) >= n, "memset buffer overflow");
    //  for(size_t i=0; i<n ; i++) s[i]=c;
    if (__CPROVER_is_zero_string(s) && n > __CPROVER_zero_string_length(s)) {
        __CPROVER_is_zero_string(s) = 1;
    } else if (c == 0) {
        __CPROVER_is_zero_string(s)     = 1;
        __CPROVER_zero_string_length(s) = 0;
    } else
        __CPROVER_is_zero_string(s) = 0;
#else

    if (n > 0) {
        (void)*(char *)s;              // check that the memory is accessible
        (void)*(((char *)s) + n - 1);  // check that the memory is accessible
        char *sp = s;
        // Don't actually do the memset, since the values aren't important
    }
#endif
    return s;
}

/* FUNCTION: __builtin_memset */

void *__builtin_memset(void *s, int c, __CPROVER_size_t n) {
__CPROVER_HIDE:;
#ifdef __CPROVER_STRING_ABSTRACTION
    __CPROVER_precondition(__CPROVER_buffer_size(s) >= n, "memset buffer overflow");
    //  for(size_t i=0; i<n ; i++) s[i]=c;
    if (__CPROVER_is_zero_string(s) && n > __CPROVER_zero_string_length(s)) {
        __CPROVER_is_zero_string(s) = 1;
    } else if (c == 0) {
        __CPROVER_is_zero_string(s)     = 1;
        __CPROVER_zero_string_length(s) = 0;
    } else {
        __CPROVER_is_zero_string(s) = 0;
    }
#else

    if (n > 0) {
        (void)*(char *)s;              // check that the memory is accessible
        (void)*(((char *)s) + n - 1);  // check that the memory is accessible
        char *sp = s;
        // Don't actually do the memset, since te values aren't important
    }
#endif
    return s;
}

/* FUNCTION: __builtin___memset_chk */

void *__builtin___memset_chk(void *s, int c, __CPROVER_size_t n, __CPROVER_size_t size) {
__CPROVER_HIDE:;
#ifdef __CPROVER_STRING_ABSTRACTION
    __CPROVER_precondition(__CPROVER_buffer_size(s) >= n, "memset buffer overflow");
    __CPROVER_precondition(__CPROVER_buffer_size(s) == size, "builtin object size");
    //  for(size_t i=0; i<n ; i++) s[i]=c;
    if (__CPROVER_is_zero_string(s) && n > __CPROVER_zero_string_length(s)) {
        __CPROVER_is_zero_string(s) = 1;
    } else if (c == 0) {
        __CPROVER_is_zero_string(s)     = 1;
        __CPROVER_zero_string_length(s) = 0;
    } else
        __CPROVER_is_zero_string(s) = 0;
#else
    (void)size;

    if (n > 0) {
        (void)*(char *)s;              // check that the memory is accessible
        (void)*(((char *)s) + n - 1);  // check that the memory is accessible
        char *sp = s;
        // Don't actually do the memset, since te values aren't important
    }
#endif
    return s;
}
