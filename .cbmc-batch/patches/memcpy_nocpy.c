/* Modified version of CBMC's string.c where memcpy doesn't copy anything.
   Temporary hack until the normal CBMC implementation's bugs are fixed. */

/* FUNCTION: memcpy */

#ifndef __CPROVER_STRING_H_INCLUDED
#    include <string.h>
#    define __CPROVER_STRING_H_INCLUDED
#endif

#undef memcpy

void *memcpy(void *dst, const void *src, size_t n) {
__CPROVER_HIDE:
#ifdef __CPROVER_STRING_ABSTRACTION
    __CPROVER_precondition(__CPROVER_buffer_size(src) >= n, "memcpy buffer overflow");
    __CPROVER_precondition(__CPROVER_buffer_size(dst) >= n, "memcpy buffer overflow");
    //  for(size_t i=0; i<n ; i++) dst[i]=src[i];
    if (__CPROVER_is_zero_string(src) && n > __CPROVER_zero_string_length(src)) {
        __CPROVER_is_zero_string(dst)     = 1;
        __CPROVER_zero_string_length(dst) = __CPROVER_zero_string_length(src);
    } else if (!(__CPROVER_is_zero_string(dst) && n <= __CPROVER_zero_string_length(dst)))
        __CPROVER_is_zero_string(dst) = 0;
#else
    __CPROVER_precondition(__CPROVER_POINTER_OBJECT(dst) != __CPROVER_POINTER_OBJECT(src), "memcpy src/dst overlap");

    if (n > 0) {
        (void)*(char *)dst;                    // check that the memory is accessible
        (void)*(const char *)src;              // check that the memory is accessible
        (void)*(((char *)dst) + n - 1);        // check that the memory is accessible
        (void)*(((const char *)src) + n - 1);  // check that the memory is accessible
                                               // Don't actually copy because the values don't matter
    }
#endif
    return dst;
}

/* FUNCTION: __builtin___memcpy_chk */

void *__builtin___memcpy_chk(void *dst, const void *src, __CPROVER_size_t n, __CPROVER_size_t size) {
__CPROVER_HIDE:
#ifdef __CPROVER_STRING_ABSTRACTION
    __CPROVER_precondition(__CPROVER_buffer_size(src) >= n, "memcpy buffer overflow");
    __CPROVER_precondition(__CPROVER_buffer_size(dst) >= n, "memcpy buffer overflow");
    __CPROVER_precondition(__CPROVER_buffer_size(dst) == s, "builtin object size");
    //  for(size_t i=0; i<n ; i++) dst[i]=src[i];
    if (__CPROVER_is_zero_string(src) && n > __CPROVER_zero_string_length(src)) {
        __CPROVER_is_zero_string(dst)     = 1;
        __CPROVER_zero_string_length(dst) = __CPROVER_zero_string_length(src);
    } else if (!(__CPROVER_is_zero_string(dst) && n <= __CPROVER_zero_string_length(dst)))
        __CPROVER_is_zero_string(dst) = 0;
#else
    __CPROVER_precondition(__CPROVER_POINTER_OBJECT(dst) != __CPROVER_POINTER_OBJECT(src), "memcpy src/dst overlap");
    (void)size;

    if (n > 0) {
        (void)*(char *)dst;                    // check that the memory is accessible
        (void)*(const char *)src;              // check that the memory is accessible
        (void)*(((char *)dst) + n - 1);        // check that the memory is accessible
        (void)*(((const char *)src) + n - 1);  // check that the memory is accessible
                                               // Don't actually copy because the values don't matter
    }
#endif
    return dst;
}
