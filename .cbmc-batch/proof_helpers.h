#include <stdlib.h>

#define ASSUME_VALID_MEMORY(ptr) ptr = malloc(sizeof(*(ptr)))
#define ASSUME_VALID_MEMORY_COUNT(ptr, count) ptr = malloc(sizeof(*(ptr)) * (count))
#define ASSUME_DEFAULT_ALLOCATOR(allocator) allocator = aws_default_allocator()

int nondet_int();
size_t nondet_size_t();
