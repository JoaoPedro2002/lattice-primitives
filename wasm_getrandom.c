#include <stddef.h>
#include <sys/random.h>
#include <stdlib.h>


ssize_t getrandom (void *__buffer, size_t __length,
                   unsigned int __flags) {
    unsigned char *buffer = ( unsigned char *)__buffer;
    for (int i = 0; i < __length; i++) {
        buffer[i] = rand() % 256;
    }
    return __length;
}