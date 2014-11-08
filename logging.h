#include <stdio.h>

/*
 * Logging macros
 */

#define log_info(str, ...)   do { \
    printf((str), __VA_ARGS__);	  \
    printf("\n");		  \
  } while(0);


#define log_error(str, ...)  do {		\
    fprintf(stderr, (str), __VA_ARGS__);	\
    fprintf(stderr, "\n");			\
  } while(0);
