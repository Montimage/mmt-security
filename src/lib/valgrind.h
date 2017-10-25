/**
 * This is used only for checking the code source using valgrind
 */

#ifdef VALGRIND_MODE
#include <valgrind/drd.h>
//redefine this macro
#undef VALGRIND_MODE
#define VALGRIND_MODE(x) x
#else
#define VALGRIND_MODE(x)
#endif
