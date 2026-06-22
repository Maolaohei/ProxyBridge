#ifndef __forceinline  
#define __forceinline __attribute__((always_inline))  
#endif  
static __forceinline int foo(void) { return 1; }  
