#ifndef _IN_LIB_LIB_13130_H
#define _IN_LIB_LIB_13130_H
#include <ultra64.h>
#include "types.h"

char *strcpy(char *dest, char *src);
char *strncpy(char *dest, char *src, u32 len);
u32 strcat(char *dst, char *src);
s32 strcmp(char *a, char *b);
u32 func000132c0(void);
char toupper(char c);
s32 isdigit(char c);
u32 func00013378(void);
u32 func000133b4(void);
s32 func00013408(char *arg0, s32 *arg1, s32 arg2);
int sprintf(char *dest, const char *format, ...);

#endif
