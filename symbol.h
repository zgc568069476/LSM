#ifndef __SYMBOL_FIND__
#define __SYMBOL_FIND__
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
unsigned long lookup_name(const char *name);
#endif
