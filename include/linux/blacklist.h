#ifndef BLACKLIST_H
#define BLACKLIST_H

#include <linux/fs.h>
#include <linux/vmalloc.h>

void blacklist_init(void);
bool blacklist_validate(struct filename *fname);
long sys_blacklist(unsigned char *uhash);

#endif
