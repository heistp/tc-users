#ifndef __LOG_H
#define __LOG_H

#include "config.h"

// Logs a normal message.
void logn(const config *cfg, const char *fmt, ...);

// Logs a verbose message.
void logv(const config *cfg, const char *fmt, ...);

#endif
