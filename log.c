#include <stdio.h>
#include <stdarg.h>

#include "log.h"
#include "config.h"

void logn(const config *cfg, const char *fmt, ...)
{
	va_list a;

	if (cfg->log != LOG_QUIET) {
		va_start(a, fmt);
		vprintf(fmt, a);
		va_end(a);
	}
}

void logv(const config *cfg, const char *fmt, ...)
{
	va_list a;

	if (cfg->log == LOG_VERBOSE) {
		va_start(a, fmt);
		vprintf(fmt, a);
		va_end(a);
	}
}
