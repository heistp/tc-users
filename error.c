#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "error.h"

// Error strings.
static const char * const err_strs[E_MAX] = {
	"EOF",
	"unknown command line option",
	"getopt internal failure",
	"too many command line arguments",
	"file argument required",
	"unable to open input file",
	"input contained no data",
	"empty range",
	"invalid range",
	"invalid range value",
	"invalid 16-bit unsigned value",
	"invalid classify by option",
	"invalid classify by address",
	"invalid classify by option (max 4 addresses)",
	"invalid classify by option, repeated address",
	"user and unclassified flow ranges overlap",
	"invalid minimum flows per user",
	"invalid maximum flows per user",
	"user flows size must be multiple of minimum flows per user",
	"user flows size must be multiple of maximum flows per user",
	"unclassified flows size must be power of two",
	"line too long",
	"too few fields",
	"user ID empty",
	"user ID too long",
	"invalid MAC address",
	"unknown address type",
	"unknown address format",
	"invalid IPv4 address",
	"invalid IPv6 address",
	"IPv4 to string conversion error",
	"IPv6 to string conversion error",
	"too many fields",
	"BPF get object failure",
	"BPF update element failure",
	"BPF get next key failure",
	"BPF lookup element failure",
	"BPF delete element failure",
};

// Global error value (only for use by errorf).
static error_t g_error;

// Sets and returns the global error.
error_t *error(enum err_code code)
{
	g_error.code = code;
	strncpy(g_error.message, err_strs[code], MAX_ERROR_STRLEN+1);
	return &g_error;
}

// Sets and returns the global error with a message.
error_t *errorf(enum err_code code, const char *fmt, ...)
{
	va_list a;

	g_error.code = code;
	strncpy(g_error.message, err_strs[code], MAX_ERROR_STRLEN+1);
	strncat(g_error.message, " (", MAX_ERROR_STRLEN+1);
	va_start(a, fmt);
	vsnprintf(g_error.message + strlen(g_error.message),
		MAX_ERROR_STRLEN+1, fmt, a);
	va_end(a);
	strncat(g_error.message, ")", MAX_ERROR_STRLEN+1);

	return &g_error;
}
