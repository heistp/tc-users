#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include "input.h"
#include "limits.h"

#define ENTRY_DELIMS " ,;"
#define MAX_LINE (2 * (MAX_USERID_STRLEN + 1 + MAX_ADDR_STRLEN + 2))

static void trim_tr(char *s)
{
	int i;

	for (i = strlen(s)-1; i >= 0; i--) {
		if (isspace(s[i])) {
			s[i] = '\0';
		} else {
			break;
		}
	}
}

static error_t *read_line(FILE *fp, char *line)
{
	if (!fgets(line, MAX_LINE+1, fp)) {
		return error(E_EOF);
	}
	if (strlen(line) >= MAX_LINE) {
		return error(E_LONG_LINE);
	}
	trim_tr(line);

	return NULL;
}

static error_t *parse_userid(const char *s, char *userid)
{
	if (strlen(s) == 0) {
		return error(E_USERID_EMPTY);
	}
	if (strlen(s) > MAX_USERID_STRLEN) {
		return error(E_USERID_LONG);
	}
	strncpy(userid, s, MAX_USERID_STRLEN+1);

	return NULL;
}

static error_t *parse_entry(FILE *fp, char *line, entry *e)
{
	char tline[MAX_LINE+1];
	error_t *err;
	char *t, *p;

	if ((err = read_line(fp, line))) {
		return err;
	}
	strncpy(tline, line, MAX_LINE+1);

	if ((t = strtok_r(tline, ENTRY_DELIMS, &p)) == NULL) {
		return error(E_TOO_FEW_FIELDS);
	}
	if ((err = parse_userid(t, e->userid))) {
		return err;
	}

	if ((t = strtok_r(NULL, ENTRY_DELIMS, &p)) == NULL) {
		return error(E_TOO_FEW_FIELDS);
	}
	if ((err = parse_addr(t, &e->addr))) {
		return err;
	}

	if ((t = strtok_r(NULL, ENTRY_DELIMS, &p)) != NULL) {
		return error(E_TOO_MANY_FIELDS);
	}

	e->classid = 0;
	e->classified = false;

	return NULL;
}

error_t *parse_input(FILE *fp, entries *es)
{
	char line[MAX_LINE+1];
	bool done = false;
	error_t *err;
	entry e;
	int n;

	n = 1;
	do {
		if ((err = parse_entry(fp, line, &e))) {
			if (err->code != E_EOF) {
				return errorf(err->code, "on line #%d, full line: '%s'", n, line);
			}
			if (es->len == 0) {
				return errorf(E_NO_INPUT, "%s", (fp == stdin ? "stdin" : "file"));
			}
			done = true;
		} else {
			append_entry(es, &e);
			n++;
		}
	} while (!done);

	return NULL;
}
