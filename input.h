#ifndef __PARSE_INPUT_H
#define __PARSE_INPUT_H

#include <stdio.h>

#include "entry.h"

// Parses all entries from input.
error_t *parse_input(FILE *fp, entries *es);

#endif
