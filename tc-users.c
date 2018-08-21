#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "config.h"
#include "bpf_config.h"
#include "bpf.h"
#include "log.h"
#include "input.h"
#include "classify.h"
#include "sync.h"
#include "error.h"
#include "version.h"

#define O_USER_FLOWS "user-flows"
#define O_UNCL_FLOWS "unclassified-flows"
#define O_FLOWS_PER_USER "flows-per-user"
#define O_CLASSIFY_BY "classify-by"
#define O_NOOP "no-op"
#define O_QUIET "quiet"
#define O_VERBOSE "verbose"
#define O_VERSION "version"
#define O_HELP "help"

// Prints help.
static void print_help(FILE *fp, char *cmd)
{
	char cbstr[MAX_CLASSIFY_BY_STRLEN+1];
	classify_by dcb = D_CLASSIFY_BY;

	fprintf(fp, "Usage: %s [options] file\n", cmd);
	fprintf(fp, "\n");
	fprintf(fp, "file must conform to Input Format below, may be '-' for stdin\n");
	fprintf(fp, "\n");
	fprintf(fp, "Options:\n");
	fprintf(fp, "\n");
	fprintf(fp, "--%s LOW-HIGH (default %s)\n", O_USER_FLOWS, D_USER_FLOWS);
    fprintf(fp, "	inclusive range of flows to allocate for user traffic\n");
    fprintf(fp, "	must not overlap with --%s\n", O_UNCL_FLOWS);
	fprintf(fp, "	HIGH must be < CAKE_FLOWS in sch_cake.c and < %d\n", UINT16_MAX+1);
	fprintf(fp, "--%s LOW-HIGH (default %s)\n", O_UNCL_FLOWS, D_UNCL_FLOWS);
    fprintf(fp, "	inclusive range of flows to allocate for unclassified traffic\n");
    fprintf(fp, "	must not overlap with --%s\n", O_USER_FLOWS);
	fprintf(fp, "	HIGH must be < CAKE_FLOWS in sch_cake.c and < %d\n", UINT16_MAX+1);
    fprintf(fp, "	HIGH-LOW+1 must be a power of two\n");
	fprintf(fp, "--%s LOW-HIGH (default %s)\n", O_FLOWS_PER_USER, D_FLOWS_PER_USER);
	fprintf(fp, "	minimum and maximum number of flows to allocate per user\n");
	fprintf(fp, "	both minimum and maximum must be a power of two, and\n");
	fprintf(fp, "	both must fit within --%s\n", O_USER_FLOWS);
	fprintf(fp, "--%s OPT (default %s)\n", O_CLASSIFY_BY, classify_by_str(dcb, cbstr));
	fprintf(fp, "	comma separated, ordered list of addresses to classify by:\n");
	fprintf(fp, "	srcip: source IP address\n");
	fprintf(fp, "	dstip: destination IP address\n");
	fprintf(fp, "	srcmac: source MAC address\n");
	fprintf(fp, "	dstmac: destination MAC address\n");
	fprintf(fp, "-n|--%s\n", O_NOOP);
	fprintf(fp, "	read input and classify, but don't sync changes to BPF map\n");
	fprintf(fp, "	allows previewing changes before actually making them\n");
	fprintf(fp, "-q|--%s\n", O_QUIET);
	fprintf(fp, "	disables logging to stdout (errors and warnings still go to stderr)\n");
	fprintf(fp, "-v|--%s\n", O_VERBOSE);
	fprintf(fp, "	enables verbose logging to stdout\n");
	fprintf(fp, "-V|--%s\n", O_VERSION);
	fprintf(fp, "	shows version\n");
	fprintf(fp, "-h|--%s\n", O_HELP);
	fprintf(fp, "	shows help\n");
	fprintf(fp, "\n");
	fprintf(fp, "Input Format:\n");
	fprintf(fp, "\n");
	fprintf(fp, "The input must contain two fields per line, and the delimiter may\n");
	fprintf(fp, "be a space, comma or semicolon. Fields:\n");
	fprintf(fp, "\n");
	fprintf(fp, "1) A user ID string, up to 32 characters. If this is an integer in the\n");
	fprintf(fp, "   range of the specified --%s, it will be used as the classid.\n",
		O_USER_FLOWS);
	fprintf(fp, "2) An IPv4/6 address or MAC address.\n");
	fprintf(fp, "\n");
	fprintf(fp, "Example Input:\n");
	fprintf(fp, "\n");
	fprintf(fp, "10 12:34:56:ab:cd:ef\n");
	fprintf(fp, "11,FE:DC:BA:65:43:21\n");
	fprintf(fp, "Wilma;2001:db8::43\n");
	fprintf(fp, "Fred,192.0.2.29\n");
}

// Prints version.
static void print_version(char *execname)
{
	printf("%s version %s\n", execname, VERSION);
}

// Prints an error to stderr.
static void print_error(char *execname, error_t *err)
{
	fprintf(stderr, "%s: %s\n", execname, err->message);
}

// Parses command line options.
static error_t *parse_cmdline(int argc, char **argv, config *cfg)
{
	const char *lopt;
	error_t *err;
	int oidx = 0;
	int c;

	init_config(cfg);

	static struct option long_opts[] = {
		{O_USER_FLOWS,             required_argument, 0,  0  },
		{O_UNCL_FLOWS,             required_argument, 0,  0  },
		{O_FLOWS_PER_USER,         required_argument, 0,  0  },
		{O_CLASSIFY_BY,            required_argument, 0,  0  },
		{O_NOOP,                   no_argument,       0, 'n' },
		{O_QUIET,                  no_argument,       0, 'q' },
		{O_VERBOSE,                no_argument,       0, 'v' },
		{O_VERSION,                no_argument,       0, 'V' },
		{O_HELP,                   no_argument,       0, 'h' },
		{0,                        0,                 0,  0  },
	};

	while ((c = getopt_long(argc, argv, "nqvVh", long_opts, &oidx)) != -1) {
		switch (c) {
		case 0:
			lopt = long_opts[oidx].name;
			if (!strcmp(lopt, O_USER_FLOWS)) {
				if ((err = parse_u16_range(optarg, &cfg->user_flows))) {
					return err;
				}
			} else if (!strcmp(lopt, O_UNCL_FLOWS)) {
				if ((err = parse_u16_range(optarg, &cfg->uncl_flows))) {
					return err;
				}
			} else if (!strcmp(lopt, O_FLOWS_PER_USER)) {
				if ((err = parse_u16_range(optarg, &cfg->fpu_range))) {
					return err;
				}
			} else if (!strcmp(lopt, O_CLASSIFY_BY)) {
				if ((err = parse_classify_by(optarg, cfg->classify_by))) {
					return err;
				}
			} else {
				fprintf(stderr, "\n");
				print_help(stderr, argv[0]);
				return errorf(E_UNKNOWN_OPT, "--%s", lopt);
			}
			break;
		case 'n':
			cfg->noop = true;
			break;
		case 'q':
			cfg->log = LOG_QUIET;
			break;
		case 'v':
			cfg->log = LOG_VERBOSE;
			break;
		case 'V':
			cfg->mode = PRINT_VERSION;
			break;
		case 'h':
			cfg->mode = PRINT_HELP;
			break;
		case '?':
			fprintf(stderr, "\n");
			print_help(stderr, argv[0]);
			return errorf(E_UNKNOWN_OPT, "-%c", optopt);
		default:
			return errorf(E_GETOPT_FAIL, "unimplemented getopt char 0x%.2x", c);
		}
	}

	if (cfg->mode == PRINT_HELP || cfg->mode == PRINT_VERSION) {
		return NULL;
	}

	if (argc == optind) {
		return error(E_FILE_ARG_REQUIRED);
	}

	if (argc > optind+1) {
		return error(E_TOO_MANY_ARGS);
	}

	cfg->input = argv[optind];

	if ((err = validate_config(cfg))) {
		return err;
	}

	return NULL;
}

// Runs the program.
static error_t *run(config *cfg)
{
	char cbstr[MAX_CLASSIFY_BY_STRLEN+1];
	char rstr[MAX_RANGE_STRLEN+1];
	entries *es = new_entries();
	FILE *in = stdin;
	bpf_config bcfg;
	bpf_handle hnd;
	error_t *err;

	if (cfg->noop) {
		logn(cfg, "NO-OP MODE: BPF will not be updated\n");
	}

	if (cfg->input && strcmp(cfg->input, "-") && (in = fopen(cfg->input, "r")) == NULL) {
		err = errorf(E_OPEN_INPUT_FILE_FAILED, "'%s', %s", cfg->input, strerror(errno));
		goto out;
	}
	if ((err = parse_input(in, es))) {
		goto out;
	}

	if ((err = bpf_open(&hnd))) {
		goto out;
	}

	finalize_config(cfg, es->len);

	init_bpf_config(cfg, &bcfg);

	printf("user flows: %s\n", u16_range_str(&cfg->user_flows, rstr));
	printf("uncl flows: %s\n", u16_range_str(&cfg->uncl_flows, rstr));
	printf("flows per user: %s\n", u16_range_str(&cfg->fpu_range, rstr));
	printf("classify by addresses: %s\n", classify_by_str(cfg->classify_by, cbstr));
	printf("bpf flows per user: %u\n", bcfg.flows_per_user);

	classify(&hnd, cfg, es);

	if ((err = sync_bpf(&hnd, cfg, es))) {
		goto out;
	}

	if (!cfg->noop) {
		err = bpf_update_config(&hnd, &bcfg);
	}

out:
	free_entries(es);
	bpf_close(&hnd);
	if (in) {
		fclose(in);
	}
	return err;
}

// Entry point.
int main(int argc, char **argv)
{
	error_t *err;
	config cfg;

	if ((err = parse_cmdline(argc, argv, &cfg))) {
		if (err->code != E_UNKNOWN_OPT) {
			print_error(argv[0], err);
			fprintf(stderr, "\n");
			print_help(stderr, argv[0]);
		}
		return EXIT_FAILURE;
	}

	switch (cfg.mode) {
	case PRINT_HELP:
		print_help(stdout, argv[0]);
		break;
	case PRINT_VERSION:
		print_version(argv[0]);
		break;
	case RUN:
		if ((err = run(&cfg))) {
			print_error(argv[0], err);
			return EXIT_FAILURE;
		}
		break;
	}

	return EXIT_SUCCESS;
}
