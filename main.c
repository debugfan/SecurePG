#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "crypt_utils.h"

#define PACKAGE_NAME    "SecurePG"
#define PROGRAM_NAME    "SecurePG"
#define PACKAGE_VERSION "1.0"

#define DECRYPT_MODE    0
#define ENCRYPT_MODE    1

typedef struct _options_t {
    int mode;
    const char *input_file;
    const char *key_file;
    const char *output_file;
    const char *comment;
} options_t;

void print_version(const char *program_name)
{
    fprintf(stdout, "%s %s %s\n",
        PACKAGE_NAME,
        program_name,
        PACKAGE_VERSION);
}

void print_help(const char *program_name)
{
    print_version(program_name);
    fprintf(stdout, " -e, --encrypt     encrypt file\n");
    fprintf(stdout, " -d, --decrypt     decrypt file\n");
    fprintf(stdout, " -c, --comment     comment used in encryption\n");
    fprintf(stdout, " -v, --version     print version infomation\n");
    fprintf(stdout, " -h, --help        print this help\n");
}

int parse_options(int argc, char **argv, options_t *opts)
{
    int c;

    while (1)
    {
        static struct option long_options[] =
        {
            { "encrypt", no_argument, 0, 'e' },
            { "decrypt", no_argument, 0, 'd' },
            { "comment", required_argument, 0, 'c' },
            { "in", required_argument, 0, 'i' },
            { "out", required_argument,   0, 'o' },
            { "inkey", required_argument, 0, 'k' },
            { "help", no_argument, 0, 'h' },
            { "version", no_argument, 0, 'v' },
            { 0, 0, 0, 0 }
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "edhvi:o:k:c:",
            long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1) {
            break;
        }

        switch (c)
        {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            printf("option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;
        case 'e':
            opts->mode = ENCRYPT_MODE;
            break;
        case 'd':
            opts->mode = DECRYPT_MODE;
            break;
        case 'c':
            opts->comment = optarg;
            break;
        case 'k':
            opts->key_file = optarg;
            break;
        case 'i':
            opts->input_file = optarg;
            break;
        case 'o':
            opts->output_file = optarg;
            break;
        case 'h':
            print_help(PROGRAM_NAME);
            exit(0);
            break;
        case 'v':
            print_version(PROGRAM_NAME);
            exit(0);
            break;
        case '?':
            /* getopt_long already printed an error message. */
            break;

        default:
            printf("Argument %c is not supported.\n", c);
            abort();
        }
    }

    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
    {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        putchar('\n');
    }

    return 0;
}

int main(int argc, char *argv[])
{
    options_t opts;
    char output_file[260];

	memset(&opts, 0, sizeof(opts));
	parse_options(argc, argv, &opts);

    if(opts.input_file == NULL)
    {
        fprintf(stderr, "No input file");
        return -1;
    }

    if(opts.key_file == NULL)
    {
        fprintf(stderr, "No key file");
        return -1;
    }

	if(opts.mode == ENCRYPT_MODE)
    {
        char comment[1024];

        if(opts.comment == NULL)
        {
            fprintf(stdout, "Input Comment: ");
            gets(comment);
            opts.comment = comment;
        }

        if(opts.output_file == NULL)
        {
            strcpy(output_file, opts.input_file);
            strcat(output_file, ".spg");
            opts.output_file = output_file;
        }

        encrypt_file(opts.input_file, opts.key_file, opts.comment, opts.output_file);
    }
    else
    {
        if(opts.output_file == NULL)
        {
            strcpy(output_file, opts.input_file);
            strcat(output_file, ".dec");
            opts.output_file = output_file;
        }

        decrypt_file(opts.input_file, opts.key_file, opts.output_file);
    }

    return 0;
}
