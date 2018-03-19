#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#include "common/crypt_utils.h"
#include "common/string_utils.h"
#include "common/spg.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

#define PACKAGE_NAME    "SecurePG"
#define PROGRAM_NAME    "spg"
#define PACKAGE_VERSION "1.0"

#define DECRYPT_MODE    0
#define ENCRYPT_MODE    1

typedef struct _options_t {
    int mode;
    const char *input_file;
    const char *key_file;
    const char *cert_file;
    const char *output_file;
    const char *label;
    const char *agent_addr;
    int agent_port;
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
    fprintf(stdout, " -e, --encrypt encrypt file\n");
    fprintf(stdout, " -d, --decrypt decrypt file\n");
    fprintf(stdout, " -l, --label   label used in encryption\n");
    fprintf(stdout, " -i, --input   input file\n");
    fprintf(stdout, " -o, --output  output file\n");
    fprintf(stdout, " -c, --cert    public key file\n");
    fprintf(stdout, " -k, --key     key file\n");
    fprintf(stdout, " -a, --address agent address used to decrypt key");
    fprintf(stdout, " -p, --port    agent port used to decrypt key");
    fprintf(stdout, " -v, --version print version information\n");
    fprintf(stdout, " -h, --help    print this help\n");
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
            { "label", required_argument, 0, 'l' },
            { "in", required_argument, 0, 'i' },
            { "out", required_argument,   0, 'o' },
            { "key", required_argument, 0, 'k' },
            { "cert", required_argument, 0, 'c' },
            { "address", required_argument, 0, 'a' },
            { "port", required_argument, 0, 'p' },
            { "help", no_argument, 0, 'h' },
            { "version", no_argument, 0, 'v' },
            { 0, 0, 0, 0 }
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "edhvi:o:k:c:l:a:p:",
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
            fprintf(stderr, "option %s", long_options[option_index].name);
            if (optarg)
                fprintf(stderr, " with arg %s", optarg);
            fprintf(stderr, "\n");
            break;
        case 'e':
            opts->mode = ENCRYPT_MODE;
            break;
        case 'd':
            opts->mode = DECRYPT_MODE;
            break;
        case 'l':
            opts->label = strdup(optarg);
            break;
        case 'c':
            opts->cert_file = strdup(optarg);
            break;
        case 'k':
            opts->key_file = strdup(optarg);
            break;
        case 'i':
            opts->input_file = strdup(optarg);
            break;
        case 'o':
            opts->output_file = strdup(optarg);
            break;
        case 'a':
            opts->agent_addr = strdup(optarg);
            break;
        case 'p':
            opts->agent_port = atoi(optarg);
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
            fprintf(stderr, "Argument %c is not supported.\n", c);
            abort();
        }
    }

    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
    {
        fprintf(stderr, "non-option ARGV-elements: ");
        while (optind < argc)
            fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    options_t opts;

    ERR_load_crypto_strings();
    SSL_library_init();                      /* initialize library */
    SSL_load_error_strings();                /* readable error messages */

	memset(&opts, 0, sizeof(opts));
	parse_options(argc, argv, &opts);

    if(opts.input_file == NULL)
    {
        fprintf(stderr, "No input file");
        return -1;
    }

	if(opts.mode == ENCRYPT_MODE)
    {
        char label[1024];

        if(opts.cert_file == NULL)
        {
            fprintf(stderr, "No cert file");
            return -1;
        }

        if(opts.label == NULL)
        {
            fprintf(stdout, "Input label: ");
            fgets(label, sizeof(label), stdin);
            rtrim(label, "\r\n");
            opts.label = label;
        }

        encrypt_file(opts.input_file, opts.cert_file, opts.label, opts.output_file);
    }
    else
    {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        if(opts.key_file != NULL)
        {
            decrypt_file_by_private_key(opts.input_file, opts.key_file, opts.output_file);
        }
        else
        {
            decrypt_file_by_agent(opts.input_file,
                         opts.agent_addr != NULL ? opts.agent_addr : "127.0.0.1",
                         opts.agent_port != 0 ? opts.agent_port : 9600,
                         opts.cert_file,
                         opts.output_file);
        }

        WSACleanup();
    }

    return 0;
}
