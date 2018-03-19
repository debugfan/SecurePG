#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <getopt.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../common/crypt_utils.h"
#include "../common/string_utils.h"
#include "../common/secure_socket.h"
#include "../common/base64.h"
#include "../common/spg.h"
#include "../common/json_utils.h"

#define PACKAGE_NAME    "SecurePG"
#define PROGRAM_NAME    "spg-agent"
#define PACKAGE_VERSION "1.0"

#define SILENT_MODE         0
#define INTERACTIVE_MODE    1

typedef struct _options_t {
    int mode;
    const char *key_file;
    int port;
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
    fprintf(stdout, " -k, --key         private key file\n");
    fprintf(stdout, " -p, --port        port to listen\n");
    fprintf(stdout, " -s, --silent      accept silently all decryption request\n");
    fprintf(stdout, " -i, --interactive interactive with decryption request\n");
    fprintf(stdout, " -v, --version     print version information\n");
    fprintf(stdout, " -h, --help        print this help\n");
}

int parse_options(int argc, char **argv, options_t *opts)
{
    int c;

    while (1)
    {
        static struct option long_options[] =
        {
            { "key", required_argument, 0, 'k' },
            { "port", required_argument, 0, 'p' },
            { "silent", no_argument, 0, 's' },
            { "interactive", no_argument, 0, 'i' },
            { "help", no_argument, 0, 'h' },
            { "version", no_argument, 0, 'v' },
            { 0, 0, 0, 0 }
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "hvsik:p:",
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
            fprintf(stderr, "Option %s", long_options[option_index].name);
            if (optarg)
                fprintf(stderr, " with arg %s", optarg);
            fprintf(stderr, "\n");
            break;
        case 'k':
            opts->key_file = strdup(optarg);
            break;
        case 'p':
            opts->port = atoi(optarg);
            break;
        case 's':
            opts->mode = SILENT_MODE;
            break;
        case 'i':
            opts->mode = INTERACTIVE_MODE;
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
        fprintf(stderr, "Non-option ARGV-elements: ");
        while (optind < argc)
            fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n");
    }

    return 0;
}

void parse_key(const char *buf, int len, char *pre_key, char *label)
{
    const char *p;
    json_item_t item;

    p = parse_json_item(buf, len, &item);
    while(p != NULL)
    {
        if(0 == strncasecmp("key", item.key, item.key_len))
        {
            memcpy(pre_key, item.value, item.value_len);
            pre_key[item.value_len] = '\0';
        }
        else if(0 == strncasecmp("label", item.key, item.key_len))
        {
            memcpy(label, item.value, item.value_len);
            label[item.value_len] = '\0';
        }
        p = parse_json_item(p, buf + len - p, &item);
    }
}

int main(int argc, char *argv[])
{
    options_t opts;
    int listenfd = 0;
    int connfd = 0;
    struct sockaddr_in srv_addr;
    struct sockaddr_in cli_addr;
    int addr_len;
    char buf[1024];
    int len;
    char prekey[1024];
    char label[1024];
    unsigned char dek[32];
    WSADATA wsaData;
    int accepted;
    secure_socket_t ss;

    ERR_load_crypto_strings();
    SSL_library_init();                      /* initialize library */
    SSL_load_error_strings();                /* readable error messages */

    memset(&opts, 0, sizeof(opts));
    parse_options(argc, argv, &opts);

    if(opts.key_file == NULL)
    {
        fprintf(stderr, "No private key file.\n");
        return -1;
    }

    if(opts.port == 0)
    {
        opts.port = 9600;
    }

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&srv_addr, '0', sizeof(srv_addr));
    memset(buf, '0', sizeof(buf));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons(opts.port);

    bind(listenfd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));

    listen(listenfd, 1);

    for(;;)
    {
        addr_len = sizeof(cli_addr);
        connfd = accept(listenfd, (struct sockaddr*)&cli_addr, &addr_len);

        init_secure_socket(&ss, connfd, NULL, opts.key_file);

        len = secure_recv(&ss, buf, sizeof(buf));
        if(len > 0)
        {
            parse_key(buf, len, prekey, label);
            fprintf(stdout,
                    "Client: %s, Label: %s\n",
                    inet_ntoa(cli_addr.sin_addr),
                    label);
            if(opts.mode != SILENT_MODE)
            {
                for(;;)
                {
                    char c;
                    fprintf(stdout, "Accept key decryption request (Y/n): ");
                    c = tolower(fgetc(stdin));
                    if(c == 'y' || c == '\n')
                    {
                        accepted = 1;
                        break;
                    }
                    else if(c == 'n')
                    {
                        accepted = 0;
                        break;
                    }
                }
            }
            else
            {
                accepted = 1;
            }
            if(accepted)
            {
                char b64_out[64];
                int len;
                decrypt_key(prekey, opts.key_file, label, dek);
                len = base64_encode(b64_out, sizeof(b64_out), dek, 32);
                secure_send(&ss, b64_out, len);
            }
        }
        closesocket(connfd);
     }

     WSACleanup();

     return 0;
}
