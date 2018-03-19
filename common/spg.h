#ifndef SPG_H_INCLUDED
#define SPG_H_INCLUDED

void encrypt_file(const char *input_file,
                  const char *key_file,
                  const char *comment,
                  const char *output_file);

void decrypt_file_by_agent(const char *input_file,
                  const char *addr,
                  int port,
                  const char *cert_file,
                  const char *output_file);

void decrypt_file_by_private_key(const char *input_file,
                  const char *key_file,
                  const char *output_file);


#endif // SPG_H_INCLUDED
