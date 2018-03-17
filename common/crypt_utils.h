#ifndef CRYPT_UTILS_H_INCLUDED
#define CRYPT_UTILS_H_INCLUDED

void encrypt_file(const char *input_file,
                  const char *key_file,
                  const char *comment,
                  const char *output_file);

void decrypt_file(const char *input_file,
                  const char *key_file,
                  const char *output_file);

#endif // CRYPT_UTILS_H_INCLUDED
