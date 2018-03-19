#ifndef JSON_UTILS_H_INCLUDED
#define JSON_UTILS_H_INCLUDED

typedef struct {
    char *key;
    int key_len;
    char *value;
    int value_len;
} json_item_t;

char *parse_json_item(const char *buf, int len, json_item_t *item);

#endif // JSON_UTILS_H_INCLUDED
