#include "json_utils.h"
#include <string.h>

char *strnchr(const char *s, int n, char c)
{
    int i;
    for(i = 0; i < n; i++)
    {
        if(s[i] == '\0')
        {
            break;
        }
        if(s[i] == c)
        {
            return (char *)s + i;
        }
    }

    return NULL;
}

char *parse_json_item(const char *buf, int len, json_item_t *item)
{
    char *start;
    char *end;
    const char *terminus;
    terminus = buf + len;
    start = strnchr(buf, len, '\"');
    if(start == NULL)
    {
        return NULL;
    }
    start++;
    end = strnchr(start, terminus - start, '\"');
    if(end == NULL)
    {
        return NULL;
    }
    item->key = start;
    item->key_len = end - start;
    end++;
    start = strnchr(end, terminus - end, '\"');
    if(start == NULL)
    {
        return NULL;
    }
    start++;
    end = strnchr(start, terminus - start, '\"');
    if(end == NULL)
    {
        return NULL;
    }
    item->value = start;
    item->value_len = end - start;
    return end + 1;
}

