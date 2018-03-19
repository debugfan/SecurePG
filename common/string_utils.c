#include "string_utils.h"

#include <string.h>

char *rtrim(char *s, const char *delims)
{
    int off, len;
    len = strlen(s);
    if(len > 0)
    {
        for(off = len - 1; off >= 0; off--)
        {
            if(NULL != strchr(delims, s[off]))
            {
                s[off] = '\0';
            }
            else
            {
                break;
            }
        }
    }
    return s;
}

char *skip(const char *s, const char *delims)
{
    for(; *s != '\0'; s++)
    {
        if(NULL == strchr(delims, *s))
        {
            break;
        }
    }
    return (char *)s;
}
