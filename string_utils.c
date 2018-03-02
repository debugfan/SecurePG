#include "string_utils.h"

#include <string.h>

char *trim_right(char *s, const char *delims)
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
