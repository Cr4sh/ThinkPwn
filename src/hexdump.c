#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//--------------------------------------------------------------------------------------
void hexdump(unsigned char *data, size_t length, void *addr) 
{
    size_t dp = 0, p = 0;
    const char trans[] =
        "................................ !\"#$%&'()*+,-./0123456789"
        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
        "nopqrstuvwxyz{|}~...................................."
        "....................................................."
        "........................................";

    char buff[0x100], byte[0x10];
    memset(buff, 0, sizeof(buff));

    for (dp = 1; dp <= length; dp++)  
    {
        sprintf(byte, "%02x ", data[dp - 1]);
        strcat(buff, byte);

        if ((dp % 8) == 0)
        {
            strcat(buff, " ");
        }

        if ((dp % 16) == 0) 
        {
            strcat(buff, "| ");
            p = dp;

            for (dp -= 16; dp < p; dp++)
            {
                sprintf(byte, "%c", trans[data[dp]]);
                strcat(buff, byte);
            }

            printf("%.8llx: %s\n", (unsigned long long)addr + dp - 16, buff);
            memset(buff, 0, sizeof(buff));
        }
    }

    if (length % 16 != 0) 
    {
        p = dp = 16 - (length % 16);

        for (dp = p; dp > 0; dp--) 
        {
            strcat(buff, "   ");

            if (((dp % 8) == 0) && (p != 8))
            {
                strcat(buff, " ");
            }
        }

        strcat(buff, " | ");

        for (dp = length - 16 - p; dp < length; dp++)
        {
            sprintf(byte, "%c", trans[data[dp]]);
            strcat(buff, byte);
        }

        printf(
            "%.8llx: %s\n", 
            (unsigned long long)addr + length - (length % 16), buff
        );
    }
}
//--------------------------------------------------------------------------------------
//EoF
