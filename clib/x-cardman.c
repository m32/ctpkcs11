#include <stdio.h>
#include "dyn_generic.h"

#define CDLL(handle, path) \
    SYS_dyn_LoadLibrary(&handle, path); \
    if (NULL == handle) \
    { \
        printf("Can't open %s", path); \
        return -1; \
    }

typedef void (*tpuk)(unsigned char *, unsigned char *);

int main(int argc, char *argv[], char **envp)
{
    void *lcrypto, *lssl, *lcertum;
    void (*info)();
    tpuk puk;
    unsigned long Osc35GetTokenInfo        = 0x00000000000ae9d0;
    unsigned long Osc35getUninitializedPuk = 0x00000000000ade50;
    CDLL(lcrypto, "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
    CDLL(lssl, "/usr/lib/x86_64-linux-gnu/libssl.so.1.1")
    CDLL(lcertum, "/devel/lib/pkcs11libs/sc30pkcs11-3.0.5.60-MS.so")

    SYS_dyn_GetAddress(lcertum, (function_ptr*)&info, "sc35GetTokenInfo");
    SYS_dyn_GetAddress(lcertum, (function_ptr*)&puk, "sc35getUninitializedPuk");

    unsigned long offset = ((unsigned long)info)-Osc35GetTokenInfo+Osc35getUninitializedPuk;
    puk = (tpuk)offset;

    printf("info=%p\n", info);
    printf("puk =%p\n", puk);

    unsigned char randomdata[8] = {1,2,3,4,5,6,7,8};
    unsigned char randompuk[33] = {0};

    puk(randomdata, randompuk);
    printf("randompuk=[\n");
    for(int i=0;i<32;i++)
        printf("%d,", randompuk[i]);
    printf("]\n");

    SYS_dyn_CloseLibrary(&lcertum);
    SYS_dyn_CloseLibrary(&lssl);
    SYS_dyn_CloseLibrary(&lcrypto);
/*
sc35GetTokenInfo        = 0x00000000000ae9d0
sc35getUninitializedPuk = 0x00000000000ade50
proc = CFUNCTYPE(c_int, c_int, c_int)(("sc35GetTokenInfo", lcertum))
print(proc)
print(dir(proc))
*/
    return 0;
}
