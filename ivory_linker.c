#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ivory.h"

int main(int argc, char** argv) {
    void * handle = ivory_open("./libdog.so", "pincode");
    int ret = 0;
    char c = 0;

    ivory_ls(handle);

    int (*myadd)(int);
    *(void**)(&myadd) = ivory_sym(handle, "myadd");
    ret = myadd(456);
    printf("add ret: [%d]\n", ret);

    void (*myprint)(void);
    *(void**)(&myprint) = ivory_sym(handle, "myprint");
    myprint();

    char (*mychar)(void);
    *(void**)(&mychar) = ivory_sym(handle, "mychar");
    c = mychar();
    printf("mychar: [%c]\n", c);

    printf("%p,%p,%d\n", myprint, myadd, (void *)myprint- (void *)myadd);
    ivory_close(handle);
    return EXIT_SUCCESS;
}
