#include <stdio.h>
#include <string.h>

int g[] = {5,5,5,5,5,5,5,5,5,5,5};

void myprint(void) {
    fprintf(stderr, "hello, stderr\n");
}

char mychar(void) {
    //int g[] = {1,1,1,1,1};
    printf("g=[%d]\n", g[2]);
    char * str = "hello, world\n";
    char str2[64];
    memcpy(str2, str, 10);
    return str2[g[2]];
}

int myadd(int a) {
    return a + 1;
}

