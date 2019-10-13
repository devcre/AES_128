#include <stdio.h>

int main(){
    int i, j;
    unsigned char blockarray[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    printf("print blockarray\n");
    for(i=0;i<10;i++){
        printf("%X ", blockarray[i]);
    }
    printf("\n");

    for(j=0;j<10;j++){
        blockarray[j] = j + 10;
    }

    printf("modified blockarray\n");
    for(j=0;j<10;j++){
        printf("%X ", blockarray[j]);
    }
    printf("\n");
    return 0;
}