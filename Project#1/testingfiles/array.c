#include <stdio.h>

unsigned char Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

unsigned char b_array[16][16] = {{0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
                     {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
                     {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
                     {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
                     {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
                     {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
                     {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
                     {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
                     {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
                     {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
                     {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
                     {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
                     {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
                     {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
                     {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
                     {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}};
unsigned char dtime(unsigned char hexa){ // hexa * 2
    unsigned char x;
    unsigned int compare;
    x = hexa * 2;
    compare = hexa * 2;

    if (x == compare){
        return x;
    }
    else{
        return (hexa << 1)^0x1b;
    }
}

unsigned char ttime(unsigned char hexa){ // hexa * 3
    return dtime(hexa)^hexa;
}

unsigned char xtime(unsigned char hexa){
    return ((hexa<<1) ^ (((hexa>>7) & 1) * 0x1b));
}

unsigned char Multiply(int hexa1, int hexa2){
    return (((hexa2 & 1) * hexa1) ^                   
    ((hexa2>>1 & 1) * xtime(hexa1)) ^                
    ((hexa2>>2 & 1) * xtime(xtime(hexa1))) ^       
    ((hexa2>>3 & 1) * xtime(xtime(xtime(hexa1)))) ^
    ((hexa2>>4 & 1) * xtime(xtime(xtime(xtime(hexa1))))));
}

void swap_ins(unsigned char *block, int s1, int s2){
    int tmp;
    tmp = block[s1];
    block[s1] = block[s2];
    block[s2] = tmp;
}

void rotWord(unsigned char* w3, unsigned char* output){
    *output = *(w3+1);
    *(output+1) = *(w3+2);
    *(output+2) = *(w3+3);
    *(output+3) = *(w3);
}

void subWord(unsigned char *output){
    int i;
    for(i=0; i<4; i++){
        *(output+i) = b_array[*(output+i)];
    }
}

void g_function(unsigned char* input, unsigned char* output, int rnd){
    rotWord(input, output); // x (rotWord)
    subWord(output); // y (subWord)
    *(output+0) ^= Rcon[rnd]; // z (y (xor) Rcon)
}

void expandKey(unsigned char *key, unsigned char *roundKey){
    /* 추가 구현 */
	int i;

    for (i=0; i<16; i++){
        *(roundKey+i) = *(key+i);
    }
    // 1~10 round key expansion

    int rnd;
    for(rnd=1; rnd<176/16; rnd++){
        int w0 = rnd * 16;
        int w1 = w0 + 4;
        int w2 = w1 + 4;
        int w3 = w2 + 4;

        unsigned char* gfunc_output = (unsigned char*) malloc(sizeof(unsigned char)*4);
        g_function((roundKey+w3-16), gfunc_output, rnd);

        // Next round w
        for (i=0; i<16/4; i++){
            *(roundKey+w0+i) = *(roundKey+w0-16+i) ^ *(gfunc_output+i);
            *(roundKey+w1+i) = *(roundKey+w1-16+i) ^ *(roundKey+w0+i);
            *(roundKey+w2+i) = *(roundKey+w2-16+i) ^ *(roundKey+w1+i);
            *(roundKey+w3+i) = *(roundKey+w3-16+i) ^ *(roundKey+w2+i);
        }
        free(gfunc_output);
    }
}
int main(){
    unsigned char block[16] = {0xD4, 0xBF, 0x5D, 0x30,
                                 0x93, 0x33, 0xFC, 0x82,
                                 0x5D, 0xE7, 0x4A, 0xC3,
                                 0x30, 0x8C, 0xD8, 0x95};

    unsigned char mix_col[4][4] = {{2,3,1,1},
                                   {1,2,3,1},
                                   {1,1,2,3},
                                   {3,1,1,2}};
    
    unsigned char result[4][4];
    
    // printf("print bolck\n");
    // ptr = block;
    // printf("%d\n", *ptr);
    // printf("%d\n", *(ptr + 1));
    // printf("%d\n", *(ptr + 2));
    // printf("%d\n", *(ptr + 3));
    // while(ptr != NULL){
    //     printf("%X ", *ptr);
    //     ptr = ptr + 1;
    // }

    // printf("sizeof block : %d\n", sizeof(block));
    // printf("sizeof(block) /  sizeof(unsigned char) : %d\n", sizeof(block)/sizeof(unsigned char));
    // printf("size of unsigned char : %d\n", sizeof(unsigned char));

    // i = block[0] / 16;
    // j = block[0] % 16;
    // block[0] = b_array[i][j];
    // printf("modified block\n");
    // printf("i: %x\n", i);
    // printf("j: %x\n", j);
    // printf("block[0] : %x\n", block[0]);

    // -- matrix mul, XOR --

    // result[0][0] = (0x2*block[0][0])^(0x3*block[1][0])^(0x1*block[2][0])^(0x1*block[3][0]);
    // printf("result[0][0] : %X\n", result[0][0]);

    // original answer : 0x57 * 2 = 0xAE
    // original answer : 0xbf * 3 = 0xda
    int i, j, c;
    int ct1, ct2, ct3;
    unsigned char arr[4];

    int a, b;

    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            printf("%X ", block[4*j+i]);
        }
        printf("\n");
    }
    printf("\n");

    for(c=0; c<16; c++){
        a = block[c] / 16;
        b = block[c] % 16;
        block[c] = b_array[a][b];
    }

    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            printf("%X ", block[4*j+i]);
        }
        printf("\n");
    }

    // for(i=0;i<4;i++){
    //     for(j=0;j<4;j++){
    //         printf("%X ", block[4*j+i]);
    //     }
    //     printf("\n");
    // }

    // for(ct1=0;ct1<4;ct1++){
    //     for(ct2=0;ct2<4;ct2++){
    //         arr[ct2]=block[ct2+4*ct1];
    //     }

    //     block[0+4*ct1] = dtime(arr[0]) ^ ttime(arr[1]) ^ arr[2] ^ arr[3];
    //     block[1+4*ct1] = arr[0] ^ dtime(arr[1]) ^ ttime(arr[2]) ^ arr[3];
    //     block[2+4*ct1] = arr[0] ^ arr[1] ^ dtime(arr[2]) ^ ttime(arr[3]);
    //     block[3+4*ct1] = ttime(arr[0]) ^ arr[1] ^ arr[2] ^ dtime(arr[3]);
    // }

    // for(i=0;i<4;i++){
    //     for(j=0;j<4;j++){
    //         printf("%X ", block[4*j+i]);
    //     }
    //     printf("\n");
    // }


    return 0;
}