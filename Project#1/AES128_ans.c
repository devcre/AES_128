#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include "AES128.h"

 

#define KEY_SIZE 16         // Key Length = 4 word

#define ROUNDKEY_SIZE 176   // # of Rounds = 10

#define BLOCK_SIZE 16       // Block Size = 4 word

 

 

// S-BOX

BYTE s_box[256] =

{

   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,

   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,

   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,

   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,

   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,

   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,

   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,

   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,

   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,

   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,

   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,

   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,

   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,

   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,

   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,

   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16

};

 

// inverse S_BOX

BYTE inv_s_box[256] =

{

   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,

   0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,

   0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,

   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,

   0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,

   0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,

   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,

   0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,

   0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,

   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,

   0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,

   0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,

   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,

   0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,

   0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,

   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D

};

 

 

// Round Constants

BYTE rcon[10] =

{

    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36

};

 

// Key Expansion Auxiliary Function

void rotWord(BYTE* w3, BYTE* output)

{

    *output = *(w3+1);

    *(output+1) = *(w3+2);

    *(output+2) = *(w3+3);

    *(output+3) = *(w3);

}

 

void subWord(BYTE *output)

{

    int i;

    for(i=0; i<4; i++)

    {

        *(output+i) = s_box[*(output+i)];

    }

}

 

void g_function(BYTE* input, BYTE* output, int rnd)

{

    rotWord(input, output); // x (rotWord)

    subWord(output); // y (subWord)

    *(output+0) ^= rcon[rnd-1]; // z (y (xor) Rcon)

}

 

/*  <키스케줄링 함수>

 *

 *  key         키스케줄링을 수행할 16바이트 키

 *  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간

 */

void expandKey(BYTE *key, BYTE *roundKey)

{

    // 0 round

    int i;

    for (i=0; i<KEY_SIZE; i++)

    {

        *(roundKey+i) = *(key+i);

    }

 

    // 1~10 round key expansion

    int rnd;

    for(rnd=1; rnd<ROUNDKEY_SIZE/KEY_SIZE; rnd++)

    {

        int w0 = rnd * KEY_SIZE;

        int w1 = w0 + 4;

        int w2 = w1 + 4;

        int w3 = w2 + 4;

 

        BYTE* gfunc_output = (BYTE*) malloc(sizeof(BYTE)*4);

        g_function((roundKey+w3-KEY_SIZE), gfunc_output, rnd);

 

        // Next round w

        for (i=0; i<KEY_SIZE/4; i++)

        {

            *(roundKey+w0+i) = *(roundKey+w0-KEY_SIZE+i) ^ *(gfunc_output+i);

            *(roundKey+w1+i) = *(roundKey+w1-KEY_SIZE+i) ^ *(roundKey+w0+i);

            *(roundKey+w2+i) = *(roundKey+w2-KEY_SIZE+i) ^ *(roundKey+w1+i);

            *(roundKey+w3+i) = *(roundKey+w3-KEY_SIZE+i) ^ *(roundKey+w2+i);

        }

        free(gfunc_output);

    }

}

 

/*  <SubBytes 함수>

 *

 *  block   SubBytes 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영

 *  mode    SubBytes 수행 모드

 */

 

BYTE* subBytes(BYTE *block, int mode)

{

    int i;

    switch(mode){

        case ENC:

        {

            for(i=0; i<BLOCK_SIZE; i++) *(block+i) = s_box[*(block+i)];

            break;

        }

        case DEC:

        {

            for(i=0; i<BLOCK_SIZE;i++) *(block+i) = inv_s_box[*(block+i)];

            break;

        }

        default:

            fprintf(stderr, "Invalid mode!\n");

            exit(1);

    }

    return block;

}

 

/*  <ShiftRows 함수>

 *

 *  block   ShiftRows 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영

 *  mode    ShiftRows 수행 모드

 */

 

BYTE* shiftRows(BYTE *block, int mode)

{

    switch(mode){

        case ENC:

        {

            BYTE temp = (BYTE) malloc(sizeof(BYTE)+1);

            temp = *(block+1);

            *(block+1) = *(block+5);

            *(block+5) = *(block+9);

            *(block+9) = *(block+13);

            *(block+13) = temp;

 

            temp = *(block+2);

            *(block+2) = *(block+10);

            *(block+10) = temp;

            temp = *(block+6);

            *(block+6) = *(block+14);

            *(block+14) = temp;

 

            temp=*(block+15);

            *(block+15) = *(block+11);

            *(block+11) = *(block+7);

            *(block+7) = *(block+3);

            *(block+3) = temp;

            break;

        }

        case DEC:

        {

            BYTE temp = (BYTE) malloc(sizeof(BYTE)+1);

            temp = *(block+13);

            *(block+13) = *(block+9);

            *(block+9) = *(block+5);

            *(block+5) = *(block+1);

            *(block+1) = temp;

 

            temp = *(block+2);

            *(block+2) = *(block+10);

            *(block+10) = temp;

            temp = *(block+6);

            *(block+6) = *(block+14);

            *(block+14) = temp;

 

            temp = *(block+3);

            *(block+3) = *(block+7);

            *(block+7) = *(block+11);

            *(block+11) = *(block+15);

            *(block+15)= temp;

            break;

        }

        default:

            fprintf(stderr, "Invalid mode!\n");

            exit(1);

    }

    return block;

}

 

// Galois Field Multiplication

BYTE gf_mult(BYTE a, BYTE b)

{

    BYTE temp = 0, mask = 0x01;

    int i;

    for(i=0; i<8; i++)

    {

        if(b & mask)

        {

            temp ^= a;

        }

        if(a & 0x80)

        {

            a = (a << 1) ^ 0x1B;

        }

        else

        {

            a <<= 1;

        }

        mask <<= 1;

    }

    return temp;

}

 

/*  <MixColumns 함수>

 *

 *  block   MixColumns을 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영

 *  mode    MixColumns의 수행 모드

 */

BYTE* mixColumns(BYTE *block, int mode)

{

    switch(mode){

        case ENC:

        {

            BYTE output[4][4] = {0, };

            BYTE mixMtx[4][4] = {2, 3, 1, 1,

                                1, 2, 3, 1,

                                1, 1, 2, 3,

                                3, 1, 1, 2};

            int i, j, k;

            for (i=0; i<4; i++)

            {

                for(j=0; j<4; j++)

                {

                    for(k=0; k<4; k++)

                    {

                        output[i][j] ^= gf_mult(*(block+4*i+k), mixMtx[j][k]);

                    }

                }

            }

            memcpy(block, &output, sizeof(BYTE)*BLOCK_SIZE);

            break;

        }

        case DEC:

        {

            BYTE output[4][4] = {0, };

            BYTE mixMtx[4][4] = {14, 11, 13, 9,

                                9, 14, 11, 13,

                                13, 9, 14, 11,

                                11, 13, 9, 14};

            int i, j, k;

            for (i=0; i<4; i++)

            {

                for(j=0; j<4; j++)

                {

                    for(k=0; k<4; k++)

                    {

                        output[i][j] ^= gf_mult(*(block+4*i+k), mixMtx[j][k]);

                    }

                }

            }

            memcpy(block, &output, sizeof(BYTE)*BLOCK_SIZE);

            break;

        }

        default:

        fprintf(stderr, "Invalid mode!\n");

        exit(1);

    }

    return block;

}

 

/*  <AddRoundKey 함수>

 *

 *  block   AddRoundKey를 수행할 16바이트 블록. 수행 결과는 해당 배열에 반영

 *  rKey    AddRoundKey를 수행할 16바이트 라운드키

 */

BYTE* addRoundKey(BYTE *block, BYTE *rKey)

{

    int i;

    for (i=0; i<BLOCK_SIZE; i++)

    {

        *(block+i) = *(block+i) ^ *(rKey+i);

    }

    return block;

}

 

 

/*  <128비트 AES 암복호화 함수>

 *

 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수

 *

 *  [ENC 모드]

 *  input   평문 바이트 배열

 *  output  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴

 *  key     128비트 암호키 (16바이트)

 *

 *  [DEC 모드]

 *  input   암호문 바이트 배열

 *  output  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴

 *  key     128비트 암호키 (16바이트)

 */

 

void AES128(BYTE *input, BYTE *output, BYTE *key, int mode)

{

    BYTE* roundkey  = (BYTE*) malloc(sizeof(BYTE)*176);

    expandKey(key, roundkey);

    memcpy(output, input, sizeof(BYTE)*BLOCK_SIZE);

    if(mode == ENC)

    {

        addRoundKey(output, key);

        int round=1;

        while(round<=10)

        {

            subBytes(output, mode);

            shiftRows(output,mode);

            if (round !=10) mixColumns(output,mode);

            addRoundKey(output,(roundkey+KEY_SIZE*round));

            round++;

        }

    }
    else if(mode == DEC){
        addRoundKey(output, roundkey+KEY_SIZE*10);
        int round=1;
        while(round<=10)
        {

            subBytes(output, mode);

            shiftRows(output,mode);

            if (round !=10)

            {

                mixColumns(output,mode);

                mixColumns((roundkey+BLOCK_SIZE*(10-round)),mode);

            }
            addRoundKey(output,(roundkey+KEY_SIZE*(10-round)));
            round++;
        }
    }
    else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}
