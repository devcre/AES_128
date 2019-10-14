/*  ======================================================================== *

                                    주 의 사 항


    1. 구현은 다양한 방식으로 이뤄질 수 있음
    2. AES128(...) 함수의 호출과 리턴이 여러번 반복되더라도 메모리 누수가 생기지 않게 함
    3. AddRoundKey 함수를 구현할 때에도 파라미터 rKey는 사전에 선언된 지역 배열을 가리키도록 해야 함
       (정확한 구현을 위해서는 포인터 개념의 이해가 필요함)
    4. 배열의 인덱스 계산시 아래에 정의된 KEY_SIZE, ROUNDKEY_SIZE, BLOCK_SIZE를 이용해야 함
       (상수 그대로 사용하면 안됨. 예로, 4, 16는 안되고 KEY_SIZE/4, BLOCK_SIZE로 사용해야 함)

 *  ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include "AES128.h"

#define KEY_SIZE 16
#define ROUNDKEY_SIZE 176
#define BLOCK_SIZE 16

/* 기타 필요한 전역 */
BYTE Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

int s_box[16][16] = {{0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
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
    
int invs_box[16][16] = {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
/* 기타 필요한 함수 */

BYTE dtime(BYTE hexa){ // hexa * 2
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

BYTE ttime(BYTE hexa){ // hexa * 3
    return dtime(hexa)^hexa;
}

void swap_ins(BYTE *block, int s1, int s2){
    int tmp;
    tmp = block[s1];
    block[s1] = block[s2];
    block[s2] = tmp;
}

BYTE xtime(BYTE hexa){
    return ((hexa<<1) ^ (((hexa>>7) & 1) * 0x1b));
}

BYTE Multiply(int hexa1, int hexa2){
    return (((hexa2 & 1) * hexa1) ^                   
    ((hexa2>>1 & 1) * xtime(hexa1)) ^                
    ((hexa2>>2 & 1) * xtime(xtime(hexa1))) ^       
    ((hexa2>>3 & 1) * xtime(xtime(xtime(hexa1)))) ^
    ((hexa2>>4 & 1) * xtime(xtime(xtime(xtime(hexa1))))));
}

void rotWord(BYTE* w3, BYTE* output){
    *output = *(w3+1);
    *(output+1) = *(w3+2);
    *(output+2) = *(w3+3);
    *(output+3) = *(w3);
}

void subWord(BYTE *output){
    int i;
    for(i=0; i<4; i++){
        *(output+i) = s_box[*(output+i)];
    }
}

void g_function(BYTE* input, BYTE* output, int rnd){
    rotWord(input, output); // x (rotWord)
    subWord(output); // y (subWord)
    *(output+0) ^= Rcon[rnd-1]; // z (y (xor) Rcon)
}

/*  <키스케줄링 함
 *   
 *  key         키
 *  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간
 */
void expandKey(BYTE *key, BYTE *roundKey){
    /* 추가 구현 */
	int i;

    for (i=0; i<KEY_SIZE; i++){
        *(roundKey+i) = *(key+i);
    }
    // 1~10 round key expansion

    int rnd;
    for(rnd=1; rnd<ROUNDKEY_SIZE/KEY_SIZE; rnd++){
        int w0 = rnd * KEY_SIZE;
        int w1 = w0 + 4;
        int w2 = w1 + 4;
        int w3 = w2 + 4;

        BYTE* gfunc_output = (BYTE*) malloc(sizeof(BYTE)*4);
        g_function((roundKey+w3-KEY_SIZE), gfunc_output, rnd);

        // Next round w
        for (i=0; i<KEY_SIZE/4; i++){
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
 BYTE* subBytes(BYTE *block, int mode){
    // int AmountOfBlock  = sizeof(block); // 4 X 4 
    int countt;
    int t_digit, o_digit;

    /* 필요하다 생각하면 추가 선언 */

    switch(mode){

        case ENC:
            /* 추가 구현 */
            for(countt=0; countt<BLOCK_SIZE; countt++){
                t_digit = block[countt] / BLOCK_SIZE;
                o_digit = block[countt] % BLOCK_SIZE;
                block[countt] = s_box[t_digit][o_digit];
            }
            break;

        case DEC:
            /* 추가 구현 */
            for(countt=0; countt<BLOCK_SIZE; countt++){
                t_digit = block[countt] / BLOCK_SIZE;
                o_digit = block[countt] % BLOCK_SIZE;
                block[countt] = invs_box[t_digit][o_digit];
            }
            break;

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
BYTE* shiftRows(BYTE *block, int mode){ 

    /* 필요하다 생각하면 추가 선언 */
    // 

    switch(mode){

        case ENC:
            /* 추가 구현 */
            swap_ins(block, 1,5);
            swap_ins(block, 5,9);
            swap_ins(block, 9,13);

            swap_ins(block, 2,10);
            swap_ins(block, 6,14);

            swap_ins(block, 11,15);
            swap_ins(block, 7,11);
            swap_ins(block, 3,7);
            break;
        case DEC:
            /* 추가 구현 */
            swap_ins(block, 9,13);
            swap_ins(block, 5,9);
            swap_ins(block, 1,5);

            swap_ins(block, 6,14);
            swap_ins(block, 2,10);

            swap_ins(block, 3,7);
            swap_ins(block, 7,11);
            swap_ins(block, 11,15);
            break;
        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}


/*  <MixColumns 함수>
 *   
 *  block   MixColumns을 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
 *  mode    MixColumns의 수행 모드
 */
BYTE* mixColumns(BYTE *block, int mode){    
    /* 필요하다 생각하면 추가 선언 */
    int ct1, ct2, ct3;
    BYTE arr[4];

    int q;
    BYTE a, b, c, d;
    switch(mode){

        case ENC:
            /* 추가 구현 */
            for(ct1=0;ct1<4;ct1++){
                for(ct2=0;ct2<4;ct2++){
                    arr[ct2]=block[ct2+4*ct1];
                }

                block[0+4*ct1] = Multiply(arr[0], 0x02) ^ Multiply(arr[1], 0x03) ^ arr[2] ^ arr[3];
                block[1+4*ct1] = arr[0] ^ Multiply(arr[1], 0x02) ^ Multiply(arr[2], 0x03) ^ arr[3];
                block[2+4*ct1] = arr[0] ^ arr[1] ^ Multiply(arr[2], 0x02) ^ Multiply(arr[3], 0x03);
                block[3+4*ct1] = Multiply(arr[0], 0x03) ^ arr[1] ^ arr[2] ^ Multiply(arr[3], 0x02);
            }
            break;

        case DEC:
            /* 추가 구현 */
            for (q=0;q<4;q++)
                {
                    a = block[0+4*q];
                    b = block[1+4*q];
                    c = block[2+4*q];
                    d = block[3+4*q];

                    block[0+4*q] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
                    block[1+4*q] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
                    block[2+4*q] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
                    block[3+4*q] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
                }
            
            break;

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
BYTE* addRoundKey(BYTE *block, BYTE *rKey){
    /* 추가 구현 */
    int cou;
    for(cou=0;cou<BLOCK_SIZE;cou++){
        *(block+cou) ^= *(rKey+cou);
    }
    return block;
}

/*  <128비트 AES 암복호화 함수>
 *  
 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
 *
 *  [ENC 모드]
 *  input   평문 바이트 배열
 *  result  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 *
 *  [DEC 모드]
 *  input   암호문 바이트 배열
 *  result  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 */
 
void AES128(BYTE *input, BYTE *result, BYTE *key, int mode){

    if(mode == ENC){
		int k, t;
        int ir, kcount;
        BYTE state[BLOCK_SIZE];
		BYTE rkey[ROUNDKEY_SIZE]; // total round key
        BYTE srkey[KEY_SIZE]; // small round key

		kcount = KEY_SIZE;
        
        /* 추가 작업이 필요하다 생각하면 추가 구현 */
        // encrypting //
        expandKey(key,rkey);

        addRoundKey(input,key);
        for(int nr=0; nr<9; nr++){
            subBytes(input,ENC);
            shiftRows(input,ENC);
            mixColumns(input,ENC);
			for(t=0;t<KEY_SIZE;t++){
                srkey[t] = rkey[t+kcount];
            }
			kcount += KEY_SIZE;
            addRoundKey(input,srkey);
        }
        subBytes(input,ENC);
        shiftRows(input,ENC);
		for(t=0;t<KEY_SIZE;t++){
            srkey[t] = rkey[t+kcount];
        }
        addRoundKey(input,srkey);

        // out = state;
        for(ir=0;ir<BLOCK_SIZE;ir++){
            result[ir] = input[ir];
        }

    }else if(mode == DEC){;
        int irr, count2;
        BYTE state[BLOCK_SIZE];

        count2 = 0;

        /* 추가 작업이 필요하다 생각하면 추가 구현 */
        // decrypting
        addRoundKey(state, key);
        for(int nr=1;nr<9;nr++){
            shiftRows(state,DEC);
            subBytes(state,DEC);
            addRoundKey(state,key);
            mixColumns(state,DEC);
        }
        shiftRows(state,DEC);
        subBytes(state,DEC);
        addRoundKey(state,key);

        // out = state
        for(irr=0;irr<16;irr++){
            result[irr] = state[irr];
        }

    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}