#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/file.h>
#include <openssl/rand.h>
#include <math.h>
#include <string.h>

//print nonce and key to console and test on the encrypt.py python script to see if program works correctly

#define BUFFER_SIZE 1024
#define KEY_SIZE 32        //Number of bytes for a 256-bit value  ->  256 bit value / 8 bytes = 32 bytes
#define NONCE_SIZE 12        //Number of bytes for 96-bit value  ->  96 bit value / 8 bytes = 12 bytes
#define ROTATE(v, c) ((v) << (c)) | ((v) >> (32 - (c)))

uint32_t state[16];

//attempt to create your own malloc function in the future
//get to understand how to use valgrind and gdb

//HOW DO YOU PROPERLY USE STRUCTSSSSS????
// typedef struct {
//     uint64_t bits[4]; // 4 words of 64 bits each
// } uint256_t;

// typedef struct {
//     //figure this out
// } uint96_t;


uint8_t* openReadFile(char filename[])
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("Error opening input file");
        exit(1);
    }

    uint8_t *buf = malloc(BUFFER_SIZE); //malloc takes in bytes

    fread(buf, sizeof(uint8_t), BUFFER_SIZE, fp);

    fclose(fp);
    return buf;
}

//add get and set for key value!!! (so I can use a key I generated to then decrypt (if I've cyrpted it prior]))
void Qround(uint32_t *working_state, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    working_state[a] += working_state[b];
    working_state[d] ^= working_state[a];
    working_state[d] = ROTATE(working_state[d], 16);
    working_state[c] += working_state[d];
    working_state[b] ^= working_state[c]; 
    working_state[b] = ROTATE(working_state[b], 12);
    working_state[a] += working_state[b];
    working_state[d] ^= working_state[a];
    working_state[d] = ROTATE(working_state[d], 8);
    working_state[c] += working_state[d];
    working_state[b] ^= working_state[c];
    working_state[b] = ROTATE(working_state[b], 7);
    
}

void inner_block(uint32_t* working_state) 
{
    Qround(working_state, 0, 4, 8,12);
    Qround(working_state, 1, 5, 9,13);
    Qround(working_state, 2, 6, 10,14);
    Qround(working_state, 3, 7, 11,15);
    Qround(working_state, 0, 5, 10,15);
    Qround(working_state, 1, 6, 11,12);
    Qround(working_state, 2, 7, 8,13);
    Qround(working_state, 3, 4, 9,14);
}

void chacha20_block(unsigned char* key, uint32_t counter,  unsigned char* nonce, uint8_t *key_stream) 
{
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    memcpy(&state[4], key, sizeof(key));
    state[12] = counter;
    memcpy(&state[13], nonce, sizeof(nonce));
    uint32_t working_state[16];
    memcpy(working_state, state, sizeof(state));

    for(int i = 0; i < 10; i++) {
        inner_block(working_state);
    }
    
    for(int i = 0; i < 16; i++) {
        state[i] += working_state[i];
    }

    //line 76 and 79 might not work (attempted fix for endian issue)
    uint32_t* temp_key_stream = (uint32_t*) key_stream;

    //serialize just means to turn data into a byte array (in this case turn state into a byte
    memcpy(temp_key_stream, state, 64);
    //endian issues only come up when dealing with bit arrays, not bytes, short etc
}

void write_encrypt_file(uint8_t* encrypted_message) {
    FILE *fp = fopen("encrypt.txt", "wb");
    if (fp == NULL) {
        perror("Error opening input file");
        exit(1);
    }

    fwrite(encrypted_message, sizeof(uint8_t), BUFFER_SIZE, fp);
    fclose(fp);
}

uint8_t* chacha20_algo(unsigned char* key, uint32_t counter,  unsigned char* nonce, uint8_t* buf)
{
    uint8_t encrypted_message[BUFFER_SIZE];
    int j;
    //dividing into groups of 64 bytes
    for(j = 0; j < floor(BUFFER_SIZE/64); j++) {
        uint8_t key_stream[64];
        chacha20_block(key, counter+j, nonce, key_stream); //for each block of 64 bytes, create a key stream
        unsigned char block[64];
        memcpy(block, &buf[j*64], 64);
        uint8_t temp_array[64];
        for(int i = 0; i < 64; i++) {
            temp_array[i] = block[i] ^ key_stream[i];
        }
        memcpy(&encrypted_message[j*64], temp_array, 64);
    }
    if((BUFFER_SIZE % 64) != 0) {
        j = floor(BUFFER_SIZE/64);
        uint8_t key_stream[64];
        chacha20_block(key, counter+j, nonce, key_stream);
        unsigned char block[64];
        uint8_t tempArray[64];

        for(int i = j*64; i < BUFFER_SIZE; i++) {
            tempArray[i-(j*64)] = block[i-(j*64)] ^ key_stream[i-(j*64)];
        }
        memcpy(&encrypted_message[j*64], tempArray, BUFFER_SIZE - (j*64));
    }

    write_encrypt_file(encrypted_message);

}


//reduce to just one function that has type parameter for either encrypt or decrypt???

void encrypt(uint8_t* buf) 
{
    //key and nonce should be generated via a secure random number generator (use a library)
    //but for debugging purposes you can just add anything for now 
    unsigned char keyRandNum[KEY_SIZE];
    int keyResult = RAND_bytes(keyRandNum, KEY_SIZE);

    unsigned char nonceRandNum[NONCE_SIZE];
    int nonceResult = RAND_bytes(nonceRandNum, NONCE_SIZE);

    printf("Key: %s\nNonce: %s\n", keyRandNum, nonceRandNum);

    if(keyResult != 1 || nonceResult != 1) {
        /* RAND_bytes failed */
        fprintf(stderr, "Error generating random bytes\n");
    }

    chacha20_algo((unsigned char*)&keyRandNum, 1, (unsigned char*)&nonceRandNum, buf);
}

void decrypt(uint8_t* buf, unsigned char* secret_key, unsigned char* nonce)    //keep secret key as integer for now
{
    chacha20_algo(secret_key, 1, nonce, buf);
}

int main(int argc, char* argv[]) {
    //check input args
        //Encrypt format: encrypt <file_name>
        //Decrypt format: decrypt <file_name> <secret_key>

        // || argc == 2 || argv[1] != "encrypt" || argv[1] != "decrypt"
    if(argc <= 2) {
        fprintf(stderr, "Usage: %s <method (encrypt or decrypt)> <path to file> <secret key (for decrypt)> <nonce (for decryption).....\n", argv[0]);
        exit(1);
    }

    //ask user for a password (can't be longer than 32 bytes)
    //if shorter than 32 bytes, pad it with something (like pad with 0s)
    //OR use the RANDbytes and concat with the user's given password to create a password that is about 32 bytes

    //OR BETTER OPTION: secure hashing algorithms -> compute a hash that will be 32 bytes (sha256)



    //read the file
    uint8_t *buffer = openReadFile(argv[2]);

    //printf("%s %s", argv[2], argv[1]);
    //pointers is still one of my weak areas :(

    if(memcmp(argv[1], "encrypt", 8) == 0) {
        encrypt(buffer);
    }
    else if(memcmp(argv[1], "decrypt", 8) == 0) {
        decrypt(buffer, argv[3], argv[4]);
    }
}
