#include <iostream>
#include <fstream>
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

using namespace std;


#define AES_BLOCK_SIZE 16

void padding(unsigned char buffer[], int length);

int main(){
    fstream in("files/file.txt", fstream::in);

    char vectorDeInitializare[16] = "abcdefghijabsed";

    unsigned char buffer[16];
    int size = 0;

    while(in.peek() != EOF){
        buffer[size] = in.get();
        size++;
    }
    buffer[size] = '\0';
    printf("Size: %d\n", size);
    in.close();
    // padding(buffer, size);

    printf("Buffer: %s\n", buffer);
    for(int i=0; i <16 && buffer[i] != '\0'; i++){
        printf("%c ", buffer[i]);
    }
    printf("|\n");

    unsigned char key[16] = "1n1aewmwew333aa";
    AES_KEY enc_key, dec_key;

    AES_set_encrypt_key(key, 128, &enc_key);

    AES_set_decrypt_key(key, 128, &dec_key);

    unsigned char textCriptat[16];
    const unsigned char *bff = buffer;
    AES_encrypt(bff, textCriptat, &enc_key);

    printf("Criptat: ");
        for(int i=0; i <16 && textCriptat[i] != '\0'; i++){
        printf("%X ", textCriptat[i]);
    }
    printf("\n");

    const unsigned char *dec = textCriptat;
    unsigned char out[16];
    AES_decrypt(dec, out, &dec_key);

    printf("Decriptat: ");
    for(int i=0; i <16 && (out[i] != '\0'); i++){
        printf("%c", out[i]);
    }
    printf("|\n");

    unsigned char key_rand[16], iv[16];
    RAND_bytes(key_rand, sizeof key_rand);
    for(int i = 0; i < sizeof key_rand; i++)
    {
        printf("%X ", key_rand[i]);
    }
    printf("\n");

    return 0;
}

void padding(unsigned char buffer[], int length){
    // int length = strlen(buffer);

    if(length < AES_BLOCK_SIZE){
        int dif = AES_BLOCK_SIZE - length;
        for(int i = length; i < AES_BLOCK_SIZE; i++){
            buffer[i] = dif;
        }
    }
    buffer[AES_BLOCK_SIZE] = '\0';
}