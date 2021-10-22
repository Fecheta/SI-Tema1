#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <fstream>

using namespace std;

#define PORT 8182
#define AES_BLOCK_SIZE 16
#define ECB 1
#define CBC 2

int operation_mode = 0;

unsigned char key[17] = {0};
unsigned char key_enc[17] = {0};
unsigned char key_prim[17] = "anaaremultemeree";
unsigned char IV[17] = "0102030405060708";

int sock = 0, valread;
struct sockaddr_in server_addr;

unsigned char file_content_blocks[1000][AES_BLOCK_SIZE +1];
unsigned char file_content_blocks_encrypted[1000][AES_BLOCK_SIZE + 1];
int no_of_blocks = 0;

void client_config(){
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("eroare la socket\n");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Eroare de conectare la sevrer\n");
        exit(EXIT_FAILURE);
    }
}

void get_operation_mode(){
    char m[4];
    read(sock, m, 4);

    operation_mode = atoi(m);

    printf("Am primit modul de operare: %s\n", m);
}

void get_key_enc(){
    read(sock, key_enc, sizeof key_enc);
    printf("Am primit cheia encodata de la A: %s\n", key_enc);
}

void dec_enc_key(){
    AES_KEY aes_key;

    AES_set_decrypt_key(key_prim, AES_BLOCK_SIZE * 8, &aes_key);
    AES_decrypt(key_enc, key, &aes_key);
    key[16] = '\0';

    printf("Cheia decriptata: %s |\n", key);
}

void send_ready_message(){
    char r_mess[] = "totul este pregatit";

    send(sock, r_mess, sizeof r_mess, 0);

    printf("Am trimis mesajul de incepere a comunicarii: %s\n", r_mess);
}

void recive_file_content_enc(){
    char no_blocks[4];
    char block_read[AES_BLOCK_SIZE + 1];
    read(sock, no_blocks, sizeof no_blocks);

    int x = atoi(no_blocks);
    no_of_blocks = x;

    printf("Astept %s blocuri\n", no_blocks);

    for(int i = 0; i < no_of_blocks; i++){
        read(sock, file_content_blocks_encrypted[i], AES_BLOCK_SIZE);
        // file_content_blocks_encrypted[i][AES_BLOCK_SIZE] = '\0';
        send(sock, "ok", 4, 0);
        // strcpy((char*)file_content_blocks_encrypted[i], block_read);
    }

    for(int i = 0; i < no_of_blocks; i++){
        // printf("%s ||\n", (const char*)file_content_blocks_encrypted[i]);
        for(int j = 0; file_content_blocks_encrypted[i][j] != '\0'; j++)
            printf("%X ", file_content_blocks_encrypted[i][j]);
        printf("\n");
    }
}

void decrypt_ECB(){
    AES_KEY aes_key;
    // unsigned char x[17] = {0};

    AES_set_decrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    for(int i = 0 ; i < no_of_blocks; i++){
        AES_decrypt(file_content_blocks_encrypted[i], file_content_blocks[i], &aes_key);

        // printf("%s", file_content_blocks[i]);
    }

    // AES_decrypt(file_content_blocks_encrypted[0], x, &aes_key);

    printf("\n");
    for(int i = 0; i < no_of_blocks; i++){
        printf("%s", file_content_blocks[i]);
    }
    printf("\n");
}

void xor_cbc(unsigned char in1[], unsigned char in2[], unsigned char out[]){
    for(int i = 0; i < AES_BLOCK_SIZE; i++){
        out[i] = in1[i] ^ in2[i];
    }
    out[AES_BLOCK_SIZE] = '\0';
}

void decrypt_CBC(){
    AES_KEY aes_key;
    unsigned char xor_block[17] = {0};
    unsigned char dec_aux[17] = {0};
    // unsigned char file_content_blocks[1000][17];

    AES_set_decrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    AES_decrypt(file_content_blocks_encrypted[0], dec_aux, &aes_key);
    xor_cbc(dec_aux, IV, file_content_blocks[0]);

    for(int i = 1; i < no_of_blocks; i++){
        AES_decrypt(file_content_blocks_encrypted[i], dec_aux, &aes_key);
        xor_cbc(dec_aux, file_content_blocks_encrypted[i-1], file_content_blocks[i]);
    }

    printf("CBC decrypted text: \n");
    for(int i = 0; i < no_of_blocks; i++){
        printf("%s", file_content_blocks[i]);
    }
    printf("\n");
}


int main()
{
    client_config();

    get_operation_mode();

    get_key_enc();

    dec_enc_key();

    send_ready_message();

    recive_file_content_enc();

    // decrypt_file_ECB();
    printf("\nText-ul decriptat: ");
    // decrypt_ECB();
    if(operation_mode == ECB)
        decrypt_ECB();
    else
        decrypt_CBC();

    // AES_KEY aes_key;

    // unsigned char x[17];
    // unsigned char y[17] = "ajxasatzomqsaxta";
    // AES_set_decrypt_key(key, 128, &aes_key);
    // AES_decrypt(file_content_blocks_encrypted[0], x, &aes_key);

    // printf("x: %s |\n", x);

    // inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    // send(sock, message, strlen(message), 0);
    // printf("Am trimis mesajul\n");
    // valread = read(sock, buffer, 1024);
    // printf("Am primit de la server: %s\n", buffer);

    return 0;
}