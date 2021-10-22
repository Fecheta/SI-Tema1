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
#define PORT_KM 8183
#define AES_BLOCK_SIZE 16
#define ECB 1
#define CBC 2

int operation_mode = 0;

unsigned char key[17] = "123";
unsigned char key_enc[17] = {0};
unsigned char key_prim[17] = "anaaremultemeree";
unsigned char IV[17] = "0102030405060708";

int server_fd, socket_B, valread;
struct sockaddr_in address, key_manager_address;
int opt = 1;
int addrlen = sizeof(address);

unsigned char file_content_blocks[1000][AES_BLOCK_SIZE + 1];
unsigned char file_content_blocks_encrypted[1000][AES_BLOCK_SIZE + 1];
int no_of_blocks = 0;
char file_path[] = "files/file.txt";

void server_config()
{
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("eroare la soket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("eroare la socket options");
        exit(EXIT_FAILURE);
    }

    if ((bind(server_fd, (struct sockaddr *)&address, sizeof(address))) < 0)
    {
        perror("nu am putut face bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0)
    {
        perror("Eroare la ascultare");
        exit(EXIT_FAILURE);
    }
}

void read_content_on_blocks()
{
    fstream in(file_path, fstream::in);

    int size = -1;

    while (in.peek() != EOF)
    {
        size++;
        char x = in.get();
        // if(x == '\n')
        //     file_content_blocks[no_of_blocks][size] = ' ';
        // else
        file_content_blocks[no_of_blocks][size] = x;

        if (size == AES_BLOCK_SIZE - 1 && in.peek() != EOF)
        {
            file_content_blocks[no_of_blocks][AES_BLOCK_SIZE + 1] = '\0';
            no_of_blocks++;
            size = -1;
        }
    }
    no_of_blocks++;

    in.close();

    for (int i = 0; i < no_of_blocks; i++)
        printf("%s\n", file_content_blocks[i]);
    printf("Blocks: %d\n", no_of_blocks);
}

void decrypt_key()
{
    AES_KEY aes_key;
    // unsigned char out[17] = {0};

    AES_set_decrypt_key(key_prim, AES_BLOCK_SIZE * 8, &aes_key);
    // printf("%s\n", key_prim);
    // printf("ok cu setat cheia\n");
    // printf("%s\n", key_enc);
    // printf("%s\n", key);

    AES_decrypt(key_enc, key, &aes_key);
    // printf("ok cu dec\n");

    printf("cheia decriptata: %s |\n", key);
}

void get_key_from_KM()
{
    int socket_KM;
    char text[] = "Da-mi cheia";

    key_manager_address.sin_family = AF_INET;
    key_manager_address.sin_addr.s_addr = INADDR_ANY;
    key_manager_address.sin_port = htons(PORT_KM);

    if ((socket_KM = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Probleme la socket");
        exit(EXIT_FAILURE);
    }

    if (connect(socket_KM, (struct sockaddr *)&key_manager_address, sizeof(key_manager_address)) < 0)
    {
        perror("Eroare la conectare");
        exit(EXIT_FAILURE);
    }

    printf("M-am conectat la KM\n");

    send(socket_KM, text, sizeof text, 0);

    read(socket_KM, key_enc, AES_BLOCK_SIZE);
    printf("Am primit de la KM cheia: %s\n", key_enc);
    sleep(1);

    // *key = decrypt_function(key_prim, key_enc);
    // printf("cheia decriptata este: %s\n", key);
    decrypt_key();
    // strcpy((char *)key, (char *)key_cpy);

    close(socket_KM);
}

void encrypt_file_ECB()
{
    AES_KEY aes_key;
    // unsigned char enc[17] = {0};

    AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    for (int i = 0; i < no_of_blocks; i++)
    {
        AES_encrypt(file_content_blocks[i], file_content_blocks_encrypted[i], &aes_key);
        // strcpy((char*)file_content_blocks_encrypted[i], (char*)enc);
    }

    for (int i = 0; i < no_of_blocks; i++)
    {
        // printf("%s ||\n", file_content_blocks_encrypted[i]);
        for (int j = 0; file_content_blocks_encrypted[i][j] != '\0'; j++)
            printf("%X ", file_content_blocks_encrypted[i][j]);
        printf("\n");
    }
}

void xor_cbc(unsigned char in1[], unsigned char in2[], unsigned char out[]){
    for(int i = 0; i < AES_BLOCK_SIZE; i++){
        out[i] = in1[i] ^ in2[i];
    }
    out[AES_BLOCK_SIZE] = '\0';
}

void encrypt_file_CBC(){
    AES_KEY aes_key;
    unsigned char xor_block[17] = {0};

    AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    xor_cbc(file_content_blocks[0], IV, xor_block);
    AES_encrypt(xor_block, file_content_blocks_encrypted[0], &aes_key);

    for(int i = 1; i < no_of_blocks; i++){
        xor_cbc(file_content_blocks_encrypted[i-1], file_content_blocks[i], xor_block);
        AES_encrypt(xor_block, file_content_blocks_encrypted[i], &aes_key);
    }

    printf("CBC encrypted text: \n");
    for(int i = 0; i < no_of_blocks; i++){
        for(int j = 0; j < AES_BLOCK_SIZE; j++)
            printf("%X ", file_content_blocks_encrypted[i][j]);
        printf("\n");
    }
}

void decrypt_file_CBC(){
    AES_KEY aes_key;
    unsigned char xor_block[17] = {0};
    unsigned char dec_aux[17] = {0};
    unsigned char aux[1000][17];

    AES_set_decrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    AES_decrypt(file_content_blocks_encrypted[0], dec_aux, &aes_key);
    xor_cbc(dec_aux, IV, aux[0]);

    for(int i = 1; i < no_of_blocks; i++){
        AES_decrypt(file_content_blocks_encrypted[i], dec_aux, &aes_key);
        xor_cbc(dec_aux, file_content_blocks_encrypted[i-1], aux[i]);
    }

    printf("CBC decrypted text: \n");
    for(int i = 0; i < no_of_blocks; i++){
        printf("%s \n", aux[i]);
    }
}

void decrypt_file_ECB()
{
    AES_KEY aes_key;
    unsigned char enc[17] = {0};
    unsigned char aux[1000][17];

    AES_set_decrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    for (int i = 0; i < no_of_blocks; i++)
    {
        AES_decrypt(file_content_blocks_encrypted[i], aux[i], &aes_key);
        // strcpy((char*)file_content_blocks_encrypted[i], (char*)enc);
    }

    for (int i = 0; i < no_of_blocks; i++)
        printf("%s", aux[i]);
    fflush(stdout);
}

void communicate_with_B()
{
    if ((socket_B = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("eroare la accept");
        exit(EXIT_FAILURE);
    }
    printf("Incep comunicarea cu nodul B\n");

    // printf("Am trecut de acceptare\n");

    // read(new_socket, buffer, 100);
    // printf("Am primit de la client: %s\n", buffer);

    // printf("Am trimis mesajul\n");
    // send(new_socket, message, 100, 0);
}

void send_operation_mode(int mode)
{
    char m[4];
    sprintf(m, "%d", mode);

    if (mode == CBC || mode == ECB)
        operation_mode = mode;

    send(socket_B, m, sizeof m, 0);
    printf("Am trimis modul de operare catre B: %d\n", operation_mode);
}

void send_key_enc_to_B()
{
    send(socket_B, key_enc, sizeof key_enc, 0);
    printf("Am trimis cheia encriptata\n");
}

void wait_until_B_is_ready()
{
    char r_mess[100] = {0};

    read(socket_B, r_mess, sizeof r_mess);

    printf("Am primit mesajul de incepere a comunicarii de la B:%s\n", r_mess);
}

void send_file_content_enc()
{
    char no_blocks[4];
    char ok_msk[4];
    sprintf(no_blocks, "%d", no_of_blocks);
    send(socket_B, no_blocks, sizeof no_blocks, 0);

    printf("Am trimis numarul de blocuri pe care trebuie sa le primeasca B: %s\n", no_blocks);

    for (int i = 0; i < no_of_blocks; i++)
    {
        send(socket_B, file_content_blocks_encrypted[i], AES_BLOCK_SIZE, 0);
        read(socket_B, ok_msk, sizeof ok_msk);
    }

    printf("Am trimis continutul fisierului encriptat\n");
}

int main()
{
    cout<<"Alegeti un mod de operare: \n 1. ECB \n 2. CBC \n Modul de operare: ";
    cin>>operation_mode;

    read_content_on_blocks();
    // decrypt_file_ECB();
    // encrypt_file_CBC();
    // decrypt_file_CBC();

    server_config();

    communicate_with_B();

    send_operation_mode(operation_mode);
    // encrypt_file_ECB();

    get_key_from_KM();

    send_key_enc_to_B();

    wait_until_B_is_ready();

    // encrypt_file_ECB();
    if(operation_mode == ECB){
        encrypt_file_ECB();
        decrypt_file_ECB();
    }
    else
        encrypt_file_CBC();

    send_file_content_enc();

    // read_content_on_blocks();
    return 0;
}