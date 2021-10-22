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

using namespace std;

#define PORT 8183
#define AES_BLOCK_SIZE 16

unsigned char key[17] = {0};
unsigned char key_enc[17] = {0};
unsigned char key_prim[17] = "anaaremultemeree";

int server_fd;
int node_wich_need_key_socket;
struct sockaddr_in address_of_server;
int addlen = sizeof address_of_server;
int option = 1;

void config_server(){
    address_of_server.sin_family = AF_INET;
    address_of_server.sin_addr.s_addr = INADDR_ANY;
    address_of_server.sin_port = htons(PORT);

    if( (server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0 ){
        perror("Eroare la crearea socket-ului");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option))){
        perror("Eroare la socket options");
        exit(EXIT_FAILURE);
    }

    if((bind(server_fd, (struct sockaddr*)&address_of_server, sizeof(address_of_server))) < 0){
        perror("Nu am putut face bind");
        exit(EXIT_FAILURE);
    }

    if(listen(server_fd, 3) <0){
        perror("Eroare la ascultare");
        exit(EXIT_FAILURE);
    }
}

void communicate_with_client(){
    int client_socket;

    char buffer[AES_BLOCK_SIZE];

    if((client_socket = accept(server_fd, (struct sockaddr *)&address_of_server, (socklen_t*)&addlen)) < 0){
        perror("eroare la accept");
        exit(EXIT_FAILURE);
    }

    printf("Am venit un client\n");
    // fflush(stdout);

    read(client_socket, buffer, AES_BLOCK_SIZE);
    printf("Am primit de la client: %s\n", buffer);

    write(client_socket, key_enc, AES_BLOCK_SIZE);
    printf("Am trimis cheia encryptata: %s\n", key_enc);

    close(client_socket);
}

void encrypt_key(){
    RAND_bytes(key, AES_BLOCK_SIZE);
    // strcpy((char *)key, "ajxasatzomqsaxta");

    AES_KEY enc_key;
    AES_set_encrypt_key(key_prim, AES_BLOCK_SIZE * 8, &enc_key);
    AES_encrypt(key, key_enc, &enc_key);

    printf("Am encryptat cheia: %s\n", key);
    fflush(stdout);


    // printf("%s |\n", key);
    // for(int i = 0; key_enc[i] != '\0'; i++){
    //     printf("%X ", key_enc[i]);
    // }
    // printf("|\n");
}

int main(){
    // for(int i = 0; i < strlen((const char *)key_prim); i++)
    //     printf("%c ", key_prim[i]);
    // printf("|\n");

    config_server();
    encrypt_key();
    communicate_with_client();

    // for(int i = 0; i < 20; i++){
    //     printf("%c ", key_prim[i]);
    // }
    // printf("|\n");

    // printf("%d \n", (int)strlen((const char*)key_prim));
    // printf("%l \n", sizeof key_prim);



    close(server_fd);
    return 0;
}