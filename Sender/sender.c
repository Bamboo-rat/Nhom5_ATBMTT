#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

// Hàm mã hóa khóa AES bằng RSA public key sử dụng EVP API
unsigned char* encryptRSA(EVP_PKEY* pkey, const unsigned char* data, size_t data_len, size_t* encrypted_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed\n");
        return NULL;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_len, data, data_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt (size) failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char* encrypted = (unsigned char*)malloc(*encrypted_len);
    if (!encrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, encrypted, encrypted_len, data, data_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(encrypted);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

// Hàm mã hóa file bằng AES-CBC
unsigned char* encryptAES(const unsigned char* key, const unsigned char* iv, const char* inputFile, size_t* ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    FILE* in = fopen(inputFile, "rb");
    if (!in) {
        fprintf(stderr, "Cannot open input file\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Đọc kích thước file
    fseek(in, 0, SEEK_END);
    size_t file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    // Tạo buffer tạm thời cho ciphertext
    size_t max_ciphertext_len = file_size + AES_BLOCK_SIZE;
    unsigned char* ciphertext = (unsigned char*)malloc(max_ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(in);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int len, total_len = 0;
    size_t read_size;

    while ((read_size = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, out_buf, &len, in_buf, read_size);
        memcpy(ciphertext + total_len, out_buf, len);
        total_len += len;
    }

    EVP_EncryptFinal_ex(ctx, out_buf, &len);
    memcpy(ciphertext + total_len, out_buf, len);
    total_len += len;

    fclose(in);
    EVP_CIPHER_CTX_free(ctx);
    *ciphertext_len = total_len;
    return ciphertext;
}

// Hàm nhận public key qua socket
EVP_PKEY* receivePublicKey(SOCKET sock) {
    long key_len;
    recv(sock, (char*)&key_len, sizeof(long), 0);

    char* key_data = (char*)malloc(key_len);
    if (!key_data) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    recv(sock, key_data, key_len, 0);

    BIO* bio = BIO_new_mem_buf(key_data, key_len);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(key_data);
    return pkey;
}

int main() {
    // Khởi tạo OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Khởi tạo Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // Tạo socket
    SOCKET sender_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (sender_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    // Thiết lập địa chỉ server
    struct sockaddr_in receiver_addr;
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(PORT);
    receiver_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Kết nối đến server
    if (connect(sender_socket, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Connection failed\n");
        closesocket(sender_socket);
        WSACleanup();
        return 1;
    }

    // Nhận public key từ server
    EVP_PKEY* pkey = receivePublicKey(sender_socket);
    if (!pkey) {
        fprintf(stderr, "Failed to receive public key\n");
        closesocket(sender_socket);
        WSACleanup();
        return 1;
    }

    // Tạo khóa AES 
    unsigned char aes_key[32]; // AES-256
    RAND_bytes(aes_key, sizeof(aes_key));

    // Tạo IV 
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // Mã hóa khóa AES bằng RSA public key
    size_t encrypted_key_len;
    unsigned char* encrypted_key = encryptRSA(pkey, aes_key, sizeof(aes_key), &encrypted_key_len);
    if (!encrypted_key) {
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        WSACleanup();
        return 1;
    }

    // Gửi kích thước khóa AES đã mã hóa
    int encrypted_key_len_int = (int)encrypted_key_len;
    send(sender_socket, (char*)&encrypted_key_len_int, sizeof(int), 0);

    // Gửi khóa AES đã mã hóa
    send(sender_socket, (char*)encrypted_key, encrypted_key_len, 0);

    // Gửi IV
    send(sender_socket, (char*)iv, AES_BLOCK_SIZE, 0);

    // Mã hóa file
    const char* input_file = "input.txt";
    size_t ciphertext_len;
    unsigned char* ciphertext = encryptAES(aes_key, iv, input_file, &ciphertext_len);
    if (!ciphertext) {
        free(encrypted_key);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        WSACleanup();
        return 1;
    }

    // Gửi kích thước file đã mã hóa
    int file_size = (int)ciphertext_len;
    send(sender_socket, (char*)&file_size, sizeof(int), 0);

    // Gửi file đã mã hóa
    int total_sent = 0;
    while (total_sent < file_size) {
        int sent = send(sender_socket, (char*)(ciphertext + total_sent), file_size - total_sent, 0);
        if (sent <= 0) break;
        total_sent += sent;
    }

    printf("File sent successfully.\n");

    // Dọn dẹp
    free(ciphertext);
    free(encrypted_key);
    EVP_PKEY_free(pkey);
    closesocket(sender_socket);
    WSACleanup();
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}