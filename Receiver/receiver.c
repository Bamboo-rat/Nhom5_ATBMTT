#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

// Hàm gửi public key qua socket
int sendPublicKey(SOCKET client_socket, EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "BIO_new failed\n");
        return 0;
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        fprintf(stderr, "PEM_write_bio_PUBKEY failed\n");
        BIO_free(bio);
        return 0;
    }

    char* key_data;
    long key_len = BIO_get_mem_data(bio, &key_data);

    send(client_socket, (char*)&key_len, sizeof(long), 0);
    send(client_socket, key_data, key_len, 0);

    BIO_free(bio);
    return 1;
}

// Hàm giải mã khóa AES bằng RSA private key sử dụng EVP API
unsigned char* decryptRSA(EVP_PKEY* pkey, const unsigned char* encrypted, size_t encrypted_len, size_t* decrypted_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed\n");
        return NULL;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, decrypted_len, encrypted, encrypted_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt (size) failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char* decrypted = (unsigned char*)malloc(*decrypted_len);
    if (!decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_decrypt(ctx, decrypted, decrypted_len, encrypted, encrypted_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(decrypted);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

// Hàm giải mã file bằng AES-CBC
void decryptAES(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, size_t ciphertext_len, const char* outputFile) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    FILE* out = fopen(outputFile, "wb");
    if (!out) {
        fprintf(stderr, "Cannot open output file\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    unsigned char out_buf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int len;
    size_t offset = 0;

    while (offset < ciphertext_len) {
        int chunk = BUFFER_SIZE;
        if (ciphertext_len - offset < BUFFER_SIZE) {
            chunk = ciphertext_len - offset;
        }
        if (EVP_DecryptUpdate(ctx, out_buf, &len, ciphertext + offset, chunk) != 1) {
            fprintf(stderr, "EVP_DecryptUpdate failed\n");
            fclose(out);
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        fwrite(out_buf, 1, len, out);
        offset += chunk;
    }

    if (EVP_DecryptFinal_ex(ctx, out_buf, &len) != 1) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    fwrite(out_buf, 1, len, out);

    fclose(out);
    EVP_CIPHER_CTX_free(ctx);
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
    SOCKET receiver_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (receiver_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    // Thiết lập địa chỉ server
    struct sockaddr_in receiver_addr;
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = INADDR_ANY;
    receiver_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(receiver_socket, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed\n");
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Lắng nghe kết nối
    if (listen(receiver_socket, 1) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed\n");
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    printf("Waiting for sender...\n");

    // Chấp nhận kết nối từ client
    SOCKET sender_socket = accept(receiver_socket, NULL, NULL);
    if (sender_socket == INVALID_SOCKET) {
        fprintf(stderr, "Accept failed\n");
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Tạo cặp khóa RSA
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id failed\n");
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    // Gửi public key cho client
    if (!sendPublicKey(sender_socket, pkey)) {
        fprintf(stderr, "Failed to send public key\n");
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Nhận kích thước khóa AES đã mã hóa
    int encrypted_key_len;
    if (recv(sender_socket, (char*)&encrypted_key_len, sizeof(int), 0) <= 0) {
        fprintf(stderr, "Failed to receive encrypted key length\n");
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Nhận khóa AES đã mã hóa
    unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    if (!encrypted_key) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }
    if (recv(sender_socket, (char*)encrypted_key, encrypted_key_len, 0) <= 0) {
        fprintf(stderr, "Failed to receive encrypted key\n");
        free(encrypted_key);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Giải mã khóa AES
    size_t aes_key_len;
    unsigned char* aes_key = decryptRSA(pkey, encrypted_key, encrypted_key_len, &aes_key_len);
    if (!aes_key) {
        fprintf(stderr, "Failed to decrypt AES key\n");
        free(encrypted_key);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }
    if (aes_key_len != 32) { // AES-256 yêu cầu khóa 32 byte
        fprintf(stderr, "Invalid AES key length: %zu\n", aes_key_len);
        free(aes_key);
        free(encrypted_key);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Nhận IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (recv(sender_socket, (char*)iv, AES_BLOCK_SIZE, 0) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Failed to receive IV\n");
        free(aes_key);
        free(encrypted_key);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Nhận kích thước file đã mã hóa
    int file_size;
    if (recv(sender_socket, (char*)&file_size, sizeof(int), 0) <= 0) {
        fprintf(stderr, "Failed to receive file size\n");
        free(aes_key);
        free(encrypted_key);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }

    // Nhận file đã mã hóa
    unsigned char* ciphertext = (unsigned char*)malloc(file_size);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        free(aes_key);
        free(encrypted_key);
        EVP_PKEY_free(pkey);
        closesocket(sender_socket);
        closesocket(receiver_socket);
        WSACleanup();
        return 1;
    }
    int received = 0;
    while (received < file_size) {
        int r = recv(sender_socket, (char*)(ciphertext + received), file_size - received, 0);
        if (r <= 0) {
            fprintf(stderr, "Failed to receive ciphertext\n");
            free(ciphertext);
            free(aes_key);
            free(encrypted_key);
            EVP_PKEY_free(pkey);
            closesocket(sender_socket);
            closesocket(receiver_socket);
            WSACleanup();
            return 1;
        }
        received += r;
    }

    // Giải mã file
    decryptAES(aes_key, iv, ciphertext, file_size, "received_file.txt");

    printf("File received and decrypted.\n");

    // Dọn dẹp
    free(ciphertext);
    free(aes_key);
    free(encrypted_key);
    EVP_PKEY_free(pkey);
    closesocket(sender_socket);
    closesocket(receiver_socket);
    WSACleanup();
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}