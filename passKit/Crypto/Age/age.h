#ifndef age_h
#define age_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Allocates memory using `malloc`.
void *age_malloc(size_t size);

// Frees memory using `free`.
void age_free(void *ptr);

// Returns a pointer to a static string containing the last error message.
const char *age_err();

// Clears the last error message.
void age_clear_err();

// Generates a new X25519 key pair.
// The public key is 32 bytes and the private key is 32 bytes.
// Returns 0 on success, -1 on error.
int age_generate_x25519_key_pair(uint8_t *public_key, uint8_t *private_key);

// Encrypts a plaintext with a given recipient public key.
// The encrypted data is written to `ciphertext_out` and its length to `ciphertext_out_len`.
// `ciphertext_out` must be pre-allocated to at least `plaintext_len + AGE_X25519_OVERHEAD` bytes.
// Returns 0 on success, -1 on error.
int age_encrypt_x25519(const uint8_t *plaintext, size_t plaintext_len,
                       const uint8_t *recipient_public_key,
                       uint8_t *ciphertext_out, size_t *ciphertext_out_len);

// Decrypts a ciphertext with a given recipient private key.
// The decrypted data is written to `plaintext_out` and its length to `plaintext_out_len`.
// `plaintext_out` must be pre-allocated to at least `ciphertext_len - AGE_X25519_OVERHEAD` bytes.
// Returns 0 on success, -1 on error.
int age_decrypt_x25519(const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *recipient_private_key,
                       uint8_t *plaintext_out, size_t *plaintext_out_len);

// Overhead for X25519 encryption.
// This is the maximum additional bytes required for the ciphertext compared to the plaintext.
#define AGE_X25519_OVERHEAD 73

// Generates a new Scrypt key.
// `password` is the input password, `salt` is a random 16-byte salt, `key_out` is the 32-byte derived key.
// Returns 0 on success, -1 on error.
int age_generate_scrypt_key(const char *password, size_t password_len,
                            const uint8_t *salt, uint8_t *key_out);

// Encrypts a plaintext with a given Scrypt key.
// The encrypted data is written to `ciphertext_out` and its length to `ciphertext_out_len`.
// `ciphertext_out` must be pre-allocated to at least `plaintext_len + AGE_SCRYPT_OVERHEAD` bytes.
// Returns 0 on success, -1 on error.
int age_encrypt_scrypt(const uint8_t *plaintext, size_t plaintext_len,
                       const uint8_t *scrypt_key,
                       uint8_t *ciphertext_out, size_t *ciphertext_out_len);

// Decrypts a ciphertext with a given Scrypt key.
// The decrypted data is written to `plaintext_out` and its length to `plaintext_out_len`.
// `plaintext_out` must be pre-allocated to at least `ciphertext_len - AGE_SCRYPT_OVERHEAD` bytes.
// Returns 0 on success, -1 on error.
int age_decrypt_scrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *scrypt_key,
                       uint8_t *plaintext_out, size_t *plaintext_out_len);

// Overhead for Scrypt encryption.
// This is the maximum additional bytes required for the ciphertext compared to the plaintext.
#define AGE_SCRYPT_OVERHEAD 73

#ifdef __cplusplus
}
#endif

#endif /* age_h */
