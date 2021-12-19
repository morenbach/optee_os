#include "tracer.h"
#include "sign.h"

#define SHA256_DIGEST_LENGTH 32

status_t sign_trace(unsigned char* msg, unsigned int msg_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* msg_hash) {
    mbedtls_sha256_context ctx;   
    // mbedtls_ecp_keypair keypair;
    mbedtls_ecdsa_context ctx_sign;
    // unsigned char msg_hash[SHA256_DIGEST_LENGTH] = {0};
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;

    // Compute hash for the message and extend it with the nonce
    //
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); /* SHA-256, not 224 */
    mbedtls_sha256_update(&ctx, msg, msg_len);
    mbedtls_sha256_update(&ctx, nonce, nonce_len);
    mbedtls_sha256_finish(&ctx, msg_hash);

    // sign the extended hash
    //
    mbedtls_ecdsa_init( &ctx_sign );
    // mbedtls_ecp_curve_list()->grp_id;
    // mbedtls_ecp_point_read_binary()
    // mbedtls_ecdsa_from_keypair(&ctx_sign, &keypair)
    

    if ((0 != mbedtls_ecdsa_write_signature( &ctx_sign, MBEDTLS_MD_SHA256, msg_hash, sizeof(msg_hash), sig, sizeof(sig), &sig_len, NULL, NULL))) {
        mbedtls_ecdsa_free( &ctx_sign );
        return TRACER_F;                                        
    }

    mbedtls_ecdsa_free( &ctx_sign );

    return TRACER_S;
}