#ifndef __PTA_TRACER_SIGN_H
#define __PTA_TRACER_SIGN_H

status_t sign_trace(unsigned char* msg, unsigned int msg_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* msg_hash);

#endif