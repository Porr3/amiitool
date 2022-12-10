#ifndef AMIITOOL_LIB_H
#define AMIITOOL_LIB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif 

int encrypt(const char* pKeyFile, const uint8_t* pOriginal, uint8_t* pModified, const size_t orgSize, const size_t modSize);
int decrypt(const char* pKeyFile, const uint8_t* pOriginal, uint8_t* pModified, const size_t orgSize, const size_t modSize);

#ifdef __cplusplus
}
#endif

#endif /* AMIITOOL_LIB_H */