
#pragma once

#include <map>
#include <vector>
#include <stdint.h>
#include <ctype.h>
#include <botan/key_filt.h>

#include <common/stream.hpp>

struct Key {
    U64 minver;
    U64 maxver;
    U32 keyrev;
    U8 key[32];
    U8 iv[16];
};

/*
#define HEX(str) \
    ([]() { \
        static U8 o[(sizeof(str)-1) / 2]; \
        for(int i = 0; i < sizeof(str)-1; i += 2) \
            o[i] = (toupper(str[i]) - '0' + (toupper(str[i + 1]) - '0') * 16); \
        return o; \
    }())
*/

class Keys {
public:
    static const Key* getKey(KeyType keyType, SceType sceType, SelfType selfType, U64 version, U8 key_rev);
    static Botan::Keyed_Filter* getCipher(std::string algo, KeyType keyType, SceType sceType, SelfType selfType, U64 version, U8 key_rev);
};

