#pragma once

#include <common/types.h>
#include <common/stream.h>
#include <botan/aes.h>

Buffer zlib_decompress(Buffer b);

class SceSegment : public Buffer {
public:
    SceSegment(Stream& s, U64 offset, S32 idx, U64 size, bool compressed, U8 _key[0x10], U8 _iv[0x10]) : Buffer(size) {
        s.seek(offset, StreamSeek::Set);
        s.read(size, data());

        Botan::SymmetricKey key(_key, 16);
        Botan::InitializationVector iv(_iv, 16);
        Botan::Keyed_Filter* cipher = Botan::get_cipher("AES-128/CTR-BE", key, iv, Botan::DECRYPTION);
        Decrypt(cipher);
        if(compressed) {
            auto decompressed = zlib_decompress(*this);
            resize(decompressed.size());
            memcpy(data(), decompressed.data(), decompressed.size());
        }
    };
};


std::vector<SceSegment> SceDecrypt(Stream& s);

