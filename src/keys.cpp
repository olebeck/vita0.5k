#include "keys.hpp"
#include "_keys.h"
#include <stdexcept>
#include <cstring>

static const std::map<KeyType, std::map<SceType, std::map<SelfType, std::vector<Key>>>> keys = KEYS;

const Key* Keys::getKey(KeyType keyType, SceType sceType, SelfType selfType, U64 version, U8 key_rev) {
    auto possible = keys.at(keyType).at(sceType).at(selfType);
    for (const auto& key : possible) {
        if (version >= key.minver && version <= key.maxver && key_rev == key.keyrev) {
            return &key;
        }
    }
    throw std::runtime_error("No key found");
}

Botan::Keyed_Filter* Keys::getCipher(std::string algo, KeyType keyType, SceType sceType, SelfType selfType, U64 version, U8 key_rev) {
    const Key* key = getKey(keyType, sceType, selfType, version, key_rev);
    if (key == nullptr) {
        return nullptr;
    }
    Botan::SymmetricKey _key(key->key, 32);
    Botan::InitializationVector _iv(key->iv, 16);
    return Botan::get_cipher(algo, _key, _iv, Botan::Cipher_Dir::DECRYPTION);
}