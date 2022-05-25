#include <cassert>
#include <zlib.h>
#include <botan/aes.h>
#include <botan/pipe.h>
#include <botan/hash.h>
#include <stdexcept>

#include "sce_decrypt.hpp"
#include "keys.hpp"

Botan::Keyed_Filter* sce_get_key(Stream& s, SceHeader sce) {
    U64 sysver = 0xFF;
    SelfType self_type = static_cast<SelfType>(0xFF);

    if(sce.sce_type == SELF) {
        s.seek(sizeof(SceHeader), StreamSeek::Set);
        auto self = s.read_t<SelfHeader>();
        s.seek(self.appinfo_offset, StreamSeek::Set);
        auto appinfo = s.read_t<AppInfo>();
        sysver = appinfo.sys_version;
        self_type = appinfo.self_type;

    } else if(sce.sce_type == SRVK) {
        s.seek(sce.header_length, StreamSeek::Set);
        auto srvk = s.read_t<SrvkHeader>();
        sysver = srvk.sys_version;
        self_type = NONE;

    } else if(sce.sce_type == SPKG) {
        s.seek(sce.header_length, StreamSeek::Set);
        auto spkg = s.read_t<SpkgHeader>();
        sysver = spkg.update_version << 16;
        self_type = NONE;

    } else {
        throw std::runtime_error("Unknown SCE type");
    }
    assert(sysver != 0xFF);
    assert(self_type != 0xFF);

    return Keys::getCipher("AES-256/CBC/NoPadding", METADATA, sce.sce_type, self_type, sysver, sce.kev_rev);
}

Buffer zlib_decompress(Buffer b) {
    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    zs.avail_in = b.size();
    zs.next_in = b.data();
    zs.avail_out = b.size();
    zs.next_out = b.data();

    int ret = inflateInit(&zs);
    if (ret != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib");
    }

    ret = inflate(&zs, Z_FINISH);
    if (ret != Z_STREAM_END) {
        throw std::runtime_error("Failed to decompress");
    }

    inflateEnd(&zs);
    Buffer out(b.size() - zs.avail_out);
    memcpy(out.data(), b.data(), out.size());
    return out;
}



std::vector<SceSegment> getSegments(Stream& s, SceHeader sce, Botan::Keyed_Filter* info_cipher) {
    s.seek(sce.meta_off+48, StreamSeek::Set);
    Buffer metadata_info_buf = s.read_b(sizeof(MetadataInfo));
    metadata_info_buf.Decrypt(info_cipher);
    auto metadata_info = reinterpret_cast<MetadataInfo*>(metadata_info_buf.data());
    assert(metadata_info->pad0 == 0);
    assert(metadata_info->pad1 == 0);
    assert(metadata_info->pad2 == 0);
    assert(metadata_info->pad3 == 0);

    Botan::SymmetricKey meta_key(metadata_info->key, 16);
    Botan::InitializationVector meta_iv(metadata_info->iv, 16);
    auto header_cipher = Botan::get_cipher("AES-128/CBC/NoPadding", meta_key, meta_iv, Botan::DECRYPTION);

    auto metadata_header_buf = s.read_b(sce.header_length - sce.meta_off - 48 - sizeof(MetadataInfo));
    metadata_header_buf.Decrypt(header_cipher);
    auto metadata_header = reinterpret_cast<MetadataHeader*>(metadata_header_buf.data());
    BufferStream metadata_stream(metadata_header_buf);
    metadata_stream.seek(sizeof(MetadataHeader), StreamSeek::Set);


    std::vector<MetadataSection> sections;
    for (size_t i = 0; i < metadata_header->section_count; i++) {
        sections.push_back(metadata_stream.read_t<MetadataSection>());
    }

    std::vector<std::vector<U8>> vault;
    for (size_t i = 0; i < metadata_header->key_count; i++) {
        U8 key[16];
        metadata_stream.read(16, key);
        vault.push_back(std::vector<U8>(key, key+16));
    }

    std::vector<SceSegment> segments;
    for(auto section : sections) {
        if(section.encryption != AES128CTR) continue;
        auto key = vault[section.key_idx];
        auto iv = vault[section.iv_idx];

        SceSegment seg(s, section.offset, section.seg_idx, section.size, section.compression == DEFLATE, key.data(), iv.data());
        segments.push_back(seg);
    }
    return segments;
}


std::vector<SceSegment> SceDecrypt(Stream& s) {
    auto sce = s.read_t<SceHeader>();
    assert(sce.magic == 0x454353);
    assert(sce.version == 3);

    auto hdr_cipher = sce_get_key(s, sce);
    return getSegments(s, sce, hdr_cipher);
}
