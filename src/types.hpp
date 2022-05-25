#pragma once

#include <stdint.h>

typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;

typedef int8_t S8;
typedef int16_t S16;
typedef int32_t S32;
typedef int64_t S64;


typedef enum KeyType {
    METADATA = 0,
    NPDRM = 1,
} KeyType;

typedef enum SceType {
    SELF = 1,
    SRVK = 2,
    SPKG = 3,
    DEV = 0xC0,
} SceType;

typedef enum SelfType {
    NONE = 0,
    KERNEL = 0x07,
    APP = 0x08,
    BOOT = 0x09,
    SECURE = 0x0B,
    USER = 0x0D,
} SelfType;

typedef enum EncryptionType {
    ENC_NONE = 1,
    AES128CTR = 3,
} EncryptionType;

typedef enum CompressionType {
    COMPRESS_NONE = 1,
    DEFLATE = 2,
} CompressionType;

typedef struct SrvkHeader {
    U32 field_0;
    U32 field_4;
    U32 sys_version;
    U32 field_C;
    U32 field_10;
    U32 field_14;
    U32 field_18;
    U32 field_1C;
} SrvkHeader;

typedef struct SpkgHeader {
    U32 field_0;
    U32 pkg_type;
    U32 flags;
    U32 field_C;
    U64 update_version;
    U64 final_size;
    U64 decrypted_size;
    U64 field_28;
    U32 field_30;
    U32 field_34;
    U32 field_38;
    U32 field_3C;
    U64 field_40;
    U64 field_48;
    U64 offset;
    U64 size;
    U64 part_idx;
    U64 total_parts;
    U64 field_70;
    U64 field_78;
} SpkgHeader;

typedef struct MetadataInfo {
    U8 key[0x10];
    U64 pad0, pad1;
    U8 iv[0x10];
    U64 pad2, pad3;
} MetadataInfo;

typedef struct MetadataHeader {
    U64 signature_input_length;
    U32 signature_type;
    U32 section_count;
    U32 key_count;
    U32 opt_header_size;
    U32 field_18;
    U32 field_1C;
} MetadataHeader;

typedef struct MetadataSection {
    U64 offset;
    U64 size;
    U32 type;
    S32 seg_idx;
    U32 hashtype;
    S32 hash_idx;
    EncryptionType encryption : 32;
    S32 key_idx;
    S32 iv_idx;
    U32 compression;
} MetadataSection;

typedef struct {
    U32 magic;
    U32 version;
    U8  platform;
    U8  kev_rev;
    SceType sce_type : 16;
    U32 meta_off;
    U64 header_length;
    U64 data_length;
} SceHeader;

typedef struct SelfHeader {
    U64 file_length;
    U64 field_8;
    U64 self_offset;
    U64 appinfo_offset;
    U64 elf_offset;
    U64 phdr_offset;
    U64 shdr_offset;
    U64 segment_info_offset;
    U64 sceversion_offset;
    U64 controlinfo_offset;
    U64 controlinfo_length;
} SelfHeader;

typedef struct {
    U64 auth_id;
    U32 vendor_id;
    SelfType self_type : 32;
    U64 sys_version;
    U64 field_18;
} AppInfo;
