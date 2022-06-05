/**
 * BLS format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <common/types.h>
#include <common/stream.h>

#include <string>
#include <string_view>
#include <vector>
#include <mutex>

// Forward declarations
class BlsParser;

struct BlsEntry {
    U32 block_offset;
    U32 file_size;
    U32 padding[2];
    char file_name[32];
};

struct BlsHeader {
    U32 magic;
    U32 version;
    U32 flags;
    U32 num_files;
    U32 num_blocks;
    U32 padding[3];
};

class BlsStream : public Stream {
    BlsParser* bls;
    const U64 base;
    U32 offset;

public:
    BlsStream(BlsParser* bls, U32 base, U32 size)
        : bls(bls), base(base), size(size), offset(0) {}

    virtual U64 read(U64 size, void* buffer) override;
    virtual U64 write(U64 size, const void* buffer) override;
    virtual void seek(U64 offset, StreamSeek mode) override;
    virtual U64 tell() const override;

    const U32 size;
};

class BlsParser {
    friend BlsStream;
    Stream& s;
    BlsHeader header;
    std::mutex mtx;

public:
    BlsParser(Stream& s);
    ~BlsParser();

    /**
     * Return list of file names corresponding to the BLS entries.
     * @return  Vector of strings of the file names
     */
    std::vector<std::string> files();

    /**
     * Get BLS stream by file name
     */
    BlsStream get(std::string_view name);

    /**
     * Get BLS stream by index
     */
    BlsStream get(U32 index);
};
