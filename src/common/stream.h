#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include "types.h"
#include <botan/key_filt.h>

class Stream;

class Buffer : public std::vector<uint8_t> {
public:
    Buffer(size_t size) : std::vector<uint8_t>(size) {}
    Buffer(Stream& s);
    void Decrypt(Botan::Keyed_Filter* cipher);
};

enum StreamSeek {
    Set,
    Cur,
    End,
};

class Stream {
public:
    virtual ~Stream() { }
    virtual uint64_t read(uint64_t size, void* buffer) = 0;
    virtual uint64_t write(uint64_t size, const void* buffer) = 0;
    virtual void seek(uint64_t offset, StreamSeek mode) = 0;
    virtual uint64_t tell() const = 0;
    uint64_t size() {
        uint64_t pos = tell();
        seek(0, StreamSeek::End);
        uint64_t size = tell();
        seek(pos, StreamSeek::Set);
        return size;
    }

    template<typename T> T read_t() {
        T v;
        read(sizeof(T), &v);
        return v;
    }

    Buffer read_b(size_t size) {
        Buffer buffer(size);
        read(size, buffer.data());
        return buffer;
    }
};


class FileStream : public Stream {
    FILE* file;
public:
    FileStream(const std::string filename, const char* mode);
    virtual ~FileStream();
    virtual uint64_t read(uint64_t size, void* buffer) override;
    virtual uint64_t write(uint64_t size, const void* buffer) override;
    virtual void seek(uint64_t offset, StreamSeek mode) override;
    virtual uint64_t tell() const override;
};


class BufferStream : public Stream {
    Buffer buffer;
    uint64_t offset;
public:
    BufferStream(Buffer buffer);
    virtual ~BufferStream();
    virtual uint64_t read(uint64_t size, void* buffer) override;
    virtual uint64_t write(uint64_t size, const void* buffer) override;
    virtual void seek(uint64_t offset, StreamSeek mode) override;
    virtual uint64_t tell() const override;
    uint64_t size() {
        return buffer.size();
    }
};