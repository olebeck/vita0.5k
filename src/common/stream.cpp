#include "stream.hpp"
#include <stdexcept>
#include <cstring>
#include <botan/pipe.h>


void Buffer::Decrypt(Botan::Keyed_Filter* cipher) {
    Botan::Pipe pipe(cipher);
    pipe.start_msg();
    pipe.write(data(), size());
    pipe.end_msg();
    size_t _ = pipe.read(data(), size());
}

FileStream::FileStream(std::string filename, const char* mode)
{
    file = fopen(filename.c_str(), mode);
    if (!file)
        throw std::runtime_error("Failed to open file");
}

FileStream::~FileStream()
{
    fclose(file);
}

U64 FileStream::read(U64 size, void* buffer)
{
    return fread(buffer, 1, size, file);
}

U64 FileStream::write(U64 size, const void* buffer)
{
    return fwrite(buffer, 1, size, file);
}

void FileStream::seek(U64 offset, StreamSeek mode)
{
    fseek(file, offset, mode);
}

U64 FileStream::tell() const
{
    return ftell(file);
}


BufferStream::BufferStream(Buffer buffer) : buffer(buffer), offset(0), size(buffer.size()) { };

BufferStream::~BufferStream() { };

U64 BufferStream::read(U64 size, void* _buffer)
{
    if (offset + size > buffer.size())
        throw std::runtime_error("BufferStream::read: out of bounds");
    memcpy(_buffer, buffer.data() + offset, size);
    offset += size;
    return size;
}

U64 BufferStream::write(U64 size, const void* _buffer) {
    throw std::runtime_error("BufferStream::write: not implemented");
}

void BufferStream::seek(U64 offset, StreamSeek mode)
{
    switch (mode) {
    case StreamSeek::Set:
        this->offset = offset;
        break;
    case StreamSeek::Cur:
        this->offset += offset;
        break;
    case StreamSeek::End:
        this->offset = buffer.size() + offset;
        break;
    default:
        throw std::runtime_error("Unsupported mode");
    }
}

U64 BufferStream::tell() const
{
    return offset;
}

