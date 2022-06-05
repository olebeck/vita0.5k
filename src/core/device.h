#pragma once

#include "common/types.h"

class Device {
public:
    Device(U32 address, U32 size) : address(address), size(size) {}
    virtual ~Device() {}

    virtual void Read(U32 address, U32 size, void* buffer) = 0;
    virtual void Write(U32 address, U32 size, const void* buffer) = 0;

    U32 Read(U32 address) {
        U32 buffer;
        Read(address, sizeof(U32), &buffer);
        return buffer;
    }

    U32 address;
    U32 size;
};
