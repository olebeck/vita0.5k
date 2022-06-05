#pragma once
#include "common/types.h"
#include "core/device.h"
#include "common/stream.h"

#include <vector>
#include <unicorn/unicorn.h>

enum BankType {
    BANK_TYPE_DEVICE,
    BANK_TYPE_BUFFER
};

struct Bank {
    BankType type;
    union {
        Device* device;
        Buffer* buffer;
    };
    U32 address;
    U32 size;
};

class Memory {
private:
    uc_engine* uc;
    std::vector<Bank> banks;
public:
    Memory(uc_engine* uc);
    ~Memory() {};

    void Add(Device* device, U32 address, U32 size);
    void Add(Buffer buffer, U32 address, U32 size);
};
