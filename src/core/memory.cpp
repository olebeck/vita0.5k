#include "memory.h"
#include "common/util.h"

Memory::Memory(uc_engine* uc) : uc(uc) {
}


void Memory::Add(Device* device, U32 address, U32 size) {
    Bank bank;
    bank.type = BANK_TYPE_DEVICE;
    bank.device = device;
    bank.address = address;
    bank.size = size;
    banks.push_back(bank);
}

void Memory::Add(Buffer buffer, U32 address, U32 size) {
    Bank bank;
    bank.type = BANK_TYPE_BUFFER;
    bank.buffer = &buffer;
    bank.address = address;
    bank.size = size;
    banks.push_back(bank);

    UCD(uc_mem_write(uc, address, buffer.data(), size));
}
