#include "common/types.h"
#include "core/memory.h"
#include "core/device.h"

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>



#define ADDR_ARM_BOOT 0x00000000
#define SIZE_ARM_BOOT 0x8000

#define ADDR_SECURE_DRAM 0x40000000
#define SIZE_SECURE_DRAM (ADDR_SHARED_RAM - ADDR_SECURE_DRAM)

#define ADDR_SHARED_RAM 0x40200000
#define SIZE_SHARED_RAM 0x7FE00000

#define ADDR_KBL_PARAM 0x40073570
#define SIZE_KBL_PARAM sizeof(KBLparam)


#define ADDR_KPRX_AUTH_SM (ADDR_SECURE_DRAM + 0x500)
#define ADDR_PROG_RVK (ADDR_SECURE_DRAM + 0x9B00)


class Emulator
{
private:
    uc_engine* uc;
    Memory* memory;
    /* data */
public:
    csh cs;
    
    Emulator(/* args */);
    ~Emulator();

    inline void Map(Device* device, U32 address, U32 size) { memory->Add(device, address, size); }
    inline void Map(Buffer buffer, U32 address, U32 size) { memory->Add(buffer, address, size); }
    inline void Map(Buffer buffer, U32 address) { memory->Add(buffer, address, buffer.size()); }
    inline void Map(U32 address, U32 size, void* buffer) {
        Buffer b(size);
        memcpy(b.data(), buffer, size);
        memory->Add(b, address, size);
    }

    void Start();
};
