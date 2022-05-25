#include <string>
#include "stream.hpp"
#include "pup.hpp"
#include "bls.hpp"
#include "keys.hpp"
#include "sce_decrypt.hpp"

#include <unicorn/unicorn.h>

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
           address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    printf(">>> Tracing instruction at 0x%" PRIx64
           ", instruction size = 0x%x\n",
           address, size);
    uint32_t insn;
    uc_mem_read(uc, address, &insn, sizeof(insn));
    printf(">>> Instruction is 0x%x\n", insn);
}

static void hook_mem_fetch(uc_engine *uc, uc_mem_type type,
                           uint64_t address, int size, int64_t value,
                           void *user_data)
{
    printf(">>> Memory fetch at 0x%" PRIx64 ", size = %u, value = 0x%" PRIx64 "\n",
           address, size, value);
}

static void hook_insn_invalid(uc_engine *uc, uint32_t insn, void *user_data)
{
    uint32_t* pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf(">>> Invalid instruction at 0x%" PRIx32 ", insn = 0x%x\n",
           pc, insn);
}

#define UCD(x) \
    do { \
        uc_err err = x; \
        if (err != UC_ERR_OK) { \
            printf(#x " failed with error returned: %u (%s)\n", \
                   err, uc_strerror(err)); \
            return 1; \
        } \
    } while (0)

#define align(x,y) (((x) + (y) - 1) & ~((y) - 1))
#define align_lower(x,y) ((x) & ~((y) - 1))


int main(int argc, char** argv) {
    uc_engine* uc;
    UCD(uc_open(UC_ARCH_ARM, UC_MODE_ARM946, &uc));

    /*
    std::string filename = "";
    for (int i = 0; i < argc; i++) {
        if (std::string(argv[i]) == "-f") {
            filename = argv[i + 1];
        }
    }
    if (filename == "") {
        printf("Usage: %s -f <filename>\n", argv[0]);
        return 1;
    }
    */
    FileStream fs("../PSP2UPDAT.PUP", "rb");
    PupParser pup(fs);
    auto boot_pkg_segs = pup.get("boot_slb2-0.pkg");
    BufferStream boot_pkg(boot_pkg_segs.at(0));
    BlsParser bls(boot_pkg);

    // basic map:
    // kprx auth  = 0x40000500
    // prog_rvk   = 0x40009B00
    // skbl param = 0x4001FD00 (without magic)
    // skbl seg 0 = 0x40020000
    // skbl seg 1 = 0x40057100
    // skbl param = 0x40073570 (with magic)
    // nsbl       = 0x50000000 (arzl compressed)

    #define UC_MEM_ADD(uc, addr, buf) do { \
        UCD(uc_mem_write(uc, addr, buf.data(), buf.size())); \
    } while (0);

    UCD(uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL));
    UCD(uc_mem_map(uc, 0x40000000, 0x100000, UC_PROT_ALL));
    UCD(uc_mem_map(uc, 0x50000000, 0x100000, UC_PROT_ALL));

    BlsStream kprx_auth = bls.get("kprx_auth_sm.self"); 
    Buffer kprx_auth_buf(kprx_auth.size);
    kprx_auth.read(kprx_auth.size, kprx_auth_buf.data());
    UC_MEM_ADD(uc, 0x40000500, kprx_auth_buf);

    BlsStream prog_rvk = bls.get("prog_rvk.srvk");
    Buffer prog_rvk_buf(prog_rvk.size);
    kprx_auth.read(prog_rvk.size, prog_rvk_buf.data());
    UC_MEM_ADD(uc, 0x40009B00, prog_rvk_buf);


    BlsStream skbl = bls.get("kernel_boot_loader.self");
    auto skbl_segs = SceDecrypt(skbl);

    // load reset vector
    const auto skbl_reset_vector = skbl_segs.at(0);
    UC_MEM_ADD(uc, 0x00000000, skbl_reset_vector);

    // load segment 0
    const auto skbl_seg0 = skbl_segs.at(1);
    UC_MEM_ADD(uc, 0x40020000, skbl_seg0);

    // load segment 1
    const auto skbl_seg1 = skbl_segs.at(2);
    UC_MEM_ADD(uc, 0x40057100, skbl_seg1);

    // load nsbl
    const auto nsbl = skbl_segs.at(3);
    UC_MEM_ADD(uc, 0x50000000, nsbl);


    uc_hook trace1, trace2, trace3, trace4;
    UCD(uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void*)hook_block, NULL, 1, 0));
    UCD(uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void*)hook_code, NULL, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace3, UC_HOOK_MEM_FETCH_UNMAPPED, (void*)hook_mem_fetch, NULL, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace4, UC_HOOK_INSN_INVALID, (void*)hook_insn_invalid, NULL, 0, 0xFFFFFFFF));

    UCD(uc_emu_start(uc, 0x00000000, 0xFFFFFFFF, 0, 100));
}