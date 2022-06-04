#include <string>
#include "common/stream.hpp"
#include "software/pup.hpp"
#include "software/bls.hpp"
#include "software/keys.hpp"
#include "software/sce_decrypt.hpp"

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    printf(">>> Tracing basic block at 0x%" PRIx32 ", block size = 0x%x\n",
           address, size);
}

void uc_reg_dump(uc_engine *uc) {
    #define DUMP_REG(name) do { \
        uint64_t val; \
        uc_reg_read(uc, UC_ARM_REG_##name, &val); \
        printf(#name " = 0x%08x " , val); \
    } while (0)

    DUMP_REG(PC);
    DUMP_REG(R0);
    DUMP_REG(R1);
    DUMP_REG(R2);
    DUMP_REG(R3);
    DUMP_REG(R4);
    printf("\n");
    //usleep(100000);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    csh cs = (csh)user_data;
    uint8_t insn[size];
    uc_mem_read(uc, address, &insn, size);
    cs_insn* insn_info;
    int ret = cs_disasm(cs, insn, size, address, 1, &insn_info);
    if(ret > 0) {
        char buf[256];
        size_t len = sprintf(buf, ">>> %s %s", insn_info->mnemonic, insn_info->op_str);
        const int max_len = 34;
        int pad = max_len - len;
        sprintf(buf + len, "%*s", pad, " ");
        printf("%s ", buf);
        uc_reg_dump(uc);

        if(insn_info->id == ARM_INS_B) {
            bool is_jump = false;

            U32 cpsr;
            uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);

            if(insn_info->detail->arm.cc == ARM_CC_AL) {
                is_jump = true;
            } else if(insn_info->detail->arm.cc == ARM_CC_EQ) {
                is_jump = (cpsr & 0x40000000) != 0;
            } else if(insn_info->detail->arm.cc == ARM_CC_NE) {
                is_jump = (cpsr & 0x40000000) == 0;
            }

            U32 addr = insn_info->detail->arm.operands[0].imm;
            if(is_jump) {
                printf("\n// Jump to 0x%08x\n", addr);
            } else {
                printf("// Not jumping\n");
            }
        }
        cs_free(insn_info, 1);
    } else {
        printf(">>> Failed to disassemble instruction! %08x\n", insn);
    }
}

static void hook_mem_fetch(uc_engine *uc, uc_mem_type type,
                           uint64_t address, int size, int64_t value,
                           void *user_data)
{
    printf(">>> Memory fetch at 0x%" PRIx64 ", size = %u, value = 0x%" PRIx64 "\n",
           address, size, value);
}

static void hook_write_invalid(uc_engine *uc, uc_mem_type type,
                               uint64_t address, int size, int64_t value,
                               void *user_data)
{
    printf(">>> Write invalid at 0x%" PRIx64 ", size = %u, value = 0x%" PRIx64 "\n",
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

#define ADDR_ARM_BOOT 0x00000000
#define SIZE_ARM_BOOT 0x8000
#define ADDR_SECURE_DRAM 0x40000000
#define SIZE_SECURE_DRAM (ADDR_SHARED_RAM - ADDR_SECURE_DRAM)
#define ADDR_SHARED_RAM 0x40200000
#define SIZE_SHARED_RAM 0x7FE00000


int main(int argc, char** argv) {
    uc_engine* uc;
    UCD(uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc));

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
    // skbl reset vector = 0x0
    // kprx auth  = 0x40000500
    // prog_rvk   = 0x40009B00
    // skbl param = 0x4001FD00 (without magic)
    // skbl seg 0 = 0x40020000
    // skbl seg 1 = 0x40057100
    // skbl param = 0x40073570 (with magic)
    // nsbl       = 0x50000000 (arzl compressed)

    #define UC_MEM_ADD(uc, addr, buf) UCD(uc_mem_write(uc, addr, buf.data(), buf.size()));

    UCD(uc_mem_map(uc, ADDR_ARM_BOOT, SIZE_ARM_BOOT, UC_PROT_ALL));
    UCD(uc_mem_map(uc, ADDR_SECURE_DRAM, SIZE_SECURE_DRAM, UC_PROT_ALL));
    UCD(uc_mem_map(uc, ADDR_SHARED_RAM, SIZE_SHARED_RAM, UC_PROT_ALL)); // memory

    UCD(uc_mem_map(uc, 0x1A000000, 0x2000, UC_PROT_ALL)); // interrupt controller
    UCD(uc_mem_map(uc, 0x1A002000, 0x1000, UC_PROT_ALL)); // l2 cache

    

    BlsStream kprx_auth = bls.get("kprx_auth_sm.self"); 
    Buffer kprx_auth_buf(kprx_auth.size);
    kprx_auth.read(kprx_auth.size, kprx_auth_buf.data());
    UC_MEM_ADD(uc, ADDR_SECURE_DRAM + 0x500, kprx_auth_buf);

    BlsStream prog_rvk = bls.get("prog_rvk.srvk");
    Buffer prog_rvk_buf(prog_rvk.size);
    kprx_auth.read(prog_rvk.size, prog_rvk_buf.data());
    UC_MEM_ADD(uc, ADDR_SECURE_DRAM + 0x9B00, prog_rvk_buf);


    BlsStream skbl = bls.get("kernel_boot_loader.self");
    auto skbl_segs = SceDecrypt(skbl);

    // load reset vector
    const auto skbl_reset_vector = skbl_segs.at(0);
    UC_MEM_ADD(uc, ADDR_ARM_BOOT, skbl_reset_vector);

    // load segment 0
    const auto skbl_seg0 = skbl_segs.at(1);
    UC_MEM_ADD(uc, ADDR_SECURE_DRAM + 0x20000, skbl_seg0);

    // load segment 1
    const auto skbl_seg1 = skbl_segs.at(2);
    UC_MEM_ADD(uc, ADDR_SECURE_DRAM + 0x57100, skbl_seg1);

    // load nsbl
    const auto nsbl = skbl_segs.at(3);
    UC_MEM_ADD(uc, 0x50000000, nsbl);

    csh cs;
    cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs);
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    uc_hook trace1, trace2, trace3, trace4;
    //UCD(uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void*)hook_block, NULL, 1, 0));
    UCD(uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void*)hook_code, (void*)cs, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace3, UC_HOOK_MEM_FETCH_UNMAPPED, (void*)hook_mem_fetch, NULL, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace4, UC_HOOK_MEM_WRITE_UNMAPPED, (void*)hook_write_invalid, NULL, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace4, UC_HOOK_INSN_INVALID, (void*)hook_insn_invalid, NULL, 0, 0xFFFFFFFF));

    UCD(uc_emu_start(uc, ADDR_ARM_BOOT, 0xFFFFFFFF, 0, 1000));
}
