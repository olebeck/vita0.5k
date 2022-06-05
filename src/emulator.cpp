#include "emulator.h"
#include <common/util.h>
#include <unicorn/unicorn.h>

#include <common/cp15_info.h>



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
    //usleep(100000);
}


void print_cp15_instruction(cs_insn* insn) {
    auto mnemonic = insn->mnemonic;
    auto processor = insn->detail->arm.operands[0].reg;
    auto idk1 = insn->detail->arm.operands[1].reg;
    auto _register = insn->detail->arm.operands[2].reg;
    auto cmd0 = insn->detail->arm.operands[3].imm;
    auto cmd1 = insn->detail->arm.operands[4].imm;
    auto cmd2 = insn->detail->arm.operands[5].imm;

    char buffer[256];
    snprintf(buffer, 256, "%s p%d %d <Rd> c%d c%d %d", mnemonic, processor, idk1, cmd0, cmd1, cmd2);
    auto key = std::string(buffer);
    if(cp15_ops.count(key))
        printf("  (CP15: %s)", cp15_ops.at(key).c_str());
    else
        printf("  (CP15: unknown)");
}

#define PSR_F_BIT	0x00000040	/* >= V4, but not V7M */
#define PSR_I_BIT	0x00000080	/* >= V4, but not V7M */
#define PSR_A_BIT	0x00000100	/* >= V6, but not V7M */
#define PSR_E_BIT	0x00000200	/* >= V6, but not V7M */
#define PSR_J_BIT	0x01000000	/* >= V5J, but not V7M */
#define PSR_Q_BIT	0x08000000	/* >= V5E, including V7M */
#define PSR_V_BIT	0x10000000
#define PSR_C_BIT	0x20000000
#define PSR_Z_BIT	0x40000000
#define PSR_N_BIT	0x80000000

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    Emulator* emu = (Emulator*)user_data;

    if(address == 0x0) printf("// RESET\n\n");
    uint8_t insn[size];
    uc_mem_read(uc, address, &insn, size);
    cs_insn* insn_info;
    int ret = cs_disasm(emu->cs, insn, size, address, 1, &insn_info);
    if(ret > 0) {
        char buf[256];
        size_t len = sprintf(buf, ">>> %s %s", insn_info->mnemonic, insn_info->op_str);
        const int max_len = 34;
        int pad = max_len - len;
        sprintf(buf + len, "%*s", pad, " ");
        printf("%s ", buf);
        uc_reg_dump(uc);

        if(insn_info->id == ARM_INS_B) {
            bool will_jump = false;

            U32 cpsr;
            uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);

            switch (insn_info->detail->arm.cc)
            {
            case ARM_CC_EQ:
                will_jump = (cpsr & PSR_Z_BIT) != 0;
                break;
            case ARM_CC_NE:
                will_jump = (cpsr & PSR_Z_BIT) == 0;
                break;
            case ARM_CC_HS:
                will_jump = (cpsr & PSR_C_BIT) != 0;
                break;
            case ARM_CC_LO:
                will_jump = (cpsr & PSR_C_BIT) == 0;
                break;
            case ARM_CC_MI:
                will_jump = (cpsr & PSR_N_BIT) != 0;
                break;
            case ARM_CC_PL:
                will_jump = (cpsr & PSR_N_BIT) == 0;
                break;
            case ARM_CC_VS:
                will_jump = (cpsr & PSR_V_BIT) != 0;
                break;
            case ARM_CC_VC:
                will_jump = (cpsr & PSR_V_BIT) == 0;
                break;
            case ARM_CC_HI:
                will_jump = (cpsr & (PSR_C_BIT | PSR_Z_BIT)) == (PSR_C_BIT | PSR_Z_BIT);
                break;
            case ARM_CC_LS:
                will_jump = (cpsr & (PSR_C_BIT | PSR_Z_BIT)) != (PSR_C_BIT | PSR_Z_BIT);
                break;
            case ARM_CC_GE:
                will_jump = (cpsr & (PSR_N_BIT ^ PSR_V_BIT)) == 0;
                break;
            case ARM_CC_LT:
                will_jump = (cpsr & (PSR_N_BIT ^ PSR_V_BIT)) != 0;
                break;
            case ARM_CC_GT:
                will_jump = ((cpsr & (PSR_Z_BIT | PSR_N_BIT ^ PSR_V_BIT)) == 0);
                break;
            case ARM_CC_LE:
                will_jump = ((cpsr & (PSR_Z_BIT | PSR_N_BIT ^ PSR_V_BIT)) != 0);
                break;
            case ARM_CC_AL:
                will_jump = true;
                break;
            default:
                printf("  (unhandled condition) %d\n", insn_info->detail->arm.cc);
                exit(0);
            }

            U32 addr = insn_info->detail->arm.operands[0].imm;
            if(will_jump) {
                printf("\n// Jump to 0x%08x\n", addr);
            } else {
                printf("// Not jumping");
            }
        }
        
        if(insn_info->id == ARM_INS_MCR || insn_info->id == ARM_INS_MRC) {
            print_cp15_instruction(insn_info);
        }

        cs_free(insn_info, 1);
        printf("\n");
    } else {
        printf(">>> Failed to disassemble instruction! %08x\n", insn);
    }
}

static void hook_mem_read_after(uc_engine *uc, uc_mem_type type,
                                uint64_t address, int size, int64_t value,
                                void *user_data)
{
    printf("// Memory Read from 0x%llx, value = 0x%llx\n", address, value);
}

static void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                           int size, int64_t value, void *user_data)
{
    printf("// Memory write to 0x%llx, data size = %d, data value = 0x%llx\n",
           address, size, value);
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

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    printf(">>> Interrupt %u\n", intno);
}



Emulator::Emulator()
{
    UCD(uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc));
    memory = new Memory(uc);

    cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs);
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    uc_hook trace1, trace2, trace3, trace4, trace5, trace6;
    UCD(uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_AFTER,    (void*)hook_mem_read_after, this, 0, 0XFFFFFFFF));
    UCD(uc_hook_add(uc, &trace2, UC_HOOK_CODE,              (void*)hook_code, this, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace3, UC_HOOK_MEM_FETCH_UNMAPPED,(void*)hook_mem_fetch, this, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace4, UC_HOOK_MEM_WRITE_UNMAPPED,(void*)hook_write_invalid, this, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace4, UC_HOOK_INSN_INVALID,      (void*)hook_insn_invalid, this, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace5, UC_HOOK_MEM_WRITE,         (void*)hook_mem_write, this, 0, 0xFFFFFFFF));
    UCD(uc_hook_add(uc, &trace6, UC_HOOK_INTR,              (void*)hook_intr, this, 0, 0xFFFFFFFF));

    UCD(uc_mem_map(uc, ADDR_ARM_BOOT, SIZE_ARM_BOOT, UC_PROT_ALL));
    UCD(uc_mem_map(uc, ADDR_SECURE_DRAM, SIZE_SECURE_DRAM, UC_PROT_ALL));
    UCD(uc_mem_map(uc, ADDR_SHARED_RAM, SIZE_SHARED_RAM, UC_PROT_ALL)); // memory

    UCD(uc_mem_map(uc, 0x1A000000, 0x2000, UC_PROT_ALL)); // interrupt controller
    UCD(uc_mem_map(uc, 0x1A002000, 0x1000, UC_PROT_ALL)); // l2 cache

}

Emulator::~Emulator()
{
    delete memory;
    UCD(uc_close(uc));
}

void Emulator::Start() {
    UCD(uc_emu_start(uc, ADDR_ARM_BOOT, 0xFFFFFFFF, 0, 9000));
}
