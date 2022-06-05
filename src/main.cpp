#include <string>
#include "common/stream.h"
#include "software/pup.hpp"
#include "software/bls.hpp"
#include "software/keys.hpp"
#include "software/sce_decrypt.hpp"
#include "common/util.h"
#include "emulator.h"

#include <common/cp15_info.h>

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>



static KBLparam kbl_param = {
    .version = 1,
    .size = sizeof(KBLparam),
    .current_fw = 0,
    .minimum_fw = 0,
    .unk0 = 0,
    .unk1 = 0,
    .unk2 = 0,
    .qa_flags = 0,
    .boot_flags = 0,
    .DIPSwitches = 0,
    .DRAMBase = ADDR_SECURE_DRAM,
    .DRAMSize = 0x20000000,
    .unk3 = 0,
    .BootTypeIndicator = 0x1,
    .secure_kernel_enp_addr = 0x0,
    .secure_kernel_enp_size = 0,
    .context_auth_sm_self_addr = 0x0,
    .context_auth_sm_self_size = 0,
    .kprx_auth_sm_self_addr = ADDR_KPRX_AUTH_SM,
    .kprx_auth_sm_self_size = 0xFFFF, // set this later
    .prog_rvk_srvk_addr = ADDR_PROG_RVK,
    .prog_rvk_srvk_size = 0xFFFF, // set this later
};


int main(int argc, char** argv) {

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

    Emulator emu;

    // basic map:
    // skbl reset vector = 0x0
    // kprx auth  = 0x40000500
    // prog_rvk   = 0x40009B00
    // skbl param = 0x4001FD00 (without magic)
    // skbl seg 0 = 0x40020000
    // skbl seg 1 = 0x40057100
    // skbl param = 0x40073570 (with magic)
    // nsbl       = 0x50000000 (arzl compressed)

    BlsStream kprx_auth = bls.get("kprx_auth_sm.self"); 
    emu.Map(Buffer(kprx_auth), ADDR_KPRX_AUTH_SM, kprx_auth.size);
    kbl_param.kprx_auth_sm_self_size = kprx_auth.size;

    BlsStream prog_rvk = bls.get("prog_rvk.srvk");
    emu.Map(Buffer(prog_rvk), ADDR_PROG_RVK, prog_rvk.size);
    kbl_param.prog_rvk_srvk_size = prog_rvk.size;


    BlsStream skbl = bls.get("kernel_boot_loader.self");
    auto skbl_segs = SceDecrypt(skbl);

    // load reset vector
    const auto skbl_reset_vector = skbl_segs.at(0);
    emu.Map(skbl_reset_vector, ADDR_ARM_BOOT);

    // load segment 0
    const auto skbl_seg0 = skbl_segs.at(1);
    emu.Map(skbl_seg0, ADDR_SECURE_DRAM + 0x20000);

    // load segment 1
    const auto skbl_seg1 = skbl_segs.at(2);
    emu.Map(skbl_seg1, ADDR_SECURE_DRAM + 0x57100);

    emu.Map(ADDR_SECURE_DRAM + 0x73570, sizeof(kbl_param), &kbl_param);

    // load nsbl
    const auto nsbl = skbl_segs.at(3);
    emu.Map(nsbl, 0x50000000);

    emu.Start();
}
