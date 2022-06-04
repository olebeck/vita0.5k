#include "pup.hpp"
#include "keys.hpp"

#include <cassert>
#include <botan/aes.h>
#include <botan/pipe.h>
#include "sce_decrypt.hpp"

std::map<U32, std::string> type_names = {
    {0x100, "version.txt"},
    {0x101, "license.xml"},
    {0x200, "psp2swu.self"},
    {0x204, "cui_setupper.self"},
    {0x400, "package_scewm.wm"},
    {0x401, "package_sceas.as"},
    {0x2005, "UpdaterES1.CpUp"},
    {0x2006, "UpdaterES2.CpUp"},
};

std::map<U32, U32> G_typecount = {};

std::vector<std::string> FSTYPE = {
    "unknown0",
    "os0",
    "unknown2",
    "unknown3",
    "vs0_chmod",
    "unknown5",
    "unknown6",
    "unknown7",
    "pervasive8",
    "boot_slb2",
    "vs0",
    "devkit_cp",
    "motionC",
    "bbmc",
    "unknownE",
    "motionF",
    "touch10",
    "touch11",
    "syscon12",
    "syscon13",
    "pervasive14",
    "unknown15",
    "vs0_tarpatch",
    "sa0",
    "pd0",
    "pervasive19",
    "unknown1A",
    "psp_emulist",
};

PUPSegmentEntry::PUPSegmentEntry(Stream& s) {
    auto entry = s.read_t<entry_t>();
    s.seek(entry.offset, StreamSeek::Set);
    name = type_names[entry.id];
    if(name.empty()) {
        name = get_filename(s);
    }
    id = entry.id;
    offset = entry.offset;
    size = entry.size;
    sign_algorithm = entry.sign_algorithm;
}


std::string PUPSegmentEntry::get_filename(Stream& s) {
    s.seek(offset, StreamSeek::Set);
    auto head = s.read_t<SceHeader>();
    if(head.magic == 0x454353 && head.version == 3) {
        s.seek(offset + head.header_length + 4, StreamSeek::Set);
        U8 meta;
        s.read(1, &meta);
        if(meta < 0x1C) {
            return FSTYPE[meta] + "-" + std::to_string(G_typecount[meta]++) + ".pkg";
        }
    }
    return "unknown" + std::to_string(id) + ".pkg";
}

PupParser::PupParser(Stream& s) : s(s) {
    header = s.read_t<PupHeader>();
    for (int i = 0; i < header.segment_count; i++) {
        s.seek(sizeof(PupHeader) + i * sizeof(PUPSegmentEntry::entry_t), StreamSeek::Set);
        PUPSegmentEntry entry(s);
        segments.push_back(entry);
    }
    for (int i = 0; i < header.segment_count; i++) {
        PUPDigestEntry_v2 entry = s.read_t<PUPDigestEntry_v2>();
        digests.push_back(entry);
    }

};

PupParser::~PupParser() {
};

std::vector<SceSegment> PupParser::get(U64 id) {
    const auto index = find(id);
    const PUPSegmentEntry& entry = segments[index];
    return get(entry);
}

std::vector<SceSegment> PupParser::get(std::string name) {
    const auto index = find([=](const PUPSegmentEntry& entry) {
        return entry.name == name;
    });
    const PUPSegmentEntry& entry = segments[index];
    return get(entry);
}




std::vector<SceSegment> PupParser::get(PUPSegmentEntry entry) {
    s.seek(entry.offset, StreamSeek::Set);
    BufferStream buf = s.read_b(entry.size);
    return SceDecrypt(buf);
}


U64 PupParser::find(const std::function<bool(const PUPSegmentEntry&)>& pred) const {
    for (size_t i = 0; i < header.segment_count; i++) {
        if (pred(segments[i])) {
            return i - 1;
        }
    }
    throw std::out_of_range("PUP segment not found");
}

U64 PupParser::find(U64 id) const {
    return find([=](const PUPSegmentEntry& entry) -> bool {
        return entry.id == id;
    });
}

void PupParser::list_segments() const {
    for(size_t i = 0; i < header.segment_count; i++) {
        const PUPSegmentEntry& entry = segments[i];
        printf("0x%x (%s) %d %d %x\n", entry.id, entry.name.c_str(), entry.offset, entry.size, entry.sign_algorithm);
    }
}