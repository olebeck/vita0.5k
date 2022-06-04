#pragma once

#include <vector>
#include <functional>
#include <stdexcept>
#include <map>

#include <common/stream.hpp>
#include <common/types.hpp>
#include "sce_decrypt.hpp"


typedef struct {
    U8  magic[7];
    U8  format_flag;
    U8  format_version[8];
    U32 version;
    U32 build;
    U64 segment_count;
    U64 header_length;
    U64 data_length;
    U32 sign_algo;
    U32 sign_key_idx;
    U8  attr[4];
    U32 target;
    U32 subtarget;
    U32 support_list;
    U32 base_version;
    U32 base_build;
    U8 unk[0x30];
} PupHeader;

class PUPSegmentEntry {
public:
    struct entry_t {
        U64 id;
        U64 offset;
        U64 size;
        U32 sign_algorithm;
        U8 padding[4];
    };
    U64 id;
    U64 offset;
    U64 size;
    U32 sign_algorithm;
    std::string name;

    PUPSegmentEntry(Stream& s);
    std::string get_filename(Stream& s);
};

typedef struct {
  uint64_t segment_index;
  uint8_t digest[0x20];
  uint8_t padding[0x18];
} PUPDigestEntry_v2;

class PupParser {
    PupHeader header;
    std::vector<PUPSegmentEntry> segments;
    std::vector<PUPDigestEntry_v2> digests;

    Stream& s;
public:
    PupParser(Stream& s);
    ~PupParser();

    /**
     * Get PUP segment by identifier.
     * @param[in]  id  Segment identifier (44-bits).
     * @return  Segment data.
     */
    std::vector<SceSegment> get(U64 id);

    /**
     * Get PUP segment by identifier.
     * @param[in]  entry  The Entry.
     */
    std::vector<SceSegment> get(PUPSegmentEntry entry);

    /**
     * Get PUP segment by name.
     * @param[in]  name Segment name.
     */
    std::vector<SceSegment> get(std::string name);

private:
    /**
     * Get index of first PUP segment satisfying the given predicate, if any.
     * @param[in]  pred  Predicate function.
     */
    U64 find(const std::function<bool(const PUPSegmentEntry&)>& pred) const;

    /**
     * Get index of first PUP segment with the given identifier, if any.
     * @param[in]  id  Segment identifier (44-bits).
     */
    U64 find(U64 id) const;

    void list_segments() const;

    /**
     * Get blocked PUP segment by identifier.
     * @param[in]  id  Segment identifier (44-bits).
     */
    Buffer get_blocked(U64 index);
};

