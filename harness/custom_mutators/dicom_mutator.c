/*
 * AFL++ Custom Mutator for DICOM Structure-Aware Fuzzing
 *
 * This mutator provides DICOM-aware mutations for more effective fuzzing.
 * It understands DICOM file structure and generates mutations that maintain
 * partial validity while exploring edge cases.
 *
 * Features:
 * - Tag-aware mutations (valid and invalid tags)
 * - VR-specific value mutations
 * - Length field manipulation
 * - Sequence/item structure mutations
 * - Transfer syntax aware encoding
 *
 * Build:
 *   afl-clang-fast -shared -fPIC -O2 -o dicom_mutator.so dicom_mutator.c
 *
 * Use:
 *   AFL_CUSTOM_MUTATOR_LIBRARY=./dicom_mutator.so afl-fuzz ...
 *
 * References:
 *   - AFL++ Custom Mutators: https://aflplus.plus/docs/custom_mutators/
 *   - DICOM PS3.5: Data Structures and Encoding
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* AFL++ Custom Mutator API */
typedef struct {
    void *afl;
    unsigned int seed;
    uint8_t *mutated_buf;
    size_t mutated_size;
} dicom_mutator_t;

/* DICOM Constants */
#define DICOM_PREAMBLE_SIZE 128
#define DICOM_MAGIC_OFFSET 128
#define DICOM_MAGIC "DICM"
#define DICOM_MAGIC_LEN 4
#define MIN_DICOM_SIZE (DICOM_MAGIC_OFFSET + DICOM_MAGIC_LEN + 8)

/* Common DICOM tags for mutation */
static const uint32_t INTERESTING_TAGS[] = {
    0x00020000,  /* FileMetaInformationGroupLength */
    0x00020001,  /* FileMetaInformationVersion */
    0x00020002,  /* MediaStorageSOPClassUID */
    0x00020010,  /* TransferSyntaxUID */
    0x00080016,  /* SOPClassUID */
    0x00080018,  /* SOPInstanceUID */
    0x00080060,  /* Modality */
    0x00100010,  /* PatientName */
    0x00100020,  /* PatientID */
    0x00280002,  /* SamplesPerPixel */
    0x00280010,  /* Rows */
    0x00280011,  /* Columns */
    0x00280100,  /* BitsAllocated */
    0x00280101,  /* BitsStored */
    0x00280102,  /* HighBit */
    0x00280103,  /* PixelRepresentation */
    0x7FE00010,  /* PixelData */
    0xFFFEE000,  /* Item */
    0xFFFEE00D,  /* ItemDelimitationItem */
    0xFFFEE0DD,  /* SequenceDelimitationItem */
};
#define NUM_INTERESTING_TAGS (sizeof(INTERESTING_TAGS) / sizeof(INTERESTING_TAGS[0]))

/* VR (Value Representation) types */
static const char *VR_TYPES[] = {
    "AE", "AS", "AT", "CS", "DA", "DS", "DT", "FL",
    "FD", "IS", "LO", "LT", "OB", "OD", "OF", "OL",
    "OW", "PN", "SH", "SL", "SQ", "SS", "ST", "TM",
    "UC", "UI", "UL", "UN", "UR", "US", "UT"
};
#define NUM_VR_TYPES (sizeof(VR_TYPES) / sizeof(VR_TYPES[0]))

/* Interesting length values */
static const uint32_t INTERESTING_LENGTHS[] = {
    0x00000000,  /* Zero length */
    0x00000001,  /* One byte */
    0x00000002,  /* Two bytes */
    0x00000004,  /* Four bytes */
    0x0000FFFE,  /* Just below max 16-bit */
    0x0000FFFF,  /* Max 16-bit */
    0x00010000,  /* Just above max 16-bit */
    0x7FFFFFFF,  /* Max signed 32-bit */
    0x80000000,  /* Min signed 32-bit (negative) */
    0xFFFFFFFE,  /* Just below undefined */
    0xFFFFFFFF,  /* Undefined length */
};
#define NUM_INTERESTING_LENGTHS (sizeof(INTERESTING_LENGTHS) / sizeof(INTERESTING_LENGTHS[0]))

/* Simple PRNG */
static uint32_t prng_state;

static void prng_seed(uint32_t seed) {
    prng_state = seed;
}

static uint32_t prng_next(void) {
    prng_state = prng_state * 1664525 + 1013904223;
    return prng_state;
}

static uint32_t prng_range(uint32_t max) {
    return prng_next() % max;
}

/* Helper: Read 16-bit little-endian */
static uint16_t read_u16_le(const uint8_t *buf) {
    return (uint16_t)(buf[0] | (buf[1] << 8));
}

/* Helper: Write 16-bit little-endian */
static void write_u16_le(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

/* Helper: Read 32-bit little-endian */
static uint32_t read_u32_le(const uint8_t *buf) {
    return (uint32_t)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
}

/* Helper: Write 32-bit little-endian */
static void write_u32_le(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

/* Check if buffer is a DICOM file */
static int is_dicom(const uint8_t *buf, size_t len) {
    if (len < MIN_DICOM_SIZE) return 0;
    return memcmp(buf + DICOM_MAGIC_OFFSET, DICOM_MAGIC, DICOM_MAGIC_LEN) == 0;
}

/* Mutation: Flip bits in preamble (CVE-2019-11687 style) */
static size_t mutate_preamble(uint8_t *buf, size_t len) {
    if (len < DICOM_MAGIC_OFFSET) return len;

    int mutation_type = prng_range(4);
    switch (mutation_type) {
        case 0:
            /* Insert PE header */
            buf[0] = 'M';
            buf[1] = 'Z';
            write_u32_le(buf + 60, 0x80);
            break;
        case 1:
            /* Insert ELF header */
            buf[0] = 0x7F;
            buf[1] = 'E';
            buf[2] = 'L';
            buf[3] = 'F';
            break;
        case 2:
            /* Random bytes */
            for (int i = 0; i < 16; i++) {
                buf[prng_range(DICOM_PREAMBLE_SIZE)] = prng_next() & 0xFF;
            }
            break;
        case 3:
            /* Fill with pattern */
            memset(buf, prng_next() & 0xFF, DICOM_PREAMBLE_SIZE);
            break;
    }
    return len;
}

/* Mutation: Corrupt DICOM magic */
static size_t mutate_magic(uint8_t *buf, size_t len) {
    if (len < DICOM_MAGIC_OFFSET + DICOM_MAGIC_LEN) return len;

    int mutation_type = prng_range(3);
    uint8_t *magic = buf + DICOM_MAGIC_OFFSET;

    switch (mutation_type) {
        case 0:
            /* Single byte corruption */
            magic[prng_range(4)] = prng_next() & 0xFF;
            break;
        case 1:
            /* Wrong magic */
            memcpy(magic, "MCID", 4);  /* Reversed */
            break;
        case 2:
            /* Empty magic */
            memset(magic, 0, 4);
            break;
    }
    return len;
}

/* Mutation: Manipulate tags */
static size_t mutate_tag(uint8_t *buf, size_t len, size_t offset) {
    if (offset + 4 > len) return len;

    int mutation_type = prng_range(5);
    switch (mutation_type) {
        case 0:
            /* Replace with interesting tag */
            {
                uint32_t tag = INTERESTING_TAGS[prng_range(NUM_INTERESTING_TAGS)];
                write_u16_le(buf + offset, tag >> 16);       /* Group */
                write_u16_le(buf + offset + 2, tag & 0xFFFF); /* Element */
            }
            break;
        case 1:
            /* Invalid group (private range) */
            write_u16_le(buf + offset, 0x0009 + (prng_range(0x100) << 8));
            break;
        case 2:
            /* Zero tag */
            write_u32_le(buf + offset, 0);
            break;
        case 3:
            /* Max tag */
            write_u32_le(buf + offset, 0xFFFFFFFF);
            break;
        case 4:
            /* Random tag */
            write_u16_le(buf + offset, prng_next() & 0xFFFF);
            write_u16_le(buf + offset + 2, prng_next() & 0xFFFF);
            break;
    }
    return len;
}

/* Mutation: Manipulate VR */
static size_t mutate_vr(uint8_t *buf, size_t len, size_t offset) {
    if (offset + 2 > len) return len;

    int mutation_type = prng_range(4);
    switch (mutation_type) {
        case 0:
            /* Valid VR */
            {
                const char *vr = VR_TYPES[prng_range(NUM_VR_TYPES)];
                buf[offset] = vr[0];
                buf[offset + 1] = vr[1];
            }
            break;
        case 1:
            /* Invalid VR */
            buf[offset] = prng_next() & 0xFF;
            buf[offset + 1] = prng_next() & 0xFF;
            break;
        case 2:
            /* Special VRs (4-byte length) */
            {
                const char *special_vrs[] = {"OB", "OW", "OF", "SQ", "UN", "UC", "UR", "UT"};
                const char *vr = special_vrs[prng_range(8)];
                buf[offset] = vr[0];
                buf[offset + 1] = vr[1];
            }
            break;
        case 3:
            /* Null VR */
            buf[offset] = 0;
            buf[offset + 1] = 0;
            break;
    }
    return len;
}

/* Mutation: Manipulate length field */
static size_t mutate_length(uint8_t *buf, size_t len, size_t offset, int is_4byte) {
    if (is_4byte) {
        if (offset + 4 > len) return len;
        uint32_t new_len = INTERESTING_LENGTHS[prng_range(NUM_INTERESTING_LENGTHS)];
        write_u32_le(buf + offset, new_len);
    } else {
        if (offset + 2 > len) return len;
        uint16_t new_len = prng_range(5) == 0 ? 0xFFFF : prng_range(0x10000);
        write_u16_le(buf + offset, new_len);
    }
    return len;
}

/* Mutation: Insert sequence/item */
static size_t mutate_insert_sequence(uint8_t *buf, size_t len, size_t max_len) {
    if (len + 16 > max_len) return len;

    size_t insert_pos = DICOM_MAGIC_OFFSET + 4 + prng_range(len - DICOM_MAGIC_OFFSET - 4);

    /* Shift existing data */
    memmove(buf + insert_pos + 16, buf + insert_pos, len - insert_pos);

    /* Insert sequence start */
    write_u16_le(buf + insert_pos, 0xFFFE);      /* Item tag group */
    write_u16_le(buf + insert_pos + 2, 0xE000);  /* Item tag element */
    write_u32_le(buf + insert_pos + 4, 0xFFFFFFFF);  /* Undefined length */

    /* Insert item delimitation */
    write_u16_le(buf + insert_pos + 8, 0xFFFE);
    write_u16_le(buf + insert_pos + 10, 0xE00D);
    write_u32_le(buf + insert_pos + 12, 0);

    return len + 16;
}

/* Mutation: Truncate at random position */
static size_t mutate_truncate(uint8_t *buf, size_t len) {
    if (len < MIN_DICOM_SIZE) return len;

    /* Keep at least the header */
    size_t min_keep = DICOM_MAGIC_OFFSET + 4 + prng_range(20);
    if (min_keep >= len) return len;

    return min_keep + prng_range(len - min_keep);
}

/* Main mutation function */
static size_t mutate_dicom(uint8_t *buf, size_t len, size_t max_len) {
    if (!is_dicom(buf, len)) {
        /* Not a DICOM file - just do random mutations */
        for (int i = 0; i < 5; i++) {
            size_t pos = prng_range(len);
            buf[pos] = prng_next() & 0xFF;
        }
        return len;
    }

    /* Choose mutation strategy */
    int strategy = prng_range(10);

    switch (strategy) {
        case 0:
            return mutate_preamble(buf, len);
        case 1:
            return mutate_magic(buf, len);
        case 2:
            /* Find and mutate a random tag */
            if (len > MIN_DICOM_SIZE + 8) {
                size_t offset = DICOM_MAGIC_OFFSET + 4 + prng_range(len - MIN_DICOM_SIZE - 8);
                offset &= ~3;  /* Align to 4 bytes */
                return mutate_tag(buf, len, offset);
            }
            break;
        case 3:
            /* Mutate VR at random position */
            if (len > MIN_DICOM_SIZE + 6) {
                size_t offset = DICOM_MAGIC_OFFSET + 4 + prng_range(len - MIN_DICOM_SIZE - 6);
                return mutate_vr(buf, len, offset);
            }
            break;
        case 4:
        case 5:
            /* Mutate length field */
            if (len > MIN_DICOM_SIZE + 8) {
                size_t offset = DICOM_MAGIC_OFFSET + 4 + prng_range(len - MIN_DICOM_SIZE - 8);
                return mutate_length(buf, len, offset, prng_range(2));
            }
            break;
        case 6:
            return mutate_insert_sequence(buf, len, max_len);
        case 7:
            return mutate_truncate(buf, len);
        case 8:
        case 9:
            /* Multiple random byte mutations */
            {
                int num_mutations = 1 + prng_range(10);
                for (int i = 0; i < num_mutations; i++) {
                    size_t pos = prng_range(len);
                    buf[pos] = prng_next() & 0xFF;
                }
            }
            break;
    }

    return len;
}

/* ============= AFL++ Custom Mutator API ============= */

/**
 * Initialize the custom mutator.
 */
void *afl_custom_init(void *afl, unsigned int seed) {
    dicom_mutator_t *data = (dicom_mutator_t *)calloc(1, sizeof(dicom_mutator_t));
    if (!data) return NULL;

    data->afl = afl;
    data->seed = seed;
    data->mutated_buf = NULL;
    data->mutated_size = 0;

    prng_seed(seed);

    fprintf(stderr, "[DICOM Mutator] Initialized with seed %u\n", seed);
    return data;
}

/**
 * Perform custom mutation.
 */
size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {
    dicom_mutator_t *mutator = (dicom_mutator_t *)data;

    /* Reseed occasionally */
    if (prng_range(1000) == 0) {
        prng_seed(mutator->seed ^ (uint32_t)buf_size);
    }

    /* Allocate or reallocate mutation buffer */
    if (mutator->mutated_buf == NULL || mutator->mutated_size < max_size) {
        free(mutator->mutated_buf);
        mutator->mutated_buf = (uint8_t *)malloc(max_size);
        mutator->mutated_size = max_size;
    }

    if (!mutator->mutated_buf) {
        *out_buf = buf;
        return buf_size;
    }

    /* Copy input to mutation buffer */
    memcpy(mutator->mutated_buf, buf, buf_size);

    /* Perform DICOM-aware mutation */
    size_t new_size = mutate_dicom(mutator->mutated_buf, buf_size, max_size);

    *out_buf = mutator->mutated_buf;
    return new_size;
}

/**
 * Deinitialize the custom mutator.
 */
void afl_custom_deinit(void *data) {
    dicom_mutator_t *mutator = (dicom_mutator_t *)data;
    if (mutator) {
        free(mutator->mutated_buf);
        free(mutator);
    }
    fprintf(stderr, "[DICOM Mutator] Deinitialized\n");
}

/**
 * Return the probability of using this mutator.
 * 100 means always use it alongside AFL's default mutators.
 */
unsigned int afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size) {
    (void)data;
    (void)buf;
    (void)buf_size;
    return 1;  /* Always call once per mutation round */
}
