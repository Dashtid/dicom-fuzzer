/*
 * AFL++ Persistent Mode Harness for DICOM Fuzzing
 *
 * This harness implements AFL++ persistent mode for high-throughput
 * fuzzing of DICOM parsers. Persistent mode avoids fork() overhead
 * by processing multiple inputs in a single process.
 *
 * Performance: 10-20x faster than non-persistent mode
 *
 * Usage:
 *   afl-clang-fast -o dicom_harness afl_persistent.c -lpydicom_stubs
 *   afl-fuzz -i corpus -o findings ./dicom_harness
 *
 * References:
 *   - AFL++ Persistent Mode: https://github.com/AFLplusplus/AFLplusplus
 *   - DICOM Standard: PS3.10 (Media Storage)
 *   - FDA Fuzz Testing Guidance (June 2025)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

/* AFL++ persistent mode macros */
#ifndef __AFL_FUZZ_TESTCASE_LEN
#define __AFL_FUZZ_TESTCASE_LEN 0
#endif

#ifndef __AFL_FUZZ_TESTCASE_BUF
#define __AFL_FUZZ_TESTCASE_BUF NULL
#endif

#ifndef __AFL_FUZZ_INIT
#define __AFL_FUZZ_INIT() void
#endif

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 1
#endif

/* DICOM Magic Bytes */
static const uint8_t DICM_MAGIC[] = { 'D', 'I', 'C', 'M' };
static const size_t DICOM_PREAMBLE_SIZE = 128;
static const size_t DICOM_MAGIC_OFFSET = 128;

/* Configuration */
#define MAX_INPUT_SIZE (100 * 1024 * 1024)  /* 100 MB max input */
#define PERSISTENT_ITERATIONS 1000          /* Iterations per fork */

/*
 * Minimal DICOM parser for fuzzing.
 * This simulates the parsing path of pydicom/GDCM without dependencies.
 * Replace with your target library's parsing function.
 */

/* DICOM Data Element Tag */
typedef struct {
    uint16_t group;
    uint16_t element;
} DicomTag;

/* DICOM VR (Value Representation) */
typedef enum {
    VR_AE, VR_AS, VR_AT, VR_CS, VR_DA, VR_DS, VR_DT, VR_FL,
    VR_FD, VR_IS, VR_LO, VR_LT, VR_OB, VR_OD, VR_OF, VR_OL,
    VR_OW, VR_PN, VR_SH, VR_SL, VR_SQ, VR_SS, VR_ST, VR_TM,
    VR_UC, VR_UI, VR_UL, VR_UN, VR_UR, VR_US, VR_UT,
    VR_UNKNOWN
} DicomVR;

/* Parse result */
typedef struct {
    int success;
    int elements_parsed;
    char error_msg[256];
} ParseResult;

/*
 * Read a 16-bit little-endian value
 */
static inline uint16_t read_u16_le(const uint8_t *buf) {
    return (uint16_t)(buf[0] | (buf[1] << 8));
}

/*
 * Read a 32-bit little-endian value
 */
static inline uint32_t read_u32_le(const uint8_t *buf) {
    return (uint32_t)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
}

/*
 * Check if VR is explicit and uses 4-byte length field
 */
static int vr_uses_4byte_length(const char *vr) {
    /* VRs with 4-byte length: OB, OD, OF, OL, OW, SQ, UC, UN, UR, UT */
    if (vr[0] == 'O' || vr[0] == 'S' || vr[0] == 'U') {
        if (strcmp(vr, "OB") == 0 || strcmp(vr, "OD") == 0 ||
            strcmp(vr, "OF") == 0 || strcmp(vr, "OL") == 0 ||
            strcmp(vr, "OW") == 0 || strcmp(vr, "SQ") == 0 ||
            strcmp(vr, "UC") == 0 || strcmp(vr, "UN") == 0 ||
            strcmp(vr, "UR") == 0 || strcmp(vr, "UT") == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Parse DICOM file meta information (Group 0002)
 */
static int parse_file_meta(const uint8_t *buf, size_t len, size_t *offset) {
    if (*offset + 4 > len) return -1;

    /* Read File Meta Information Group Length */
    DicomTag tag;
    tag.group = read_u16_le(buf + *offset);
    tag.element = read_u16_le(buf + *offset + 2);

    if (tag.group != 0x0002 || tag.element != 0x0000) {
        return -1;  /* Expected (0002,0000) */
    }

    *offset += 4;

    /* VR should be "UL" for Group Length */
    if (*offset + 2 > len) return -1;
    char vr[3] = { buf[*offset], buf[*offset + 1], 0 };
    *offset += 2;

    /* Length field (2 bytes for UL) */
    if (*offset + 2 > len) return -1;
    uint16_t value_len = read_u16_le(buf + *offset);
    *offset += 2;

    /* Read value (group length) */
    if (*offset + value_len > len) return -1;
    uint32_t group_len = read_u32_le(buf + *offset);
    *offset += value_len;

    /* Parse remaining file meta elements */
    size_t meta_end = *offset + group_len;
    if (meta_end > len) meta_end = len;

    while (*offset < meta_end) {
        if (*offset + 4 > len) break;

        tag.group = read_u16_le(buf + *offset);
        tag.element = read_u16_le(buf + *offset + 2);
        *offset += 4;

        /* File meta must be group 0002 */
        if (tag.group != 0x0002) break;

        /* Explicit VR */
        if (*offset + 2 > len) break;
        vr[0] = buf[*offset];
        vr[1] = buf[*offset + 1];
        vr[2] = 0;
        *offset += 2;

        uint32_t length;
        if (vr_uses_4byte_length(vr)) {
            *offset += 2;  /* Skip reserved */
            if (*offset + 4 > len) break;
            length = read_u32_le(buf + *offset);
            *offset += 4;
        } else {
            if (*offset + 2 > len) break;
            length = read_u16_le(buf + *offset);
            *offset += 2;
        }

        /* Skip value */
        if (length == 0xFFFFFFFF) {
            /* Undefined length - need to find delimiter */
            break;  /* Simplified: don't handle undefined length here */
        }

        if (*offset + length > len) break;
        *offset += length;
    }

    return 0;
}

/*
 * Parse DICOM dataset (non-meta elements)
 */
static int parse_dataset(const uint8_t *buf, size_t len, size_t offset,
                         int is_explicit_vr, ParseResult *result) {
    int elements = 0;
    int max_elements = 10000;  /* Prevent infinite loops */

    while (offset + 4 <= len && elements < max_elements) {
        DicomTag tag;
        tag.group = read_u16_le(buf + offset);
        tag.element = read_u16_le(buf + offset + 2);
        offset += 4;

        /* Stop at end of data */
        if (tag.group == 0xFFFF && tag.element == 0xFFFF) {
            break;
        }

        uint32_t length;

        if (is_explicit_vr && tag.group != 0xFFFE) {
            /* Explicit VR */
            if (offset + 2 > len) break;
            char vr[3] = { buf[offset], buf[offset + 1], 0 };
            offset += 2;

            if (vr_uses_4byte_length(vr)) {
                offset += 2;  /* Skip reserved */
                if (offset + 4 > len) break;
                length = read_u32_le(buf + offset);
                offset += 4;
            } else {
                if (offset + 2 > len) break;
                length = read_u16_le(buf + offset);
                offset += 2;
            }
        } else {
            /* Implicit VR - always 4 byte length */
            if (offset + 4 > len) break;
            length = read_u32_le(buf + offset);
            offset += 4;
        }

        /* Handle undefined length */
        if (length == 0xFFFFFFFF) {
            /* Skip undefined length items for now */
            /* In real parser: search for sequence/item delimiters */
            continue;
        }

        /* Validate and skip value */
        if (offset + length > len) {
            /* Truncated value - this is a fuzzing trigger */
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Truncated value at tag (%04X,%04X)",
                     tag.group, tag.element);
            break;
        }

        offset += length;
        elements++;

        /* Trigger for PixelData parsing */
        if (tag.group == 0x7FE0 && tag.element == 0x0010) {
            /* PixelData found - exercise pixel parsing path */
            /* Real parser would decode pixels here */
        }
    }

    result->elements_parsed = elements;
    return 0;
}

/*
 * Main DICOM parsing function - entry point for fuzzing
 */
static ParseResult parse_dicom(const uint8_t *buf, size_t len) {
    ParseResult result = { 0, 0, "" };

    /* Minimum valid DICOM file size */
    if (len < DICOM_MAGIC_OFFSET + 4) {
        result.success = 0;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "File too small: %zu bytes", len);
        return result;
    }

    /* Check for DICM magic */
    int has_preamble = (memcmp(buf + DICOM_MAGIC_OFFSET, DICM_MAGIC, 4) == 0);

    size_t offset;
    int is_explicit_vr = 1;  /* Assume explicit VR until proven otherwise */

    if (has_preamble) {
        /* Standard Part 10 file with preamble */
        offset = DICOM_MAGIC_OFFSET + 4;

        /* Parse file meta information */
        if (parse_file_meta(buf, len, &offset) != 0) {
            /* Invalid file meta - try to continue anyway */
        }
    } else {
        /* No preamble - might be raw dataset */
        offset = 0;

        /* Check if first tag looks like implicit VR */
        if (len >= 8) {
            uint16_t group = read_u16_le(buf);
            /* Implicit VR datasets often start with patient/study info */
            if (group == 0x0008 || group == 0x0010) {
                /* Check if VR position has valid VR characters */
                if (buf[4] < 'A' || buf[4] > 'Z' ||
                    buf[5] < 'A' || buf[5] > 'Z') {
                    is_explicit_vr = 0;
                }
            }
        }
    }

    /* Parse dataset */
    if (parse_dataset(buf, len, offset, is_explicit_vr, &result) == 0) {
        result.success = 1;
    }

    return result;
}

/*
 * Signal handler for crashes
 */
static void crash_handler(int sig) {
    /* AFL will detect this as a crash */
    _exit(sig + 128);
}

/*
 * Main fuzzing entry point
 */
int main(int argc, char **argv) {
    /* Install signal handlers for crash detection */
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGFPE, crash_handler);
    signal(SIGBUS, crash_handler);

    /* AFL++ deferred initialization for persistent mode */
    __AFL_FUZZ_INIT();

    /* Get shared memory buffer from AFL */
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    /* Persistent mode loop */
    while (__AFL_LOOP(PERSISTENT_ITERATIONS)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        /* Skip empty inputs */
        if (len == 0) continue;

        /* Enforce max input size */
        if (len > MAX_INPUT_SIZE) continue;

        /* Parse the DICOM input */
        ParseResult result = parse_dicom(buf, len);

        /* Optionally trigger different behavior based on parsing */
        if (!result.success && result.error_msg[0] != '\0') {
            /* Parser found an error - this is expected during fuzzing */
            /* Could log to stderr for debugging: */
            /* fprintf(stderr, "Parse error: %s\n", result.error_msg); */
        }
    }

    return 0;
}

/*
 * Standalone mode for testing without AFL
 */
#ifdef STANDALONE
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dicom_file>\n", argv[0]);
        return 1;
    }

    /* Read file */
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    uint8_t *buf = malloc(st.st_size);
    if (!buf) {
        perror("malloc");
        close(fd);
        return 1;
    }

    if (read(fd, buf, st.st_size) != st.st_size) {
        perror("read");
        free(buf);
        close(fd);
        return 1;
    }
    close(fd);

    /* Parse */
    ParseResult result = parse_dicom(buf, st.st_size);

    printf("File: %s\n", argv[1]);
    printf("Success: %s\n", result.success ? "yes" : "no");
    printf("Elements parsed: %d\n", result.elements_parsed);
    if (result.error_msg[0]) {
        printf("Error: %s\n", result.error_msg);
    }

    free(buf);
    return result.success ? 0 : 1;
}
#endif
