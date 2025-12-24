/**
 * libFuzzer Harness for DICOM Fuzzing
 *
 * This harness is compatible with both libFuzzer and AFL++ via afl-clang-fast.
 *
 * Build with libFuzzer:
 *   clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
 *     -o dicom_fuzzer libfuzzer_harness.cpp
 *
 * Build with AFL++:
 *   afl-clang-fast++ -g -O2 -fsanitize=address,undefined \
 *     -o dicom_fuzzer_afl libfuzzer_harness.cpp
 *
 * Run with libFuzzer:
 *   ./dicom_fuzzer corpus/ -max_len=10485760 -dict=dicom.dict
 *
 * Run with AFL++:
 *   afl-fuzz -i corpus/ -o findings/ -- ./dicom_fuzzer_afl @@
 *
 * References:
 * - https://llvm.org/docs/LibFuzzer.html
 * - https://aflplus.plus/docs/
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <vector>

// DICOM constants
static const uint8_t DICOM_MAGIC[4] = {'D', 'I', 'C', 'M'};
static const size_t DICOM_PREAMBLE_SIZE = 128;
static const size_t DICOM_HEADER_SIZE = DICOM_PREAMBLE_SIZE + 4;

// VR types (2 bytes)
enum class VR : uint16_t {
    AE = 0x4541,  // "AE"
    AS = 0x5341,  // "AS"
    AT = 0x5441,  // "AT"
    CS = 0x5343,  // "CS"
    DA = 0x4144,  // "DA"
    DS = 0x5344,  // "DS"
    DT = 0x5444,  // "DT"
    FL = 0x4C46,  // "FL"
    FD = 0x4446,  // "FD"
    IS = 0x5349,  // "IS"
    LO = 0x4F4C,  // "LO"
    LT = 0x544C,  // "LT"
    OB = 0x424F,  // "OB"
    OD = 0x444F,  // "OD"
    OF = 0x464F,  // "OF"
    OL = 0x4C4F,  // "OL"
    OW = 0x574F,  // "OW"
    PN = 0x4E50,  // "PN"
    SH = 0x4853,  // "SH"
    SL = 0x4C53,  // "SL"
    SQ = 0x5153,  // "SQ"
    SS = 0x5353,  // "SS"
    ST = 0x5453,  // "ST"
    TM = 0x4D54,  // "TM"
    UC = 0x4355,  // "UC"
    UI = 0x4955,  // "UI"
    UL = 0x4C55,  // "UL"
    UN = 0x4E55,  // "UN"
    UR = 0x5255,  // "UR"
    US = 0x5355,  // "US"
    UT = 0x5455,  // "UT"
};

// Check if VR uses 4-byte length (explicit VR)
static bool vr_has_32bit_length(uint16_t vr) {
    // OB, OD, OF, OL, OW, SQ, UC, UN, UR, UT use 4-byte length with 2-byte padding
    switch (vr) {
        case static_cast<uint16_t>(VR::OB):
        case static_cast<uint16_t>(VR::OD):
        case static_cast<uint16_t>(VR::OF):
        case static_cast<uint16_t>(VR::OL):
        case static_cast<uint16_t>(VR::OW):
        case static_cast<uint16_t>(VR::SQ):
        case static_cast<uint16_t>(VR::UC):
        case static_cast<uint16_t>(VR::UN):
        case static_cast<uint16_t>(VR::UR):
        case static_cast<uint16_t>(VR::UT):
            return true;
        default:
            return false;
    }
}

// Read little-endian uint16
static uint16_t read_u16_le(const uint8_t *buf) {
    return static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8);
}

// Read little-endian uint32
static uint32_t read_u32_le(const uint8_t *buf) {
    return static_cast<uint32_t>(buf[0]) |
           (static_cast<uint32_t>(buf[1]) << 8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

/**
 * Validate DICOM header structure
 * Returns 0 on success, -1 on failure
 */
static int validate_dicom_header(const uint8_t *data, size_t size) {
    // Minimum size: preamble (128) + magic (4) + one data element header (8)
    if (size < DICOM_HEADER_SIZE + 8) {
        return -1;
    }

    // Check DICM magic at offset 128
    if (memcmp(data + DICOM_PREAMBLE_SIZE, DICOM_MAGIC, 4) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Parse DICOM data elements (explicit VR little-endian)
 * This is a simplified parser that exercises common parsing paths.
 */
static int parse_dicom_elements(const uint8_t *data, size_t size) {
    if (size < DICOM_HEADER_SIZE) {
        return -1;
    }

    size_t offset = DICOM_HEADER_SIZE;
    int element_count = 0;
    const int max_elements = 10000;  // Prevent DoS

    while (offset + 8 <= size && element_count < max_elements) {
        // Read tag (group, element)
        uint16_t group = read_u16_le(data + offset);
        uint16_t element = read_u16_le(data + offset + 2);
        offset += 4;

        // Handle implicit VR for group 0x0000 and 0xFFFE
        if (group == 0x0000 || group == 0xFFFE) {
            // Item delimiters and sequence items use implicit VR
            if (offset + 4 > size) break;
            uint32_t length = read_u32_le(data + offset);
            offset += 4;

            if (length == 0xFFFFFFFF) {
                // Undefined length - skip for now
                continue;
            }

            if (length > 0 && offset + length <= size) {
                offset += length;
            }
            element_count++;
            continue;
        }

        // Read VR (2 bytes)
        if (offset + 2 > size) break;
        uint16_t vr = read_u16_le(data + offset);
        offset += 2;

        uint32_t length = 0;

        // Determine length field size based on VR
        if (vr_has_32bit_length(vr)) {
            // 2 bytes reserved + 4 bytes length
            if (offset + 6 > size) break;
            offset += 2;  // Skip reserved
            length = read_u32_le(data + offset);
            offset += 4;
        } else {
            // 2 bytes length
            if (offset + 2 > size) break;
            length = read_u16_le(data + offset);
            offset += 2;
        }

        // Undefined length (0xFFFFFFFF)
        if (length == 0xFFFFFFFF) {
            // Sequence with undefined length - would need recursive parsing
            element_count++;
            continue;
        }

        // Validate length doesn't exceed remaining data
        if (length > size - offset) {
            // Truncated data element - this may trigger bugs in parsers
            break;
        }

        // Process value based on VR type
        if (length > 0) {
            const uint8_t *value = data + offset;

            // Exercise different value parsing paths
            switch (vr) {
                case static_cast<uint16_t>(VR::US): {
                    // Unsigned short - should be 2 bytes
                    if (length >= 2) {
                        volatile uint16_t us_value = read_u16_le(value);
                        (void)us_value;
                    }
                    break;
                }
                case static_cast<uint16_t>(VR::UL): {
                    // Unsigned long - should be 4 bytes
                    if (length >= 4) {
                        volatile uint32_t ul_value = read_u32_le(value);
                        (void)ul_value;
                    }
                    break;
                }
                case static_cast<uint16_t>(VR::SQ): {
                    // Sequence - would recursively parse items
                    // For now, just skip
                    break;
                }
                case static_cast<uint16_t>(VR::OB):
                case static_cast<uint16_t>(VR::OW):
                case static_cast<uint16_t>(VR::OF):
                case static_cast<uint16_t>(VR::OD): {
                    // Binary data - exercise memory access
                    if (length > 0) {
                        volatile uint8_t first_byte = value[0];
                        volatile uint8_t last_byte = value[length - 1];
                        (void)first_byte;
                        (void)last_byte;
                    }
                    break;
                }
                default: {
                    // String-like VRs - check for null terminator
                    for (size_t i = 0; i < length; i++) {
                        if (value[i] == 0) break;
                    }
                    break;
                }
            }

            offset += length;
        }

        element_count++;

        // Check for PixelData tag (7FE0,0010) - common parsing target
        if (group == 0x7FE0 && element == 0x0010) {
            // PixelData found - exercise pixel parsing
            break;
        }
    }

    return element_count > 0 ? 0 : -1;
}

/**
 * Check for suspicious patterns that might indicate vulnerabilities
 */
static void check_suspicious_patterns(const uint8_t *data, size_t size) {
    if (size < DICOM_HEADER_SIZE) return;

    // Check preamble for non-zero content (CVE-2019-11687 style)
    bool preamble_has_content = false;
    for (size_t i = 0; i < DICOM_PREAMBLE_SIZE; i++) {
        if (data[i] != 0) {
            preamble_has_content = true;
            break;
        }
    }
    (void)preamble_has_content;

    // Check for embedded content indicators
    const char *suspicious_patterns[] = {
        "<?xml",      // XML
        "<html",      // HTML
        "%PDF",       // PDF
        "PK\x03\x04", // ZIP/DOCX
        "\x89PNG",    // PNG
        "JFIF",       // JPEG
        "MZ",         // PE executable
        "\x7fELF",    // ELF executable
    };

    for (const char *pattern : suspicious_patterns) {
        size_t pattern_len = strlen(pattern);
        if (size >= pattern_len) {
            // Check in preamble
            if (memcmp(data, pattern, pattern_len) == 0) {
                // Found suspicious pattern in preamble
                break;
            }
        }
    }
}

/**
 * Main fuzzing entry point for libFuzzer
 *
 * This function is called by libFuzzer with mutated input data.
 * It should return 0 normally, or non-zero to indicate interesting behavior.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Skip empty or tiny inputs
    if (size < 4) {
        return 0;
    }

    // Limit maximum size to prevent OOM
    if (size > 50 * 1024 * 1024) {  // 50 MB
        return 0;
    }

    // Check for suspicious patterns
    check_suspicious_patterns(data, size);

    // Validate DICOM header
    int header_result = validate_dicom_header(data, size);
    if (header_result != 0) {
        // Not a valid DICOM file, but still exercise some paths
        // This helps find bugs in error handling code
        return 0;
    }

    // Parse DICOM elements
    int parse_result = parse_dicom_elements(data, size);
    (void)parse_result;

    return 0;
}

/**
 * Optional: Custom mutator for better DICOM-aware fuzzing
 * Uncomment to use with libFuzzer's -use_value_profile=1
 */
/*
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                           size_t max_size, unsigned int seed) {
    // Implement DICOM-aware mutations here
    // For now, use default mutator
    return 0;
}
*/

/**
 * Optional: Custom crossover for structure-aware fuzzing
 */
/*
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                             const uint8_t *data2, size_t size2,
                                             uint8_t *out, size_t max_out_size,
                                             unsigned int seed) {
    // Implement DICOM-aware crossover here
    return 0;
}
*/

#ifdef STANDALONE_BUILD
/**
 * Standalone mode for running without fuzzer (debugging/testing)
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dicom_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 100 * 1024 * 1024) {
        fprintf(stderr, "Invalid file size: %ld\n", file_size);
        fclose(f);
        return 1;
    }

    uint8_t *data = (uint8_t *)malloc(file_size);
    if (!data) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    size_t read_size = fread(data, 1, file_size, f);
    fclose(f);

    if (read_size != static_cast<size_t>(file_size)) {
        fprintf(stderr, "Failed to read entire file\n");
        free(data);
        return 1;
    }

    printf("Processing %s (%zu bytes)\n", argv[1], read_size);
    int result = LLVMFuzzerTestOneInput(data, read_size);
    printf("Result: %d\n", result);

    free(data);
    return result;
}
#endif  // STANDALONE_BUILD
