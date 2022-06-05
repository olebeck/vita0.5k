
#define align(x,y) (((x) + (y) - 1) & ~((y) - 1))
#define align_lower(x,y) ((x) & ~((y) - 1))

#define UCD(x) \
    do { \
        uc_err err = x; \
        if (err != UC_ERR_OK) { \
            printf(#x " failed with error returned: %u (%s)\n", \
                   err, uc_strerror(err)); \
            exit(1); \
        } \
    } while (0)
