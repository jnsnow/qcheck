#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/param.h>
#include <assert.h>
#include <getopt.h>
#include <time.h>

#include "range.h"

#ifndef ROUND_UP
#define ROUND_UP(n,d) (((n) + (d) - 1) & -(d))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

typedef enum message_type {
    M_RANGE_BEGIN,
    M_ERROR = M_RANGE_BEGIN,      /* Fatal error messages */
    M_WARN,       /* Nonfatal warnings, distinct from analysis problems */
    M_SUMMARY,    /* Analysis summaries */
    M_HELLO,      /* Bootup logging message(s) */
    M_HEADERS,    /* Headers, Progress */
    M_INFO,       /* Misc. output */
    M_PROBLEMS,   /* All problems found, one-by-one */
    M_POSITIVE,   /* Positive confirmation of successful tests */
    M_DEBUG,      /* Debugging messages */
    /* Tables */
    M_HEADER_DATA, /* Dump Header block */
    M_L1_TABLE,   /* Dump entire L1 table, even if uninteresting */
    M_L2_TABLE,   /* Dump entire L2 table, even if uninteresting */
    M_REFTABLE,   /* Dump entire Refcount table, even if uninteresting */
    M_REFBLOCK_2, /* Dump refblock entries at 2+ */
    M_REFBLOCK_1, /* Dump refblock entries at 1 */
    M_REFBLOCK_0, /* Dump refblock entries of 0 */
    /* Ranges */
    M_METADATA,   /* Dump metadata ranges */
    M_DATA,       /* Dump data ranges */
    M_VACANT,     /* Dump vacant ranges */
    M_LEAKED,     /* Dump leaked ranges */
    M_ALLOCATED,  /* Dump allocated (metadata + data) ranges, squashed */
    M_UNALLOCATED, /* Dump unallocated (vacant + leaked) ranges, squashed */
    M_RANGE_ALL,   /* Dump all ranges, unsquashed */
    M_RANGE_END
} message_type;

struct {
    const char *h;
    char c;
} message_filters[M_RANGE_END] = {
    [M_ERROR] =       { "Fatal errors",                            'f' },
    [M_WARN] =        { "Nonfatal errors",                         'w' },
    [M_SUMMARY] =     { "Analysis summaries",                      's' },
    [M_HELLO] =       { "Bootup log message",                      'e' },
    [M_HEADERS] =     { "Section headers",                         'h' },
    [M_INFO] =        { "Info / misc.",                            'i' },
    [M_PROBLEMS] =    { "Detailed problems reports",               'p' },
    [M_POSITIVE] =    { "Successful test messages (Confirmation)", 'c' },
    [M_DEBUG] =       { "Debugging messages",                      'd' },
    [M_HEADER_DATA] = { "qcow2 header information",                'H' },
    [M_L1_TABLE] =    { "L1 table",                                'L' },
    [M_L2_TABLE] =    { "L2 tables",                               'l' },
    [M_REFTABLE] =    { "Refcount Table",                          'R' },
    [M_REFBLOCK_2] =  { "Refcount Block entries (if 2+)",          '2' },
    [M_REFBLOCK_1] =  { "Refcount Block entries (if 1)",           '1' },
    [M_REFBLOCK_0] =  { "Refcount Block entries (if 0)",           '0' },
    [M_METADATA] =    { "Dump metadata rangeset",                  'M' },
    [M_DATA] =        { "Dump guest data rangeset",                'D' },
    [M_VACANT] =      { "Dump vacant rangeset",                    'V' },
    [M_LEAKED] =      { "Dump leaked ([F]orgotten) rangeset",      'F' },
    [M_ALLOCATED] =   { "Dump allocated rangeset",                 'A' },
    [M_UNALLOCATED] = { "Dump unallocated rangeset",               'U' },
    [M_RANGE_ALL]   = { "Dump entire rangeset",                    'E' }
};

#define LMASK(mtype) (1 << (mtype))
#define SMASK (LMASK(M_ERROR) | LMASK(M_WARN) | LMASK(M_DEBUG))
#define MSTREAM(mtype) ((LMASK(mtype) & mtype_stderr) ? stderr : stdout)

#define LOG_SILENT (0)
#define LOG_QUIET (LMASK(M_ERROR) | LMASK(M_WARN))
#define LOG_BASIC (LOG_QUIET | LMASK(M_SUMMARY) | LMASK(M_HEADERS) |    \
                   LMASK(M_INFO) | LMASK(M_HEADER_DATA) | LMASK(M_L1_TABLE) | \
                   LMASK(M_REFTABLE) | LMASK(M_HELLO))
#define LOG_VERBOSE (LOG_BASIC | LMASK(M_PROBLEMS) | LMASK(M_POSITIVE))
#define LOG_DELUGE (-1UL & ~LMASK(M_DEBUG))

/**
 * mtype_stderr: which messages get logged to stderr?
 * mtype_stdout: which get logged to stdout?
 * mlevel: which messages actually get printed at all?
 */
unsigned long mtype_stderr = SMASK;
unsigned long mtype_stdout = -1UL & ~SMASK;
unsigned long mlevel = LOG_BASIC;

#define STREAM_ON(mtype) ((LMASK(mtype) & mlevel) == LMASK(mtype))
#define STREAM_OFF(mtype) ((LMASK(mtype) & mlevel) == 0)

void mvprintf(enum message_type mtype, const char *fmt, va_list va)
{
    if (STREAM_ON(mtype)) {
        vfprintf(MSTREAM(mtype), fmt, va);
    }
}

static __attribute__((format(printf, 2, 3)))
void mprintf(enum message_type mtype, const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    mvprintf(mtype, fmt, va);
    va_end(va);
}

static __attribute__((format(printf, 2, 3)))
void lprintf(enum message_type mtype, const char *fmt, ...)
{
    va_list va;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[20];

    strftime(ts, sizeof(ts), "%F %T", tm);
    mprintf(mtype, "[%s] ", ts);

    va_start(va, fmt);
    mvprintf(mtype, fmt, va);
    va_end(va);
}

char perror_buff[256];

static __attribute__((format(printf, 1, 2)))
void perrorf(const char *fmt, ...)
{
    va_list va;

    strerror_r(errno, perror_buff, sizeof(perror_buff));
    va_start(va, fmt);
    mvprintf(M_ERROR, fmt, va);
    va_end(va);
    mprintf(M_ERROR, ": %s\n", perror_buff);
}

#define msg_error(FMT, ...)   mprintf(M_ERROR, FMT, ##__VA_ARGS__)
#define msg_warn(FMT, ...)    mprintf(M_WARN, FMT, ##__VA_ARGS__)
#define msg_problem(FMT, ...) mprintf(M_PROBLEMS, FMT, ##__VA_ARGS__)
#define msg_ok(FMT, ...)      mprintf(M_POSITIVE, FMT, ##__VA_ARGS__)
#define msg_info(FMT, ...)    mprintf(M_INFO, FMT, ##__VA_ARGS__)

void do_summary(const char *section, int rc, int problems)
{
    mprintf(M_SUMMARY, "%s: ", section);

    if (rc) {
        mprintf(M_SUMMARY, "Could not complete analysis, ");
    }

    if (!rc && !problems) {
        mprintf(M_SUMMARY, "OK, 0 problems");
    } else {
        mprintf(M_SUMMARY, "%d %s found",
                problems,
                problems == 1 ? "problem" : "problems");
    }
    mprintf(M_SUMMARY, "\n");
}

void h1(const char *section)
{
    mprintf(M_HEADERS, "\n\n== %s ==\n\n", section);
}

static __attribute__((format(printf, 1, 2)))
void h2(const char *section, ...)
{
    mprintf(M_HEADERS, "== ");
    va_list va;
    va_start(va, section);
    mvprintf(M_HEADERS, section, va);
    va_end(va);
    mprintf(M_HEADERS, " ==\n");
}


typedef enum rtype {
    RANGE_TYPE_BEGIN = 0,
    RANGE_TYPE_METADATA = RANGE_TYPE_BEGIN,
    RANGE_TYPE_DATA,
    RANGE_TYPE_LEAKED,
    RANGE_TYPE_VACANT,
    RANGE_TYPE_MAX
} rtype;

const char *rtype_lookup[RANGE_TYPE_MAX] = {
    [RANGE_TYPE_METADATA] = "Metadata",
    [RANGE_TYPE_DATA] = "Data",
    [RANGE_TYPE_LEAKED] = "Leaked",
    [RANGE_TYPE_VACANT] = "Vacant"
};

struct qheader {
    unsigned char magic[4];
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;
    uint64_t size;
    uint32_t crypt_method;
    uint32_t l1_size;
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;
} __attribute__((__packed__));

struct qheader3 {
    struct qheader common;
    uint64_t incompatible_features; /* bit 0, 1 */
    uint64_t compatible_features; /* bit 0 */
    uint64_t autoclear_features; /* bit 0 */
    uint32_t refcount_order;
    uint32_t header_length;
} __attribute__((__packed__));

typedef struct l1_entry {
    union {
        uint64_t val;
        struct {
#if BITS_BIG_ENDIAN
            uint64_t cow:1;
            uint64_t reserved:7;
            uint64_t offset:47;
            uint64_t align:9;
#else
            uint64_t align:9;
            uint64_t offset:47;
            uint64_t reserved:7;
            uint64_t cow:1;
#endif
        };
    };
} l1_entry;

typedef uint64_t l2_entry;

typedef struct qfile {
    rangeset *all;                   /* cluster range data */
    /* File Info */
    FILE *fh;                        /* File stream */
    uint64_t cluster_size;           /* Size of clusters in bytes */
    uint64_t file_size;              /* Size of file in bytes */
    uint64_t host_clusters;          /* Size of file in clusters */
    /* References */
    uint16_t *ref_calc;              /* Calculated Refcounts */
    uint16_t *ref_file;              /* Refcounts according to image */
    uint64_t *refcount_table;        /* Refcount table */
    uint64_t refcount_bits;          /* refcount width */
    uint64_t refcount_table_size;    /* actual length of refcount table */
    uint64_t refcount_table_entries; /* total number of refblock pointers */
    uint64_t refcount_block_entries; /* refcounts per block */
    /***************/
    struct qheader *header;
    l1_entry *l1_table;
    uint64_t num_l2_entries;         /* Number of L2 entries per L2 cluster */
} qfile;

/**
 * destroy_qfile: close the qcow2 and clean up all resources.
 */
void destroy_qfile(qfile *qf)
{
    free(qf->l1_table);
    free(qf->refcount_table);
    free(qf->ref_calc);
    free(qf->ref_file);
    delete_rangeset(qf->all);
    free(qf->header);
    if (qf->fh) {
        fclose(qf->fh);
    }
    free(qf);
}

/**
 * new_qfile: Create a new qcow2 file object.
 * @filename: qcow2 object to open and analyze.
 * @return: NULL on error, a valid qfile object otherwise.
 */
qfile *new_qfile(const char *filename)
{
    struct qfile *qf;
    struct stat finfo;
    int rc;

    qf = (struct qfile *)calloc(1, sizeof(qfile));
    if (!qf) {
        perrorf("Failed to allocate storage for qfile object");
        return NULL;
    }

    qf->all = new_rangeset(1024);
    if (!qf->all) {
        goto error;
    }

    qf->fh = fopen(filename, "r");
    if (!qf->fh) {
        perrorf("Couldn't open file");
        goto error;
    }

    rc = fstat(fileno(qf->fh), &finfo);
    if (rc) {
        perrorf("Couldn't stat file");
        goto error;
    }
    qf->file_size = finfo.st_size;

    return qf;

 error:
    destroy_qfile(qf);
    return NULL;
}

/**
 * overlap: Check if the specified range overlaps existing ranges in a set.
 * @qf: qcow2 file whose rangeset we will operate against
 * @offset: Byte offset into file
 * @len: Length of the range
 * @return: 0 if there is no overlap, 1 otherwise.
 */
int overlap(qfile *qf, uint64_t offset, uint64_t len)
{
    return range_overlap(qf->all, offset, len, NULL);
}

/**
 * overlap_cluster: Check if the specified cluster overlaps
 *                  existing ranges in a set.
 * @qf: qcow2 file whose rangeset to check against
 * @offset: Offset in bytes of the cluster
 * @return: 0 if there is no overlap, 1 otherwise.
 */
int overlap_cluster(qfile *qf, uint64_t offset)
{
    return overlap(qf, offset, qf->cluster_size);
}

/**
 * add_host_range: define a new range in the host qcow2 file.
 * @qf: The qcow2 file object to define a new range within.
 * @offset: The host offset in the qcow2 file that starts the range, in bytes.
 * @len: The length of the range, in bytes.
 * @rtype: The 'type' of the range. See @rtype
 * @r: Return parameter for the conflicting range, if any.
 * @return: 0 if the range was added successfully.
 *          1 if the range could not be added due to overlap; see @r.
 *          -ERRNO if there was an unrecoverable error.
 */
int add_host_range(qfile *qf, uint64_t offset, uint64_t len, rtype type,
                   const range **r)
{
    int rc;

    if (!qf) {
        return -EINVAL;
    }

    rc = add_range(qf->all, offset, len, (1 << type), r);
    if (rc > 0) {
        msg_error("Unable to add range [0x%"PRIx64", 0x%"PRIx64"): "
                  "Collision against typemask %x\n",
                  offset, offset + len, rc);
        /* "one" error */
        return 1;
    }

    return rc; /* 0 or -errno */
}

/**
 * add_host_cluster: Syntactic sugar for @add_host_range.
 */
int add_host_cluster(qfile *qf, uint64_t offset, rtype type,
                     const range **r)
{
    if (!qf) {
        return -EINVAL;
    }
    return add_host_range(qf, offset, qf->cluster_size, type, r);
}

struct filter {
    qfile *qf;
    int typemask;
    int squash;
    int showtypes;
    uint64_t clusters;

    range tmp;
    int squashtypes;
    enum message_type msg_type;
};

/**
 * print_range: print a given range [r]
 *              Used as a callback by @print_rangset
 * @r: The range to print
 * @opaque: Callback information; a pointer to `struct filter` in this case.
 * @return: 0.
 */
int print_range(const range *r, void *opaque)
{
    struct filter *cfg = (struct filter *)opaque;
    int i;
    uint64_t clusters = r->length / cfg->qf->cluster_size;
    mask_t typemask = r->typemask;

    if (!(r->typemask & cfg->typemask)) {
        return 0;
    }

    if (cfg->squash) {
        if (cfg->tmp.end == r->offset) {
            cfg->tmp.end = r->end;
            cfg->tmp.length += r->length;
            cfg->squashtypes |= r->typemask;
            return 0;
        }
    }

    mprintf(cfg->msg_type, "0x%09"PRIx64" - 0x%09"PRIx64" ",
            r->offset,
            r->end - 1);
    if (cfg->showtypes) {
        for (i = RANGE_TYPE_BEGIN; i < RANGE_TYPE_MAX && typemask; i++) {
            if (typemask & (1 << i)) {
                mprintf(cfg->msg_type, "[%s] ", rtype_lookup[i]);
                typemask &= ~(1 << i);
            }
        }
    }
    if (clusters > 1) {
        mprintf(cfg->msg_type, "(%"PRId64" clusters)\n", clusters);
    } else {
        mprintf(cfg->msg_type, "\n");
    }
    cfg->clusters += clusters;
    return 0;
}

/* TODO: make 'squash' work as a setting */

/**
 * print_rangeset: print the ranges of the file occupied by a specified
 *                 type or types of data.
 * @qf: The (analyzed) file to print the ranges for.
 * @title: The title to print for this section.
 * @typemask: The type mask that selects which ranges to print.
 *            E.g. RANGE_TYPE_METADATA.
 * @showtypes: Boolean: display the type of each range next to it?
 * @squash: Boolean: "merge" adjacent ranges? If more than one type
 *          is selected, the "type display" will show only e.g.
 *          which types are present in this squashed range.
 * @msg_type: Which logging stream should this rangeset be printed to?
 *            Headers and summaries go to M_HEADERS and M_SUMMARY,
 *            but the rangeset itself will be printed to this stream.
 */
void print_rangeset(qfile *qf, const char *title, int typemask,
                    int showtypes, int squash, enum message_type msg_type)
{
    struct filter *cfg;

    if (!qf || !qf->all || STREAM_OFF(msg_type)) {
        return;
    }

    cfg = (struct filter *)malloc(sizeof(struct filter));
    cfg->qf = qf;
    cfg->typemask = typemask;
    cfg->squash = squash;
    cfg->showtypes = showtypes;
    cfg->clusters = 0;
    cfg->msg_type = msg_type;

    h1(title);
    range_traversal(qf->all, T_INORDER, print_range, cfg);
    h2("%s stats", title);
    mprintf(msg_type, "%"PRId64" clusters\n\n", cfg->clusters);
    free(cfg);
}

/**
 * qref_bump: increment reference count of cluster at given offset
 * @qf: qfile object to increment the refcount within
 * @offset: offset in bytes of the cluster to increment the refcount of
 * @return: 0 if we incremented the refcount, -ERRNO on failure.
 */
int qref_bump(qfile *qf, uint64_t offset)
{
    uint64_t cluster_no;

    if (!qf || !qf->ref_calc) {
        return -EINVAL;
    }

    if (offset % qf->cluster_size) {
        msg_error("Offset Misaligned, cannot bump refcount\n");
        return -EINVAL;
    }
    cluster_no = offset / qf->cluster_size;
    if (cluster_no >= qf->host_clusters) {
        msg_error("BEYOND EOF, cannot bump refcount\n");
        return -EINVAL;
    }
    qf->ref_calc[cluster_no] += 1;
    return 0;
}

/**
 * qref_dump: dump all calculated refcounts to M_DEBUG/stdout
 * @qf: pre-analyzed file to dump refcounts for
 */
__attribute__((__unused__))
void qref_dump(qfile *qf)
{
    int i;
    for (i = 0; i < qf->host_clusters; i++) {
        if (qf->ref_calc[i]) {
            mprintf(M_DEBUG, "%d: %d\n", i, qf->ref_calc[i]);
        }
    }
}

/* Generally, functions return -ERRNO on error,
 * and +rc on some analysis failure. */
#define CHECK_RC(rc, ret, jlabel) do {          \
        if ((rc) < 0) {                         \
            goto jlabel;                        \
        } else {                                \
            (ret) += (rc);                      \
        }                                       \
    } while(0)

/* sigh */
size_t fread_errno(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t rc = fread(ptr, size, nmemb, stream);
    if (rc != nmemb) {
        /* Treat EOF as an error; we can't get the data we want. */
        errno = EIO;
    }
    clearerr(stream);
    return rc;
}

/******************************************************************************/
/*                        Header Parsing & Analysis                           */
/******************************************************************************/


/**
 * parse_header_v3: parse the v3 header if present.
 * @qf: the qcow2 object to parse.
 * @return: -errno on failure, 0 on success.
 */
int parse_header_v3(qfile *qf)
{
    int rc;
    struct qheader3 *buff;

    if (!qf || !qf->header || qf->header->version != 3) {
        return -EINVAL;
    }

    buff = (struct qheader3 *)qf->header;

    rc = fseek(qf->fh, sizeof(struct qheader), SEEK_SET);
    if (rc) {
        rc = -errno;
        perrorf("fseek to qcow2 v3 header failed");
        return rc;
    }

    rc = fread_errno(&buff->incompatible_features,
                     sizeof(struct qheader3) - sizeof(struct qheader),
                     1, qf->fh);
    if (rc != 1) {
        rc = -errno;
        perrorf("Couldn't read qcow2v3 header");
        return rc;
    }

    *buff = (struct qheader3) {
        .common = buff->common,
        .incompatible_features = be64toh(buff->incompatible_features),
        .compatible_features = be64toh(buff->compatible_features),
        .autoclear_features = be64toh(buff->autoclear_features),
        .refcount_order = be32toh(buff->refcount_order),
        .header_length = be32toh(buff->header_length),
    };

    qf->refcount_bits = (1 << buff->refcount_order);
    return 0;
}

/**
 * parse_header: read and cache important global details of the qcow2.
 * @qf: qfile object to analyze
 * @return: 0 on success, -errno on failure.
 *          Does not perform any soft analysis or report recoverable errors.
 */
int parse_header(qfile *qf)
{
    int rc;
    struct qheader *header;

    if (!qf) {
        return -EINVAL;
    }

    qf->header = (struct qheader *)malloc(sizeof(struct qheader3));
    if (!qf->header) {
        rc = -errno;
        perrorf("Could not allocate buffer for QCOW2 header block");
        goto out;
    }

    rc = fread_errno(qf->header, sizeof(struct qheader), 1, qf->fh);
    if (rc != 1) {
        rc = -errno;
        perrorf("Could not read QCOW2 header block");
        goto error;
    }
    header = qf->header;

    *qf->header = (struct qheader) {
        .magic = { header->magic[0], header->magic[1],
                   header->magic[2], header->magic[3] },
        .version = be32toh(header->version),
        .backing_file_offset = be64toh(header->backing_file_offset),
        .backing_file_size = be32toh(header->backing_file_size),
        .cluster_bits = be32toh(header->cluster_bits),
        .size = be64toh(header->size),
        .crypt_method = be32toh(header->crypt_method),
        .l1_size = be32toh(header->l1_size),
        .l1_table_offset = be64toh(header->l1_table_offset),
        .refcount_table_offset = be64toh(header->refcount_table_offset),
        .refcount_table_clusters = be32toh(header->refcount_table_clusters),
        .nb_snapshots = be32toh(header->nb_snapshots),
        .snapshots_offset = be64toh(header->snapshots_offset),
    };

    if (header->version >= 3) {
        rc = parse_header_v3(qf);
        if (rc) {
            goto error;
        }
    } else {
        qf->refcount_bits = 16;
    }

    /* Derivative Data */
    qf->cluster_size = 1 << header->cluster_bits;
    qf->host_clusters = DIV_ROUND_UP(qf->file_size, qf->cluster_size);
    qf->refcount_block_entries = (qf->cluster_size * 8) / qf->refcount_bits;
    qf->num_l2_entries = qf->cluster_size / sizeof(l2_entry);

    /* Refcount Tables -- Calculated and Read */
    qf->ref_calc = (uint16_t *)calloc(qf->host_clusters, sizeof(*qf->ref_calc));
    if (!qf->ref_calc) {
        rc = -errno;
        perrorf("Couldn't allocate reference count table");
        goto error;
    }

    return 0;
 error:
    free(qf->header);
    qf->header = NULL;
 out:
    return rc;
}

/**
 * print_header: Print the header info to a stream in a readable format.
 * @qf: qcow2 file object with a parsed header to print.
 * @stream: Where to print.
 */
void print_header(qfile *qf)
{
    struct qheader *header;
    if (!qf || !qf->header) {
        return;
    }
    header = qf->header;

    h1("Header");
    mprintf(M_HEADER_DATA,
            "magic: 0x%x%x%x%x\n"
            "version: %d\n"
            "backing_file_offset: 0x%"PRIx64"\n"
            "backing_file_size: 0x%x (filename length, bytes)\n"
            "cluster_bits: %d (cluster size: %"PRId64" bytes)\n"
            "size: 0x%"PRIx64" / %"PRId64" (bytes)\n"
            "crypt_method: 0x%08x (%s)\n"
            "l1_size: (num entries) 0x%x (Clusters: %"PRIx64")\n"
            "l1_table_offset: 0x%"PRIx64" (Cluster Index 0x%"PRIx64")\n"
            "refcount_table_offset: 0x%"PRIx64" (Cluster Index 0x%"PRIx64")\n"
            "refcount_table_clusters: 0x%x\n"
            "nb_snapshots: %d\n"
            "snapshots_offset: 0x%"PRIx64"\n",
            header->magic[0], header->magic[1],
            header->magic[2], header->magic[3],
            header->version,
            header->backing_file_offset,
            header->backing_file_size,
            header->cluster_bits,
            qf->cluster_size,
            header->size,
            header->size,
            header->crypt_method,
            (header->crypt_method == 0) ? "None" : "AES",
            header->l1_size,
            DIV_ROUND_UP(sizeof(uint64_t) * header->l1_size, qf->cluster_size),
            header->l1_table_offset,
            header->l1_table_offset / qf->cluster_size,
            header->refcount_table_offset,
            header->refcount_table_offset / qf->cluster_size,
            header->refcount_table_clusters,
            header->nb_snapshots,
            header->snapshots_offset);

    h2("Derivative Data");
    mprintf(M_HEADER_DATA, "Host Clusters: %"PRId64"\n", qf->host_clusters);
    mprintf(M_HEADER_DATA, "File Size: 0x%016"PRIx64"\n", qf->file_size);
}

/**
 * analyze_header: check header metadata for issues,
 *                 including metadata range bookkeeping steps.
 * @qf: qcow2 file with parsed header to analyze.
 * @return: -EINVAL if the qfile is absent or the header was not parsed.
 *          0 if there are no issues found.
 *          The number of issues found otherwise.
 */
int analyze_header(qfile *qf)
{
    int rc, ret = 0;
    struct qheader *header;

    if (!qf || !qf->header) {
        return -EINVAL;
    }
    header = qf->header;

    h1("Header Analysis");

    /* Reference counting calculation */
    rc = qref_bump(qf, 0);
    CHECK_RC(rc, ret, error);
    rc = qref_bump(qf, header->l1_table_offset);
    CHECK_RC(rc, ret, error);
    rc = qref_bump(qf, header->refcount_table_offset);
    CHECK_RC(rc, ret, error);

    /* Metadata range bookkeeping */
    rc = add_host_cluster(qf, 0, RANGE_TYPE_METADATA, NULL);
    CHECK_RC(rc, ret, error);
    rc = add_host_range(qf, header->l1_table_offset,
                        DIV_ROUND_UP(sizeof(l1_entry) * header->l1_size,
                                     qf->cluster_size) * qf->cluster_size,
                        RANGE_TYPE_METADATA, NULL);
    CHECK_RC(rc, ret, error);
    rc = add_host_range(qf, header->refcount_table_offset,
                        header->refcount_table_clusters * qf->cluster_size,
                        RANGE_TYPE_METADATA, NULL);
    CHECK_RC(rc, ret, error);

    if (header->snapshots_offset) {
        rc = qref_bump(qf, header->snapshots_offset);
        CHECK_RC(rc, ret, error);
        /* FIXME: How many clusters for snapshots table? */
        rc = add_host_cluster(qf, header->snapshots_offset,
                              RANGE_TYPE_METADATA, NULL);
        CHECK_RC(rc, ret, error);
    }


    /* Misc Checks */
    if (memcmp(&header->magic, "QFI\xfb", 4) == 0) {
        msg_ok("Magic OK\n");
    } else {
        msg_problem("Bad header Magic\n");
        ret++;
    }

    if (qf->cluster_size < 512) {
        msg_problem("Bad cluster size, too small.\n");
        ret++;
    } else if (qf->cluster_size > (2 * 1024 * 1024)) {
        msg_problem("Warning, cluster size is too big for QEMU.\n");
        ret++;
    } else {
        msg_ok("Cluster size OK.\n");
    }

    if (header->l1_table_offset % qf->cluster_size) {
        msg_problem("L1 table misalinged\n");
        ret++;
    } else {
        msg_ok("L1 table OK\n");
    }

    if (header->refcount_table_offset % qf->cluster_size) {
        msg_problem("Refcount table misaligned\n");
        ret++;
    } else {
        msg_ok("Refcount table OK\n");
    }

    if (header->nb_snapshots) {
        if (header->snapshots_offset % qf->cluster_size) {
            msg_problem("Snapshots table misaligned\n");
            ret++;
        } else {
            msg_ok("Snapshots table OK, cluster index %"PRId64"\n",
                   header->snapshots_offset);
        }
    } else {
        msg_info("No snapshots or snapshots table.\n");
    }

 error:
    do_summary("Header", rc, ret);
    return rc ? rc : ret;
}

/**
 * print_header_v3: Print the header info to a stream in a readable format.
 * @qf: qcow2 file object with a parsed header to print.
 * @stream: Where to print.
 */
void print_header_v3(qfile *qf)
{
    struct qheader3 *buff;

    if (!qf || !qf->header || qf->header->version != 3) {
        return;
    }

    buff = (struct qheader3 *)qf->header;
    h1("Header (v3)");
    mprintf(M_HEADER_DATA,
            "incompatible_features: 0x%"PRIx64"\n"
            "compatible_features: 0x%"PRIx64"\n"
            "autoclear_features: 0x%"PRIx64"\n"
            "refcount_order: %d\n"
            "header_length: %d\n",
            buff->incompatible_features,
            buff->compatible_features,
            buff->autoclear_features,
            buff->refcount_order,
            buff->header_length);
}

/**
 * analyze_header_v3: check header metadata for issues.
 * @qf: qcow2 file with parsed header to analyze.
 * @return: -EINVAL if the qfile is absent, header was not parsed,
 *          or if the header version was not 3.
 *          -ENOTSUP if the refcount width is not 4.
 *          0 if there are no issues found,
 *          The number of issues found otherwise.
 */
int analyze_header_v3(qfile *qf)
{
    int ret = 0;
    struct qheader3 *header;

    if (!qf || !qf->header || (qf->header->version != 3)) {
        return -EINVAL;
    }
    header = (struct qheader3 *)qf->header;

    if (header->refcount_order != 4) {
        msg_error("refcnt tool can't cope with refcount_bits != 4\n");
        return -ENOTSUP;
    }

    if (header->header_length != sizeof(struct qheader3)) {
        msg_problem("header_length (%d) is not what we think it is (%zu)\n",
                    header->header_length,
                    sizeof(struct qheader3));
        ret++;
    }

    do_summary("Header (v3)", 0, ret);
    return ret;
}


/******************************************************************************/
/*                       Refcount Parsing & Analysis                          */
/******************************************************************************/


/**
 * parse_refcount_table: Read the reference count table into memory.
 * @qf: The qcow2 file to obtain the refcount table of.
 * @return: 0 on success, -ERRNO on critical failure.
 *          Does not perform soft analysis.
 */
int parse_refcount_table(qfile *qf)
{
    int rc, i;
    struct qheader *header;

    if (!qf || !qf->header) {
        return -EINVAL;
    }

    header = qf->header;
    /* refcount_table_size is the total number of refcount block pointers we can
     * store in the reference count table.
     * refcount_table_entries is the total number of refcount block pointers we
     * expect to see given the length of the host file.
     */
    qf->refcount_table_size = (header->refcount_table_clusters *        \
                               qf->cluster_size) / sizeof(uint64_t);
    qf->refcount_table_entries = DIV_ROUND_UP(qf->host_clusters,
                                              qf->refcount_block_entries);

    rc = fseek(qf->fh, header->refcount_table_offset, SEEK_SET);
    if (rc) {
        rc = -errno;
        perrorf("Couldn't seek to refcount table");
        return rc;
    }

    qf->refcount_table = (uint64_t *)malloc(sizeof(*qf->refcount_table) *
                                            MAX(qf->refcount_table_size,
                                                qf->refcount_table_entries));
    if (!qf->refcount_table) {
        rc = -errno;
        perrorf("Couldn't allocate space for reference count table");
        return rc;
    }

    rc = fread_errno(qf->refcount_table, sizeof(*qf->refcount_table),
                     qf->refcount_table_size, qf->fh);
    if (rc != qf->refcount_table_size) {
        rc = -errno;
        perrorf("Couldn't read refcount table");
        free(qf->refcount_table);
        qf->refcount_table = NULL;
        return rc;
    }

    for (i = 0; i < qf->refcount_table_size; i++) {
        if (qf->refcount_table[i]) {
            qf->refcount_table[i] = be64toh(qf->refcount_table[i]);
        }
    }

    return 0;
}

enum reftable_errors {
    R_BEGIN,
    R_MISALIGNED = R_BEGIN,
    R_OUT_OF_BOUNDS,
    R_BEYOND_EOF,
    R_MAX
};

/* Refblock pointer %s */
const char *reftable_errors[R_MAX] = {
    [R_MISALIGNED] = "is not aligned to a cluster boundary",
    [R_OUT_OF_BOUNDS] = "is beyond EOF or overruns EOF",
    [R_BEYOND_EOF] = "implies reference counts for clusters beyond EOF",
};

/**
 * analyze_refcount_table: Investigate a parsed refcount table for potential
 * issues, including pointer alignment, range overlap and refcount analysis.
 * @qf: the qcow2 file whose refcount table to analyze
 * @return: 0 on success, -ERRNO on unrecoverable error.
 *          The number of issues found otherwise.
 */
int analyze_refcount_table(qfile *qf)
{
    int i, j;
    int ret = 0;
    int rc = 0;
    enum message_type table_msg_type;

    if (!qf || !qf->refcount_table || !qf->header) {
        return -EINVAL;
    }

    h1("Refcount Table");

    if (qf->refcount_table_size < qf->refcount_table_entries) {
        msg_problem("Error: refcount_table_clusters is insufficiently small"
                    " (%d) and can only hold %"PRId64" pointers, but at "
                    "least %"PRId64" are needed as determined by the size of "
                    "the file.\n",
                    qf->header->refcount_table_clusters,
                    qf->refcount_table_size,
                    qf->refcount_table_entries);
        ret++;
    }

    for (i = 0; i < qf->refcount_table_size; i++) {
        uint64_t offset, idx, errors;

        if (!qf->refcount_table[i]) {
            continue;
        }

        offset = qf->refcount_table[i];
        idx = offset / qf->cluster_size;
        errors = 0;
        errors |= (offset % qf->cluster_size) ? (1 << R_MISALIGNED) : 0;
        errors |= (offset > qf->file_size) ? (1 << R_OUT_OF_BOUNDS) : 0;
        errors |= (i > qf->refcount_table_entries) ? (1 << R_BEYOND_EOF) : 0;

        rc = qref_bump(qf, offset);
        CHECK_RC(rc, ret, error);
        rc = add_host_cluster(qf, offset, RANGE_TYPE_METADATA, NULL);
        CHECK_RC(rc, ret, error);

        /* If we have errors but aren't printing the table, make sure we print
         * the entry as a Problem, at least. */
        if (errors && STREAM_OFF(M_REFTABLE)) {
            table_msg_type = M_PROBLEMS;
        } else {
            table_msg_type = M_REFTABLE;
        }

        mprintf(table_msg_type,
                "0x%x: 0x%"PRIx64" (host cluster 0x%"PRIx64" for clusters "
                "[0x%"PRIx64" - 0x%"PRIx64"]\n",
                i, offset, idx,
                i * qf->refcount_block_entries,
                (i + 1) * qf->refcount_block_entries - 1);

        for (j = R_BEGIN; errors && j < R_MAX; j++) {
            if (errors & (1 << j)) {
                msg_problem("Error: Refblock pointer [%d] (%"PRIx64") %s\n",
                            i, offset,
                            reftable_errors[j]);
                ret++;
                errors &= ~(1 << j);
            }
        }
    }

 error:
    do_summary("Refcount Table", rc, ret);
    return rc ? rc : ret;
}

/**
 * buffer_refcount_block: Read in a particular refcount block.
 * Does not correct endianness of the block. (Hence 'buffer' and not 'parse'.)
 * @qf: Qcow2 file to read.
 * @entry: The index of the refcount table we're reading.
 * @refblock: Buffer to read into.
 * @return: 0 on success, -errno on unrecoverable error.
 */
int buffer_refcount_block(qfile *qf, int entry, uint16_t *refblock)
{
    int rc;
    uint64_t offset;

    if (!qf || !qf->fh || !qf->refcount_table) {
        return -EINVAL;
    }

    offset = qf->refcount_table[entry];
    rc = fseek(qf->fh, offset, SEEK_SET);
    if (rc) {
        rc = -errno;
        perrorf("Couldn't seek to refcount block");
        return rc;
    }

    rc = fread_errno(refblock, sizeof(*refblock),
                     qf->refcount_block_entries, qf->fh);
    if (rc != qf->refcount_block_entries) {
        rc = -errno;
        perrorf("Couldn't read reference block");
        return rc;
    }

    return 0;
}

/**
 * analyze_refcount_block: Analyze a reference count block for inconsistencies.
 * @qf: qcow2 file associated with this reference count block
 * @entry: Index in the reference count table this block belongs to
 * @refblock: Buffered, big-endian refcount block to analyze.
 * @return: 0 on success, -errno on unrecoverable error.
 *          The number of errors found otherwise.
 */
int analyze_refcount_block(qfile *qf, int entry,
                           uint16_t *refblock)
{
    int j, refcount;
    int ret = 0;
    uint64_t cluster;
    unsigned char eof;
    enum message_type refblock_msg_type;

    if (!qf || !refblock || !qf->ref_file) {
        return -EINVAL;
    }

    h2("Refcount Block %d", entry);

    for (j = 0; j < qf->refcount_block_entries; j++) {
        refcount = be16toh(refblock[j]);
        cluster = entry * qf->refcount_block_entries + j;
        eof = !!(refcount && (cluster >= qf->host_clusters));

        if (refcount == 0) {
            refblock_msg_type = M_REFBLOCK_0;
        } else if (refcount == 1) {
            refblock_msg_type = M_REFBLOCK_1;
        } else {
            refblock_msg_type = M_REFBLOCK_2;
        }

        if (eof && STREAM_OFF(refblock_msg_type)) {
            refblock_msg_type = M_PROBLEMS;
        }

        mprintf(refblock_msg_type,
                "0x%04x, cluster 0x%08"PRIx64": %d\n",
                j, cluster, refcount);

        if (!refblock[j]) {
            continue;
        }

        if (eof) {
            msg_problem("Refcount for cluster beyond EOF (0x%"PRIx64")\n",
                        cluster);
            ret++;
        }

        qf->ref_file[cluster] = refcount;
    }

    return ret;
}

/**
 * parse_and_analyze_refcount_blocks: Parses, then analyzes every refcount block
 *     present within the already-parsed refcount table.
 * @qf: Qcow2 file to parse/analyze.
 * @return: 0 on success, -ERRNO on unrecoverable failure.
 *          The number of errors found otherwise.
 */
int parse_and_analyze_refcount_blocks(struct qfile *qf)
{
    uint16_t *refblock = NULL;
    int i;
    int ret = 0;
    int rc = 0;

    if (!qf || !qf->refcount_table) {
        return -EINVAL;
    }

    h1("Refcount Blocks");

    qf->ref_file = (uint16_t *)calloc(qf->host_clusters, sizeof(*qf->ref_file));
    if (!qf->ref_file) {
        rc = -errno;
        perrorf("Couldn't allocate reference count cache");
        return rc;
    }

    refblock = (uint16_t *)malloc(qf->cluster_size);
    if (!refblock) {
        rc = -errno;
        perrorf("Couldn't allocate memory for refblocks");
        goto out;
    }

    for (i = 0; i < qf->refcount_table_entries; i++) {
        if (!qf->refcount_table[i]) {
            continue;
        }
        rc = buffer_refcount_block(qf, i, refblock);
        CHECK_RC(rc, ret, out);
        rc = analyze_refcount_block(qf, i, refblock);
        CHECK_RC(rc, ret, out);
    }

 out:
    do_summary("Refblocks", rc, ret);
    free(refblock);
    if (rc) {
        free(qf->ref_file);
        qf->ref_file = NULL;
    }
    return rc ? rc : ret;
}


/******************************************************************************/
/*                       L1 & L2 Parsing & Analysis                           */
/******************************************************************************/

enum L1_ERRORS {
    L1_BEGIN,
    L1_MISALIGNED = L1_BEGIN,
    L1_OUT_OF_BOUNDS,
    L1_OVERLAP,
    L1_RESERVED,
    L1_EMPTY_FLAGS,
    L1_END
};

const char *l1_errors[L1_END] = {
    [L1_MISALIGNED] = "has a misaligned pointer",
    [L1_OUT_OF_BOUNDS] = "implies a cluster beyond EOF",
    [L1_OVERLAP] = "points to a cluster already in use",
    [L1_RESERVED] = "has reserved bits set",
    [L1_EMPTY_FLAGS] = "has an empty pointer, but L1 flags set"
};

/**
 * parse_l1_table: read the L1 table from file into memory for analysis.
 * @qf: Qcow2 file to read L1 table of.
 * @return: 0 on success, -errno otherwise.
 *          Does not perform any analysis.
 */
int parse_l1_table(qfile *qf)
{
    int rc, i;
    struct qheader *header;

    if (!qf || !qf->header) {
        return -EINVAL;
    }

    header = qf->header;
    rc = fseek(qf->fh, header->l1_table_offset, SEEK_SET);
    if (rc) {
        rc = -errno;
        perrorf("Couldn't seek to L1 table");
        return rc;
    }

    qf->l1_table = (l1_entry *)malloc(sizeof(l1_entry) * header->l1_size);
    if (!qf->l1_table) {
        rc = -errno;
        perrorf("Couldn't allocate L1 table");
        return rc;
    }

    rc = fread_errno(qf->l1_table, sizeof(l1_entry), header->l1_size, qf->fh);
    if (rc != header->l1_size) {
        rc = -errno;
        perrorf("Failed to read L1 table");
        free(qf->l1_table);
        return rc;
    }

    for (i = 0; i < header->l1_size; i++) {
        qf->l1_table[i].val = be64toh(qf->l1_table[i].val);
    }

    return 0;
}

/**
 * analyze_l1_table: validate the pointers and ranges of pointers in the
 *                   buffered l1 table.
 * @qf: Qcow2 file whose L1 table we should analyze.
 * @return: 0 on success,
 *          -errno on critical failure,
 *          the number of issues found otherwise.
 */
int analyze_l1_table(qfile *qf)
{
    int i, j;
    int rc = 0;
    int ret = 0;
    struct qheader *header;
    uint64_t l1_ent, l1_ptr;
    uint64_t errors;
    enum message_type msg_type;

    if (!qf || !qf->header || !qf->l1_table) {
        return -EINVAL;
    }

    h1("L1 Table");

    header = qf->header;
    for (i = 0; i < header->l1_size; i++) {
        l1_ent = qf->l1_table[i].val;
        l1_ptr = l1_ent & 0x00ffffffffffffff;

        if (!l1_ent) {
            mprintf(M_L1_TABLE, "0x%02x: [EMPTY]\n", i);
            continue;
        }

        errors = (l1_ptr % qf->cluster_size) ? (1 << L1_MISALIGNED) : 0;
        errors |= (overlap_cluster(qf, l1_ptr)) ? (1 << L1_OVERLAP) : 0;
        errors |= (l1_ptr & 0x7f00000000000000) ? (1 << L1_RESERVED) : 0;
        errors |= (l1_ptr >= qf->file_size) ? (1 << L1_OUT_OF_BOUNDS) : 0;
        /* Add the EOF check, too? or make this more robust... ? */
        errors |= (!l1_ptr && l1_ent) ? (1 << L1_EMPTY_FLAGS) : 0;

        /* If there are errors and we are not printing the table, print this
         * entry in the table as an error for reference. */
        msg_type = (errors && STREAM_OFF(M_L1_TABLE)) ? M_PROBLEMS : M_L1_TABLE;

        mprintf(msg_type, "0x%02x: 0x%016"PRIx64" offset 0x%016"PRIx64"; "
                "cluster idx 0x%"PRIx64"\n",
                i, l1_ent, l1_ptr, l1_ptr / qf->cluster_size);

        for (j = L1_BEGIN; errors && j < L1_END; j++) {
            if (errors & (1 << j)) {
                mprintf(M_PROBLEMS, "Error: L1 entry %s\n",
                        l1_errors[j]);
                ret++;
                errors &= ~(1 << j);
            }
        }

        /* Don't perform any book-keeping for pointers that appear broken */
        if (l1_ptr && ret == 0) {
            rc = qref_bump(qf, l1_ptr);
            CHECK_RC(rc, ret, out);
            rc = add_host_cluster(qf, l1_ptr, RANGE_TYPE_METADATA, NULL);
            CHECK_RC(rc, ret, out);
        }
    }

 out:
    do_summary("L1 table", rc, ret);
    return rc ? rc : ret;
}

/**
 * buffer_l2_cluster: Read in a particular L2 cluster.
 *                    Does not correct endianness of the block, 'buffer' only.
 * @qf: qcow2 file to read L2 block from.
 * @l1_index: The index into the L1 table that points to the L2 cluster we want.
 * @l2_cache: The buffer to read the cluster into.
 * @return: 0 on success,
 *          -errno on unrecoverable problem.
 */
int buffer_l2_cluster(qfile *qf, uint64_t ptr, l2_entry *l2_cache)
{
    int rc;

    if (!qf || !qf->fh || !ptr) {
        return -EINVAL;
    }

    rc = fseek(qf->fh, ptr, SEEK_SET);
    if (rc) {
        rc = -errno;
        perrorf("Couldn't seek to L2 cluster");
        return rc;
    }

    rc = fread_errno(l2_cache, sizeof(l2_entry), qf->num_l2_entries, qf->fh);
    if (rc != qf->num_l2_entries) {
        rc = -errno;
        perrorf("Couldn't read L2 block");
        return rc;
    }

    return 0;
}

enum L2_ERRORS {
    L2_BEGIN,
    L2_MISALIGNED = R_BEGIN,
    L2_OUT_OF_BOUNDS,
    L2_OVERLAP,
    L2_RESERVED,
    L2_EMPTY_FLAGS,
    L2_CONFLICT,
    L2_EXTRA_COPIED,
    L2_MISSING_COPIED,
    L2_TOO_LONG,
    L2_MAX
};

/* L2 Entry %s */
const char *l2_errors[L2_MAX] = {
    [L2_MISALIGNED] = "has a misaligned pointer",
    [L2_OUT_OF_BOUNDS] = "implies a cluster beyond EOF",
    /* What about something that runs off the end of the file? */
    [L2_OVERLAP] = "overlaps existing data",
    [L2_RESERVED] = "has reserved bits set",
    [L2_EMPTY_FLAGS] = "has an empty pointer, but L2 flags set",
    [L2_CONFLICT] = "has both compressed and copied bits set",
    [L2_EXTRA_COPIED] = "has more than one reference, but copy bit is set",
    [L2_MISSING_COPIED] = "has only one reference, but copy bit is empty",
    [L2_TOO_LONG] = "has a compressed size greater than one cluster",
};

/**
 * analyze_l2_cluster: analyze a buffered l2 cluster for issues.
 * @qf: Qcow2 file whose L2 cluster is to be analyzed
 * @l1_index: l1_index that points to the L2 cluster to be analyzed
 * @l2_cache: The buffered, big-endian L2 cluster to be analyzed.
 * @return: 0 on success,
 *          -errno on unrecoverable error,
 *          the number of issues detected otherwise.
 */
int analyze_l2_cluster(qfile *qf, int l1_index, l2_entry *l2_cache)
{
    int i, j, rc, ret = 0;
    int nz = 0;
    int cr = 0;
    enum message_type msg_type;

    if (!qf || !l2_cache) {
        return -EINVAL;
    }

    for (i = 0; i < qf->num_l2_entries; i++) {
        uint64_t l2_ent = be64toh(l2_cache[i]);
        uint64_t l2_ptr = l2_ent & 0x00fffffffffffe00;
        uint64_t errors = 0;
        uint16_t refcnt;
        /* features of interest */
        char compressed, copied, zeroes = 0;
        uint64_t len = qf->cluster_size;

        if (!l2_ent) {
            continue;
        }

        nz++;

        /* Bits 63 and 62 are valid for all L2 entry types. */
        compressed = !!(l2_ent & 0x4000000000000000);
        copied = !!(l2_ent & 0x8000000000000000);

        if (compressed) {
            int shift = 62 - (qf->header->cluster_bits - 8);
            int csize_mask = (1 << (qf->header->cluster_bits - 8)) - 1;

            /* l2_ptr is a bit different for compressed pointers: */
            l2_ptr = l2_ent & 0x3fffffffffffffff;
            l2_ptr &= ((1ULL << shift) - 1);
            /* FIXME: The sector length as presented is a lower bound,
             *        and the +1 may not always actually be appropriate. */
            len = (((l2_ent >> shift) & csize_mask) + 1) << 9;
            errors |= (len > qf->cluster_size) ? (1 << L2_TOO_LONG) : 0;
        } else {
            zeroes = !!(l2_ent & 0x01);
            errors |= (l2_ent & 0x3f00000000000000) ? (1 << L2_RESERVED) : 0;
            errors |= (l2_ptr % qf->cluster_size) ? (1 << L2_MISALIGNED) : 0;
        }

        if (l2_ptr + len > qf->file_size) {
            errors |= (1 << L2_OUT_OF_BOUNDS);
            refcnt = 0;
        } else {
            refcnt = qf->ref_file[l2_ptr / qf->cluster_size];
        }
        if (!compressed) {
            errors |= (copied && (refcnt != 1)) ? (1 << L2_EXTRA_COPIED) : 0;
            errors |= (!copied && (refcnt == 0)) ? (1 << L2_MISSING_COPIED) : 0;
        }
        errors |= (overlap(qf, l2_ptr, len)) ? (1 << L2_OVERLAP) : 0;
        errors |= ((l2_ptr == 0) && (l2_ent != 0)) ? (1 << L2_EMPTY_FLAGS) : 0;
        errors |= (copied && compressed) ? (1 << L2_CONFLICT) : 0;

        if (compressed && !errors) {
            mprintf(M_DEBUG, "COMPRESSED PTR W/O ERRORS: 0x%016lx LEN: %ld\n",
                    l2_ent, len);
        }

        msg_type = (errors && STREAM_OFF(M_L2_TABLE)) ? M_PROBLEMS : M_L2_TABLE;

        if (!errors) {
            rc = add_host_range(qf, l2_ptr,
                                len, RANGE_TYPE_DATA, NULL);
            CHECK_RC(rc, ret, error);
            rc = qref_bump(qf, l2_ptr & ~((1 << qf->header->cluster_bits) - 1));
            CHECK_RC(rc, ret, error);
            continue;
        } else {
            cr++;
        }

        mprintf(msg_type, "0x%04x: CLUSTER 0x%08"PRIx64"; ent: 0x%016"PRIx64"; "
                "ptr: 0x%016"PRIx64"; ",
                i, l1_index * qf->num_l2_entries + i, l2_ent, l2_ptr);
        if (compressed || copied || zeroes) {
            mprintf(msg_type, "%cCOMPRESSED %cCOPIED %cZEROES",
                    compressed ? '+' : '-',
                    copied ? '+' : '-',
                    zeroes ? '+' : '-');
        }
        mprintf(msg_type, "\n");

        for (j = L2_BEGIN; errors && j < L2_MAX; j++) {
            if (errors & (1 << j)) {
                mprintf(M_PROBLEMS, "Error: L2 entry %s\n",
                        l2_errors[j]);
                ret++;
                errors &= ~(1 << j);
            }
        }

    }

    if (cr) {
        mprintf(M_SUMMARY, "Corrupt entries: %d; Non-zero entries: %d; "
                "Corrupt:Non-zero ratio: %f\n",
                cr, nz, (float)cr/(float)nz);
    }

    return ret;
 error:
    return rc;
}

/**
 * parse_and_analyze_l2_tables: Parses, then analyzes every l2 cluster
 *     present within the already-parsed l1 table.
 * @qf: Qcow2 file to parse/analyze.
 * @return: 0 on success, -ERRNO on unrecoverable failure.
 *          The number of errors found otherwise.
 */
int parse_and_analyze_l2_tables(qfile *qf)
{
    struct qheader *header;
    int i;
    int rc = 0;
    int ret = 0;
    l2_entry *l2_cache;

    if (!qf || !qf->header || !qf->l1_table) {
        return -EINVAL;
    }

    h1("L2 Tables");
    header = qf->header;

    l2_cache = (l2_entry *)malloc(sizeof(l2_entry) * qf->num_l2_entries);
    if (!l2_cache) {
        rc = -errno;
        perrorf("Couldn't allocate L2 block");
        return rc;
    }

    for (i = 0; i < header->l1_size; i++) {
        uint64_t l1_ptr = qf->l1_table[i].val & 0x00ffffffffffffff;

        if (l1_ptr == 0) {
            continue;
        }
        h2("L2 cluster l1[%d] : 0x%016"PRIx64, i, l1_ptr);
        rc = buffer_l2_cluster(qf, l1_ptr, l2_cache);
        CHECK_RC(rc, ret, out);
        rc = analyze_l2_cluster(qf, i, l2_cache);
        CHECK_RC(rc, ret, out);
    }

 out:
    free(l2_cache);
    do_summary("L2 tables", rc, ret);
    return rc ? rc : ret;
}


/******************************************************************************/
/*                              Final Analysis                                */
/******************************************************************************/

int analyze_refcounts(qfile *qf)
{
    int rc = 0;
    int ret = 0;
    int i;
    uint64_t ghost_clusters = 0;
    uint64_t mismatched_clusters = 0;

    if (!qf || !qf->all || !qf->ref_file || !qf->ref_calc) {
        return -EINVAL;
    }

    h1("Reference Count Analysis");
    for (i = 0; i < qf->host_clusters; i++) {

        /* No references calculated or stored */
        if (qf->ref_calc[i] == 0 &&
            qf->ref_file[i] == 0) {
            ret++;
            msg_problem("Vacant cluster #%d, no references or refcount\n", i);
            rc = add_host_cluster(qf, (uint64_t)i * qf->cluster_size,
                                  RANGE_TYPE_VACANT, NULL);
            CHECK_RC(rc, ret, out);
            continue;
        }

        /* Fine */
        if (qf->ref_calc[i] == qf->ref_file[i]) {
            continue;
        }

        /* Leak! */
        if (qf->ref_calc[i] == 0) {
            ret++;
            msg_problem("Leaked cluster #%d, 0 references but refcount of %d\n",
                        i, qf->ref_file[i]);
            rc = add_host_cluster(qf, (uint64_t)i * qf->cluster_size,
                                  RANGE_TYPE_LEAKED, NULL);
            CHECK_RC(rc, ret, out);
            continue;
        }

        if (qf->ref_file[i] == 0) {
            ret++;
            msg_problem("Ghost cluster #%d, %d references but empty refcount\n",
                        i, qf->ref_calc[i]);
            ghost_clusters++;
        } else if (qf->ref_calc[i] != qf->ref_file[i]) {
            ret++;
            msg_problem("Miscounted cluster #%d, %d references but refcount "
                        "of %d\n", i, qf->ref_calc[i], qf->ref_file[i]);
            mismatched_clusters++;
        }
    }

    mprintf(M_SUMMARY, "Refcount analysis: %02"PRId64" vacant clusters\n",
            get_type_size(qf->all, RANGE_TYPE_VACANT) / qf->cluster_size);
    mprintf(M_SUMMARY, "Refcount analysis: %02"PRId64" leaked clusters\n",
            get_type_size(qf->all, RANGE_TYPE_LEAKED) / qf->cluster_size);
    mprintf(M_SUMMARY, "Refcount analysis: %02"PRId64" ghost clusters\n",
            ghost_clusters);
    mprintf(M_SUMMARY, "Refcount analysis: %02"PRId64" miscounted clusters\n",
            mismatched_clusters);

 out:
    do_summary("Refcount analysis", rc, ret);
    return rc ? rc : ret;
}

int log_filters(const char *opt, int additive)
{
    int i, j;

    for (i = 0; i < strlen(opt); i++) {
        for (j = M_RANGE_BEGIN; j < M_RANGE_END; j++) {
            if (opt[i] == message_filters[j].c) {
                mprintf(M_DEBUG, "Output:%c%s\n",
                        additive ? '+' : '-',
                        message_filters[j].h);
                if (additive) {
                    mlevel |= LMASK(j);
                } else {
                    mlevel &= ~LMASK(j);
                }
                break;
            }
        }
        if (j == M_RANGE_END) {
            mprintf(M_ERROR, "Unrecognized log filter '%c'\n", opt[i]);
            return -EINVAL;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int rc = 0;
    int ret = 0;
    int i;
    qfile *qf;

#define _CHECK_RC() CHECK_RC(rc, ret, fail)

    opterr = 0;
    static struct option long_opts[] = {
        {"silent",  no_argument,       0, 's' },
        {"quiet",   no_argument,       0, 'q' },
        {"basic",   no_argument,       0, 'b' },
        {"verbose", no_argument,       0, 'v' },
        {"deluge",  no_argument,       0, 'x' },
        {"debug",   no_argument,       0, 'd' },
        {"log",     required_argument, 0, 'l' },
        {"exclude", required_argument, 0, 'e' },
        {"help",    no_argument,       0, 'h' },
        {0, 0, 0, 0}
    };

    for (i = 0; optind < argc && i != -1; ) {
        switch(getopt_long(argc, argv, "sqbvxdl:e:h", long_opts, &i)) {
        case -1:
            i = -1;
            break;
        case 's':
            mlevel = LOG_SILENT;
            break;
        case 'q':
            mlevel = LOG_QUIET;
            break;
        case 'b':
            mlevel = LOG_BASIC;
            break;
        case 'v':
            mlevel = LOG_VERBOSE;
            break;
        case 'x':
            mlevel = LOG_DELUGE;
            break;
        case 'd':
            mlevel |= LMASK(M_DEBUG);
            break;
        case 'l':
            rc = log_filters(optarg, 1);
            if (rc) {
                goto efail;
            }
            break;
        case 'e':
            rc = log_filters(optarg, 0);
            if (rc) {
                goto efail;
            }
            break;
        case 'h':
            fprintf(stderr, "Usage:\n\t%s [opts] <qcow2_file>\n", argv[0]);
            fprintf(stderr, "\t%s --help\n", argv[0]);
            fprintf(stderr, "\n");
            fprintf(stderr, "-h --help: Display help text and exit.\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "Logging presets: these are all mutually exclusive,"
                    " except for debug.\n");
            fprintf(stderr, "\t-s --silent: No output whatsoever.\n");
            fprintf(stderr, "\t-q --quiet: Fatal and nonfatal qcheck errors."
                    " (--log fw)\n");
            fprintf(stderr, "\t-b --basic: Basic analysis and summaries."
                    " This is the default. (--log fwshiHLR)\n");
            fprintf(stderr, "\t-v --verbose: Detailed problem analysis."
                    " (--log fwshiHLRpc)\n");
            fprintf(stderr, "\t-x --deluge: Everything except debug output.\n");
            fprintf(stderr, "\t-d --debug: The same as `--log d`."
                    " `--deluge --debug` or `-xd` enables all output.\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "-l [...] --log=[...]: detailed logging filters."
                    " Specify individual output streams.\n");
            fprintf(stderr, "All filters are additive and "
                    "will combine with presets.\n");
            fprintf(stderr, "-e [...] --exclude=[...]: exclude these filters."
                    "Will subtract filters from presets.\n");
            for (i = 0; i < M_RANGE_END; i++) {
                fprintf(stderr, "\t'%c': %s\n",
                        message_filters[i].c,
                        message_filters[i].h);
            }
            goto efail;
            break;
        case 0:
        case '?':
        default:
            msg_error("Unrecognized argument: %s\n", argv[optind - 1]);
            goto efail;
            break;
        }
    }

    if (optind >= argc) {
        msg_error("Need a file to analyze, no filename provided.\n");
        goto efail;
    } else if (optind + 1 < argc) {
        msg_warn("Warning: More than one filename given.\n"
                 "Ignoring '%s' onward.\n", argv[optind + 1]);
    }

    lprintf(M_HELLO, "%s analyzing '%s' for corruption\n",
            argv[0], argv[optind]);

    qf = new_qfile(argv[optind]);
    if (!qf) {
        goto efail;
    }

    /* Header */
    rc = parse_header(qf);
    _CHECK_RC();
    print_header(qf);
    rc = analyze_header(qf);
    _CHECK_RC();

    if (qf->header->version == 3) {
        print_header_v3(qf);
        rc = analyze_header_v3(qf);
        _CHECK_RC();
    }


    /* Refcount Table and Refcount Blocks */
    rc = parse_refcount_table(qf);
    _CHECK_RC();
    rc = analyze_refcount_table(qf);
    _CHECK_RC();
    rc = parse_and_analyze_refcount_blocks(qf);
    _CHECK_RC();


    /* L1 Table */
    rc = parse_l1_table(qf);
    _CHECK_RC();
    rc = analyze_l1_table(qf);
    _CHECK_RC();


    /* L2 Tables */
    rc = parse_and_analyze_l2_tables(qf);
    _CHECK_RC();


    /* Final Refcount Analysis */
    rc = analyze_refcounts(qf);
    _CHECK_RC();


    /* Print ranges and cluster maps */
    print_rangeset(qf, "Metadata", (1 << RANGE_TYPE_METADATA), 0, 0, M_METADATA);
    print_rangeset(qf, "Data", (1 << RANGE_TYPE_DATA), 0, 0, M_DATA);
    print_rangeset(qf, "Vacant", (1 << RANGE_TYPE_VACANT), 0, 0, M_VACANT);
    print_rangeset(qf, "Data", (1 << RANGE_TYPE_LEAKED), 0, 0, M_LEAKED);
    print_rangeset(qf, "Allocated",
                   (1 << RANGE_TYPE_METADATA) |
                   (1 << RANGE_TYPE_DATA), 0, 1, M_ALLOCATED);
    print_rangeset(qf, "Unallocated",
                   (1 << RANGE_TYPE_LEAKED) |
                   (1 << RANGE_TYPE_VACANT), 0, 1, M_UNALLOCATED);
    print_rangeset(qf, "File Map", -1, 1, 0, M_RANGE_ALL);

    /* Print cluster counts */
    if (STREAM_ON(M_SUMMARY)) {
        h1("Cluster Counts");
        for (i = RANGE_TYPE_BEGIN; i < RANGE_TYPE_MAX; i++) {
            mprintf(M_SUMMARY, "%s: 0x%"PRIx64"\n", rtype_lookup[i],
                    get_type_size(qf->all, i));
        }
        mprintf(M_SUMMARY, "total: 0x%"PRIx64"\n", get_size(qf->all));
    }

    do_summary("qcheck", 0, ret);
    destroy_qfile(qf);
    return ret;
 fail:
    destroy_qfile(qf);
    do_summary("qcheck", rc, ret);
 efail:
    return EXIT_FAILURE;
}
