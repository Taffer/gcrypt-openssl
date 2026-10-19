/*
 * gcrypt.h - Public interface of gcrypt-openssl.
 *
 * This header is an API/ABI compatible replacement for the header shipped
 * with Libgcrypt 1.12, written against that header's interface.  It deliberately carries no
 * dependency on libgpg-error: the subset of that library's interface that
 * Libgcrypt exposes (error types, codes and the inline helpers) is defined
 * here, guarded so that a real <gpg-error.h> included *before* this file
 * takes precedence.
 *
 * This file is in the public domain.
 */
#ifndef _GCRYPT_H
#define _GCRYPT_H

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#if defined _WIN32 || defined __WIN32__
    #ifndef __GNUC__
        #include <basetsd.h>
        typedef SSIZE_T ssize_t;
        typedef int pid_t;
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

/* The Libgcrypt API level this library implements.  gcry_check_version()
 * reports the same string so that existing version checks keep working. */
#define GCRYPT_VERSION "1.12.4"
#define GCRYPT_VERSION_NUMBER 0x010c04

/* ------------------------------------------------------------------ */
/* Compiler attribute helpers                                          */
/* ------------------------------------------------------------------ */

#ifdef __GNUC__
#define _GCRY_GCC_VERSION \
        (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if _GCRY_GCC_VERSION >= 30100
#define _GCRY_GCC_ATTR_DEPRECATED __attribute__((__deprecated__))
#endif
#if _GCRY_GCC_VERSION >= 29600
#define _GCRY_GCC_ATTR_PURE __attribute__((__pure__))
#endif
#if _GCRY_GCC_VERSION >= 30200
#define _GCRY_GCC_ATTR_MALLOC __attribute__((__malloc__))
#endif
#define _GCRY_GCC_ATTR_PRINTF(f, a) __attribute__((format(printf, f, a)))
#if _GCRY_GCC_VERSION >= 40000
#define _GCRY_GCC_ATTR_SENTINEL(a) __attribute__((sentinel(a)))
#endif
#if defined __has_attribute
#if __has_attribute(__nonstring__)
#define _GCRY_GCC_ATTR_NONSTRING __attribute__((__nonstring__))
#endif
#endif
#endif

#ifndef _GCRY_GCC_ATTR_DEPRECATED
#define _GCRY_GCC_ATTR_DEPRECATED
#endif
#ifndef _GCRY_GCC_ATTR_PURE
#define _GCRY_GCC_ATTR_PURE
#endif
#ifndef _GCRY_GCC_ATTR_MALLOC
#define _GCRY_GCC_ATTR_MALLOC
#endif
#ifndef _GCRY_GCC_ATTR_PRINTF
#define _GCRY_GCC_ATTR_PRINTF(f, a)
#endif
#ifndef _GCRY_GCC_ATTR_SENTINEL
#define _GCRY_GCC_ATTR_SENTINEL(a)
#endif
#ifndef _GCRY_GCC_ATTR_NONSTRING
#define _GCRY_GCC_ATTR_NONSTRING
#endif

#ifdef _GCRYPT_IN_LIBGCRYPT
#define _GCRY_ATTR_INTERNAL
#ifndef GCRYPT_NO_MPI_MACROS
#define GCRYPT_NO_MPI_MACROS 1
#endif
#else
#define _GCRY_ATTR_INTERNAL _GCRY_GCC_ATTR_DEPRECATED
#endif

/* ------------------------------------------------------------------ */
/* libgpg-error compatibility subset                                   */
/* ------------------------------------------------------------------ */

#ifndef GPG_ERROR_H
#define GPG_ERROR_H 1
#define GCRYPT_PROVIDES_GPG_ERROR 1

#include <errno.h>

#ifndef GPG_ERR_INLINE
#if defined(__GNUC__) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)
#define GPG_ERR_INLINE static inline
#else
#define GPG_ERR_INLINE static
#endif
#endif

typedef unsigned int gpg_error_t;

typedef enum {
    GPG_ERR_SOURCE_UNKNOWN = 0,
    GPG_ERR_SOURCE_GCRYPT = 1,
    GPG_ERR_SOURCE_GPG = 2,
    GPG_ERR_SOURCE_GPGSM = 3,
    GPG_ERR_SOURCE_GPGAGENT = 4,
    GPG_ERR_SOURCE_PINENTRY = 5,
    GPG_ERR_SOURCE_SCD = 6,
    GPG_ERR_SOURCE_GPGME = 7,
    GPG_ERR_SOURCE_KEYBOX = 8,
    GPG_ERR_SOURCE_KSBA = 9,
    GPG_ERR_SOURCE_DIRMNGR = 10,
    GPG_ERR_SOURCE_GSTI = 11,
    GPG_ERR_SOURCE_GPA = 12,
    GPG_ERR_SOURCE_KLEO = 13,
    GPG_ERR_SOURCE_G13 = 14,
    GPG_ERR_SOURCE_ASSUAN = 15,
    GPG_ERR_SOURCE_TPM2D = 16,
    GPG_ERR_SOURCE_TLS = 17,
    GPG_ERR_SOURCE_TKD = 18,
    GPG_ERR_SOURCE_ANY = 31,
    GPG_ERR_SOURCE_USER_1 = 32,
    GPG_ERR_SOURCE_USER_2 = 33,
    GPG_ERR_SOURCE_USER_3 = 34,
    GPG_ERR_SOURCE_USER_4 = 35,
    GPG_ERR_SOURCE_DIM = 128
} gpg_err_source_t;

typedef enum {
    GPG_ERR_NO_ERROR = 0,
    GPG_ERR_GENERAL = 1,
    GPG_ERR_UNKNOWN_PACKET = 2,
    GPG_ERR_UNKNOWN_VERSION = 3,
    GPG_ERR_PUBKEY_ALGO = 4,
    GPG_ERR_DIGEST_ALGO = 5,
    GPG_ERR_BAD_PUBKEY = 6,
    GPG_ERR_BAD_SECKEY = 7,
    GPG_ERR_BAD_SIGNATURE = 8,
    GPG_ERR_NO_PUBKEY = 9,
    GPG_ERR_CHECKSUM = 10,
    GPG_ERR_BAD_PASSPHRASE = 11,
    GPG_ERR_CIPHER_ALGO = 12,
    GPG_ERR_KEYRING_OPEN = 13,
    GPG_ERR_INV_PACKET = 14,
    GPG_ERR_INV_ARMOR = 15,
    GPG_ERR_NO_USER_ID = 16,
    GPG_ERR_NO_SECKEY = 17,
    GPG_ERR_WRONG_SECKEY = 18,
    GPG_ERR_BAD_KEY = 19,
    GPG_ERR_COMPR_ALGO = 20,
    GPG_ERR_NO_PRIME = 21,
    GPG_ERR_NO_ENCODING_METHOD = 22,
    GPG_ERR_NO_ENCRYPTION_SCHEME = 23,
    GPG_ERR_NO_SIGNATURE_SCHEME = 24,
    GPG_ERR_INV_ATTR = 25,
    GPG_ERR_NO_VALUE = 26,
    GPG_ERR_NOT_FOUND = 27,
    GPG_ERR_VALUE_NOT_FOUND = 28,
    GPG_ERR_SYNTAX = 29,
    GPG_ERR_BAD_MPI = 30,
    GPG_ERR_INV_PASSPHRASE = 31,
    GPG_ERR_SIG_CLASS = 32,
    GPG_ERR_RESOURCE_LIMIT = 33,
    GPG_ERR_INV_KEYRING = 34,
    GPG_ERR_TRUSTDB = 35,
    GPG_ERR_BAD_CERT = 36,
    GPG_ERR_INV_USER_ID = 37,
    GPG_ERR_UNEXPECTED = 38,
    GPG_ERR_TIME_CONFLICT = 39,
    GPG_ERR_KEYSERVER = 40,
    GPG_ERR_WRONG_PUBKEY_ALGO = 41,
    GPG_ERR_TRIBUTE_TO_D_A = 42,
    GPG_ERR_WEAK_KEY = 43,
    GPG_ERR_INV_KEYLEN = 44,
    GPG_ERR_INV_ARG = 45,
    GPG_ERR_BAD_URI = 46,
    GPG_ERR_INV_URI = 47,
    GPG_ERR_NETWORK = 48,
    GPG_ERR_UNKNOWN_HOST = 49,
    GPG_ERR_SELFTEST_FAILED = 50,
    GPG_ERR_NOT_ENCRYPTED = 51,
    GPG_ERR_NOT_PROCESSED = 52,
    GPG_ERR_UNUSABLE_PUBKEY = 53,
    GPG_ERR_UNUSABLE_SECKEY = 54,
    GPG_ERR_INV_VALUE = 55,
    GPG_ERR_BAD_CERT_CHAIN = 56,
    GPG_ERR_MISSING_CERT = 57,
    GPG_ERR_NO_DATA = 58,
    GPG_ERR_BUG = 59,
    GPG_ERR_NOT_SUPPORTED = 60,
    GPG_ERR_INV_OP = 61,
    GPG_ERR_TIMEOUT = 62,
    GPG_ERR_INTERNAL = 63,
    GPG_ERR_EOF_GCRYPT = 64,
    GPG_ERR_INV_OBJ = 65,
    GPG_ERR_TOO_SHORT = 66,
    GPG_ERR_TOO_LARGE = 67,
    GPG_ERR_NO_OBJ = 68,
    GPG_ERR_NOT_IMPLEMENTED = 69,
    GPG_ERR_CONFLICT = 70,
    GPG_ERR_INV_CIPHER_MODE = 71,
    GPG_ERR_INV_FLAG = 72,
    GPG_ERR_INV_HANDLE = 73,
    GPG_ERR_TRUNCATED = 74,
    GPG_ERR_INCOMPLETE_LINE = 75,
    GPG_ERR_INV_RESPONSE = 76,
    GPG_ERR_NO_AGENT = 77,
    GPG_ERR_AGENT = 78,
    GPG_ERR_INV_DATA = 79,
    GPG_ERR_ASSUAN_SERVER_FAULT = 80,
    GPG_ERR_ASSUAN = 81,
    GPG_ERR_INV_SESSION_KEY = 82,
    GPG_ERR_INV_SEXP = 83,
    GPG_ERR_UNSUPPORTED_ALGORITHM = 84,
    GPG_ERR_NO_PIN_ENTRY = 85,
    GPG_ERR_PIN_ENTRY = 86,
    GPG_ERR_BAD_PIN = 87,
    GPG_ERR_INV_NAME = 88,
    GPG_ERR_BAD_DATA = 89,
    GPG_ERR_INV_PARAMETER = 90,
    GPG_ERR_WRONG_CARD = 91,
    GPG_ERR_NO_DIRMNGR = 92,
    GPG_ERR_DIRMNGR = 93,
    GPG_ERR_CERT_REVOKED = 94,
    GPG_ERR_NO_CRL_KNOWN = 95,
    GPG_ERR_CRL_TOO_OLD = 96,
    GPG_ERR_LINE_TOO_LONG = 97,
    GPG_ERR_NOT_TRUSTED = 98,
    GPG_ERR_CANCELED = 99,
    GPG_ERR_BAD_CA_CERT = 100,
    GPG_ERR_CERT_EXPIRED = 101,
    GPG_ERR_CERT_TOO_YOUNG = 102,
    GPG_ERR_UNSUPPORTED_CERT = 103,
    GPG_ERR_UNKNOWN_SEXP = 104,
    GPG_ERR_UNSUPPORTED_PROTECTION = 105,
    GPG_ERR_CORRUPTED_PROTECTION = 106,
    GPG_ERR_AMBIGUOUS_NAME = 107,
    GPG_ERR_CARD = 108,
    GPG_ERR_CARD_RESET = 109,
    GPG_ERR_CARD_REMOVED = 110,
    GPG_ERR_INV_CARD = 111,
    GPG_ERR_CARD_NOT_PRESENT = 112,
    GPG_ERR_NO_PKCS15_APP = 113,
    GPG_ERR_NOT_CONFIRMED = 114,
    GPG_ERR_CONFIGURATION = 115,
    GPG_ERR_NO_POLICY_MATCH = 116,
    GPG_ERR_INV_INDEX = 117,
    GPG_ERR_INV_ID = 118,
    GPG_ERR_NO_SCDAEMON = 119,
    GPG_ERR_SCDAEMON = 120,
    GPG_ERR_UNSUPPORTED_PROTOCOL = 121,
    GPG_ERR_BAD_PIN_METHOD = 122,
    GPG_ERR_CARD_NOT_INITIALIZED = 123,
    GPG_ERR_UNSUPPORTED_OPERATION = 124,
    GPG_ERR_WRONG_KEY_USAGE = 125,
    GPG_ERR_NOTHING_FOUND = 126,
    GPG_ERR_WRONG_BLOB_TYPE = 127,
    GPG_ERR_MISSING_VALUE = 128,
    GPG_ERR_HARDWARE = 129,
    GPG_ERR_PIN_BLOCKED = 130,
    GPG_ERR_USE_CONDITIONS = 131,
    GPG_ERR_PIN_NOT_SYNCED = 132,
    GPG_ERR_INV_CRL = 133,
    GPG_ERR_BAD_BER = 134,
    GPG_ERR_INV_BER = 135,
    GPG_ERR_ELEMENT_NOT_FOUND = 136,
    GPG_ERR_IDENTIFIER_NOT_FOUND = 137,
    GPG_ERR_INV_TAG = 138,
    GPG_ERR_INV_LENGTH = 139,
    GPG_ERR_INV_KEYINFO = 140,
    GPG_ERR_UNEXPECTED_TAG = 141,
    GPG_ERR_NOT_DER_ENCODED = 142,
    GPG_ERR_NO_CMS_OBJ = 143,
    GPG_ERR_INV_CMS_OBJ = 144,
    GPG_ERR_UNKNOWN_CMS_OBJ = 145,
    GPG_ERR_UNSUPPORTED_CMS_OBJ = 146,
    GPG_ERR_UNSUPPORTED_ENCODING = 147,
    GPG_ERR_UNSUPPORTED_CMS_VERSION = 148,
    GPG_ERR_UNKNOWN_ALGORITHM = 149,
    GPG_ERR_INV_ENGINE = 150,
    GPG_ERR_PUBKEY_NOT_TRUSTED = 151,
    GPG_ERR_DECRYPT_FAILED = 152,
    GPG_ERR_KEY_EXPIRED = 153,
    GPG_ERR_SIG_EXPIRED = 154,
    GPG_ERR_ENCODING_PROBLEM = 155,
    GPG_ERR_INV_STATE = 156,
    GPG_ERR_DUP_VALUE = 157,
    GPG_ERR_MISSING_ACTION = 158,
    GPG_ERR_MODULE_NOT_FOUND = 159,
    GPG_ERR_INV_OID_STRING = 160,
    GPG_ERR_INV_TIME = 161,
    GPG_ERR_INV_CRL_OBJ = 162,
    GPG_ERR_UNSUPPORTED_CRL_VERSION = 163,
    GPG_ERR_INV_CERT_OBJ = 164,
    GPG_ERR_UNKNOWN_NAME = 165,
    GPG_ERR_LOCALE_PROBLEM = 166,
    GPG_ERR_NOT_LOCKED = 167,
    GPG_ERR_PROTOCOL_VIOLATION = 168,
    GPG_ERR_INV_MAC = 169,
    GPG_ERR_INV_REQUEST = 170,
    GPG_ERR_UNKNOWN_EXTN = 171,
    GPG_ERR_UNKNOWN_CRIT_EXTN = 172,
    GPG_ERR_LOCKED = 173,
    GPG_ERR_UNKNOWN_OPTION = 174,
    GPG_ERR_UNKNOWN_COMMAND = 175,
    GPG_ERR_NOT_OPERATIONAL = 176,
    GPG_ERR_NO_PASSPHRASE = 177,
    GPG_ERR_NO_PIN = 178,
    GPG_ERR_NOT_ENABLED = 179,
    GPG_ERR_NO_ENGINE = 180,
    GPG_ERR_MISSING_KEY = 181,
    GPG_ERR_TOO_MANY = 182,
    GPG_ERR_LIMIT_REACHED = 183,
    GPG_ERR_NOT_INITIALIZED = 184,
    GPG_ERR_MISSING_ISSUER_CERT = 185,
    GPG_ERR_NO_KEYSERVER = 186,
    GPG_ERR_INV_CURVE = 187,
    GPG_ERR_UNKNOWN_CURVE = 188,
    GPG_ERR_DUP_KEY = 189,
    GPG_ERR_AMBIGUOUS = 190,
    GPG_ERR_NO_CRYPT_CTX = 191,
    GPG_ERR_WRONG_CRYPT_CTX = 192,
    GPG_ERR_BAD_CRYPT_CTX = 193,
    GPG_ERR_CRYPT_CTX_CONFLICT = 194,
    GPG_ERR_BROKEN_PUBKEY = 195,
    GPG_ERR_BROKEN_SECKEY = 196,
    GPG_ERR_MAC_ALGO = 197,
    GPG_ERR_FULLY_CANCELED = 198,
    GPG_ERR_UNFINISHED = 199,
    GPG_ERR_BUFFER_TOO_SHORT = 200,
    GPG_ERR_SEXP_INV_LEN_SPEC = 201,
    GPG_ERR_SEXP_STRING_TOO_LONG = 202,
    GPG_ERR_SEXP_UNMATCHED_PAREN = 203,
    GPG_ERR_SEXP_NOT_CANONICAL = 204,
    GPG_ERR_SEXP_BAD_CHARACTER = 205,
    GPG_ERR_SEXP_BAD_QUOTATION = 206,
    GPG_ERR_SEXP_ZERO_PREFIX = 207,
    GPG_ERR_SEXP_NESTED_DH = 208,
    GPG_ERR_SEXP_UNMATCHED_DH = 209,
    GPG_ERR_SEXP_UNEXPECTED_PUNC = 210,
    GPG_ERR_SEXP_BAD_HEX_CHAR = 211,
    GPG_ERR_SEXP_ODD_HEX_NUMBERS = 212,
    GPG_ERR_SEXP_BAD_OCT_CHAR = 213,
    GPG_ERR_PUBKEY_NON_COMPLIANT = 214,
    GPG_ERR_CIPHER_NON_COMPLIANT = 215,
    GPG_ERR_UNEXPECTED_PACKET = 216,
    GPG_ERR_SUBKEYS_EXP_OR_REV = 217,
    GPG_ERR_DB_CORRUPTED = 218,
    GPG_ERR_SERVER_FAILED = 219,
    GPG_ERR_NO_NAME = 220,
    GPG_ERR_NO_KEY = 221,
    GPG_ERR_LEGACY_KEY = 222,
    GPG_ERR_REQUEST_TOO_SHORT = 223,
    GPG_ERR_REQUEST_TOO_LONG = 224,
    GPG_ERR_OBJ_TERM_STATE = 225,
    GPG_ERR_NO_CERT_CHAIN = 226,
    GPG_ERR_CERT_TOO_LARGE = 227,
    GPG_ERR_INV_RECORD = 228,
    GPG_ERR_BAD_MAC = 229,
    GPG_ERR_UNEXPECTED_MSG = 230,
    GPG_ERR_COMPR_FAILED = 231,
    GPG_ERR_WOULD_WRAP = 232,
    GPG_ERR_FATAL_ALERT = 233,
    GPG_ERR_NO_CIPHER = 234,
    GPG_ERR_MISSING_CLIENT_CERT = 235,
    GPG_ERR_CLOSE_NOTIFY = 236,
    GPG_ERR_TICKET_EXPIRED = 237,
    GPG_ERR_BAD_TICKET = 238,
    GPG_ERR_UNKNOWN_IDENTITY = 239,
    GPG_ERR_BAD_HS_CERT = 240,
    GPG_ERR_BAD_HS_CERT_REQ = 241,
    GPG_ERR_BAD_HS_CERT_VER = 242,
    GPG_ERR_BAD_HS_CHANGE_CIPHER = 243,
    GPG_ERR_BAD_HS_CLIENT_HELLO = 244,
    GPG_ERR_BAD_HS_SERVER_HELLO = 245,
    GPG_ERR_BAD_HS_SERVER_HELLO_DONE = 246,
    GPG_ERR_BAD_HS_FINISHED = 247,
    GPG_ERR_BAD_HS_SERVER_KEX = 248,
    GPG_ERR_BAD_HS_CLIENT_KEX = 249,
    GPG_ERR_BOGUS_STRING = 250,
    GPG_ERR_FORBIDDEN = 251,
    GPG_ERR_KEY_DISABLED = 252,
    GPG_ERR_KEY_ON_CARD = 253,
    GPG_ERR_INV_LOCK_OBJ = 254,
    GPG_ERR_TRUE = 255,
    GPG_ERR_FALSE = 256,
    GPG_ERR_ASS_GENERAL = 257,
    GPG_ERR_ASS_ACCEPT_FAILED = 258,
    GPG_ERR_ASS_CONNECT_FAILED = 259,
    GPG_ERR_ASS_INV_RESPONSE = 260,
    GPG_ERR_ASS_INV_VALUE = 261,
    GPG_ERR_ASS_INCOMPLETE_LINE = 262,
    GPG_ERR_ASS_LINE_TOO_LONG = 263,
    GPG_ERR_ASS_NESTED_COMMANDS = 264,
    GPG_ERR_ASS_NO_DATA_CB = 265,
    GPG_ERR_ASS_NO_INQUIRE_CB = 266,
    GPG_ERR_ASS_NOT_A_SERVER = 267,
    GPG_ERR_ASS_NOT_A_CLIENT = 268,
    GPG_ERR_ASS_SERVER_START = 269,
    GPG_ERR_ASS_READ_ERROR = 270,
    GPG_ERR_ASS_WRITE_ERROR = 271,
    GPG_ERR_ASS_TOO_MUCH_DATA = 273,
    GPG_ERR_ASS_UNEXPECTED_CMD = 274,
    GPG_ERR_ASS_UNKNOWN_CMD = 275,
    GPG_ERR_ASS_SYNTAX = 276,
    GPG_ERR_ASS_CANCELED = 277,
    GPG_ERR_ASS_NO_INPUT = 278,
    GPG_ERR_ASS_NO_OUTPUT = 279,
    GPG_ERR_ASS_PARAMETER = 280,
    GPG_ERR_ASS_UNKNOWN_INQUIRE = 281,
    GPG_ERR_ENGINE_TOO_OLD = 300,
    GPG_ERR_WINDOW_TOO_SMALL = 301,
    GPG_ERR_WINDOW_TOO_LARGE = 302,
    GPG_ERR_MISSING_ENVVAR = 303,
    GPG_ERR_USER_ID_EXISTS = 304,
    GPG_ERR_NAME_EXISTS = 305,
    GPG_ERR_DUP_NAME = 306,
    GPG_ERR_TOO_YOUNG = 307,
    GPG_ERR_TOO_OLD = 308,
    GPG_ERR_UNKNOWN_FLAG = 309,
    GPG_ERR_INV_ORDER = 310,
    GPG_ERR_ALREADY_FETCHED = 311,
    GPG_ERR_TRY_LATER = 312,
    GPG_ERR_WRONG_NAME = 313,
    GPG_ERR_NO_AUTH = 314,
    GPG_ERR_BAD_AUTH = 315,
    GPG_ERR_NO_KEYBOXD = 316,
    GPG_ERR_KEYBOXD = 317,
    GPG_ERR_NO_SERVICE = 318,
    GPG_ERR_SERVICE = 319,
    GPG_ERR_BAD_PUK = 320,
    GPG_ERR_NO_RESET_CODE = 321,
    GPG_ERR_BAD_RESET_CODE = 322,
    GPG_ERR_DIGEST_NON_COMPLIANT = 323,
    GPG_ERR_SYSTEM_BUG = 666,
    GPG_ERR_DNS_UNKNOWN = 711,
    GPG_ERR_DNS_SECTION = 712,
    GPG_ERR_DNS_ADDRESS = 713,
    GPG_ERR_DNS_NO_QUERY = 714,
    GPG_ERR_DNS_NO_ANSWER = 715,
    GPG_ERR_DNS_CLOSED = 716,
    GPG_ERR_DNS_VERIFY = 717,
    GPG_ERR_DNS_TIMEOUT = 718,
    GPG_ERR_LDAP_GENERAL = 721,
    GPG_ERR_LDAP_ATTR_GENERAL = 722,
    GPG_ERR_LDAP_NAME_GENERAL = 723,
    GPG_ERR_LDAP_SECURITY_GENERAL = 724,
    GPG_ERR_LDAP_SERVICE_GENERAL = 725,
    GPG_ERR_LDAP_UPDATE_GENERAL = 726,
    GPG_ERR_LDAP_E_GENERAL = 727,
    GPG_ERR_LDAP_X_GENERAL = 728,
    GPG_ERR_LDAP_OTHER_GENERAL = 729,
    GPG_ERR_LDAP_X_CONNECTING = 750,
    GPG_ERR_LDAP_REFERRAL_LIMIT = 751,
    GPG_ERR_LDAP_CLIENT_LOOP = 752,
    GPG_ERR_LDAP_NO_RESULTS = 754,
    GPG_ERR_LDAP_CONTROL_NOT_FOUND = 755,
    GPG_ERR_LDAP_NOT_SUPPORTED = 756,
    GPG_ERR_LDAP_CONNECT = 757,
    GPG_ERR_LDAP_NO_MEMORY = 758,
    GPG_ERR_LDAP_PARAM = 759,
    GPG_ERR_LDAP_USER_CANCELLED = 760,
    GPG_ERR_LDAP_FILTER = 761,
    GPG_ERR_LDAP_AUTH_UNKNOWN = 762,
    GPG_ERR_LDAP_TIMEOUT = 763,
    GPG_ERR_LDAP_DECODING = 764,
    GPG_ERR_LDAP_ENCODING = 765,
    GPG_ERR_LDAP_LOCAL = 766,
    GPG_ERR_LDAP_SERVER_DOWN = 767,
    GPG_ERR_LDAP_SUCCESS = 768,
    GPG_ERR_LDAP_OPERATIONS = 769,
    GPG_ERR_LDAP_PROTOCOL = 770,
    GPG_ERR_LDAP_TIMELIMIT = 771,
    GPG_ERR_LDAP_SIZELIMIT = 772,
    GPG_ERR_LDAP_COMPARE_FALSE = 773,
    GPG_ERR_LDAP_COMPARE_TRUE = 774,
    GPG_ERR_LDAP_UNSUPPORTED_AUTH = 775,
    GPG_ERR_LDAP_STRONG_AUTH_RQRD = 776,
    GPG_ERR_LDAP_PARTIAL_RESULTS = 777,
    GPG_ERR_LDAP_REFERRAL = 778,
    GPG_ERR_LDAP_ADMINLIMIT = 779,
    GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN = 780,
    GPG_ERR_LDAP_CONFIDENT_RQRD = 781,
    GPG_ERR_LDAP_SASL_BIND_INPROG = 782,
    GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE = 784,
    GPG_ERR_LDAP_UNDEFINED_TYPE = 785,
    GPG_ERR_LDAP_BAD_MATCHING = 786,
    GPG_ERR_LDAP_CONST_VIOLATION = 787,
    GPG_ERR_LDAP_TYPE_VALUE_EXISTS = 788,
    GPG_ERR_LDAP_INV_SYNTAX = 789,
    GPG_ERR_LDAP_NO_SUCH_OBJ = 800,
    GPG_ERR_LDAP_ALIAS_PROBLEM = 801,
    GPG_ERR_LDAP_INV_DN_SYNTAX = 802,
    GPG_ERR_LDAP_IS_LEAF = 803,
    GPG_ERR_LDAP_ALIAS_DEREF = 804,
    GPG_ERR_LDAP_X_PROXY_AUTH_FAIL = 815,
    GPG_ERR_LDAP_BAD_AUTH = 816,
    GPG_ERR_LDAP_INV_CREDENTIALS = 817,
    GPG_ERR_LDAP_INSUFFICIENT_ACC = 818,
    GPG_ERR_LDAP_BUSY = 819,
    GPG_ERR_LDAP_UNAVAILABLE = 820,
    GPG_ERR_LDAP_UNWILL_TO_PERFORM = 821,
    GPG_ERR_LDAP_LOOP_DETECT = 822,
    GPG_ERR_LDAP_NAMING_VIOLATION = 832,
    GPG_ERR_LDAP_OBJ_CLS_VIOLATION = 833,
    GPG_ERR_LDAP_NOT_ALLOW_NONLEAF = 834,
    GPG_ERR_LDAP_NOT_ALLOW_ON_RDN = 835,
    GPG_ERR_LDAP_ALREADY_EXISTS = 836,
    GPG_ERR_LDAP_NO_OBJ_CLASS_MODS = 837,
    GPG_ERR_LDAP_RESULTS_TOO_LARGE = 838,
    GPG_ERR_LDAP_AFFECTS_MULT_DSAS = 839,
    GPG_ERR_LDAP_VLV = 844,
    GPG_ERR_LDAP_OTHER = 848,
    GPG_ERR_LDAP_CUP_RESOURCE_LIMIT = 881,
    GPG_ERR_LDAP_CUP_SEC_VIOLATION = 882,
    GPG_ERR_LDAP_CUP_INV_DATA = 883,
    GPG_ERR_LDAP_CUP_UNSUP_SCHEME = 884,
    GPG_ERR_LDAP_CUP_RELOAD = 885,
    GPG_ERR_LDAP_CANCELLED = 886,
    GPG_ERR_LDAP_NO_SUCH_OPERATION = 887,
    GPG_ERR_LDAP_TOO_LATE = 888,
    GPG_ERR_LDAP_CANNOT_CANCEL = 889,
    GPG_ERR_LDAP_ASSERTION_FAILED = 890,
    GPG_ERR_LDAP_PROX_AUTH_DENIED = 891,
    GPG_ERR_USER_1 = 1024,
    GPG_ERR_USER_2 = 1025,
    GPG_ERR_USER_3 = 1026,
    GPG_ERR_USER_4 = 1027,
    GPG_ERR_USER_5 = 1028,
    GPG_ERR_USER_6 = 1029,
    GPG_ERR_USER_7 = 1030,
    GPG_ERR_USER_8 = 1031,
    GPG_ERR_USER_9 = 1032,
    GPG_ERR_USER_10 = 1033,
    GPG_ERR_USER_11 = 1034,
    GPG_ERR_USER_12 = 1035,
    GPG_ERR_USER_13 = 1036,
    GPG_ERR_USER_14 = 1037,
    GPG_ERR_USER_15 = 1038,
    GPG_ERR_USER_16 = 1039,
    GPG_ERR_SQL_OK = 1500,
    GPG_ERR_SQL_ERROR = 1501,
    GPG_ERR_SQL_INTERNAL = 1502,
    GPG_ERR_SQL_PERM = 1503,
    GPG_ERR_SQL_ABORT = 1504,
    GPG_ERR_SQL_BUSY = 1505,
    GPG_ERR_SQL_LOCKED = 1506,
    GPG_ERR_SQL_NOMEM = 1507,
    GPG_ERR_SQL_READONLY = 1508,
    GPG_ERR_SQL_INTERRUPT = 1509,
    GPG_ERR_SQL_IOERR = 1510,
    GPG_ERR_SQL_CORRUPT = 1511,
    GPG_ERR_SQL_NOTFOUND = 1512,
    GPG_ERR_SQL_FULL = 1513,
    GPG_ERR_SQL_CANTOPEN = 1514,
    GPG_ERR_SQL_PROTOCOL = 1515,
    GPG_ERR_SQL_EMPTY = 1516,
    GPG_ERR_SQL_SCHEMA = 1517,
    GPG_ERR_SQL_TOOBIG = 1518,
    GPG_ERR_SQL_CONSTRAINT = 1519,
    GPG_ERR_SQL_MISMATCH = 1520,
    GPG_ERR_SQL_MISUSE = 1521,
    GPG_ERR_SQL_NOLFS = 1522,
    GPG_ERR_SQL_AUTH = 1523,
    GPG_ERR_SQL_FORMAT = 1524,
    GPG_ERR_SQL_RANGE = 1525,
    GPG_ERR_SQL_NOTADB = 1526,
    GPG_ERR_SQL_NOTICE = 1527,
    GPG_ERR_SQL_WARNING = 1528,
    GPG_ERR_SQL_ROW = 1600,
    GPG_ERR_SQL_DONE = 1601,
    GPG_ERR_MISSING_ERRNO = 16381,
    GPG_ERR_UNKNOWN_ERRNO = 16382,
    GPG_ERR_EOF = 16383,
    GPG_ERR_SYSTEM_ERROR = (1 << 15),
    GPG_ERR_E2BIG = GPG_ERR_SYSTEM_ERROR | 0,
    GPG_ERR_EACCES = GPG_ERR_SYSTEM_ERROR | 1,
    GPG_ERR_EADDRINUSE = GPG_ERR_SYSTEM_ERROR | 2,
    GPG_ERR_EADDRNOTAVAIL = GPG_ERR_SYSTEM_ERROR | 3,
    GPG_ERR_EADV = GPG_ERR_SYSTEM_ERROR | 4,
    GPG_ERR_EAFNOSUPPORT = GPG_ERR_SYSTEM_ERROR | 5,
    GPG_ERR_EAGAIN = GPG_ERR_SYSTEM_ERROR | 6,
    GPG_ERR_EALREADY = GPG_ERR_SYSTEM_ERROR | 7,
    GPG_ERR_EAUTH = GPG_ERR_SYSTEM_ERROR | 8,
    GPG_ERR_EBACKGROUND = GPG_ERR_SYSTEM_ERROR | 9,
    GPG_ERR_EBADE = GPG_ERR_SYSTEM_ERROR | 10,
    GPG_ERR_EBADF = GPG_ERR_SYSTEM_ERROR | 11,
    GPG_ERR_EBADFD = GPG_ERR_SYSTEM_ERROR | 12,
    GPG_ERR_EBADMSG = GPG_ERR_SYSTEM_ERROR | 13,
    GPG_ERR_EBADR = GPG_ERR_SYSTEM_ERROR | 14,
    GPG_ERR_EBADRPC = GPG_ERR_SYSTEM_ERROR | 15,
    GPG_ERR_EBADRQC = GPG_ERR_SYSTEM_ERROR | 16,
    GPG_ERR_EBADSLT = GPG_ERR_SYSTEM_ERROR | 17,
    GPG_ERR_EBFONT = GPG_ERR_SYSTEM_ERROR | 18,
    GPG_ERR_EBUSY = GPG_ERR_SYSTEM_ERROR | 19,
    GPG_ERR_ECANCELED = GPG_ERR_SYSTEM_ERROR | 20,
    GPG_ERR_ECHILD = GPG_ERR_SYSTEM_ERROR | 21,
    GPG_ERR_ECHRNG = GPG_ERR_SYSTEM_ERROR | 22,
    GPG_ERR_ECOMM = GPG_ERR_SYSTEM_ERROR | 23,
    GPG_ERR_ECONNABORTED = GPG_ERR_SYSTEM_ERROR | 24,
    GPG_ERR_ECONNREFUSED = GPG_ERR_SYSTEM_ERROR | 25,
    GPG_ERR_ECONNRESET = GPG_ERR_SYSTEM_ERROR | 26,
    GPG_ERR_ED = GPG_ERR_SYSTEM_ERROR | 27,
    GPG_ERR_EDEADLK = GPG_ERR_SYSTEM_ERROR | 28,
    GPG_ERR_EDEADLOCK = GPG_ERR_SYSTEM_ERROR | 29,
    GPG_ERR_EDESTADDRREQ = GPG_ERR_SYSTEM_ERROR | 30,
    GPG_ERR_EDIED = GPG_ERR_SYSTEM_ERROR | 31,
    GPG_ERR_EDOM = GPG_ERR_SYSTEM_ERROR | 32,
    GPG_ERR_EDOTDOT = GPG_ERR_SYSTEM_ERROR | 33,
    GPG_ERR_EDQUOT = GPG_ERR_SYSTEM_ERROR | 34,
    GPG_ERR_EEXIST = GPG_ERR_SYSTEM_ERROR | 35,
    GPG_ERR_EFAULT = GPG_ERR_SYSTEM_ERROR | 36,
    GPG_ERR_EFBIG = GPG_ERR_SYSTEM_ERROR | 37,
    GPG_ERR_EFTYPE = GPG_ERR_SYSTEM_ERROR | 38,
    GPG_ERR_EGRATUITOUS = GPG_ERR_SYSTEM_ERROR | 39,
    GPG_ERR_EGREGIOUS = GPG_ERR_SYSTEM_ERROR | 40,
    GPG_ERR_EHOSTDOWN = GPG_ERR_SYSTEM_ERROR | 41,
    GPG_ERR_EHOSTUNREACH = GPG_ERR_SYSTEM_ERROR | 42,
    GPG_ERR_EIDRM = GPG_ERR_SYSTEM_ERROR | 43,
    GPG_ERR_EIEIO = GPG_ERR_SYSTEM_ERROR | 44,
    GPG_ERR_EILSEQ = GPG_ERR_SYSTEM_ERROR | 45,
    GPG_ERR_EINPROGRESS = GPG_ERR_SYSTEM_ERROR | 46,
    GPG_ERR_EINTR = GPG_ERR_SYSTEM_ERROR | 47,
    GPG_ERR_EINVAL = GPG_ERR_SYSTEM_ERROR | 48,
    GPG_ERR_EIO = GPG_ERR_SYSTEM_ERROR | 49,
    GPG_ERR_EISCONN = GPG_ERR_SYSTEM_ERROR | 50,
    GPG_ERR_EISDIR = GPG_ERR_SYSTEM_ERROR | 51,
    GPG_ERR_EISNAM = GPG_ERR_SYSTEM_ERROR | 52,
    GPG_ERR_EL2HLT = GPG_ERR_SYSTEM_ERROR | 53,
    GPG_ERR_EL2NSYNC = GPG_ERR_SYSTEM_ERROR | 54,
    GPG_ERR_EL3HLT = GPG_ERR_SYSTEM_ERROR | 55,
    GPG_ERR_EL3RST = GPG_ERR_SYSTEM_ERROR | 56,
    GPG_ERR_ELIBACC = GPG_ERR_SYSTEM_ERROR | 57,
    GPG_ERR_ELIBBAD = GPG_ERR_SYSTEM_ERROR | 58,
    GPG_ERR_ELIBEXEC = GPG_ERR_SYSTEM_ERROR | 59,
    GPG_ERR_ELIBMAX = GPG_ERR_SYSTEM_ERROR | 60,
    GPG_ERR_ELIBSCN = GPG_ERR_SYSTEM_ERROR | 61,
    GPG_ERR_ELNRNG = GPG_ERR_SYSTEM_ERROR | 62,
    GPG_ERR_ELOOP = GPG_ERR_SYSTEM_ERROR | 63,
    GPG_ERR_EMEDIUMTYPE = GPG_ERR_SYSTEM_ERROR | 64,
    GPG_ERR_EMFILE = GPG_ERR_SYSTEM_ERROR | 65,
    GPG_ERR_EMLINK = GPG_ERR_SYSTEM_ERROR | 66,
    GPG_ERR_EMSGSIZE = GPG_ERR_SYSTEM_ERROR | 67,
    GPG_ERR_EMULTIHOP = GPG_ERR_SYSTEM_ERROR | 68,
    GPG_ERR_ENAMETOOLONG = GPG_ERR_SYSTEM_ERROR | 69,
    GPG_ERR_ENAVAIL = GPG_ERR_SYSTEM_ERROR | 70,
    GPG_ERR_ENEEDAUTH = GPG_ERR_SYSTEM_ERROR | 71,
    GPG_ERR_ENETDOWN = GPG_ERR_SYSTEM_ERROR | 72,
    GPG_ERR_ENETRESET = GPG_ERR_SYSTEM_ERROR | 73,
    GPG_ERR_ENETUNREACH = GPG_ERR_SYSTEM_ERROR | 74,
    GPG_ERR_ENFILE = GPG_ERR_SYSTEM_ERROR | 75,
    GPG_ERR_ENOANO = GPG_ERR_SYSTEM_ERROR | 76,
    GPG_ERR_ENOBUFS = GPG_ERR_SYSTEM_ERROR | 77,
    GPG_ERR_ENOCSI = GPG_ERR_SYSTEM_ERROR | 78,
    GPG_ERR_ENODATA = GPG_ERR_SYSTEM_ERROR | 79,
    GPG_ERR_ENODEV = GPG_ERR_SYSTEM_ERROR | 80,
    GPG_ERR_ENOENT = GPG_ERR_SYSTEM_ERROR | 81,
    GPG_ERR_ENOEXEC = GPG_ERR_SYSTEM_ERROR | 82,
    GPG_ERR_ENOLCK = GPG_ERR_SYSTEM_ERROR | 83,
    GPG_ERR_ENOLINK = GPG_ERR_SYSTEM_ERROR | 84,
    GPG_ERR_ENOMEDIUM = GPG_ERR_SYSTEM_ERROR | 85,
    GPG_ERR_ENOMEM = GPG_ERR_SYSTEM_ERROR | 86,
    GPG_ERR_ENOMSG = GPG_ERR_SYSTEM_ERROR | 87,
    GPG_ERR_ENONET = GPG_ERR_SYSTEM_ERROR | 88,
    GPG_ERR_ENOPKG = GPG_ERR_SYSTEM_ERROR | 89,
    GPG_ERR_ENOPROTOOPT = GPG_ERR_SYSTEM_ERROR | 90,
    GPG_ERR_ENOSPC = GPG_ERR_SYSTEM_ERROR | 91,
    GPG_ERR_ENOSR = GPG_ERR_SYSTEM_ERROR | 92,
    GPG_ERR_ENOSTR = GPG_ERR_SYSTEM_ERROR | 93,
    GPG_ERR_ENOSYS = GPG_ERR_SYSTEM_ERROR | 94,
    GPG_ERR_ENOTBLK = GPG_ERR_SYSTEM_ERROR | 95,
    GPG_ERR_ENOTCONN = GPG_ERR_SYSTEM_ERROR | 96,
    GPG_ERR_ENOTDIR = GPG_ERR_SYSTEM_ERROR | 97,
    GPG_ERR_ENOTEMPTY = GPG_ERR_SYSTEM_ERROR | 98,
    GPG_ERR_ENOTNAM = GPG_ERR_SYSTEM_ERROR | 99,
    GPG_ERR_ENOTSOCK = GPG_ERR_SYSTEM_ERROR | 100,
    GPG_ERR_ENOTSUP = GPG_ERR_SYSTEM_ERROR | 101,
    GPG_ERR_ENOTTY = GPG_ERR_SYSTEM_ERROR | 102,
    GPG_ERR_ENOTUNIQ = GPG_ERR_SYSTEM_ERROR | 103,
    GPG_ERR_ENXIO = GPG_ERR_SYSTEM_ERROR | 104,
    GPG_ERR_EOPNOTSUPP = GPG_ERR_SYSTEM_ERROR | 105,
    GPG_ERR_EOVERFLOW = GPG_ERR_SYSTEM_ERROR | 106,
    GPG_ERR_EPERM = GPG_ERR_SYSTEM_ERROR | 107,
    GPG_ERR_EPFNOSUPPORT = GPG_ERR_SYSTEM_ERROR | 108,
    GPG_ERR_EPIPE = GPG_ERR_SYSTEM_ERROR | 109,
    GPG_ERR_EPROCLIM = GPG_ERR_SYSTEM_ERROR | 110,
    GPG_ERR_EPROCUNAVAIL = GPG_ERR_SYSTEM_ERROR | 111,
    GPG_ERR_EPROGMISMATCH = GPG_ERR_SYSTEM_ERROR | 112,
    GPG_ERR_EPROGUNAVAIL = GPG_ERR_SYSTEM_ERROR | 113,
    GPG_ERR_EPROTO = GPG_ERR_SYSTEM_ERROR | 114,
    GPG_ERR_EPROTONOSUPPORT = GPG_ERR_SYSTEM_ERROR | 115,
    GPG_ERR_EPROTOTYPE = GPG_ERR_SYSTEM_ERROR | 116,
    GPG_ERR_ERANGE = GPG_ERR_SYSTEM_ERROR | 117,
    GPG_ERR_EREMCHG = GPG_ERR_SYSTEM_ERROR | 118,
    GPG_ERR_EREMOTE = GPG_ERR_SYSTEM_ERROR | 119,
    GPG_ERR_EREMOTEIO = GPG_ERR_SYSTEM_ERROR | 120,
    GPG_ERR_ERESTART = GPG_ERR_SYSTEM_ERROR | 121,
    GPG_ERR_EROFS = GPG_ERR_SYSTEM_ERROR | 122,
    GPG_ERR_ERPCMISMATCH = GPG_ERR_SYSTEM_ERROR | 123,
    GPG_ERR_ESHUTDOWN = GPG_ERR_SYSTEM_ERROR | 124,
    GPG_ERR_ESOCKTNOSUPPORT = GPG_ERR_SYSTEM_ERROR | 125,
    GPG_ERR_ESPIPE = GPG_ERR_SYSTEM_ERROR | 126,
    GPG_ERR_ESRCH = GPG_ERR_SYSTEM_ERROR | 127,
    GPG_ERR_ESRMNT = GPG_ERR_SYSTEM_ERROR | 128,
    GPG_ERR_ESTALE = GPG_ERR_SYSTEM_ERROR | 129,
    GPG_ERR_ESTRPIPE = GPG_ERR_SYSTEM_ERROR | 130,
    GPG_ERR_ETIME = GPG_ERR_SYSTEM_ERROR | 131,
    GPG_ERR_ETIMEDOUT = GPG_ERR_SYSTEM_ERROR | 132,
    GPG_ERR_ETOOMANYREFS = GPG_ERR_SYSTEM_ERROR | 133,
    GPG_ERR_ETXTBSY = GPG_ERR_SYSTEM_ERROR | 134,
    GPG_ERR_EUCLEAN = GPG_ERR_SYSTEM_ERROR | 135,
    GPG_ERR_EUNATCH = GPG_ERR_SYSTEM_ERROR | 136,
    GPG_ERR_EUSERS = GPG_ERR_SYSTEM_ERROR | 137,
    GPG_ERR_EWOULDBLOCK = GPG_ERR_SYSTEM_ERROR | 138,
    GPG_ERR_EXDEV = GPG_ERR_SYSTEM_ERROR | 139,
    GPG_ERR_EXFULL = GPG_ERR_SYSTEM_ERROR | 140,
    GPG_ERR_CODE_DIM = 65536
} gpg_err_code_t;

#define GPG_ERR_CODE_MASK (GPG_ERR_CODE_DIM - 1)
#define GPG_ERR_SOURCE_MASK (GPG_ERR_SOURCE_DIM - 1)
#define GPG_ERR_SOURCE_SHIFT 24

#ifndef GPG_ERR_SOURCE_DEFAULT
#define GPG_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_UNKNOWN
#endif

GPG_ERR_INLINE gpg_error_t
gpg_err_make(gpg_err_source_t source, gpg_err_code_t code)
{
    return code == GPG_ERR_NO_ERROR
           ? GPG_ERR_NO_ERROR
           : (((gpg_error_t)source & GPG_ERR_SOURCE_MASK)
              << GPG_ERR_SOURCE_SHIFT)
           | ((gpg_error_t)code & GPG_ERR_CODE_MASK);
}

GPG_ERR_INLINE gpg_error_t
gpg_error(gpg_err_code_t code)
{
    return gpg_err_make(GPG_ERR_SOURCE_DEFAULT, code);
}

GPG_ERR_INLINE gpg_err_code_t
gpg_err_code(gpg_error_t err)
{
    return (gpg_err_code_t)(err & GPG_ERR_CODE_MASK);
}

GPG_ERR_INLINE gpg_err_source_t
gpg_err_source(gpg_error_t err)
{
    return (gpg_err_source_t)((err >> GPG_ERR_SOURCE_SHIFT)
                              & GPG_ERR_SOURCE_MASK);
}

GPG_ERR_INLINE void
gpg_err_set_errno(int err)
{
    errno = err;
}

#endif /* !GPG_ERROR_H */

/* Needed for error-code compatibility with the reference library. */
#define _GCRY_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_GCRYPT

/* ------------------------------------------------------------------ */
/* Error handling                                                      */
/* ------------------------------------------------------------------ */

typedef gpg_error_t gcry_error_t;
typedef gpg_err_code_t gcry_err_code_t;
typedef gpg_err_source_t gcry_err_source_t;

GPG_ERR_INLINE gcry_error_t
gcry_err_make(gcry_err_source_t source, gcry_err_code_t code)
{
    return gpg_err_make(source, code);
}

#ifndef GCRY_ERR_SOURCE_DEFAULT
#define GCRY_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_USER_1
#endif

GPG_ERR_INLINE gcry_error_t
gcry_error(gcry_err_code_t code)
{
    return gcry_err_make(GCRY_ERR_SOURCE_DEFAULT, code);
}

GPG_ERR_INLINE gcry_err_code_t
gcry_err_code(gcry_error_t err)
{
    return gpg_err_code(err);
}

GPG_ERR_INLINE gcry_err_source_t
gcry_err_source(gcry_error_t err)
{
    return gpg_err_source(err);
}

const char *gcry_strerror(gcry_error_t err);
const char *gcry_strsource(gcry_error_t err);
gcry_err_code_t gcry_err_code_from_errno(int err);
int gcry_err_code_to_errno(gcry_err_code_t code);
gcry_error_t gcry_err_make_from_errno(gcry_err_source_t source, int err);
gcry_error_t gcry_error_from_errno(int err);

#ifdef GCRYPT_PROVIDES_GPG_ERROR
/* Convenience wrappers so that code written against libgpg-error's string
 * and errno helpers still compiles when only this library is available. */
GPG_ERR_INLINE const char *
gpg_strerror(gpg_error_t err)
{
    return gcry_strerror(err);
}

GPG_ERR_INLINE const char *
gpg_strsource(gpg_error_t err)
{
    return gcry_strsource(err);
}

GPG_ERR_INLINE gpg_err_code_t
gpg_err_code_from_errno(int err)
{
    return gcry_err_code_from_errno(err);
}

GPG_ERR_INLINE int
gpg_err_code_to_errno(gpg_err_code_t code)
{
    return gcry_err_code_to_errno(code);
}

GPG_ERR_INLINE gpg_error_t
gpg_err_make_from_errno(gpg_err_source_t source, int err)
{
    return gcry_err_make_from_errno(source, err);
}

GPG_ERR_INLINE gpg_error_t
gpg_error_from_errno(int err)
{
    return gcry_error_from_errno(err);
}

GPG_ERR_INLINE gpg_err_code_t
gpg_err_code_from_syserror(void)
{
    return gcry_err_code_from_errno(errno);
}

GPG_ERR_INLINE gpg_error_t
gpg_error_from_syserror(void)
{
    return gcry_error_from_errno(errno);
}
#endif /* GCRYPT_PROVIDES_GPG_ERROR */

/* ------------------------------------------------------------------ */
/* Legacy thread callbacks (no effect since Libgcrypt 1.6)             */
/* ------------------------------------------------------------------ */

#define GCRY_THREAD_OPTION_DEFAULT 0
#define GCRY_THREAD_OPTION_USER 1
#define GCRY_THREAD_OPTION_PTH 2
#define GCRY_THREAD_OPTION_PTHREAD 3
#define GCRY_THREAD_OPTION_VERSION 1

struct gcry_thread_cbs {
    unsigned int option;
} _GCRY_GCC_ATTR_DEPRECATED;

#define GCRY_THREAD_OPTION_PTH_IMPL                            \
    static struct gcry_thread_cbs gcry_threads_pth = {         \
        (GCRY_THREAD_OPTION_PTH | (GCRY_THREAD_OPTION_VERSION << 8)) \
    }

#define GCRY_THREAD_OPTION_PTHREAD_IMPL                        \
    static struct gcry_thread_cbs gcry_threads_pthread = {     \
        (GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8)) \
    }

/* ------------------------------------------------------------------ */
/* Basic object types                                                  */
/* ------------------------------------------------------------------ */

struct gcry_context;
typedef struct gcry_context *gcry_ctx_t;

struct gcry_mpi;
typedef struct gcry_mpi *gcry_mpi_t;
struct gcry_mpi_point;
typedef struct gcry_mpi_point *gcry_mpi_point_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_mpi *GCRY_MPI _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_mpi *GcryMPI _GCRY_GCC_ATTR_DEPRECATED;
#endif

typedef struct {
    size_t size;
    size_t off;
    size_t len;
    void *data;
} gcry_buffer_t;

const char *gcry_check_version(const char *req_version);

/* ------------------------------------------------------------------ */
/* Control commands                                                    */
/* ------------------------------------------------------------------ */

enum gcry_ctl_cmds {
    GCRYCTL_CFB_SYNC = 3,
    GCRYCTL_RESET = 4,
    GCRYCTL_FINALIZE = 5,
    GCRYCTL_GET_KEYLEN = 6,
    GCRYCTL_GET_BLKLEN = 7,
    GCRYCTL_TEST_ALGO = 8,
    GCRYCTL_IS_SECURE = 9,
    GCRYCTL_GET_ASNOID = 10,
    GCRYCTL_ENABLE_ALGO = 11,
    GCRYCTL_DISABLE_ALGO = 12,
    GCRYCTL_DUMP_RANDOM_STATS = 13,
    GCRYCTL_DUMP_SECMEM_STATS = 14,
    GCRYCTL_GET_ALGO_NPKEY = 15,
    GCRYCTL_GET_ALGO_NSKEY = 16,
    GCRYCTL_GET_ALGO_NSIGN = 17,
    GCRYCTL_GET_ALGO_NENCR = 18,
    GCRYCTL_SET_VERBOSITY = 19,
    GCRYCTL_SET_DEBUG_FLAGS = 20,
    GCRYCTL_CLEAR_DEBUG_FLAGS = 21,
    GCRYCTL_USE_SECURE_RNDPOOL = 22,
    GCRYCTL_DUMP_MEMORY_STATS = 23,
    GCRYCTL_INIT_SECMEM = 24,
    GCRYCTL_TERM_SECMEM = 25,
    GCRYCTL_DISABLE_SECMEM_WARN = 27,
    GCRYCTL_SUSPEND_SECMEM_WARN = 28,
    GCRYCTL_RESUME_SECMEM_WARN = 29,
    GCRYCTL_DROP_PRIVS = 30,
    GCRYCTL_ENABLE_M_GUARD = 31,
    GCRYCTL_START_DUMP = 32,
    GCRYCTL_STOP_DUMP = 33,
    GCRYCTL_GET_ALGO_USAGE = 34,
    GCRYCTL_IS_ALGO_ENABLED = 35,
    GCRYCTL_DISABLE_INTERNAL_LOCKING = 36,
    GCRYCTL_DISABLE_SECMEM = 37,
    GCRYCTL_INITIALIZATION_FINISHED = 38,
    GCRYCTL_INITIALIZATION_FINISHED_P = 39,
    GCRYCTL_ANY_INITIALIZATION_P = 40,
    GCRYCTL_SET_CBC_CTS = 41,
    GCRYCTL_SET_CBC_MAC = 42,
    GCRYCTL_ENABLE_QUICK_RANDOM = 44,
    GCRYCTL_SET_RANDOM_SEED_FILE = 45,
    GCRYCTL_UPDATE_RANDOM_SEED_FILE = 46,
    GCRYCTL_SET_THREAD_CBS = 47,
    GCRYCTL_FAST_POLL = 48,
    GCRYCTL_SET_RANDOM_DAEMON_SOCKET = 49,
    GCRYCTL_USE_RANDOM_DAEMON = 50,
    GCRYCTL_FAKED_RANDOM_P = 51,
    GCRYCTL_SET_RNDEGD_SOCKET = 52,
    GCRYCTL_PRINT_CONFIG = 53,
    GCRYCTL_OPERATIONAL_P = 54,
    GCRYCTL_FIPS_MODE_P = 55,
    GCRYCTL_FORCE_FIPS_MODE = 56,
    GCRYCTL_SELFTEST = 57,
    GCRYCTL_DISABLE_HWF = 63,
    GCRYCTL_SET_ENFORCED_FIPS_FLAG = 64,
    GCRYCTL_SET_PREFERRED_RNG_TYPE = 65,
    GCRYCTL_GET_CURRENT_RNG_TYPE = 66,
    GCRYCTL_DISABLE_LOCKED_SECMEM = 67,
    GCRYCTL_DISABLE_PRIV_DROP = 68,
    GCRYCTL_SET_CCM_LENGTHS = 69,
    GCRYCTL_CLOSE_RANDOM_DEVICE = 70,
    GCRYCTL_INACTIVATE_FIPS_FLAG = 71,
    GCRYCTL_REACTIVATE_FIPS_FLAG = 72,
    GCRYCTL_SET_SBOX = 73,
    GCRYCTL_DRBG_REINIT = 74,
    GCRYCTL_SET_TAGLEN = 75,
    GCRYCTL_GET_TAGLEN = 76,
    GCRYCTL_REINIT_SYSCALL_CLAMP = 77,
    GCRYCTL_AUTO_EXPAND_SECMEM = 78,
    GCRYCTL_SET_ALLOW_WEAK_KEY = 79,
    GCRYCTL_SET_DECRYPTION_TAG = 80,
    GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER = 81,
    GCRYCTL_FIPS_SERVICE_INDICATOR_KDF = 82,
    GCRYCTL_NO_FIPS_MODE = 83,
    GCRYCTL_FIPS_SERVICE_INDICATOR_FUNCTION = 84,
    GCRYCTL_FIPS_SERVICE_INDICATOR_MAC = 85,
    GCRYCTL_FIPS_SERVICE_INDICATOR_MD = 86,
    GCRYCTL_FIPS_SERVICE_INDICATOR_PK_FLAGS = 87,
    GCRYCTL_MD_CUSTOMIZE = 88,
    GCRYCTL_FIPS_SERVICE_INDICATOR = 89,
    GCRYCTL_FIPS_REJECT_NON_FIPS = 90
};

gcry_error_t gcry_control(enum gcry_ctl_cmds CMD, ...);

/* ------------------------------------------------------------------ */
/* S-expressions                                                       */
/* ------------------------------------------------------------------ */

struct gcry_sexp;
typedef struct gcry_sexp *gcry_sexp_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_sexp *GCRY_SEXP _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_sexp *GcrySexp _GCRY_GCC_ATTR_DEPRECATED;
#endif

enum gcry_sexp_format {
    GCRYSEXP_FMT_DEFAULT = 0,
    GCRYSEXP_FMT_CANON = 1,
    GCRYSEXP_FMT_BASE64 = 2,
    GCRYSEXP_FMT_ADVANCED = 3
};

gcry_error_t gcry_sexp_new(gcry_sexp_t *retsexp, const void *buffer,
                           size_t length, int autodetect);
gcry_error_t gcry_sexp_create(gcry_sexp_t *retsexp, void *buffer,
                              size_t length, int autodetect,
                              void (*freefnc)(void *));
gcry_error_t gcry_sexp_sscan(gcry_sexp_t *retsexp, size_t *erroff,
                             const char *buffer, size_t length);
gcry_error_t gcry_sexp_build(gcry_sexp_t *retsexp, size_t *erroff,
                             const char *format, ...);
gcry_error_t gcry_sexp_build_array(gcry_sexp_t *retsexp, size_t *erroff,
                                   const char *format, void **arg_list);
void gcry_sexp_release(gcry_sexp_t sexp);
size_t gcry_sexp_canon_len(const unsigned char *buffer, size_t length,
                           size_t *erroff, gcry_error_t *errcode);
size_t gcry_sexp_sprint(gcry_sexp_t sexp, int mode, void *buffer,
                        size_t maxlength);
void gcry_sexp_dump(const gcry_sexp_t a);
gcry_sexp_t gcry_sexp_cons(const gcry_sexp_t a, const gcry_sexp_t b);
gcry_sexp_t gcry_sexp_alist(const gcry_sexp_t *array);
gcry_sexp_t gcry_sexp_vlist(const gcry_sexp_t a, ...);
gcry_sexp_t gcry_sexp_append(const gcry_sexp_t a, const gcry_sexp_t n);
gcry_sexp_t gcry_sexp_prepend(const gcry_sexp_t a, const gcry_sexp_t n);
gcry_sexp_t gcry_sexp_find_token(gcry_sexp_t list, const char *tok,
                                 size_t toklen);
int gcry_sexp_length(const gcry_sexp_t list);
gcry_sexp_t gcry_sexp_nth(const gcry_sexp_t list, int number);
gcry_sexp_t gcry_sexp_car(const gcry_sexp_t list);
gcry_sexp_t gcry_sexp_cdr(const gcry_sexp_t list);
gcry_sexp_t gcry_sexp_cadr(const gcry_sexp_t list);
const char *gcry_sexp_nth_data(const gcry_sexp_t list, int number,
                               size_t *datalen);
void *gcry_sexp_nth_buffer(const gcry_sexp_t list, int number,
                           size_t *rlength);
char *gcry_sexp_nth_string(gcry_sexp_t list, int number);
gcry_mpi_t gcry_sexp_nth_mpi(gcry_sexp_t list, int number, int mpifmt);
gpg_error_t gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path,
                                    const char *list, ...)
_GCRY_GCC_ATTR_SENTINEL(0);

/* ------------------------------------------------------------------ */
/* Multi precision integers                                            */
/* ------------------------------------------------------------------ */

enum gcry_mpi_format {
    GCRYMPI_FMT_NONE = 0,
    GCRYMPI_FMT_STD = 1,
    GCRYMPI_FMT_PGP = 2,
    GCRYMPI_FMT_SSH = 3,
    GCRYMPI_FMT_HEX = 4,
    GCRYMPI_FMT_USG = 5,
    GCRYMPI_FMT_OPAQUE = 8
};

enum gcry_mpi_flag {
    GCRYMPI_FLAG_SECURE = 1,
    GCRYMPI_FLAG_OPAQUE = 2,
    GCRYMPI_FLAG_IMMUTABLE = 4,
    GCRYMPI_FLAG_CONST = 8,
    GCRYMPI_FLAG_USER1 = 0x0100,
    GCRYMPI_FLAG_USER2 = 0x0200,
    GCRYMPI_FLAG_USER3 = 0x0400,
    GCRYMPI_FLAG_USER4 = 0x0800
};

#define GCRYMPI_CONST_ONE (_gcry_mpi_get_const(1))
#define GCRYMPI_CONST_TWO (_gcry_mpi_get_const(2))
#define GCRYMPI_CONST_THREE (_gcry_mpi_get_const(3))
#define GCRYMPI_CONST_FOUR (_gcry_mpi_get_const(4))
#define GCRYMPI_CONST_EIGHT (_gcry_mpi_get_const(8))

gcry_mpi_t gcry_mpi_new(unsigned int nbits);
gcry_mpi_t gcry_mpi_snew(unsigned int nbits);
void gcry_mpi_release(gcry_mpi_t a);
gcry_mpi_t gcry_mpi_copy(const gcry_mpi_t a);
void gcry_mpi_snatch(gcry_mpi_t w, gcry_mpi_t u);
gcry_mpi_t gcry_mpi_set(gcry_mpi_t w, const gcry_mpi_t u);
gcry_mpi_t gcry_mpi_set_ui(gcry_mpi_t w, unsigned long u);
gpg_error_t gcry_mpi_get_ui(unsigned int *w, gcry_mpi_t u);
void gcry_mpi_swap(gcry_mpi_t a, gcry_mpi_t b);
int gcry_mpi_is_neg(gcry_mpi_t a);
void gcry_mpi_neg(gcry_mpi_t w, gcry_mpi_t u);
void gcry_mpi_abs(gcry_mpi_t w);
int gcry_mpi_cmp(const gcry_mpi_t u, const gcry_mpi_t v);
int gcry_mpi_cmp_ui(const gcry_mpi_t u, unsigned long v);
gcry_error_t gcry_mpi_scan(gcry_mpi_t *ret_mpi, enum gcry_mpi_format format,
                           const void *buffer, size_t buflen,
                           size_t *nscanned);
gcry_error_t gcry_mpi_print(enum gcry_mpi_format format,
                            unsigned char *buffer, size_t buflen,
                            size_t *nwritten, const gcry_mpi_t a);
gcry_error_t gcry_mpi_aprint(enum gcry_mpi_format format,
                             unsigned char **buffer, size_t *nwritten,
                             const gcry_mpi_t a);
void gcry_mpi_dump(const gcry_mpi_t a);
void gcry_mpi_add(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
void gcry_mpi_add_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v);
void gcry_mpi_addm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
void gcry_mpi_sub(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
void gcry_mpi_sub_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v);
void gcry_mpi_subm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
void gcry_mpi_mul(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
void gcry_mpi_mul_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v);
void gcry_mpi_mulm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
void gcry_mpi_mul_2exp(gcry_mpi_t w, gcry_mpi_t u, unsigned long cnt);
void gcry_mpi_div(gcry_mpi_t q, gcry_mpi_t r, gcry_mpi_t dividend,
                  gcry_mpi_t divisor, int round);
void gcry_mpi_mod(gcry_mpi_t r, gcry_mpi_t dividend, gcry_mpi_t divisor);
void gcry_mpi_powm(gcry_mpi_t w, const gcry_mpi_t b, const gcry_mpi_t e,
                   const gcry_mpi_t m);
int gcry_mpi_gcd(gcry_mpi_t g, gcry_mpi_t a, gcry_mpi_t b);
int gcry_mpi_invm(gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t m);

gcry_mpi_point_t gcry_mpi_point_new(unsigned int nbits);
void gcry_mpi_point_release(gcry_mpi_point_t point);
gcry_mpi_point_t gcry_mpi_point_copy(gcry_mpi_point_t point);
void gcry_mpi_point_get(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
                        gcry_mpi_point_t point);
void gcry_mpi_point_snatch_get(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
                               gcry_mpi_point_t point);
gcry_mpi_point_t gcry_mpi_point_set(gcry_mpi_point_t point, gcry_mpi_t x,
                                    gcry_mpi_t y, gcry_mpi_t z);
gcry_mpi_point_t gcry_mpi_point_snatch_set(gcry_mpi_point_t point,
                                           gcry_mpi_t x, gcry_mpi_t y,
                                           gcry_mpi_t z);

gpg_error_t gcry_mpi_ec_new(gcry_ctx_t *r_ctx, gcry_sexp_t keyparam,
                            const char *curvename);
gcry_mpi_t gcry_mpi_ec_get_mpi(const char *name, gcry_ctx_t ctx, int copy);
gcry_mpi_point_t gcry_mpi_ec_get_point(const char *name, gcry_ctx_t ctx,
                                       int copy);
gpg_error_t gcry_mpi_ec_set_mpi(const char *name, gcry_mpi_t newvalue,
                                gcry_ctx_t ctx);
gpg_error_t gcry_mpi_ec_set_point(const char *name,
                                  gcry_mpi_point_t newvalue, gcry_ctx_t ctx);
gpg_error_t gcry_mpi_ec_decode_point(gcry_mpi_point_t result,
                                     gcry_mpi_t value, gcry_ctx_t ctx);
int gcry_mpi_ec_get_affine(gcry_mpi_t x, gcry_mpi_t y,
                           gcry_mpi_point_t point, gcry_ctx_t ctx);
void gcry_mpi_ec_dup(gcry_mpi_point_t w, gcry_mpi_point_t u, gcry_ctx_t ctx);
void gcry_mpi_ec_add(gcry_mpi_point_t w, gcry_mpi_point_t u,
                     gcry_mpi_point_t v, gcry_ctx_t ctx);
void gcry_mpi_ec_sub(gcry_mpi_point_t w, gcry_mpi_point_t u,
                     gcry_mpi_point_t v, gcry_ctx_t ctx);
void gcry_mpi_ec_mul(gcry_mpi_point_t w, gcry_mpi_t n, gcry_mpi_point_t u,
                     gcry_ctx_t ctx);
int gcry_mpi_ec_curve_point(gcry_mpi_point_t w, gcry_ctx_t ctx);

unsigned int gcry_mpi_get_nbits(gcry_mpi_t a);
int gcry_mpi_test_bit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_set_bit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_clear_bit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_set_highbit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_clear_highbit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_rshift(gcry_mpi_t x, gcry_mpi_t a, unsigned int n);
void gcry_mpi_lshift(gcry_mpi_t x, gcry_mpi_t a, unsigned int n);
gcry_mpi_t gcry_mpi_set_opaque(gcry_mpi_t a, void *p, unsigned int nbits);
gcry_mpi_t gcry_mpi_set_opaque_copy(gcry_mpi_t a, const void *p,
                                    unsigned int nbits);
void *gcry_mpi_get_opaque(gcry_mpi_t a, unsigned int *nbits);
void gcry_mpi_set_flag(gcry_mpi_t a, enum gcry_mpi_flag flag);
void gcry_mpi_clear_flag(gcry_mpi_t a, enum gcry_mpi_flag flag);
int gcry_mpi_get_flag(gcry_mpi_t a, enum gcry_mpi_flag flag);
gcry_mpi_t _gcry_mpi_get_const(int no);

#ifndef GCRYPT_NO_MPI_MACROS
#define mpi_new(n) gcry_mpi_new((n))
#define mpi_secure_new(n) gcry_mpi_snew((n))
#define mpi_release(a)        \
        do {                      \
            gcry_mpi_release((a));\
            (a) = NULL;           \
        } while (0)
#define mpi_copy(a) gcry_mpi_copy((a))
#define mpi_snatch(w, u) gcry_mpi_snatch((w), (u))
#define mpi_set(w, u) gcry_mpi_set((w), (u))
#define mpi_set_ui(w, u) gcry_mpi_set_ui((w), (u))
#define mpi_get_ui(w, u) gcry_mpi_get_ui((w), (u))
#define mpi_abs(w) gcry_mpi_abs((w))
#define mpi_neg(w, u) gcry_mpi_neg((w), (u))
#define mpi_cmp(u, v) gcry_mpi_cmp((u), (v))
#define mpi_cmp_ui(u, v) gcry_mpi_cmp_ui((u), (v))
#define mpi_is_neg(a) gcry_mpi_is_neg((a))
#define mpi_add_ui(w, u, v) gcry_mpi_add_ui((w), (u), (v))
#define mpi_add(w, u, v) gcry_mpi_add((w), (u), (v))
#define mpi_addm(w, u, v, m) gcry_mpi_addm((w), (u), (v), (m))
#define mpi_sub_ui(w, u, v) gcry_mpi_sub_ui((w), (u), (v))
#define mpi_sub(w, u, v) gcry_mpi_sub((w), (u), (v))
#define mpi_subm(w, u, v, m) gcry_mpi_subm((w), (u), (v), (m))
#define mpi_mul_ui(w, u, v) gcry_mpi_mul_ui((w), (u), (v))
#define mpi_mul_2exp(w, u, v) gcry_mpi_mul_2exp((w), (u), (v))
#define mpi_mul(w, u, v) gcry_mpi_mul((w), (u), (v))
#define mpi_mulm(w, u, v, m) gcry_mpi_mulm((w), (u), (v), (m))
#define mpi_powm(w, b, e, m) gcry_mpi_powm((w), (b), (e), (m))
#define mpi_tdiv(q, r, a, m) gcry_mpi_div((q), (r), (a), (m), 0)
#define mpi_fdiv(q, r, a, m) gcry_mpi_div((q), (r), (a), (m), -1)
#define mpi_mod(r, a, m) gcry_mpi_mod((r), (a), (m))
#define mpi_gcd(g, a, b) gcry_mpi_gcd((g), (a), (b))
#define mpi_invm(g, a, b) gcry_mpi_invm((g), (a), (b))
#define mpi_point_new(n) gcry_mpi_point_new((n))
#define mpi_point_release(p)        \
        do {                            \
            gcry_mpi_point_release((p));\
            (p) = NULL;                 \
        } while (0)
#define mpi_point_copy(p) gcry_mpi_point_copy((p))
#define mpi_point_get(x, y, z, p) gcry_mpi_point_get((x), (y), (z), (p))
#define mpi_point_snatch_get(x, y, z, p) \
        gcry_mpi_point_snatch_get((x), (y), (z), (p))
#define mpi_point_set(p, x, y, z) gcry_mpi_point_set((p), (x), (y), (z))
#define mpi_point_snatch_set(p, x, y, z) \
        gcry_mpi_point_snatch_set((p), (x), (y), (z))
#define mpi_get_nbits(a) gcry_mpi_get_nbits((a))
#define mpi_test_bit(a, b) gcry_mpi_test_bit((a), (b))
#define mpi_set_bit(a, b) gcry_mpi_set_bit((a), (b))
#define mpi_set_highbit(a, b) gcry_mpi_set_highbit((a), (b))
#define mpi_clear_bit(a, b) gcry_mpi_clear_bit((a), (b))
#define mpi_clear_highbit(a, b) gcry_mpi_clear_highbit((a), (b))
#define mpi_rshift(a, b, c) gcry_mpi_rshift((a), (b), (c))
#define mpi_lshift(a, b, c) gcry_mpi_lshift((a), (b), (c))
#define mpi_set_opaque(a, b, c) gcry_mpi_set_opaque((a), (b), (c))
#define mpi_get_opaque(a, b) gcry_mpi_get_opaque((a), (b))
#endif /* GCRYPT_NO_MPI_MACROS */

/* ------------------------------------------------------------------ */
/* Symmetric ciphers                                                   */
/* ------------------------------------------------------------------ */

struct gcry_cipher_handle;
typedef struct gcry_cipher_handle *gcry_cipher_hd_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_cipher_handle *GCRY_CIPHER_HD _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_cipher_handle *GcryCipherHd _GCRY_GCC_ATTR_DEPRECATED;
#endif

enum gcry_cipher_algos {
    GCRY_CIPHER_NONE = 0,
    GCRY_CIPHER_IDEA = 1,
    GCRY_CIPHER_3DES = 2,
    GCRY_CIPHER_CAST5 = 3,
    GCRY_CIPHER_BLOWFISH = 4,
    GCRY_CIPHER_SAFER_SK128 = 5,
    GCRY_CIPHER_DES_SK = 6,
    GCRY_CIPHER_AES = 7,
    GCRY_CIPHER_AES192 = 8,
    GCRY_CIPHER_AES256 = 9,
    GCRY_CIPHER_TWOFISH = 10,
    GCRY_CIPHER_ARCFOUR = 301,
    GCRY_CIPHER_DES = 302,
    GCRY_CIPHER_TWOFISH128 = 303,
    GCRY_CIPHER_SERPENT128 = 304,
    GCRY_CIPHER_SERPENT192 = 305,
    GCRY_CIPHER_SERPENT256 = 306,
    GCRY_CIPHER_RFC2268_40 = 307,
    GCRY_CIPHER_RFC2268_128 = 308,
    GCRY_CIPHER_SEED = 309,
    GCRY_CIPHER_CAMELLIA128 = 310,
    GCRY_CIPHER_CAMELLIA192 = 311,
    GCRY_CIPHER_CAMELLIA256 = 312,
    GCRY_CIPHER_SALSA20 = 313,
    GCRY_CIPHER_SALSA20R12 = 314,
    GCRY_CIPHER_GOST28147 = 315,
    GCRY_CIPHER_CHACHA20 = 316,
    GCRY_CIPHER_GOST28147_MESH = 317,
    GCRY_CIPHER_SM4 = 318,
    GCRY_CIPHER_ARIA128 = 319,
    GCRY_CIPHER_ARIA192 = 320,
    GCRY_CIPHER_ARIA256 = 321
};

#define GCRY_CIPHER_AES128 GCRY_CIPHER_AES
#define GCRY_CIPHER_RIJNDAEL GCRY_CIPHER_AES
#define GCRY_CIPHER_RIJNDAEL128 GCRY_CIPHER_AES128
#define GCRY_CIPHER_RIJNDAEL192 GCRY_CIPHER_AES192
#define GCRY_CIPHER_RIJNDAEL256 GCRY_CIPHER_AES256

enum gcry_cipher_modes {
    GCRY_CIPHER_MODE_NONE = 0,
    GCRY_CIPHER_MODE_ECB = 1,
    GCRY_CIPHER_MODE_CFB = 2,
    GCRY_CIPHER_MODE_CBC = 3,
    GCRY_CIPHER_MODE_STREAM = 4,
    GCRY_CIPHER_MODE_OFB = 5,
    GCRY_CIPHER_MODE_CTR = 6,
    GCRY_CIPHER_MODE_AESWRAP = 7,
    GCRY_CIPHER_MODE_CCM = 8,
    GCRY_CIPHER_MODE_GCM = 9,
    GCRY_CIPHER_MODE_POLY1305 = 10,
    GCRY_CIPHER_MODE_OCB = 11,
    GCRY_CIPHER_MODE_CFB8 = 12,
    GCRY_CIPHER_MODE_XTS = 13,
    GCRY_CIPHER_MODE_EAX = 14,
    GCRY_CIPHER_MODE_SIV = 15,
    GCRY_CIPHER_MODE_GCM_SIV = 16
};

enum gcry_cipher_flags {
    GCRY_CIPHER_SECURE = 1,
    GCRY_CIPHER_ENABLE_SYNC = 2,
    GCRY_CIPHER_CBC_CTS = 4,
    GCRY_CIPHER_CBC_MAC = 8,
    GCRY_CIPHER_EXTENDED = 16
};

enum gcry_cipher_geniv_methods {
    GCRY_CIPHER_GENIV_METHOD_CONCAT = 1,
    GCRY_CIPHER_GENIV_METHOD_XOR = 2
};

#define GCRY_GCM_BLOCK_LEN (128 / 8)
#define GCRY_CCM_BLOCK_LEN (128 / 8)
#define GCRY_OCB_BLOCK_LEN (128 / 8)
#define GCRY_XTS_BLOCK_LEN (128 / 8)
#define GCRY_SIV_BLOCK_LEN (128 / 8)

gcry_error_t gcry_cipher_open(gcry_cipher_hd_t *handle, int algo, int mode,
                              unsigned int flags);
void gcry_cipher_close(gcry_cipher_hd_t h);
gcry_error_t gcry_cipher_ctl(gcry_cipher_hd_t h, int cmd, void *buffer,
                             size_t buflen);
gcry_error_t gcry_cipher_info(gcry_cipher_hd_t h, int what, void *buffer,
                              size_t *nbytes);
gcry_error_t gcry_cipher_algo_info(int algo, int what, void *buffer,
                                   size_t *nbytes);
const char *gcry_cipher_algo_name(int algorithm) _GCRY_GCC_ATTR_PURE;
int gcry_cipher_map_name(const char *name) _GCRY_GCC_ATTR_PURE;
int gcry_cipher_mode_from_oid(const char *string) _GCRY_GCC_ATTR_PURE;
gcry_error_t gcry_cipher_encrypt(gcry_cipher_hd_t h, void *out,
                                 size_t outsize, const void *in,
                                 size_t inlen);
gcry_error_t gcry_cipher_decrypt(gcry_cipher_hd_t h, void *out,
                                 size_t outsize, const void *in,
                                 size_t inlen);
gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t hd, const void *key,
                                size_t keylen);
gcry_error_t gcry_cipher_setiv(gcry_cipher_hd_t hd, const void *iv,
                               size_t ivlen);
gcry_error_t gcry_cipher_setup_geniv(gcry_cipher_hd_t hd, int method,
                                     const void *fixed_iv,
                                     size_t fixed_ivlen, const void *dyn_iv,
                                     size_t dyn_ivlen);
gcry_error_t gcry_cipher_geniv(gcry_cipher_hd_t hd, void *iv, size_t ivlen);
gcry_error_t gcry_cipher_authenticate(gcry_cipher_hd_t hd, const void *abuf,
                                      size_t abuflen);
gcry_error_t gcry_cipher_gettag(gcry_cipher_hd_t hd, void *outtag,
                                size_t taglen);
gcry_error_t gcry_cipher_checktag(gcry_cipher_hd_t hd, const void *intag,
                                  size_t taglen);

#define gcry_cipher_reset(h) gcry_cipher_ctl((h), GCRYCTL_RESET, NULL, 0)
#define gcry_cipher_sync(h) gcry_cipher_ctl((h), GCRYCTL_CFB_SYNC, NULL, 0)
#define gcry_cipher_cts(h, on) \
    gcry_cipher_ctl((h), GCRYCTL_SET_CBC_CTS, NULL, on)
#define gcry_cipher_set_sbox(h, oid) \
    gcry_cipher_ctl((h), GCRYCTL_SET_SBOX, (void *)oid, 0);
#define gcry_cipher_final(a) gcry_cipher_ctl((a), GCRYCTL_FINALIZE, NULL, 0)

gpg_error_t gcry_cipher_setctr(gcry_cipher_hd_t hd, const void *ctr,
                               size_t ctrlen);
size_t gcry_cipher_get_algo_keylen(int algo);
size_t gcry_cipher_get_algo_blklen(int algo);

#define gcry_cipher_test_algo(a) \
    gcry_cipher_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)
#define gcry_cipher_set_decryption_tag(a, tag, taglen) \
    gcry_cipher_ctl((a), GCRYCTL_SET_DECRYPTION_TAG, (void *)(tag), (taglen))

/* ------------------------------------------------------------------ */
/* Public key algorithms                                               */
/* ------------------------------------------------------------------ */

enum gcry_pk_algos {
    GCRY_PK_RSA = 1,
    GCRY_PK_RSA_E = 2,
    GCRY_PK_RSA_S = 3,
    GCRY_PK_ELG_E = 16,
    GCRY_PK_DSA = 17,
    GCRY_PK_ECC = 18,
    GCRY_PK_ELG = 20,
    GCRY_PK_ECDSA = 301,
    GCRY_PK_ECDH = 302,
    GCRY_PK_EDDSA = 303,
    GCRY_PK_MLDSA = 332,
    GCRY_PK_KEM = 333
};

#define GCRY_PK_USAGE_SIGN 1
#define GCRY_PK_USAGE_ENCR 2
#define GCRY_PK_USAGE_CERT 4
#define GCRY_PK_USAGE_AUTH 8
#define GCRY_PK_USAGE_UNKN 128

#define GCRY_PK_GET_PUBKEY 1
#define GCRY_PK_GET_SECKEY 2

gcry_error_t gcry_pk_encrypt(gcry_sexp_t *result, gcry_sexp_t data,
                             gcry_sexp_t pkey);
gcry_error_t gcry_pk_decrypt(gcry_sexp_t *result, gcry_sexp_t data,
                             gcry_sexp_t skey);
gcry_error_t gcry_pk_sign(gcry_sexp_t *result, gcry_sexp_t data,
                          gcry_sexp_t skey);
gcry_error_t gcry_pk_verify(gcry_sexp_t sigval, gcry_sexp_t data,
                            gcry_sexp_t pkey);
gcry_error_t gcry_pk_testkey(gcry_sexp_t key);
gcry_error_t gcry_pk_genkey(gcry_sexp_t *r_key, gcry_sexp_t s_parms);
gcry_error_t gcry_pk_ctl(int cmd, void *buffer, size_t buflen);
gcry_error_t gcry_pk_algo_info(int algo, int what, void *buffer,
                               size_t *nbytes);
const char *gcry_pk_algo_name(int algorithm) _GCRY_GCC_ATTR_PURE;
int gcry_pk_map_name(const char *name) _GCRY_GCC_ATTR_PURE;
unsigned int gcry_pk_get_nbits(gcry_sexp_t key) _GCRY_GCC_ATTR_PURE;
unsigned char *gcry_pk_get_keygrip(gcry_sexp_t key, unsigned char *array);
const char *gcry_pk_get_curve(gcry_sexp_t key, int iterator,
                              unsigned int *r_nbits);
gcry_sexp_t gcry_pk_get_param(int algo, const char *name);

#define gcry_pk_test_algo(a) \
    gcry_pk_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)

gcry_error_t gcry_pubkey_get_sexp(gcry_sexp_t *r_sexp, int mode,
                                  gcry_ctx_t ctx);

/* Modern ECC helpers. */
enum gcry_ecc_curves {
    GCRY_ECC_CURVE25519 = 1,
    GCRY_ECC_CURVE448 = 2
};

unsigned int gcry_ecc_get_algo_keylen(int curveid);
gpg_error_t gcry_ecc_mul_point(int curveid, unsigned char *result,
                               const unsigned char *scalar,
                               const unsigned char *point);

/* ------------------------------------------------------------------ */
/* Message digests                                                     */
/* ------------------------------------------------------------------ */

enum gcry_md_algos {
    GCRY_MD_NONE = 0,
    GCRY_MD_MD5 = 1,
    GCRY_MD_SHA1 = 2,
    GCRY_MD_RMD160 = 3,
    GCRY_MD_MD2 = 5,
    GCRY_MD_TIGER = 6,
    GCRY_MD_HAVAL = 7,
    GCRY_MD_SHA256 = 8,
    GCRY_MD_SHA384 = 9,
    GCRY_MD_SHA512 = 10,
    GCRY_MD_SHA224 = 11,
    GCRY_MD_MD4 = 301,
    GCRY_MD_CRC32 = 302,
    GCRY_MD_CRC32_RFC1510 = 303,
    GCRY_MD_CRC24_RFC2440 = 304,
    GCRY_MD_WHIRLPOOL = 305,
    GCRY_MD_TIGER1 = 306,
    GCRY_MD_TIGER2 = 307,
    GCRY_MD_GOSTR3411_94 = 308,
    GCRY_MD_STRIBOG256 = 309,
    GCRY_MD_STRIBOG512 = 310,
    GCRY_MD_GOSTR3411_CP = 311,
    GCRY_MD_SHA3_224 = 312,
    GCRY_MD_SHA3_256 = 313,
    GCRY_MD_SHA3_384 = 314,
    GCRY_MD_SHA3_512 = 315,
    GCRY_MD_SHAKE128 = 316,
    GCRY_MD_SHAKE256 = 317,
    GCRY_MD_BLAKE2B_512 = 318,
    GCRY_MD_BLAKE2B_384 = 319,
    GCRY_MD_BLAKE2B_256 = 320,
    GCRY_MD_BLAKE2B_160 = 321,
    GCRY_MD_BLAKE2S_256 = 322,
    GCRY_MD_BLAKE2S_224 = 323,
    GCRY_MD_BLAKE2S_160 = 324,
    GCRY_MD_BLAKE2S_128 = 325,
    GCRY_MD_SM3 = 326,
    GCRY_MD_SHA512_256 = 327,
    GCRY_MD_SHA512_224 = 328,
    GCRY_MD_CSHAKE128 = 329,
    GCRY_MD_CSHAKE256 = 330
};

enum gcry_md_flags {
    GCRY_MD_FLAG_SECURE = 1,
    GCRY_MD_FLAG_HMAC = 2,
    GCRY_MD_FLAG_BUGEMU1 = 0x0100
};

struct gcry_md_context;

/* The layout of this structure is part of the ABI: the gcry_md_putc()
 * macro below touches its members directly. */
typedef struct gcry_md_handle {
    struct gcry_md_context *ctx;
    int bufpos;
    int bufsize;
    unsigned char buf[1];
} *gcry_md_hd_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_md_handle *GCRY_MD_HD _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_md_handle *GcryMDHd _GCRY_GCC_ATTR_DEPRECATED;
#endif

gcry_error_t gcry_md_open(gcry_md_hd_t *h, int algo, unsigned int flags);
void gcry_md_close(gcry_md_hd_t hd);
gcry_error_t gcry_md_enable(gcry_md_hd_t hd, int algo);
gcry_error_t gcry_md_copy(gcry_md_hd_t *bhd, gcry_md_hd_t ahd);
void gcry_md_reset(gcry_md_hd_t hd);
gcry_error_t gcry_md_ctl(gcry_md_hd_t hd, int cmd, void *buffer,
                         size_t buflen);
void gcry_md_write(gcry_md_hd_t hd, const void *buffer, size_t length);
unsigned char *gcry_md_read(gcry_md_hd_t hd, int algo);
gpg_error_t gcry_md_extract(gcry_md_hd_t hd, int algo, void *buffer,
                            size_t length);
void gcry_md_hash_buffer(int algo, void *digest, const void *buffer,
                         size_t length);
gpg_error_t gcry_md_hash_buffers(int algo, unsigned int flags, void *digest,
                                 const gcry_buffer_t *iov, int iovcnt);
gpg_error_t gcry_md_hash_buffers_ext(int algo, unsigned int flags,
                                     void *digest, int digestlen,
                                     const gcry_buffer_t *iov, int iovcnt);
int gcry_md_get_algo(gcry_md_hd_t hd);
unsigned int gcry_md_get_algo_dlen(int algo);
int gcry_md_is_enabled(gcry_md_hd_t a, int algo);
int gcry_md_is_secure(gcry_md_hd_t a);
gcry_error_t gcry_md_info(gcry_md_hd_t h, int what, void *buffer,
                          size_t *nbytes) _GCRY_ATTR_INTERNAL;
gcry_error_t gcry_md_algo_info(int algo, int what, void *buffer,
                               size_t *nbytes);
const char *gcry_md_algo_name(int algo) _GCRY_GCC_ATTR_PURE;
int gcry_md_map_name(const char *name) _GCRY_GCC_ATTR_PURE;
gcry_error_t gcry_md_setkey(gcry_md_hd_t hd, const void *key, size_t keylen);
void gcry_md_debug(gcry_md_hd_t hd, const char *suffix);

#define gcry_md_putc(h, c)                                \
    do {                                                  \
        gcry_md_hd_t h__ = (h);                           \
        if ((h__)->bufpos == (h__)->bufsize)              \
            gcry_md_write((h__), NULL, 0);                \
        (h__)->buf[(h__)->bufpos++] = (c) & 0xff;         \
    } while (0)

#define gcry_md_final(a) gcry_md_ctl((a), GCRYCTL_FINALIZE, NULL, 0)
#define gcry_md_test_algo(a) \
    gcry_md_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)
#define gcry_md_get_asnoid(a, b, n) \
    gcry_md_algo_info((a), GCRYCTL_GET_ASNOID, (b), (n))

struct gcry_cshake_customization {
    const void *n;
    unsigned int n_len;
    const void *s;
    unsigned int s_len;
};

/* ------------------------------------------------------------------ */
/* Message authentication codes                                        */
/* ------------------------------------------------------------------ */

struct gcry_mac_handle;
typedef struct gcry_mac_handle *gcry_mac_hd_t;

enum gcry_mac_algos {
    GCRY_MAC_NONE = 0,
    GCRY_MAC_GOST28147_IMIT = 1,
    GCRY_MAC_HMAC_SHA256 = 101,
    GCRY_MAC_HMAC_SHA224 = 102,
    GCRY_MAC_HMAC_SHA512 = 103,
    GCRY_MAC_HMAC_SHA384 = 104,
    GCRY_MAC_HMAC_SHA1 = 105,
    GCRY_MAC_HMAC_MD5 = 106,
    GCRY_MAC_HMAC_MD4 = 107,
    GCRY_MAC_HMAC_RMD160 = 108,
    GCRY_MAC_HMAC_TIGER1 = 109,
    GCRY_MAC_HMAC_WHIRLPOOL = 110,
    GCRY_MAC_HMAC_GOSTR3411_94 = 111,
    GCRY_MAC_HMAC_STRIBOG256 = 112,
    GCRY_MAC_HMAC_STRIBOG512 = 113,
    GCRY_MAC_HMAC_MD2 = 114,
    GCRY_MAC_HMAC_SHA3_224 = 115,
    GCRY_MAC_HMAC_SHA3_256 = 116,
    GCRY_MAC_HMAC_SHA3_384 = 117,
    GCRY_MAC_HMAC_SHA3_512 = 118,
    GCRY_MAC_HMAC_GOSTR3411_CP = 119,
    GCRY_MAC_HMAC_BLAKE2B_512 = 120,
    GCRY_MAC_HMAC_BLAKE2B_384 = 121,
    GCRY_MAC_HMAC_BLAKE2B_256 = 122,
    GCRY_MAC_HMAC_BLAKE2B_160 = 123,
    GCRY_MAC_HMAC_BLAKE2S_256 = 124,
    GCRY_MAC_HMAC_BLAKE2S_224 = 125,
    GCRY_MAC_HMAC_BLAKE2S_160 = 126,
    GCRY_MAC_HMAC_BLAKE2S_128 = 127,
    GCRY_MAC_HMAC_SM3 = 128,
    GCRY_MAC_HMAC_SHA512_256 = 129,
    GCRY_MAC_HMAC_SHA512_224 = 130,
    GCRY_MAC_CMAC_AES = 201,
    GCRY_MAC_CMAC_3DES = 202,
    GCRY_MAC_CMAC_CAMELLIA = 203,
    GCRY_MAC_CMAC_CAST5 = 204,
    GCRY_MAC_CMAC_BLOWFISH = 205,
    GCRY_MAC_CMAC_TWOFISH = 206,
    GCRY_MAC_CMAC_SERPENT = 207,
    GCRY_MAC_CMAC_SEED = 208,
    GCRY_MAC_CMAC_RFC2268 = 209,
    GCRY_MAC_CMAC_IDEA = 210,
    GCRY_MAC_CMAC_GOST28147 = 211,
    GCRY_MAC_CMAC_SM4 = 212,
    GCRY_MAC_CMAC_ARIA = 213,
    GCRY_MAC_GMAC_AES = 401,
    GCRY_MAC_GMAC_CAMELLIA = 402,
    GCRY_MAC_GMAC_TWOFISH = 403,
    GCRY_MAC_GMAC_SERPENT = 404,
    GCRY_MAC_GMAC_SEED = 405,
    GCRY_MAC_GMAC_SM4 = 406,
    GCRY_MAC_GMAC_ARIA = 407,
    GCRY_MAC_POLY1305 = 501,
    GCRY_MAC_POLY1305_AES = 502,
    GCRY_MAC_POLY1305_CAMELLIA = 503,
    GCRY_MAC_POLY1305_TWOFISH = 504,
    GCRY_MAC_POLY1305_SERPENT = 505,
    GCRY_MAC_POLY1305_SEED = 506,
    GCRY_MAC_POLY1305_SM4 = 507,
    GCRY_MAC_POLY1305_ARIA = 508
};

enum gcry_mac_flags {
    GCRY_MAC_FLAG_SECURE = 1
};

gcry_error_t gcry_mac_open(gcry_mac_hd_t *handle, int algo,
                           unsigned int flags, gcry_ctx_t ctx);
void gcry_mac_close(gcry_mac_hd_t h);
gcry_error_t gcry_mac_ctl(gcry_mac_hd_t h, int cmd, void *buffer,
                          size_t buflen);
gcry_error_t gcry_mac_algo_info(int algo, int what, void *buffer,
                                size_t *nbytes);
gcry_error_t gcry_mac_setkey(gcry_mac_hd_t hd, const void *key,
                             size_t keylen);
gcry_error_t gcry_mac_setiv(gcry_mac_hd_t hd, const void *iv, size_t ivlen);
gcry_error_t gcry_mac_write(gcry_mac_hd_t hd, const void *buffer,
                            size_t length);
gcry_error_t gcry_mac_read(gcry_mac_hd_t hd, void *buffer, size_t *buflen);
gcry_error_t gcry_mac_verify(gcry_mac_hd_t hd, const void *buffer,
                             size_t buflen);
int gcry_mac_get_algo(gcry_mac_hd_t hd);
unsigned int gcry_mac_get_algo_maclen(int algo);
unsigned int gcry_mac_get_algo_keylen(int algo);
const char *gcry_mac_algo_name(int algorithm) _GCRY_GCC_ATTR_PURE;
int gcry_mac_map_name(const char *name) _GCRY_GCC_ATTR_PURE;

#define gcry_mac_reset(h) gcry_mac_ctl((h), GCRYCTL_RESET, NULL, 0)
#define gcry_mac_test_algo(a) \
    gcry_mac_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)

/* ------------------------------------------------------------------ */
/* Key derivation                                                      */
/* ------------------------------------------------------------------ */

enum gcry_kdf_algos {
    GCRY_KDF_NONE = 0,
    GCRY_KDF_SIMPLE_S2K = 16,
    GCRY_KDF_SALTED_S2K = 17,
    GCRY_KDF_ITERSALTED_S2K = 19,
    GCRY_KDF_PBKDF1 = 33,
    GCRY_KDF_PBKDF2 = 34,
    GCRY_KDF_SCRYPT = 48,
    GCRY_KDF_ARGON2 = 64,
    GCRY_KDF_BALLOON = 65,
    GCRY_KDF_ONESTEP_KDF = 96,
    GCRY_KDF_ONESTEP_KDF_MAC = 97,
    GCRY_KDF_HKDF = 98,
    GCRY_KDF_X963_KDF = 101
};

enum gcry_kdf_subalgo_argon2 {
    GCRY_KDF_ARGON2D = 0,
    GCRY_KDF_ARGON2I = 1,
    GCRY_KDF_ARGON2ID = 2
};

gpg_error_t gcry_kdf_derive(const void *passphrase, size_t passphraselen,
                            int algo, int subalgo, const void *salt,
                            size_t saltlen, unsigned long iterations,
                            size_t keysize, void *keybuffer);

typedef struct gcry_kdf_handle *gcry_kdf_hd_t;

typedef void (*gcry_kdf_job_fn_t)(void *priv);
typedef int (*gcry_kdf_dispatch_job_fn_t)(void *jobs_context,
                                          gcry_kdf_job_fn_t job_fn,
                                          void *job_priv);
typedef int (*gcry_kdf_wait_all_jobs_fn_t)(void *jobs_context);

typedef struct gcry_kdf_thread_ops {
    void *jobs_context;
    gcry_kdf_dispatch_job_fn_t dispatch_job;
    gcry_kdf_wait_all_jobs_fn_t wait_all_jobs;
} gcry_kdf_thread_ops_t;

gcry_error_t gcry_kdf_open(gcry_kdf_hd_t *hd, int algo, int subalgo,
                           const unsigned long *param, unsigned int paramlen,
                           const void *passphrase, size_t passphraselen,
                           const void *salt, size_t saltlen, const void *key,
                           size_t keylen, const void *ad, size_t adlen);
gcry_error_t gcry_kdf_compute(gcry_kdf_hd_t h,
                              const gcry_kdf_thread_ops_t *ops);
gcry_error_t gcry_kdf_final(gcry_kdf_hd_t h, size_t resultlen, void *result);
void gcry_kdf_close(gcry_kdf_hd_t h);

/* ------------------------------------------------------------------ */
/* Key encapsulation                                                   */
/* ------------------------------------------------------------------ */

enum gcry_kem_algos {
    GCRY_KEM_NONE = 0,
    GCRY_KEM_SNTRUP761 = 1,
#define GCRY_KEM_SNTRUP761 GCRY_KEM_SNTRUP761
    GCRY_KEM_CM6688128F = 2,
#define GCRY_KEM_CM6688128F GCRY_KEM_CM6688128F
    GCRY_KEM_MLKEM512 = 3,
#define GCRY_KEM_RAW_MLKEM512 GCRY_KEM_RAW_MLKEM512
    GCRY_KEM_MLKEM768 = 4,
#define GCRY_KEM_RAW_MLKEM768 GCRY_KEM_RAW_MLKEM768
    GCRY_KEM_MLKEM1024 = 5,
#define GCRY_KEM_RAW_MLKEM1024 GCRY_KEM_RAW_MLKEM1024
    GCRY_KEM_RAW_X25519 = 31,
#define GCRY_KEM_RAW_X25519 GCRY_KEM_RAW_X25519
    GCRY_KEM_RAW_X448 = 32,
#define GCRY_KEM_RAW_X448 GCRY_KEM_RAW_X448
    GCRY_KEM_RAW_BP256 = 33,
#define GCRY_KEM_RAW_BP256 GCRY_KEM_RAW_BP256
    GCRY_KEM_RAW_BP384 = 34,
#define GCRY_KEM_RAW_BP384 GCRY_KEM_RAW_BP384
    GCRY_KEM_RAW_BP512 = 35,
#define GCRY_KEM_RAW_BP512 GCRY_KEM_RAW_BP512
    GCRY_KEM_RAW_P256R1 = 36,
#define GCRY_KEM_RAW_P256R1 GCRY_KEM_RAW_P256R1
    GCRY_KEM_RAW_P384R1 = 37,
#define GCRY_KEM_RAW_P384R1 GCRY_KEM_RAW_P384R1
    GCRY_KEM_RAW_P521R1 = 38,
#define GCRY_KEM_RAW_P521R1 GCRY_KEM_RAW_P521R1
    GCRY_KEM_RAW_P256K1 = 39,
#define GCRY_KEM_RAW_P256K1 GCRY_KEM_RAW_P256K1
    GCRY_KEM_DHKEM25519 = 41,
#define GCRY_KEM_DHKEM25519 GCRY_KEM_DHKEM25519
    GCRY_KEM_DHKEM448 = 42,
#define GCRY_KEM_DHKEM448 GCRY_KEM_DHKEM448
    GCRY_KEM_DHKEMP256R1 = 43,
#define GCRY_KEM_DHKEMP256R1 GCRY_KEM_DHKEMP256R1
    GCRY_KEM_DHKEMP384R1 = 44,
#define GCRY_KEM_DHKEMP384R1 GCRY_KEM_DHKEMP384R1
    GCRY_KEM_DHKEMP521R1 = 45
#define GCRY_KEM_DHKEMP521R1 GCRY_KEM_DHKEMP521R1
};

#define GCRY_KEM_SNTRUP761_SECKEY_LEN 1763
#define GCRY_KEM_SNTRUP761_PUBKEY_LEN 1158
#define GCRY_KEM_SNTRUP761_ENCAPS_LEN 1039
#define GCRY_KEM_SNTRUP761_CIPHER_LEN GCRY_KEM_SNTRUP761_ENCAPS_LEN
#define GCRY_KEM_SNTRUP761_SHARED_LEN 32

#define GCRY_KEM_CM6688128F_SECKEY_LEN 13932
#define GCRY_KEM_CM6688128F_PUBKEY_LEN 1044992
#define GCRY_KEM_CM6688128F_ENCAPS_LEN 208
#define GCRY_KEM_CM6688128F_CIPHER_LEN GCRY_KEM_CM6688128F_ENCAPS_LEN
#define GCRY_KEM_CM6688128F_SHARED_LEN 32

#define GCRY_KEM_MLKEM_RANDOM_LEN 32
#define GCRY_KEM_MLKEM512_RANDOM_LEN GCRY_KEM_MLKEM_RANDOM_LEN
#define GCRY_KEM_MLKEM768_RANDOM_LEN GCRY_KEM_MLKEM_RANDOM_LEN
#define GCRY_KEM_MLKEM1024_RANDOM_LEN GCRY_KEM_MLKEM_RANDOM_LEN

#define GCRY_KEM_MLKEM512_SECKEY_LEN (2 * 384 + 2 * 384 + 32 + 2 * 32)
#define GCRY_KEM_MLKEM512_PUBKEY_LEN (2 * 384 + 32)
#define GCRY_KEM_MLKEM512_ENCAPS_LEN (128 + 2 * 320)
#define GCRY_KEM_MLKEM512_CIPHER_LEN GCRY_KEM_MLKEM512_ENCAPS_LEN
#define GCRY_KEM_MLKEM512_SHARED_LEN 32

#define GCRY_KEM_MLKEM768_SECKEY_LEN (3 * 384 + 3 * 384 + 32 + 2 * 32)
#define GCRY_KEM_MLKEM768_PUBKEY_LEN (3 * 384 + 32)
#define GCRY_KEM_MLKEM768_ENCAPS_LEN (128 + 3 * 320)
#define GCRY_KEM_MLKEM768_CIPHER_LEN GCRY_KEM_MLKEM768_ENCAPS_LEN
#define GCRY_KEM_MLKEM768_SHARED_LEN 32

#define GCRY_KEM_MLKEM1024_SECKEY_LEN (4 * 384 + 4 * 384 + 32 + 2 * 32)
#define GCRY_KEM_MLKEM1024_PUBKEY_LEN (4 * 384 + 32)
#define GCRY_KEM_MLKEM1024_ENCAPS_LEN (160 + 4 * 352)
#define GCRY_KEM_MLKEM1024_CIPHER_LEN GCRY_KEM_MLKEM1024_ENCAPS_LEN
#define GCRY_KEM_MLKEM1024_SHARED_LEN 32

#define GCRY_KEM_ECC_X25519_SECKEY_LEN 32
#define GCRY_KEM_ECC_X25519_PUBKEY_LEN 32
#define GCRY_KEM_ECC_X25519_ENCAPS_LEN 32
#define GCRY_KEM_ECC_X25519_CIPHER_LEN GCRY_KEM_ECC_X25519_ENCAPS_LEN
#define GCRY_KEM_RAW_X25519_SHARED_LEN 32

#define GCRY_KEM_DHKEM25519_SECKEY_LEN GCRY_KEM_ECC_X25519_SECKEY_LEN
#define GCRY_KEM_DHKEM25519_PUBKEY_LEN GCRY_KEM_ECC_X25519_PUBKEY_LEN
#define GCRY_KEM_DHKEM25519_ENCAPS_LEN GCRY_KEM_ECC_X25519_ENCAPS_LEN
#define GCRY_KEM_DHKEM25519_CIPHER_LEN GCRY_KEM_DHKEM25519_ENCAPS_LEN
#define GCRY_KEM_DHKEM25519_SHARED_LEN 32

#define GCRY_KEM_ECC_X448_SECKEY_LEN 56
#define GCRY_KEM_ECC_X448_PUBKEY_LEN 56
#define GCRY_KEM_ECC_X448_ENCAPS_LEN 56
#define GCRY_KEM_ECC_X448_CIPHER_LEN GCRY_KEM_ECC_X448_ENCAPS_LEN
#define GCRY_KEM_RAW_X448_SHARED_LEN 56

#define GCRY_KEM_DHKEM448_SECKEY_LEN GCRY_KEM_ECC_X448_SECKEY_LEN
#define GCRY_KEM_DHKEM448_PUBKEY_LEN GCRY_KEM_ECC_X448_PUBKEY_LEN
#define GCRY_KEM_DHKEM448_ENCAPS_LEN GCRY_KEM_ECC_X448_ENCAPS_LEN
#define GCRY_KEM_DHKEM448_CIPHER_LEN GCRY_KEM_DHKEM448_ENCAPS_LEN
#define GCRY_KEM_DHKEM448_SHARED_LEN 56

#define GCRY_KEM_ECC_BP256_SECKEY_LEN 32
#define GCRY_KEM_ECC_BP256_PUBKEY_LEN (1 + 32 + 32)
#define GCRY_KEM_ECC_BP256_ENCAPS_LEN (1 + 32 + 32)
#define GCRY_KEM_ECC_BP256_CIPHER_LEN GCRY_KEM_ECC_BP256_ENCAPS_LEN
#define GCRY_KEM_RAW_BP256_SHARED_LEN (1 + 32 + 32)

#define GCRY_KEM_ECC_BP384_SECKEY_LEN 48
#define GCRY_KEM_ECC_BP384_PUBKEY_LEN (1 + 48 + 48)
#define GCRY_KEM_ECC_BP384_ENCAPS_LEN (1 + 48 + 48)
#define GCRY_KEM_ECC_BP384_CIPHER_LEN GCRY_KEM_ECC_BP384_ENCAPS_LEN
#define GCRY_KEM_RAW_BP384_SHARED_LEN (1 + 48 + 48)

gcry_error_t gcry_kem_genkey(int algo, void *pubkey, size_t pubkey_len,
                             void *seckey, size_t seckey_len,
                             const void *optional, size_t optional_len);
gcry_error_t gcry_kem_keypair(int algo, void *pubkey, size_t pubkey_len,
                              void *seckey, size_t seckey_len);
gcry_error_t gcry_kem_encap(int algo, const void *pubkey, size_t pubkey_len,
                            void *ciphertext, size_t ciphertext_len,
                            void *shared, size_t shared_len,
                            const void *optional, size_t optional_len);
gcry_error_t gcry_kem_decap(int algo, const void *seckey, size_t seckey_len,
                            const void *ciphertext, size_t ciphertext_len,
                            void *shared, size_t shared_len,
                            const void *optional, size_t optional_len);

/* ------------------------------------------------------------------ */
/* Random numbers                                                      */
/* ------------------------------------------------------------------ */

enum gcry_rng_types {
    GCRY_RNG_TYPE_STANDARD = 1,
    GCRY_RNG_TYPE_FIPS = 2,
    GCRY_RNG_TYPE_SYSTEM = 3
};

typedef enum gcry_random_level {
    GCRY_WEAK_RANDOM = 0,
    GCRY_STRONG_RANDOM = 1,
    GCRY_VERY_STRONG_RANDOM = 2
} gcry_random_level_t;

void gcry_randomize(void *buffer, size_t length,
                    enum gcry_random_level level);
gcry_error_t gcry_random_add_bytes(const void *buffer, size_t length,
                                   int quality);

#define gcry_fast_random_poll() gcry_control(GCRYCTL_FAST_POLL, NULL)

void *gcry_random_bytes(size_t nbytes, enum gcry_random_level level)
_GCRY_GCC_ATTR_MALLOC;
void *gcry_random_bytes_secure(size_t nbytes, enum gcry_random_level level)
_GCRY_GCC_ATTR_MALLOC;
void gcry_mpi_randomize(gcry_mpi_t w, unsigned int nbits,
                        enum gcry_random_level level);
void gcry_create_nonce(void *buffer, size_t length);

/* ------------------------------------------------------------------ */
/* Prime numbers                                                       */
/* ------------------------------------------------------------------ */

#define GCRY_PRIME_CHECK_AT_FINISH 0
#define GCRY_PRIME_CHECK_AT_GOT_PRIME 1
#define GCRY_PRIME_CHECK_AT_MAYBE_PRIME 2

typedef int (*gcry_prime_check_func_t)(void *arg, int mode,
                                       gcry_mpi_t candidate);

#define GCRY_PRIME_FLAG_SECRET (1 << 0)
#define GCRY_PRIME_FLAG_SPECIAL_FACTOR (1 << 1)

gcry_error_t gcry_prime_generate(gcry_mpi_t *prime, unsigned int prime_bits,
                                 unsigned int factor_bits,
                                 gcry_mpi_t **factors,
                                 gcry_prime_check_func_t cb_func,
                                 void *cb_arg,
                                 gcry_random_level_t random_level,
                                 unsigned int flags);
gcry_error_t gcry_prime_group_generator(gcry_mpi_t *r_g, gcry_mpi_t prime,
                                        gcry_mpi_t *factors,
                                        gcry_mpi_t start_g);
void gcry_prime_release_factors(gcry_mpi_t *factors);
gcry_error_t gcry_prime_check(gcry_mpi_t x, unsigned int flags);

/* ------------------------------------------------------------------ */
/* Miscellaneous                                                       */
/* ------------------------------------------------------------------ */

void gcry_ctx_release(gcry_ctx_t ctx);

void gcry_log_debug(const char *fmt, ...) _GCRY_GCC_ATTR_PRINTF(1, 2);
void gcry_log_debughex(const char *text, const void *buffer, size_t length);
void gcry_log_debugmpi(const char *text, gcry_mpi_t mpi);
void gcry_log_debugpnt(const char *text, gcry_mpi_point_t point,
                       gcry_ctx_t ctx);
void gcry_log_debugsxp(const char *text, gcry_sexp_t sexp);

char *gcry_get_config(int mode, const char *what);

#define gcry_get_fips_service_indicator() \
    gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR)

#define GCRY_FIPS_FLAG_REJECT_KDF (1 << 0)
#define GCRY_FIPS_FLAG_REJECT_MD_MD5 (1 << 1)
#define GCRY_FIPS_FLAG_REJECT_MD_OTHERS (1 << 2)
#define GCRY_FIPS_FLAG_REJECT_MAC (1 << 3)
#define GCRY_FIPS_FLAG_REJECT_CIPHER (1 << 4)
#define GCRY_FIPS_FLAG_REJECT_PK (1 << 5)
#define GCRY_FIPS_FLAG_REJECT_PK_MD (1 << 6)
#define GCRY_FIPS_FLAG_REJECT_PK_GOST_SM2 (1 << 7)
#define GCRY_FIPS_FLAG_REJECT_CIPHER_MODE (1 << 8)
#define GCRY_FIPS_FLAG_REJECT_MD_SHA1 (1 << 9)
#define GCRY_FIPS_FLAG_REJECT_PK_ECC_K (1 << 10)
#define GCRY_FIPS_FLAG_REJECT_PK_FLAGS (1 << 11)

#define GCRY_FIPS_FLAG_REJECT_MD                                 \
    (GCRY_FIPS_FLAG_REJECT_MD_MD5 | GCRY_FIPS_FLAG_REJECT_MD_SHA1 \
     | GCRY_FIPS_FLAG_REJECT_MD_OTHERS)

#define GCRY_FIPS_FLAG_REJECT_COMPAT110                                    \
    (GCRY_FIPS_FLAG_REJECT_MD_OTHERS | GCRY_FIPS_FLAG_REJECT_MAC           \
     | GCRY_FIPS_FLAG_REJECT_CIPHER | GCRY_FIPS_FLAG_REJECT_KDF            \
     | GCRY_FIPS_FLAG_REJECT_PK)

#define GCRY_FIPS_FLAG_REJECT_DEFAULT GCRY_FIPS_FLAG_REJECT_COMPAT110

enum gcry_log_levels {
    GCRY_LOG_CONT = 0,
    GCRY_LOG_INFO = 10,
    GCRY_LOG_WARN = 20,
    GCRY_LOG_ERROR = 30,
    GCRY_LOG_FATAL = 40,
    GCRY_LOG_BUG = 50,
    GCRY_LOG_DEBUG = 100
};

typedef void (*gcry_handler_progress_t)(void *, const char *, int, int, int);
typedef void *(*gcry_handler_alloc_t)(size_t n);
typedef int (*gcry_handler_secure_check_t)(const void *);
typedef void *(*gcry_handler_realloc_t)(void *p, size_t n);
typedef void (*gcry_handler_free_t)(void *);
typedef int (*gcry_handler_no_mem_t)(void *, size_t, unsigned int);
typedef void (*gcry_handler_error_t)(void *, int, const char *);
typedef void (*gcry_handler_log_t)(void *, int, const char *, va_list);

void gcry_set_progress_handler(gcry_handler_progress_t cb, void *cb_data);
void gcry_set_allocation_handler(gcry_handler_alloc_t func_alloc,
                                 gcry_handler_alloc_t func_alloc_secure,
                                 gcry_handler_secure_check_t func_secure_check,
                                 gcry_handler_realloc_t func_realloc,
                                 gcry_handler_free_t func_free);
void gcry_set_outofcore_handler(gcry_handler_no_mem_t h, void *opaque);
void gcry_set_fatalerror_handler(gcry_handler_error_t fnc, void *opaque);
void gcry_set_log_handler(gcry_handler_log_t f,
                          void *opaque) _GCRY_ATTR_INTERNAL;
void gcry_set_gettext_handler(const char *(*f)(const char *));

void *gcry_malloc(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_calloc(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_malloc_secure(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_calloc_secure(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_realloc(void *a, size_t n);
char *gcry_strdup(const char *string) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xmalloc(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xcalloc(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xmalloc_secure(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xcalloc_secure(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xrealloc(void *a, size_t n);
char *gcry_xstrdup(const char *a) _GCRY_GCC_ATTR_MALLOC;
void gcry_free(void *a);
int gcry_is_secure(const void *a) _GCRY_GCC_ATTR_PURE;

#define gcry_fips_mode_active() !!gcry_control(GCRYCTL_FIPS_MODE_P, 0)

gcry_error_t gcry_pk_hash_sign(gcry_sexp_t *result, const char *data_tmpl,
                               gcry_sexp_t skey, gcry_md_hd_t hd,
                               gcry_ctx_t ctx);
gcry_error_t gcry_pk_hash_verify(gcry_sexp_t sigval, const char *data_tmpl,
                                 gcry_sexp_t pkey, gcry_md_hd_t hd,
                                 gcry_ctx_t ctx);
gcry_error_t gcry_pk_random_override_new(gcry_ctx_t *r_ctx,
                                         const unsigned char *p, size_t len);
#define gcry_pk_input_data_push gcry_pk_random_override_new

#ifdef __cplusplus
}
#endif
#endif /* _GCRYPT_H */
