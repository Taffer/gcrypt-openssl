/* Tests of the public key API (gcry_pk_*). */
#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"
#include "test_pk_rsa_vector.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Whether SEXP contains a list starting with TOKEN; the sublist that
 * gcry_sexp_find_token returns is released, so this does not leak. */
static int
has_token(gcry_sexp_t sexp, const char *token)
{
    gcry_sexp_t l = gcry_sexp_find_token(sexp, token, 0);

    gcry_sexp_release(l);
    return l != NULL;
}

static gcry_sexp_t
sexp(const char *text)
{
    gcry_sexp_t s = NULL;

    if (gcry_sexp_sscan(&s, NULL, text, strlen(text))) {
        return NULL;
    }

    return s;
}

static char *
advanced(gcry_sexp_t s)
{
    size_t n = gcry_sexp_sprint(s, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char *buf = malloc(n);

    gcry_sexp_sprint(s, GCRYSEXP_FMT_ADVANCED, buf, n);
    return buf;
}

static gcry_mpi_t
hex_mpi(const char *hex)
{
    gcry_mpi_t m = NULL;

    gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, hex, 0, NULL);
    return m;
}

/* Fetch the data of parameter NAME of the (public|private)-key or
 * sig-val/enc-val list as a fresh buffer. */
static void *
param_bytes(gcry_sexp_t s, const char *name, size_t *r_len)
{
    gcry_sexp_t l = gcry_sexp_find_token(s, name, 0);
    void *buf;

    if (!l) {
        return NULL;
    }

    buf = gcry_sexp_nth_buffer(l, 1, r_len);
    gcry_sexp_release(l);
    return buf;
}

static gcry_mpi_t
param_mpi(gcry_sexp_t s, const char *name)
{
    gcry_sexp_t l = gcry_sexp_find_token(s, name, 0);
    gcry_mpi_t m;

    if (!l) {
        return NULL;
    }

    m = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(l);
    return m;
}

static int
bytes_eq_hex(const void *buf, size_t len, const char *hex)
{
    size_t i;
    const unsigned char *p = buf;

    if (len * 2 != strlen(hex)) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        unsigned int v;

        sscanf(hex + 2 * i, "%2x", &v);

        if (p[i] != v) {
            return 0;
        }
    }

    return 1;
}

static gcry_sexp_t
genkey(const char *parms)
{
    gcry_sexp_t p = sexp(parms);
    gcry_sexp_t key = NULL;
    gcry_error_t err;

    if (!p) {
        return NULL;
    }

    err = gcry_pk_genkey(&key, p);
    gcry_sexp_release(p);

    if (err) {
        fprintf(stderr, "genkey %s: %s\n", parms, gcry_strerror(err));
        return NULL;
    }

    return key;
}

/* "(sig-val (ALGO RS))", optionally with a leading empty flags list, so
 * that the same checks run with a DSA key or (in FIPS mode) an ECDSA key. */
static const char *
sigval_text(const char *algo, const char *rs, int with_flags)
{
    static char buf[256];

    if (with_flags) {
        snprintf(buf, sizeof buf, "(sig-val (flags) (%s %s))", algo, rs);
    } else {
        snprintf(buf, sizeof buf, "(sig-val (%s %s))", algo, rs);
    }

    return buf;
}

/* Whether DSA keys can be generated: not in FIPS mode, and under a strict
 * provider only if the provider has DSA at all, which one key generation
 * tells (its outcome is cached). */
static int
dsa_available(void)
{
    static int probed = -1;

    if (gcry_fips_mode_active()) {
        return 0;
    }

    if (!TEST_STRICT_PROVIDER) {
        return 1;
    }

    if (probed < 0) {
        gcry_sexp_t parms = sexp("(genkey (dsa (nbits 4:1024)))");
        gcry_sexp_t key = NULL;

        probed = parms != NULL && gcry_pk_genkey(&key, parms) == 0;
        gcry_sexp_release(key);
        gcry_sexp_release(parms);
    }

    return probed;
}

/* Whether a digest the library's tables list is not offered: always in
 * FIPS mode (every use of this asks about a non-approved digest), and
 * under a strict provider whenever the provider lacks it. */
static int
md_unavailable(int algo)
{
    return gcry_fips_mode_active()
           || (TEST_STRICT_PROVIDER && gcry_md_test_algo(algo) != 0);
}

/* In FIPS mode a non-approved algorithm (DSA, ElGamal) is refused by
 * every operation, as in the reference library; only the keygrip, a pure
 * function of the key material, is still computed. */
static void
expect_fips_refusal(const char *genparms, const char *keytext,
                    const char *datatext, const char *sigtext,
                    const char *enctext)
{
    gcry_sexp_t parms = sexp(genparms);
    gcry_sexp_t key = sexp(keytext);
    gcry_sexp_t data = sexp(datatext);
    gcry_sexp_t sig = sexp(sigtext);
    gcry_sexp_t enc = sexp(enctext);
    gcry_sexp_t out = NULL;
    unsigned char grip[20];

    ASSERT_NOT_NULL(parms);
    ASSERT_NOT_NULL(key);
    ASSERT_NOT_NULL(data);
    ASSERT_NOT_NULL(sig);
    ASSERT_NOT_NULL(enc);
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&out, parms));
    ASSERT_NULL(out);
    ASSERT_EQ(0, gcry_pk_get_nbits(key));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_testkey(key));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_sign(&out, data, key));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_verify(sig, data, key));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_encrypt(&out, data, key));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_decrypt(&out, enc, key));
    ASSERT_NULL(out);
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(key, grip));
    gcry_sexp_release(parms);
    gcry_sexp_release(key);
    gcry_sexp_release(data);
    gcry_sexp_release(sig);
    gcry_sexp_release(enc);
}

/* ------------------------------------------------------------------ */
/* Keygrips (vectors from the reference test suite)                    */
/* ------------------------------------------------------------------ */

static const struct {
    int algo;
    const char *key;
    const char *grip;
} key_grips[] = {
    {
        GCRY_PK_RSA,
        "(private-key"
        " (rsa"
        "  (n #00B6B509596A9ECABC939212F891E656A626BA07DA8521A9CAD4C08E640C04052FBB87F424EF1A0275A48A9299AC9DB69ABE3D0124E6C756B1F7DFB9B842D6251AEA6EE85390495CADA73D671537FCE5850A932F32BAB60AB1AC1F852C1F83C625E7A7D70CDA9EF16D5C8E47739D77DF59261ABE8454807FF441E143FBD37F8545#)"
        "  (e #010001#)"
        "  (d #077AD3DE284245F4806A1B82B79E616FBDE821C82D691A65665E57B5FAD3F34E67F401E7BD2E28699E89D9C496CF821945AE83AC7A1231176A196BA6027E77D85789055D50404A7A2A95B1512F91F190BBAEF730ED550D227D512F89C0CDB31AC06FA9A19503DDF6B66D0B42B9691BFD6140EC1720FFC48AE00C34796DC899E5#)"
        "  (p #00D586C78E5F1B4BF2E7CD7A04CA091911706F19788B93E44EE20AAF462E8363E98A72253ED845CCBF2481BB351E8557C85BCFFF0DABDBFF8E26A79A0938096F27#)"
        "  (q #00DB0CDF60F26F2A296C88D6BF9F8E5BE45C0DDD713C96CC73EBCB48B061740943F21D2A93D6E42A7211E7F02A95DCED6C390A67AD21ECF739AE8A0CA46FF2EBB3#)"
        "  (u #33149195F16912DB20A48D020DBC3B9E3881B39D722BF79378F6340F43148A6E9FC5F53E2853B7387BA4443BA53A52FCA8173DE6E85B42F9783D4A7817D0680B#)))",
        "32CFFA85B1791FBB2614E91AFDF3AFE332082E25"
    },
    {
        GCRY_PK_DSA,
        " (public-key"
        " (dsa"
        "  (p #0084E4C626E16005770BD9509ABF7354492E85B8C0060EFAAAEC617F725B592FAA59DF5460575F41022776A9718CE62EDD542AB73C7720869EBDBC834D174ADCD7136827DF51E2613545A25CA573BC502A61B809000B6E35F5EB7FD6F18C35678C23EA1C3638FB9CFDBA2800EE1B62F41A4479DE824F2834666FBF8DC5B53C2617#)"
        "  (q #00B0E6F710051002A9F425D98A677B18E0E5B038AB#)"
        "  (g #44370CEE0FE8609994183DBFEBA7EEA97D466838BCF65EFF506E35616DA93FA4E572A2F08886B74977BC00CA8CD3DBEA7AEB7DB8CBB180E6975E0D2CA76E023E6DE9F8CCD8826EBA2F72B8516532F6001DEFFAE76AA5E59E0FA33DBA3999B4E92D1703098CDEDCC416CF008801964084CDE1980132B2B78CB4CE9C15A559528B#)"
        "  (y #3D5DD14AFA2BF24A791E285B90232213D0E3BA74AB1109E768AED19639A322F84BB7D959E2BA92EF73DE4C7F381AA9F4053CFA3CD4527EF9043E304E5B95ED0A3A5A9D590AA641C13DB2B6E32B9B964A6A2C730DD3EA7C8E13F7A140AFF1A91CE375E9B9B960384779DC4EA180FA1F827C52288F366C0770A220F50D6D8FD6F6#)))",
        "04A34FA02B0394D732ADD59B50AFDB5D5722A610"
    },
    {
        GCRY_PK_DSA,
        "(private-key"
        " (dsa"
        "  (p #0084E4C626E16005770BD9509ABF7354492E85B8C0060EFAAAEC617F725B592FAA59DF5460575F41022776A9718CE62EDD542AB73C7720869EBDBC834D174ADCD7136827DF51E2613545A25CA573BC502A61B809000B6E35F5EB7FD6F18C35678C23EA1C3638FB9CFDBA2800EE1B62F41A4479DE824F2834666FBF8DC5B53C2617#)"
        "  (q #00B0E6F710051002A9F425D98A677B18E0E5B038AB#)"
        "  (g #44370CEE0FE8609994183DBFEBA7EEA97D466838BCF65EFF506E35616DA93FA4E572A2F08886B74977BC00CA8CD3DBEA7AEB7DB8CBB180E6975E0D2CA76E023E6DE9F8CCD8826EBA2F72B8516532F6001DEFFAE76AA5E59E0FA33DBA3999B4E92D1703098CDEDCC416CF008801964084CDE1980132B2B78CB4CE9C15A559528B#)"
        "  (y #3D5DD14AFA2BF24A791E285B90232213D0E3BA74AB1109E768AED19639A322F84BB7D959E2BA92EF73DE4C7F381AA9F4053CFA3CD4527EF9043E304E5B95ED0A3A5A9D590AA641C13DB2B6E32B9B964A6A2C730DD3EA7C8E13F7A140AFF1A91CE375E9B9B960384779DC4EA180FA1F827C52288F366C0770A220F50D6D8FD6F6#)"
        "  (x #0087F9E91BFBCC1163DE71ED86D557708E32F8ADDE#)))",
        "04A34FA02B0394D732ADD59B50AFDB5D5722A610"
    },
    {
        GCRY_PK_ECDSA,
        "(public-key"
        " (ecdsa(flags param)"
        " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
        " (a #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC#)"
        " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
        " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
        " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
        " (h #000000000000000000000000000000000000000000000000000000000000000001#)"
        " (q #04C8A4CEC2E9A9BC8E173531A67B0840DF345C32E261ADD780E6D83D56EFADFD5DE872F8B854819B59543CE0B7F822330464FBC4E6324DADDCD9D059554F63B344#)))",
        "E6DF942DBD8C7705A3DD416EFC0401DB310E99B6"
    },
    {
        GCRY_PK_ECDSA,
        "(public-key"
        " (ecdsa(flags param)"
        " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
        " (curve \"NIST P-256\")"
        " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
        " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
        " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
        " (h #000000000000000000000000000000000000000000000000000000000000000001#)"
        " (q #04C8A4CEC2E9A9BC8E173531A67B0840DF345C32E261ADD780E6D83D56EFADFD5DE872F8B854819B59543CE0B7F822330464FBC4E6324DADDCD9D059554F63B344#)))",
        "E6DF942DBD8C7705A3DD416EFC0401DB310E99B6"
    },
    {
        GCRY_PK_ECDSA,
        "(public-key"
        " (ecdsa"
        " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
        " (curve \"NIST P-256\")"
        " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
        " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
        " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
        " (h #000000000000000000000000000000000000000000000000000000000000000001#)"
        " (q #04C8A4CEC2E9A9BC8E173531A67B0840DF345C32E261ADD780E6D83D56EFADFD5DE872F8B854819B59543CE0B7F822330464FBC4E6324DADDCD9D059554F63B344#)))",
        "E6DF942DBD8C7705A3DD416EFC0401DB310E99B6"
    },
    {
        GCRY_PK_ECDSA,
        "(public-key"
        " (ecdsa"
        " (curve secp256r1)"
        " (q #04C8A4CEC2E9A9BC8E173531A67B0840DF345C32E261ADD780E6D83D56EFADFD5DE872F8B854819B59543CE0B7F822330464FBC4E6324DADDCD9D059554F63B344#)))",
        "E6DF942DBD8C7705A3DD416EFC0401DB310E99B6"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve secp256r1)"
        " (q #04C8A4CEC2E9A9BC8E173531A67B0840DF345C32E261ADD780E6D83D56EFADFD5DE872F8B854819B59543CE0B7F822330464FBC4E6324DADDCD9D059554F63B344#)))",
        "E6DF942DBD8C7705A3DD416EFC0401DB310E99B6"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve brainpoolP256r1)"
        " (q #042ECD8679930BE2DB4AD42B8600BA3F802D4D539BFF2F69B83EC9B7BBAA7F3406436DD11A1756AFE56CD93408410FCDA9BA95024EB613BD481A14FCFEC27A448A#)))",
        "52BAD4B4A32D32A1DD065E990BF1ABC1133D84D4"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve brainpoolP256r1)"
        " (q #022ECD8679930BE2DB4AD42B8600BA3F802D4D539BFF2F69B83EC9B7BBAA7F3406#)))",
        "52BAD4B4A32D32A1DD065E990BF1ABC1133D84D4"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve brainpoolP256r1)"
        " (q #045B784CA008EE64AB3D85017EE0D2BE87558762C7300E0C8E06B1F9AF7C0314589EBBA41915313417BA54218EB0569C590B156C76DBCAB6E84575E6EF68CE7B87#)))",
        "99386A824196299C8974D6E1BF43AC9B9A12E73F"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve brainpoolP256r1)"
        " (q #035B784CA008EE64AB3D85017EE0D2BE87558762C7300E0C8E06B1F9AF7C031458#)))",
        "99386A824196299C8974D6E1BF43AC9B9A12E73F"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve Ed25519)"
        " (q #041CC662926E7EFF4982B7FB8B928E61CD74CCDD85277CC57196C3AD20B611085F47BD24842905C049257673B3F5249524E0A41FAA17B25B818D0F97E625F1A1D0#)))",
        "0CCAB2FD489A33402CE8E04A1FB245EA803D0AF1"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve Ed25519)(flags eddsa)"
        " (q #773E72848C1FD5F9652B29E2E7AF79571A04990E96F2016BF4E0EC1890C2B7DB#)))",
        "9DB6C64A38830F4960701789475520BE8C821F47"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve Ed25519)(flags eddsa)"
        " (q #40773E72848C1FD5F9652B29E2E7AF79571A04990E96F2016BF4E0EC1890C2B7DB#)))",
        "9DB6C64A38830F4960701789475520BE8C821F47"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve Ed25519)(flags eddsa)"
        " (q #04629ad237d1ed04dcd4abe1711dd699a1cf51b1584c4de7a4ef8b8a640180b26f5bb7c29018ece0f46b01f2960e99041a5779afe7e2292b65f9d51f8c84723e77#)))",
        "9DB6C64A38830F4960701789475520BE8C821F47"
    },
    {
        GCRY_PK_ECC,
        "(public-key"
        " (ecc"
        " (curve Curve25519)(flags djb-tweak)"
        " (q #40918C1733127F6BF2646FAE3D081A18AE77111C903B906310B077505EFFF12740#)))",
        "0F89A565D3EA187CE8393323 98F5D480677DF49C"
    },
    {
        GCRY_PK_RSA,
        "(shadowed-private-key"
        " (rsa"
        " (n #00B493C79928398DA9D99AC0E949FE6EB62F683CB974FFFBFBC01066F5C9A89BD3DC48EAD7C65F36EA943C2B2C865C26C4884FF9EDFDA8C99C855B737D77EEF6B85DBC0CCEC0E900C1F89A6893A2A93E8B31028469B6927CEB2F08687E547C686B0A2F7E50A194FF7AB7637E03DE0912EF7F6E5F1EC37625BD1620CCC2E7A56431E168CDAFBD1D9E61AE47A69A6FA03EF22F844528A710B2392F262B95A3078CF321DC8325F92A5691EF69F34FD0DE0B22C79D29DC87723FCADE463829E8E5F7D196D73D6C9C180F6A6A0DDBF7B9D8F7FA293C36163B12199EF6A1A95CAE4051E3069C522CC6C4A7110F663A5DAD20F66C13A1674D050088208FAE4F33B3AB5103#)"
        " (e #00010001#)"
        " (shadowed t1-v1"
        " (#D2760001240102000005000123350000# OPENPGP.1)"
        ")))",
        "E56EE6EE5A2FDC3E989DFE49DAF56743E3272833"
    }
};

TEST(keygrips)
{
    size_t i;

    for (i = 0; i < sizeof key_grips / sizeof * key_grips; i++) {
        gcry_sexp_t key = sexp(key_grips[i].key);
        unsigned char buf[20];
        unsigned char *ret;
        char hex[41];
        int j;
        const char *expect = key_grips[i].grip;
        char compact[41];
        int k = 0;

        if (!key) {
            TEST_FAIL_("vector %u does not parse", (unsigned)i);
            continue;
        }

        ret = gcry_pk_get_keygrip(key, buf);

        if (!ret) {
            TEST_FAIL_("keygrip %u failed", (unsigned)i);
            gcry_sexp_release(key);
            continue;
        }

        for (j = 0; j < 20; j++) {
            snprintf(hex + 2 * j, 3, "%02X", buf[j]);
        }

        for (j = 0; expect[j]; j++) {
            if (expect[j] != ' ') {
                compact[k++] = expect[j];
            }
        }

        compact[k] = 0;

        if (strcmp(hex, compact)) {
            TEST_FAIL_("keygrip %u: expected %s, got %s", (unsigned)i, compact,
                       hex);
        }

        /* The allocating form gives the same result. */
        ret = gcry_pk_get_keygrip(key, NULL);
        ASSERT_NOT_NULL(ret);
        ASSERT_MEM_EQ(buf, ret, 20);
        gcry_free(ret);
        gcry_sexp_release(key);
    }

    {
        gcry_sexp_t bogus = sexp("(public-key (foo (x #01#)))");

        ASSERT_NULL(gcry_pk_get_keygrip(bogus, NULL));
        gcry_sexp_release(bogus);
    }
}

/* ------------------------------------------------------------------ */
/* RSA                                                                 */
/* ------------------------------------------------------------------ */

static gcry_sexp_t
rsa_vector_key(int private)
{
    gcry_sexp_t key = NULL;
    gcry_mpi_t n = hex_mpi(RSA_N);
    gcry_mpi_t e = gcry_mpi_set_ui(NULL, RSA_E_DEC);
    gcry_mpi_t d = hex_mpi(RSA_D);
    gcry_mpi_t p = hex_mpi(RSA_P);
    gcry_mpi_t q = hex_mpi(RSA_Q);
    gcry_mpi_t u = gcry_mpi_new(0);

    /* Libgcrypt wants p < q and u = p^-1 mod q. */
    if (gcry_mpi_cmp(p, q) > 0) {
        gcry_mpi_swap(p, q);
    }

    gcry_mpi_invm(u, p, q);

    if (private) {
        gcry_sexp_build(&key, NULL,
                        "(private-key (rsa (n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                        n, e, d, p, q, u);
    } else {
        gcry_sexp_build(&key, NULL, "(public-key (rsa (n %m)(e %m)))", n, e);
    }

    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_mpi_release(d);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(u);
    return key;
}

TEST(rsa_known_signature)
{
    gcry_sexp_t skey = rsa_vector_key(1);
    gcry_sexp_t pkey = rsa_vector_key(0);
    gcry_sexp_t data = NULL;
    gcry_sexp_t bad = NULL;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t vsig = NULL;
    void *s;
    size_t slen;

    ASSERT_NOT_NULL(skey);
    ASSERT_NOT_NULL(pkey);
    ASSERT_EQ(2048, gcry_pk_get_nbits(pkey));
    ASSERT_OK(gcry_pk_testkey(skey));

    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1) (hash sha256 #" RSA_DIGEST "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    s = param_bytes(sig, "s", &slen);
    ASSERT_NOT_NULL(s);
    ASSERT_TRUE(bytes_eq_hex(s, slen, RSA_SIG));
    gcry_free(s);
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    ASSERT_OK(gcry_pk_verify(sig, data, skey)); /* Private key works too. */

    /* A signature given as an MPI verifies as well. */
    ASSERT_OK(gcry_sexp_build(&vsig, NULL, "(sig-val (rsa (s #" RSA_SIG "#)))"));
    ASSERT_OK(gcry_pk_verify(vsig, data, pkey));

    /* Tampered data and tampered signature. */
    ASSERT_OK(gcry_sexp_build(&bad, NULL,
                              "(data (flags pkcs1) (hash sha256 #00" RSA_DIGEST "#))"));
    /* A 33 byte "SHA-256" digest conflicts with the algorithm. */
    ASSERT_ERR(GPG_ERR_CONFLICT, gcry_pk_verify(sig, bad, pkey));
    gcry_sexp_release(bad);
    ASSERT_OK(gcry_sexp_build(&bad, NULL,
                              "(data (flags pkcs1) (hash sha1 #" RSA_DIGEST "#))"));
    ASSERT_TRUE(gcry_pk_verify(sig, bad, pkey) != 0);
    gcry_sexp_release(bad);
    gcry_sexp_release(vsig);
    ASSERT_OK(gcry_sexp_build(&vsig, NULL, "(sig-val (rsa (s #01" RSA_SIG "#)))"));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(vsig, data, pkey));
    gcry_sexp_release(vsig);

    /* Wrong algorithm in the signature. */
    ASSERT_OK(gcry_sexp_build(&vsig, NULL, "(sig-val (dsa (r #01#)(s #02#)))"));
    ASSERT_ERR(GPG_ERR_CONFLICT, gcry_pk_verify(vsig, data, pkey));
    gcry_sexp_release(vsig);

    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
}

TEST(rsa_sign_modes)
{
    gcry_sexp_t skey = rsa_vector_key(1);
    gcry_sexp_t pkey = rsa_vector_key(0);
    gcry_sexp_t data = NULL;
    gcry_sexp_t sig = NULL;
    void *s;
    size_t slen;

    /* PSS with the default salt length, message given for prehashing. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (hash-algo sha256) (value %s))",
                              "hello pss"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (hash-algo sha256) (value %s))",
                              "hello pss!"));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* PSS with an explicit digest and salt length. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (salt-length 2:32)"
                              " (hash sha256 #" RSA_DIGEST "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    s = param_bytes(sig, "s", &slen);
    ASSERT_EQ(256, slen);
    gcry_free(s);
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* pkcs1-raw: PKCS#1 type 1 padding without a DigestInfo. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1-raw) (value %s))", "raw bytes"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* Raw (textbook) RSA on a number. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (value #0102030405#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);

    /* The old style bare MPI is accepted as raw data. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (value #0102030405#))"));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* Prehash: the library hashes the message itself. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1 prehash) (hash-algo sha256) (value %s))",
                              "The quick brown fox jumps over the lazy dog"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    s = param_bytes(sig, "s", &slen);
    ASSERT_TRUE(bytes_eq_hex(s, slen, RSA_SIG));
    gcry_free(s);
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* Unknown flag and conflicting data elements. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags bogus) (value #01#))"));
    ASSERT_ERR(GPG_ERR_INV_FLAG, gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags pkcs1))"));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);

    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
}

TEST(rsa_encrypt_decrypt)
{
    gcry_sexp_t skey = rsa_vector_key(1);
    gcry_sexp_t pkey = rsa_vector_key(0);
    gcry_sexp_t data = NULL;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t plain = NULL;
    void *v;
    size_t vlen;
    gcry_mpi_t m;

    /* PKCS#1 v1.5.  As with the reference implementation the decrypting
     * side states the encoding in the enc-val to get the unpadded value;
     * without flags the raw padded block comes back. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags pkcs1) (value %s))",
                              "secret message"));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    v = param_bytes(ciph, "a", &vlen);
    ASSERT_EQ(256, vlen);
    gcry_free(v);
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, skey));
    m = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
    ASSERT_NOT_NULL(m);
    /* The PKCS#1 block starts with 0x00 0x02: 2034 bits for a 2048 bit key. */
    ASSERT_EQ(2034, gcry_mpi_get_nbits(m));
    gcry_mpi_release(m);
    gcry_sexp_release(plain);
    {
        gcry_sexp_t l = gcry_sexp_find_token(ciph, "rsa", 0);
        gcry_sexp_t flagged = NULL;
        gcry_mpi_t a = param_mpi(l, "a");

        ASSERT_OK(gcry_sexp_build(&flagged, NULL,
                                  "(enc-val (flags pkcs1) (rsa (a %m)))", a));
        ASSERT_OK(gcry_pk_decrypt(&plain, flagged, skey));
        v = param_bytes(plain, "value", &vlen);
        ASSERT_EQ(14, vlen);
        ASSERT_MEM_EQ("secret message", v, 14);
        gcry_free(v);
        gcry_sexp_release(plain);
        gcry_sexp_release(flagged);
        gcry_sexp_release(l);
        gcry_mpi_release(a);
    }
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);

    /* OAEP with SHA-256 and a label. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags oaep) (hash-algo sha256) (label %s) (value %s))",
                              "lbl", "oaep message"));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    {
        gcry_sexp_t l = gcry_sexp_find_token(ciph, "rsa", 0);
        gcry_sexp_t flagged = NULL;
        gcry_mpi_t a = param_mpi(l, "a");

        ASSERT_OK(gcry_sexp_build(&flagged, NULL,
                                  "(enc-val (flags oaep) (hash-algo sha256) (label %s) (rsa (a %m)))",
                                  "lbl", a));
        ASSERT_OK(gcry_pk_decrypt(&plain, flagged, skey));
        v = param_bytes(plain, "value", &vlen);
        ASSERT_EQ(12, vlen);
        ASSERT_MEM_EQ("oaep message", v, 12);
        gcry_free(v);
        gcry_sexp_release(plain);
        gcry_sexp_release(flagged);
        gcry_sexp_release(l);
        gcry_mpi_release(a);
    }

    /* Decrypting with the wrong label fails. */
    {
        gcry_sexp_t l = gcry_sexp_find_token(ciph, "rsa", 0);
        gcry_sexp_t wrong = NULL;
        gcry_mpi_t a = param_mpi(l, "a");

        ASSERT_OK(gcry_sexp_build(&wrong, NULL,
                                  "(enc-val (flags oaep) (hash-algo sha256) (label %s) (rsa (a %m)))",
                                  "other", a));
        ASSERT_ERR(GPG_ERR_ENCODING_PROBLEM, gcry_pk_decrypt(&plain, wrong, skey));
        gcry_sexp_release(wrong);
        gcry_sexp_release(l);
        gcry_mpi_release(a);
    }
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);

    /* Raw: a number in, the same number out; without flags the legacy
     * result (a bare MPI) is returned. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (value #0102030405#))"));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, skey));
    m = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_STD);
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x0102030405UL));
    gcry_mpi_release(m);
    gcry_sexp_release(plain);
    {
        gcry_sexp_t l = gcry_sexp_find_token(ciph, "rsa", 0);
        gcry_sexp_t flagged = NULL;
        gcry_mpi_t a = param_mpi(l, "a");

        ASSERT_OK(gcry_sexp_build(&flagged, NULL, "(enc-val (flags raw) (rsa (a %m)))",
                                  a));
        ASSERT_OK(gcry_pk_decrypt(&plain, flagged, skey));
        m = param_mpi(plain, "value");
        ASSERT_NOT_NULL(m);
        ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x0102030405UL));
        gcry_mpi_release(m);
        gcry_mpi_release(a);
        gcry_sexp_release(plain);
        gcry_sexp_release(flagged);
        gcry_sexp_release(l);
    }
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);

    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
}

TEST(rsa_keygen)
{
    /* FIPS 186 (and so the FIPS provider) wants e >= 65537. */
    gcry_sexp_t key = genkey(gcry_fips_mode_active()
                             ? "(genkey (rsa (nbits 4:2048) (rsa-use-e 1:1)))"
                             : "(genkey (rsa (nbits 4:2048) (rsa-use-e 1:3)))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_mpi_t n;
    gcry_mpi_t e;
    gcry_mpi_t p;
    gcry_mpi_t q;
    gcry_mpi_t u;
    gcry_mpi_t t;
    char *txt;
    gcry_sexp_t data = NULL;
    gcry_sexp_t sig = NULL;

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    ASSERT_NOT_NULL(priv);
    ASSERT_NOT_NULL(pub);
    ASSERT_EQ(2048, gcry_pk_get_nbits(priv));

    /* Parameter order and relations. */
    txt = advanced(priv);
    ASSERT_TRUE(strstr(txt, "(n ") < strstr(txt, "(e "));
    ASSERT_TRUE(strstr(txt, "(e ") < strstr(txt, "(d "));
    ASSERT_TRUE(strstr(txt, "(d ") < strstr(txt, "(p "));
    ASSERT_TRUE(strstr(txt, "(p ") < strstr(txt, "(q "));
    ASSERT_TRUE(strstr(txt, "(q ") < strstr(txt, "(u "));
    free(txt);
    n = param_mpi(priv, "n");
    e = param_mpi(priv, "e");
    p = param_mpi(priv, "p");
    q = param_mpi(priv, "q");
    u = param_mpi(priv, "u");
    ASSERT_EQ(0, gcry_mpi_cmp_ui(e, gcry_fips_mode_active() ? 65537 : 3));
    ASSERT_TRUE(gcry_mpi_cmp(p, q) < 0);
    t = gcry_mpi_new(0);
    gcry_mpi_mul(t, p, q);
    ASSERT_EQ(0, gcry_mpi_cmp(t, n));
    gcry_mpi_mulm(t, u, p, q);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 1));
    gcry_mpi_release(t);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(u);

    ASSERT_OK(gcry_pk_testkey(priv));
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1) (hash sha256 #" RSA_DIGEST "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);

    /* Bad parameters. */
    {
        gcry_sexp_t parms = sexp("(genkey (rsa (nbits 3:333)))");
        gcry_sexp_t k = NULL;

        ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&k, parms));
        gcry_sexp_release(parms);
        parms = sexp("(genkey (foo (nbits 4:1024)))");
        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&k, parms));
        gcry_sexp_release(parms);

        if (gcry_fips_mode_active()) {
            parms = sexp("(genkey (rsa (nbits 4:2048) (rsa-use-e 1:3)))");
            ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&k, parms));
            gcry_sexp_release(parms);
        }
    }
}

TEST(rsa_testkey_detects_corruption)
{
    gcry_sexp_t bad = NULL;
    gcry_mpi_t n = hex_mpi(RSA_N);
    gcry_mpi_t e = gcry_mpi_set_ui(NULL, RSA_E_DEC);
    gcry_mpi_t d = hex_mpi(RSA_D);
    gcry_mpi_t p = hex_mpi(RSA_P);
    gcry_mpi_t q = hex_mpi(RSA_Q);
    gcry_mpi_t u = gcry_mpi_set_ui(NULL, 12345);

    if (gcry_mpi_cmp(p, q) > 0) {
        gcry_mpi_swap(p, q);
    }

    /* Only n = p * q is checked, as in the reference library: a wrong u
     * passes, a wrong modulus does not. */
    ASSERT_OK(gcry_sexp_build(&bad, NULL,
                              "(private-key (rsa (n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                              n, e, d, p, q, u));
    ASSERT_OK(gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    gcry_mpi_add_ui(n, n, 2);
    ASSERT_OK(gcry_sexp_build(&bad, NULL,
                              "(private-key (rsa (n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                              n, e, d, p, q, u));
    ASSERT_ERR(GPG_ERR_BAD_SECKEY, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);

    /* A public key is not a secret key. */
    bad = rsa_vector_key(0);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_mpi_release(d);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(u);
}

/* ------------------------------------------------------------------ */
/* DSA                                                                 */
/* ------------------------------------------------------------------ */

TEST(dsa)
{
    gcry_sexp_t key;
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t data = NULL;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t sig2 = NULL;
    gcry_mpi_t q;
    gcry_mpi_t r1;
    gcry_mpi_t r2;
    unsigned char grip1[20];
    unsigned char grip2[20];

    if (gcry_fips_mode_active()) {
        expect_fips_refusal("(genkey (dsa (nbits 4:2048) (qbits 3:256)))",
                            key_grips[2].key,
                            "(data (flags raw) (hash sha256 #" RSA_DIGEST "#))",
                            "(sig-val (dsa (r #01#) (s #02#)))",
                            "(enc-val (dsa (a #01#)))");
        return;
    }

    if (!dsa_available()) {
        printf("  (skipping: DSA not available)\n");
        return;
    }

    key = genkey("(genkey (dsa (nbits 4:2048) (qbits 3:256)))");
    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    ASSERT_EQ(2048, gcry_pk_get_nbits(pub));
    q = param_mpi(pub, "q");
    ASSERT_EQ(256, gcry_mpi_get_nbits(q));
    gcry_mpi_release(q);
    ASSERT_OK(gcry_pk_testkey(priv));
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(priv, grip1));
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(pub, grip2));
    ASSERT_MEM_EQ(grip1, grip2, 20);

    /* Deterministic signatures (RFC 6979) are reproducible. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags rfc6979) (hash sha256 #" RSA_DIGEST "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_sign(&sig2, data, priv));
    r1 = param_mpi(sig, "r");
    r2 = param_mpi(sig2, "r");
    ASSERT_EQ(0, gcry_mpi_cmp(r1, r2));
    gcry_mpi_release(r1);
    gcry_mpi_release(r2);
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig2);
    gcry_sexp_release(data);

    /* The same signature fails for other data. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags rfc6979) (hash sha256 #00" RSA_DIGEST "#))"));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* Randomised signature with raw flag, and the old style bare hash. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (hash sha256 #" RSA_DIGEST "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (value #" RSA_DIGEST "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* DSA cannot encrypt. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value #01#))"));
    ASSERT_ERR(GPG_ERR_NOT_IMPLEMENTED, gcry_pk_encrypt(&sig, data, pub));
    gcry_sexp_release(data);

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* ElGamal                                                             */
/* ------------------------------------------------------------------ */

TEST(elgamal)
{
    gcry_sexp_t key;
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t data = NULL;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t sig = NULL;
    gcry_mpi_t m;
    gcry_mpi_t p;
    gcry_mpi_t factor;

    if (gcry_fips_mode_active()) {
        expect_fips_refusal("(genkey (elg (nbits 4:1024)))",
                            "(private-key (elg (p #0b#) (g #02#) (y #04#)"
                            " (x #03#)))",
                            "(data (flags raw) (value #01#))",
                            "(sig-val (elg (r #01#) (s #02#)))",
                            "(enc-val (elg (a #01#) (b #02#)))");
        return;
    }

    key = genkey("(genkey (elg (nbits 4:1024)))");
    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    ASSERT_NOT_NULL(priv);
    ASSERT_EQ(1024, gcry_pk_get_nbits(pub));
    ASSERT_OK(gcry_pk_testkey(priv));

    /* misc-key-info carries the complete factorisation of p - 1, so that
     * g is known to generate the whole group. */
    {
        gcry_sexp_t pm1 = gcry_sexp_find_token(key, "pm1-factors", 0);
        gcry_mpi_t prod = gcry_mpi_set_ui(NULL, 1);
        int i;
        int n;

        ASSERT_NOT_NULL(pm1);
        n = gcry_sexp_length(pm1);
        ASSERT_TRUE(n >= 3); /* Token, 2, q and the small factors. */

        for (i = 1; i < n; i++) {
            factor = gcry_sexp_nth_mpi(pm1, i, GCRYMPI_FMT_USG);
            ASSERT_NOT_NULL(factor);
            ASSERT_OK(gcry_prime_check(factor, 0));
            gcry_mpi_mul(prod, prod, factor);
            gcry_mpi_release(factor);
        }

        p = param_mpi(pub, "p");
        gcry_mpi_add_ui(prod, prod, 1);
        ASSERT_EQ(0, gcry_mpi_cmp(prod, p));
        gcry_mpi_release(prod);
        gcry_mpi_release(p);
        gcry_sexp_release(pm1);
    }

    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (value #0102030405060708#))"));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pub));
    ASSERT_TRUE(has_token(ciph, "elg"));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, priv));
    /* No flags in the enc-val: the legacy bare MPI result. */
    m = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_STD);
    ASSERT_NOT_NULL(m);
    ASSERT_TRUE(gcry_mpi_cmp_ui(m, 0) > 0);
    {
        gcry_mpi_t expect = hex_mpi("0102030405060708");

        ASSERT_EQ(0, gcry_mpi_cmp(m, expect));
        gcry_mpi_release(expect);
    }
    gcry_mpi_release(m);
    gcry_sexp_release(plain);
    gcry_sexp_release(ciph);

    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_TRUE(has_token(sig, "elg"));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (value #0102030405060709#))"));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* ECC                                                                 */
/* ------------------------------------------------------------------ */

/* RFC 6979 A.2.5: P-256 with SHA-256, message "sample". */
#define P256_D "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
#define P256_QX "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
#define P256_QY "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
#define SAMPLE_SHA256 "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF"
#define P256_SIG_R "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
#define P256_SIG_S "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"

TEST(ecdsa_rfc6979_vector)
{
    gcry_sexp_t skey = sexp("(private-key (ecc (curve \"NIST P-256\")"
                            " (q #04" P256_QX P256_QY "#) (d #" P256_D "#)))");
    gcry_sexp_t pkey = sexp("(public-key (ecc (curve prime256v1)"
                            " (q #04" P256_QX P256_QY "#)))");
    gcry_sexp_t data = NULL;
    gcry_sexp_t sig = NULL;
    gcry_mpi_t r;
    gcry_mpi_t s;
    gcry_mpi_t expect;
    unsigned int nbits = 0;

    ASSERT_NOT_NULL(skey);
    ASSERT_NOT_NULL(pkey);
    ASSERT_EQ(256, gcry_pk_get_nbits(pkey));
    ASSERT_STR_EQ("NIST P-256", gcry_pk_get_curve(pkey, 0, &nbits));
    ASSERT_EQ(256, nbits);
    ASSERT_OK(gcry_pk_testkey(skey));

    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags rfc6979) (hash sha256 #" SAMPLE_SHA256 "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_TRUE(has_token(sig, "ecdsa"));
    r = param_mpi(sig, "r");
    s = param_mpi(sig, "s");
    expect = hex_mpi(P256_SIG_R);
    ASSERT_EQ(0, gcry_mpi_cmp(r, expect));
    gcry_mpi_release(expect);
    expect = hex_mpi(P256_SIG_S);
    ASSERT_EQ(0, gcry_mpi_cmp(s, expect));
    gcry_mpi_release(expect);
    gcry_mpi_release(r);
    gcry_mpi_release(s);
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);

    /* Verifying the known signature given as an S-expression. */
    ASSERT_OK(gcry_sexp_build(&sig, NULL,
                              "(sig-val (ecdsa (r #" P256_SIG_R "#) (s #" P256_SIG_S "#)))"));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags rfc6979) (hash sha256 #00" SAMPLE_SHA256 "#))"));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);

    /* Prehash mode gives the same deterministic signature. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags rfc6979 prehash) (hash-algo sha256) (value %s))",
                              "sample"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    r = param_mpi(sig, "r");
    expect = hex_mpi(P256_SIG_R);
    ASSERT_EQ(0, gcry_mpi_cmp(r, expect));
    gcry_mpi_release(expect);
    gcry_mpi_release(r);
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    /* Randomised ECDSA on a raw hash. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (hash sha256 #" SAMPLE_SHA256 "#))"));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
}

TEST(ecc_keygen_and_ecdh)
{
    gcry_sexp_t key = genkey("(genkey (ecc (curve \"NIST P-256\")))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t data = NULL;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t plain = NULL;
    void *q;
    size_t qlen;
    void *s;
    size_t slen;
    void *v;
    size_t vlen;
    char *txt;

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    ASSERT_NOT_NULL(priv);
    txt = advanced(pub);
    ASSERT_TRUE(strstr(txt, "(curve \"NIST P-256\")") != NULL);
    ASSERT_TRUE(strstr(txt, "(flags") == NULL);
    free(txt);
    q = param_bytes(pub, "q", &qlen);
    ASSERT_EQ(65, qlen);
    ASSERT_EQ(0x04, ((unsigned char *)q)[0]);
    gcry_free(q);
    ASSERT_OK(gcry_pk_testkey(priv));
    ASSERT_EQ(256, gcry_pk_get_nbits(priv));

    /* ECDH: the shared point from encryption equals the decryption. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (value #" P256_D "#))"));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pub));
    s = param_bytes(ciph, "s", &slen);
    ASSERT_EQ(65, slen);
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, priv));
    v = param_bytes(plain, "value", &vlen);
    ASSERT_EQ(65, vlen);
    ASSERT_MEM_EQ(s, v, 65);
    gcry_free(s);
    gcry_free(v);
    gcry_sexp_release(plain);
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);

    /* Signing with the generated key. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (hash sha256 #" SAMPLE_SHA256 "#))"));
    ASSERT_OK(gcry_pk_sign(&ciph, data, priv));
    ASSERT_OK(gcry_pk_verify(ciph, data, pub));
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);

    /* "param" flag emits the domain parameters; "nbits" picks a curve. */
    key = genkey("(genkey (ecc (nbits 3:384) (flags param)))");
    ASSERT_NOT_NULL(key);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    txt = advanced(pub);
    ASSERT_TRUE(strstr(txt, "(curve \"NIST P-384\")") != NULL);
    ASSERT_TRUE(strstr(txt, "(flags param)") != NULL);
    ASSERT_TRUE(strstr(txt, "(p #") != NULL);
    ASSERT_TRUE(strstr(txt, "(h \"1\")") != NULL);
    free(txt);
    ASSERT_STR_EQ("NIST P-384", gcry_pk_get_curve(pub, 0, NULL));
    priv = gcry_sexp_find_token(key, "private-key", 0);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags rfc6979 prehash) (hash-algo sha384) (value %s))",
                              "sample"));
    ASSERT_OK(gcry_pk_sign(&ciph, data, priv));
    ASSERT_OK(gcry_pk_verify(ciph, data, pub));
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);

    /* P-521 with SHA-512. */
    key = genkey("(genkey (ecc (curve \"NIST P-521\")))");
    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    ASSERT_EQ(521, gcry_pk_get_nbits(pub));
    ASSERT_OK(gcry_pk_testkey(priv));
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags rfc6979 prehash) (hash-algo sha512) (value %s))",
                              "sample"));
    ASSERT_OK(gcry_pk_sign(&ciph, data, priv));
    ASSERT_OK(gcry_pk_verify(ciph, data, pub));
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);

    /* A GOST curve has no OpenSSL NID but works from explicit params;
     * FIPS mode does not know it at all (as in the reference library). */
    if (gcry_fips_mode_active()) {
        gcry_sexp_t parms = sexp("(genkey (ecc (curve GOST2001-CryptoPro-A)))");

        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
        pub = sexp("(public-key (ecc (curve GOST2001-CryptoPro-A) (q #04#)))");
        ASSERT_NULL(gcry_pk_get_curve(pub, 0, NULL));
        ASSERT_EQ(0, gcry_pk_get_nbits(pub));
        ASSERT_OK(gcry_sexp_build(&data, NULL,
                                  "(data (flags raw) (value #" P256_D "#))"));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_encrypt(&ciph, data, pub));
        gcry_sexp_release(data);
        gcry_sexp_release(pub);
        return;
    }

    key = genkey("(genkey (ecc (curve GOST2001-CryptoPro-A)))");
    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    ASSERT_OK(gcry_pk_testkey(priv));
    ASSERT_STR_EQ("GOST2001-CryptoPro-A", gcry_pk_get_curve(pub, 0, NULL));
    /* Key agreement works on it, but OpenSSL cannot sign with curves it
     * has no name for. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (value #" P256_D "#))"));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pub));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, priv));
    gcry_sexp_release(plain);
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (hash sha256 #" SAMPLE_SHA256 "#))"));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_sign(&ciph, data, priv));
    gcry_sexp_release(data);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

/* RFC 8032 section 7.1 vectors. */
static const struct {
    const char *sk;
    const char *pk;
    const char *msg;
    const char *sig;
} ed25519_vectors[] = {
    {
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    },
    {
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    },
    {
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    }
};

TEST(ed25519_vectors)
{
    size_t i;

    for (i = 0; i < sizeof ed25519_vectors / sizeof * ed25519_vectors; i++) {
        char text[512];
        gcry_sexp_t skey;
        gcry_sexp_t pkey;
        gcry_sexp_t data = NULL;
        gcry_sexp_t sig = NULL;
        void *r;
        void *s;
        size_t rlen;
        size_t slen;
        char got[129];
        size_t j;
        unsigned char grip1[20];
        unsigned char grip2[20];

        snprintf(text, sizeof text,
                 "(private-key (ecc (curve Ed25519) (flags eddsa) (d #%s#)))",
                 ed25519_vectors[i].sk);
        skey = sexp(text);
        snprintf(text, sizeof text,
                 "(public-key (ecc (curve Ed25519) (flags eddsa) (q #%s#)))",
                 ed25519_vectors[i].pk);
        pkey = sexp(text);
        ASSERT_NOT_NULL(skey);
        ASSERT_NOT_NULL(pkey);
        ASSERT_EQ(255, gcry_pk_get_nbits(pkey));
        ASSERT_STR_EQ("Ed25519", gcry_pk_get_curve(pkey, 0, NULL));

        if (ed25519_vectors[i].msg[0]) {
            snprintf(text, sizeof text, "(data (flags eddsa) (value #%s#))",
                     ed25519_vectors[i].msg);
        } else {
            snprintf(text, sizeof text, "(data (flags eddsa) (value))");
        }

        data = sexp(text);
        ASSERT_NOT_NULL(data);
        ASSERT_OK(gcry_pk_sign(&sig, data, skey));
        ASSERT_TRUE(has_token(sig, "eddsa"));
        r = param_bytes(sig, "r", &rlen);
        s = param_bytes(sig, "s", &slen);
        ASSERT_EQ(32, rlen);
        ASSERT_EQ(32, slen);

        for (j = 0; j < 32; j++) {
            snprintf(got + 2 * j, 3, "%02x", ((unsigned char *)r)[j]);
        }

        for (j = 0; j < 32; j++) {
            snprintf(got + 64 + 2 * j, 3, "%02x", ((unsigned char *)s)[j]);
        }

        ASSERT_STR_EQ(ed25519_vectors[i].sig, got);
        gcry_free(r);
        gcry_free(s);
        ASSERT_OK(gcry_pk_verify(sig, data, pkey));
        /* Verification needs q: a key with only d is rejected. */
        ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_verify(sig, data, skey));

        /* A key with only d signs, but cannot be checked (q is needed). */
        ASSERT_NOT_NULL(gcry_pk_get_keygrip(pkey, grip1));
        ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_testkey(skey));
        gcry_sexp_release(sig);
        gcry_sexp_release(data);

        /* Tampered message. */
        data = sexp("(data (flags eddsa) (value #ff#))");
        snprintf(text, sizeof text,
                 "(sig-val (eddsa (r #%.64s#) (s #%s#)))", ed25519_vectors[i].sig,
                 ed25519_vectors[i].sig + 64);
        sig = sexp(text);
        ASSERT_NOT_NULL(sig);
        ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pkey));
        gcry_sexp_release(sig);
        gcry_sexp_release(data);

        /* The hash-and-sign API with pushed input data (as the reference
         * test suite uses it). */
        {
            gcry_ctx_t ctx = NULL;
            size_t msglen = strlen(ed25519_vectors[i].msg) / 2;
            unsigned char msg[8];
            size_t k;

            for (k = 0; k < msglen; k++) {
                unsigned int v;

                sscanf(ed25519_vectors[i].msg + 2 * k, "%2x", &v);
                msg[k] = (unsigned char)v;
            }

            ASSERT_OK(gcry_pk_input_data_push(&ctx, msg, msglen));
            ASSERT_OK(gcry_pk_hash_sign(&sig, "(data(value %b))", skey, NULL, ctx));
            r = param_bytes(sig, "r", &rlen);
            ASSERT_EQ(32, rlen);
            ASSERT_TRUE(bytes_eq_hex(r, rlen, ed25519_vectors[i].sig)
                        || memcmp(got, ed25519_vectors[i].sig, 64) == 0);
            gcry_free(r);
            ASSERT_OK(gcry_pk_hash_verify(sig, "(data(value %b))", pkey, NULL, ctx));
            gcry_sexp_release(sig);
            gcry_ctx_release(ctx);
        }

        (void)grip2;
        gcry_sexp_release(skey);
        gcry_sexp_release(pkey);
    }
}

TEST(ed25519_keygen_and_ed448)
{
    gcry_sexp_t key = genkey("(genkey (ecc (curve Ed25519) (flags eddsa)))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t data = NULL;
    gcry_sexp_t sig = NULL;
    void *q;
    size_t qlen;
    char *txt;

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    txt = advanced(pub);
    ASSERT_TRUE(strstr(txt, "(curve Ed25519)") != NULL);
    ASSERT_TRUE(strstr(txt, "(flags eddsa)") != NULL);
    free(txt);
    q = param_bytes(pub, "q", &qlen);
    ASSERT_EQ(32, qlen);
    gcry_free(q);
    q = param_bytes(priv, "d", &qlen);
    ASSERT_EQ(32, qlen);
    gcry_free(q);
    ASSERT_OK(gcry_pk_testkey(priv));
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags eddsa) (value %s))",
                              "msg"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    /* Ed25519ctx (not approved by FIPS 186-5) and Ed25519ph. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags eddsa) (label %s) (value %s))", "ctx", "msg"));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_sign(&sig, data, priv));

    if (gcry_fips_mode_active()) {
        sig = sexp("(sig-val (eddsa (r #" RSA_DIGEST "#) (s #" RSA_DIGEST "#)))");
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_verify(sig, data, pub));
    } else {
        ASSERT_OK(gcry_pk_verify(sig, data, pub));
    }

    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags eddsa prehash) (hash-algo sha512) (value %s))",
                              "msg"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags eddsa) (hash-algo sha256) (value %s))", "msg"));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_pk_sign(&sig, data, priv));
    gcry_sexp_release(data);

    /* The "comp" flag adds the 0x40 prefix to q. */
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
    key = genkey("(genkey (ecc (curve Ed25519) (flags eddsa comp)))");
    ASSERT_NOT_NULL(key);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    q = param_bytes(pub, "q", &qlen);
    ASSERT_EQ(33, qlen);
    ASSERT_EQ(0x40, ((unsigned char *)q)[0]);
    gcry_free(q);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);

    /* Ed448 round trip. */
    key = genkey("(genkey (ecc (curve Ed448)))");
    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    q = param_bytes(pub, "q", &qlen);
    ASSERT_EQ(57, qlen);
    gcry_free(q);
    ASSERT_OK(gcry_pk_testkey(priv));
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (value %s))", "ed448 message"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_TRUE(has_token(sig, "eddsa"));
    q = param_bytes(sig, "r", &qlen);
    ASSERT_EQ(57, qlen);
    gcry_free(q);
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

/* RFC 7748 section 6.1 and section 5.2. */
#define X25519_ALICE_SK "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
#define X25519_ALICE_PK "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
#define X25519_BOB_SK "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
/* The same secret clamped as X25519 does it: this is what a key stores. */
#define X25519_BOB_SK_CLAMPED \
    "58ab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b"
#define X25519_BOB_PK "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
#define X25519_SHARED "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
#define X25519_V1_SCALAR "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
#define X25519_V1_U "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
#define X25519_V1_OUT "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

static void
hex_to_bytes(const char *hex, unsigned char *out)
{
    size_t i;

    for (i = 0; hex[2 * i]; i++) {
        unsigned int v;

        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
}

TEST(curve25519)
{
    unsigned char scalar[32];
    unsigned char point[32];
    unsigned char result[32];
    gcry_sexp_t pkey;
    gcry_sexp_t skey;
    gcry_sexp_t data = NULL;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t plain = NULL;
    gcry_mpi_t k;
    void *s;
    size_t slen;
    size_t i;
    unsigned char be[32];

    ASSERT_EQ(32, gcry_ecc_get_algo_keylen(GCRY_ECC_CURVE25519));
    ASSERT_EQ(56, gcry_ecc_get_algo_keylen(GCRY_ECC_CURVE448));
    ASSERT_EQ(0, gcry_ecc_get_algo_keylen(99));

    hex_to_bytes(X25519_V1_SCALAR, scalar);
    hex_to_bytes(X25519_V1_U, point);
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_ecc_mul_point(7, result, scalar, NULL));

    /* Curve25519 and X448 are not approved: nothing but the keygrip works
     * in FIPS mode, as in the reference library. */
    if (gcry_fips_mode_active()) {
        gcry_sexp_t parms;

        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_ecc_mul_point(GCRY_ECC_CURVE25519, result, scalar,
                                      point));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_ecc_mul_point(GCRY_ECC_CURVE448, result, scalar, NULL));
        pkey = sexp("(public-key (ecc (curve Curve25519) (flags djb-tweak)"
                    " (q #40" X25519_BOB_PK "#)))");
        skey = sexp("(private-key (ecc (curve Curve25519) (flags djb-tweak)"
                    " (q #40" X25519_BOB_PK "#) (d #" X25519_BOB_SK_CLAMPED "#)))");
        ASSERT_NOT_NULL(pkey);
        ASSERT_NOT_NULL(skey);
        ASSERT_NULL(gcry_pk_get_curve(pkey, 0, NULL));
        ASSERT_EQ(0, gcry_pk_get_nbits(pkey));
        ASSERT_NOT_NULL(gcry_pk_get_keygrip(pkey, be));
        ASSERT_OK(gcry_sexp_build(&data, NULL,
                                  "(data (flags raw) (value #" P256_D "#))"));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_encrypt(&ciph, data, pkey));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_testkey(skey));
        ASSERT_OK(gcry_sexp_build(&ciph, NULL,
                                  "(enc-val (ecdh (s #40" X25519_SHARED "#)"
                                  " (e #40" X25519_ALICE_PK "#)))"));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_decrypt(&plain, ciph, skey));
        parms = sexp("(genkey (ecc (curve Curve25519) (flags djb-tweak)))");
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_genkey(&plain, parms));
        gcry_sexp_release(parms);
        parms = sexp("(genkey (ecc (curve X448)))");
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_genkey(&plain, parms));
        gcry_sexp_release(parms);
        gcry_sexp_release(ciph);
        gcry_sexp_release(data);
        gcry_sexp_release(skey);
        gcry_sexp_release(pkey);
        return;
    }

    ASSERT_OK(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, result, scalar, point));
    ASSERT_TRUE(bytes_eq_hex(result, 32, X25519_V1_OUT));
    hex_to_bytes(X25519_ALICE_SK, scalar);
    ASSERT_OK(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, result, scalar, NULL));
    ASSERT_TRUE(bytes_eq_hex(result, 32, X25519_ALICE_PK));

    /* ECDH through gcry_pk_encrypt: Alice's scalar against Bob's key. */
    pkey = sexp("(public-key (ecc (curve Curve25519) (flags djb-tweak)"
                " (q #40" X25519_BOB_PK "#)))");
    skey = sexp("(private-key (ecc (curve Curve25519) (flags djb-tweak)"
                " (q #40" X25519_BOB_PK "#) (d #" X25519_BOB_SK_CLAMPED "#)))");
    ASSERT_NOT_NULL(pkey);
    ASSERT_NOT_NULL(skey);
    ASSERT_STR_EQ("Curve25519", gcry_pk_get_curve(pkey, 0, NULL));

    for (i = 0; i < 32; i++) {
        be[i] = scalar[31 - i]; /* The scalar as a big endian number. */
    }

    gcry_mpi_scan(&k, GCRYMPI_FMT_USG, be, 32, NULL);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "%m", k));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    s = param_bytes(ciph, "s", &slen);
    ASSERT_EQ(33, slen);
    ASSERT_TRUE(bytes_eq_hex(s, slen, "40" X25519_SHARED));
    gcry_free(s);
    s = param_bytes(ciph, "e", &slen);
    ASSERT_TRUE(bytes_eq_hex(s, slen, "40" X25519_ALICE_PK));
    gcry_free(s);
    gcry_mpi_release(k);
    gcry_sexp_release(data);

    /* Bob's secret key is a big endian number in Libgcrypt's convention,
     * so build the key with the reversed bytes for decryption. */
    gcry_sexp_release(skey);
    hex_to_bytes(X25519_BOB_SK_CLAMPED, scalar);

    for (i = 0; i < 32; i++) {
        be[i] = scalar[31 - i];
    }

    gcry_mpi_scan(&k, GCRYMPI_FMT_USG, be, 32, NULL);
    ASSERT_OK(gcry_sexp_build(&skey, NULL,
                              "(private-key (ecc (curve Curve25519) (flags djb-tweak)"
                              " (q #40" X25519_BOB_PK "#) (d %m)))", k));
    gcry_mpi_release(k);
    ASSERT_OK(gcry_pk_testkey(skey));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, skey));
    s = param_bytes(plain, "value", &slen);
    ASSERT_TRUE(bytes_eq_hex(s, slen, "40" X25519_SHARED));
    gcry_free(s);
    gcry_sexp_release(plain);
    gcry_sexp_release(ciph);
    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);

    /* Key generation on Curve25519 and X448. */
    {
        gcry_sexp_t key = genkey("(genkey (ecc (curve Curve25519) (flags djb-tweak)))");
        gcry_sexp_t pub;
        gcry_sexp_t priv;
        char *txt;

        ASSERT_NOT_NULL(key);
        pub = gcry_sexp_find_token(key, "public-key", 0);
        priv = gcry_sexp_find_token(key, "private-key", 0);
        txt = advanced(pub);
        ASSERT_TRUE(strstr(txt, "(flags djb-tweak)") != NULL);
        free(txt);
        s = param_bytes(pub, "q", &slen);
        ASSERT_EQ(33, slen);
        ASSERT_EQ(0x40, ((unsigned char *)s)[0]);
        gcry_free(s);
        ASSERT_OK(gcry_pk_testkey(priv));
        gcry_sexp_release(pub);
        gcry_sexp_release(priv);
        gcry_sexp_release(key);

        key = genkey("(genkey (ecc (curve X448)))");
        ASSERT_NOT_NULL(key);
        pub = gcry_sexp_find_token(key, "public-key", 0);
        priv = gcry_sexp_find_token(key, "private-key", 0);
        s = param_bytes(pub, "q", &slen);
        ASSERT_EQ(56, slen);
        gcry_free(s);
        ASSERT_OK(gcry_pk_testkey(priv));
        ASSERT_OK(gcry_sexp_build(&data, NULL,
                                  "(data (flags raw) (value #" P256_D "#))"));
        ASSERT_OK(gcry_pk_encrypt(&ciph, data, pub));
        ASSERT_OK(gcry_pk_decrypt(&plain, ciph, priv));
        s = param_bytes(ciph, "s", &slen);
        ASSERT_EQ(56, slen);
        {
            void *v = param_bytes(plain, "value", &i);

            ASSERT_EQ(56, i);
            ASSERT_MEM_EQ(s, v, 56);
            gcry_free(v);
        }
        gcry_free(s);
        gcry_sexp_release(plain);
        gcry_sexp_release(ciph);
        gcry_sexp_release(data);
        gcry_sexp_release(pub);
        gcry_sexp_release(priv);
        gcry_sexp_release(key);
    }
}

/* ------------------------------------------------------------------ */
/* Names, info, curves                                                 */
/* ------------------------------------------------------------------ */

TEST(names_and_info)
{
    size_t n;

    ASSERT_EQ(GCRY_PK_RSA, gcry_pk_map_name("rsa"));
    ASSERT_EQ(GCRY_PK_RSA, gcry_pk_map_name("RSA"));
    ASSERT_EQ(GCRY_PK_RSA, gcry_pk_map_name("openpgp-rsa"));
    ASSERT_EQ(GCRY_PK_RSA, gcry_pk_map_name("oid.1.2.840.113549.1.1.1"));
    /* Like the reference library, FIPS mode does not map the names of
     * non-approved algorithms. */
    ASSERT_EQ(gcry_fips_mode_active() ? 0 : GCRY_PK_DSA, gcry_pk_map_name("dsa"));
    ASSERT_EQ(gcry_fips_mode_active() ? 0 : GCRY_PK_ELG, gcry_pk_map_name("elg"));
    ASSERT_EQ(gcry_fips_mode_active() ? 0 : GCRY_PK_ELG,
              gcry_pk_map_name("openpgp-elg-sig"));
    ASSERT_EQ(GCRY_PK_ECC, gcry_pk_map_name("ecc"));
    ASSERT_EQ(GCRY_PK_ECC, gcry_pk_map_name("ecdsa"));
    ASSERT_EQ(GCRY_PK_ECC, gcry_pk_map_name("eddsa"));
    ASSERT_EQ(0, gcry_pk_map_name("foo"));
    ASSERT_EQ(0, gcry_pk_map_name(NULL));

    ASSERT_STR_EQ("RSA", gcry_pk_algo_name(GCRY_PK_RSA));
    ASSERT_STR_EQ("RSA", gcry_pk_algo_name(GCRY_PK_RSA_E));
    ASSERT_STR_EQ("DSA", gcry_pk_algo_name(GCRY_PK_DSA));
    ASSERT_STR_EQ("ELG", gcry_pk_algo_name(GCRY_PK_ELG_E));
    ASSERT_STR_EQ("ECC", gcry_pk_algo_name(GCRY_PK_ECC));
    ASSERT_STR_EQ("ECC", gcry_pk_algo_name(GCRY_PK_EDDSA));
    ASSERT_STR_EQ("?", gcry_pk_algo_name(4711));

    ASSERT_OK(gcry_pk_test_algo(GCRY_PK_RSA));
    ASSERT_OK(gcry_pk_test_algo(GCRY_PK_ECDH));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_test_algo(GCRY_PK_DSA));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_test_algo(GCRY_PK_ELG));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_test_algo(4711));
    n = GCRY_PK_USAGE_ENCR;
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_algo_info(GCRY_PK_DSA,
                                                      GCRYCTL_TEST_ALGO, NULL, &n));
    n = GCRY_PK_USAGE_SIGN;
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_PUBKEY_ALGO,
                          gcry_pk_algo_info(GCRY_PK_DSA, GCRYCTL_TEST_ALGO, NULL,
                                            &n));
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_GET_ALGO_USAGE, NULL, &n));
    ASSERT_EQ(GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_GET_ALGO_NPKEY, NULL, &n));
    ASSERT_EQ(2, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_GET_ALGO_NSKEY, NULL, &n));
    ASSERT_EQ(6, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_DSA, GCRYCTL_GET_ALGO_NSIGN, NULL, &n));
    ASSERT_EQ(2, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_DSA, GCRYCTL_GET_ALGO_NENCR, NULL, &n));
    ASSERT_EQ(0, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ECC, GCRYCTL_GET_ALGO_NPKEY, NULL, &n));
    ASSERT_EQ(7, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ELG, GCRYCTL_GET_ALGO_NENCR, NULL, &n));
    ASSERT_EQ(2, n);
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_pk_algo_info(GCRY_PK_RSA, 9999, NULL, &n));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_pk_ctl(9999, NULL, 0));
}

TEST(curve_queries)
{
    gcry_sexp_t key;
    gcry_sexp_t param;
    unsigned int nbits = 0;
    char *txt;
    gcry_mpi_t h;

    /* Lookup by name alias and by explicit parameters. */
    key = sexp("(public-key (ecc (curve secp384r1) (q #04#)))");
    ASSERT_STR_EQ("NIST P-384", gcry_pk_get_curve(key, 0, &nbits));
    ASSERT_EQ(384, nbits);
    gcry_sexp_release(key);
    key = sexp("(public-key (ecc (curve \"1.3.36.3.3.2.8.1.1.7\") (q #04#)))");

    if (gcry_fips_mode_active()) {
        /* Non-approved curves are unknown to the queries, as in the
         * reference library. */
        ASSERT_NULL(gcry_pk_get_curve(key, 0, NULL));
        ASSERT_EQ(0, gcry_pk_get_nbits(key));
    } else {
        ASSERT_STR_EQ("brainpoolP256r1", gcry_pk_get_curve(key, 0, NULL));
    }

    gcry_sexp_release(key);
    key = sexp("(public-key (ecc (curve nowhere) (q #04#)))");
    ASSERT_NULL(gcry_pk_get_curve(key, 0, NULL));
    gcry_sexp_release(key);
    key = sexp("(public-key (ecc"
               " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
               " (a #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC#)"
               " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
               " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
               "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
               " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
               " (h #01#)"
               " (q #04" P256_QX P256_QY "#)))");
    ASSERT_NOT_NULL(key);
    ASSERT_STR_EQ("NIST P-256", gcry_pk_get_curve(key, 0, &nbits));
    ASSERT_EQ(256, nbits);
    ASSERT_EQ(256, gcry_pk_get_nbits(key));
    gcry_sexp_release(key);

    /* gcry_pk_get_param */
    param = gcry_pk_get_param(GCRY_PK_ECC, "Ed25519");
    ASSERT_NOT_NULL(param);
    txt = advanced(param);
    ASSERT_TRUE(strstr(txt, "(public-key") == txt);
    ASSERT_TRUE(strstr(txt, "(ecc") != NULL);
    ASSERT_TRUE(strstr(txt, "(p #") != NULL);
    ASSERT_TRUE(strstr(txt, "(g #04") != NULL);
    ASSERT_TRUE(strstr(txt, "(h \"8\")") != NULL);
    free(txt);
    {
        gcry_sexp_t l = gcry_sexp_find_token(param, "h", 0);
        char *hs = gcry_sexp_nth_string(l, 1);

        ASSERT_STR_EQ("8", hs); /* The cofactor is a decimal string. */
        gcry_free(hs);
        gcry_sexp_release(l);
    }
    h = NULL;
    (void)h;
    /* a = -1 is stored reduced modulo p. */
    {
        gcry_mpi_t a = param_mpi(param, "a");
        gcry_mpi_t p = param_mpi(param, "p");

        gcry_mpi_add_ui(a, a, 1);
        ASSERT_EQ(0, gcry_mpi_cmp(a, p));
        gcry_mpi_release(a);
        gcry_mpi_release(p);
    }
    gcry_sexp_release(param);
    ASSERT_NULL(gcry_pk_get_param(GCRY_PK_RSA, "Ed25519"));
    ASSERT_NULL(gcry_pk_get_param(GCRY_PK_ECDSA, "no-curve"));
    param = gcry_pk_get_param(GCRY_PK_ECDH, "NIST P-521");
    ASSERT_NOT_NULL(param);
    ASSERT_EQ(521, gcry_pk_get_nbits(param));
    gcry_sexp_release(param);
}

/* ------------------------------------------------------------------ */
/* Algorithm queries, control and generic error handling               */
/* ------------------------------------------------------------------ */

#define D32 "0102030405060708091011121314151617181920212223242526272829303132"
#define D20 "0102030405060708091011121314151617181920"

/* Build an S-expression from TEXT and run gcry_pk_sign on it. */
static gcry_error_t
sign_text(gcry_sexp_t *r_sig, const char *text, gcry_sexp_t skey)
{
    gcry_sexp_t data = sexp(text);
    gcry_error_t err;

    if (!data) {
        return gcry_error(GPG_ERR_INTERNAL);
    }

    *r_sig = NULL;
    err = gcry_pk_sign(r_sig, data, skey);
    gcry_sexp_release(data);
    return err;
}

static gcry_error_t
verify_text(const char *sigtext, const char *datatext, gcry_sexp_t pkey)
{
    gcry_sexp_t sig = sexp(sigtext);
    gcry_sexp_t data = sexp(datatext);
    gcry_error_t err;

    if (!sig || !data) {
        return gcry_error(GPG_ERR_INTERNAL);
    }

    err = gcry_pk_verify(sig, data, pkey);
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    return err;
}

static gcry_error_t
encrypt_text(gcry_sexp_t *r_enc, const char *text, gcry_sexp_t pkey)
{
    gcry_sexp_t data = sexp(text);
    gcry_error_t err;

    if (!data) {
        return gcry_error(GPG_ERR_INTERNAL);
    }

    *r_enc = NULL;
    err = gcry_pk_encrypt(r_enc, data, pkey);
    gcry_sexp_release(data);
    return err;
}

static gcry_error_t
decrypt_text(gcry_sexp_t *r_plain, const char *text, gcry_sexp_t skey)
{
    gcry_sexp_t enc = sexp(text);
    gcry_error_t err;

    if (!enc) {
        return gcry_error(GPG_ERR_INTERNAL);
    }

    *r_plain = NULL;
    err = gcry_pk_decrypt(r_plain, enc, skey);
    gcry_sexp_release(enc);
    return err;
}

TEST(algo_info_and_ctl)
{
    size_t n;
    int algo;
    gcry_sexp_t parms;
    gcry_sexp_t key = NULL;
    gcry_sexp_t param;
    char dummy[1] = { 0 };

    /* Usage flags and element counts, including an unknown algorithm. */
    n = 0;
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ELG_E, GCRYCTL_GET_ALGO_USAGE, NULL, &n));
    ASSERT_EQ(GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ECDSA, GCRYCTL_GET_ALGO_USAGE, NULL, &n));
    ASSERT_EQ(GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR, n);
    ASSERT_OK(gcry_pk_algo_info(999, GCRYCTL_GET_ALGO_USAGE, NULL, &n));
    ASSERT_EQ(0, n);
    n = 99;
    ASSERT_OK(gcry_pk_algo_info(999, GCRYCTL_GET_ALGO_NPKEY, NULL, &n));
    ASSERT_EQ(0, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ELG, GCRYCTL_GET_ALGO_NPKEY, NULL, &n));
    ASSERT_EQ(3, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ELG, GCRYCTL_GET_ALGO_NSKEY, NULL, &n));
    ASSERT_EQ(4, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ELG, GCRYCTL_GET_ALGO_NSIGN, NULL, &n));
    ASSERT_EQ(2, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ECC, GCRYCTL_GET_ALGO_NSKEY, NULL, &n));
    ASSERT_EQ(8, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ECC, GCRYCTL_GET_ALGO_NSIGN, NULL, &n));
    ASSERT_EQ(2, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_ECC, GCRYCTL_GET_ALGO_NENCR, NULL, &n));
    ASSERT_EQ(2, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_GET_ALGO_NSIGN, NULL, &n));
    ASSERT_EQ(1, n);
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_GET_ALGO_NENCR, NULL, &n));
    ASSERT_EQ(1, n);

    /* TEST_ALGO takes no buffer; an unknown "what" is an invalid operation. */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_TEST_ALGO, dummy,
                                 NULL));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_pk_algo_info(GCRY_PK_RSA, 12345, NULL, NULL));

    /* gcry_pk_ctl argument checking. */
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_pk_ctl(12345, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_ctl(GCRYCTL_DISABLE_ALGO, NULL, 0));
    algo = GCRY_PK_RSA;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_ctl(GCRYCTL_DISABLE_ALGO, &algo, 1));

    /* Malformed genkey requests. */
    parms = sexp("(foo)");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey)");
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey ((a) b))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (rsa (nbits)))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (rsa (nbits 4:1024) (flags bogus)))");
    ASSERT_ERR(GPG_ERR_INV_FLAG, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    /* Flags are parsed last to first, so igninvflag must come after the
     * unknown flag to have an effect. */
    parms = sexp("(genkey (rsa (nbits 4:1024) (flags igninvflag bogus)))");
    ASSERT_ERR(GPG_ERR_INV_FLAG, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (dsa (nbits 4:1024) (qbits)))");
    /* FIPS mode refuses the algorithm before looking at the parameters. */
    ASSERT_ERR(gcry_fips_mode_active() ? GPG_ERR_PUBKEY_ALGO : GPG_ERR_INV_OBJ,
               gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    ASSERT_NULL(key);

    /* Queries on junk. */
    parms = sexp("(foo (bar))");
    ASSERT_EQ(0, gcry_pk_get_nbits(parms));
    ASSERT_NULL(gcry_pk_get_curve(parms, 0, NULL));
    gcry_sexp_release(parms);
    ASSERT_NULL(gcry_pk_get_param(GCRY_PK_RSA, "NIST P-256"));
    ASSERT_NULL(gcry_pk_get_param(GCRY_PK_ECC, "foo"));

    /* The parameter S-expression of a curve names the curve again; a
     * non-approved curve has no parameters in FIPS mode. */
    param = gcry_pk_get_param(GCRY_PK_ECC, "secp256k1");

    if (gcry_fips_mode_active()) {
        ASSERT_NULL(param);
        param = gcry_pk_get_param(GCRY_PK_ECC, "NIST P-256");
        ASSERT_NOT_NULL(param);
        ASSERT_STR_EQ("NIST P-256", gcry_pk_get_curve(param, 0, NULL));
        gcry_sexp_release(param);
        return;
    }

    ASSERT_NOT_NULL(param);
    ASSERT_STR_EQ("secp256k1", gcry_pk_get_curve(param, 0, NULL));
    {
        gcry_mpi_t b = param_mpi(param, "b");
        gcry_sexp_t l = gcry_sexp_find_token(param, "a", 0);
        size_t alen = 99;

        ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 7));
        gcry_mpi_release(b);
        /* a = 0 is stored as the empty string. */
        ASSERT_NOT_NULL(l);
        gcry_sexp_nth_data(l, 1, &alen);
        ASSERT_EQ(0, alen);
        gcry_sexp_release(l);
    }
    gcry_sexp_release(param);
}

TEST(rsa_genkey_flags)
{
    gcry_sexp_t key;
    gcry_mpi_t e;

    /* Generation flags are accepted; rsa-use-e 0 means 41, 1 means 65537.
     * FIPS mode needs 2048 bits and refuses the small exponent. */
    if (gcry_fips_mode_active()) {
        gcry_sexp_t parms = sexp("(genkey (rsa (nbits 4:2048) (flags transient-key"
                                 " no-keytest no-blinding use-x931) (rsa-use-e 1:0)))");

        ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
        key = genkey("(genkey (rsa (nbits 4:2048) (flags transient-key no-keytest"
                     " no-blinding use-x931) (rsa-use-e 1:1)))");
        ASSERT_NOT_NULL(key);
        e = param_mpi(key, "e");
        ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 65537));
    } else {
        key = genkey("(genkey (rsa (nbits 4:1024) (flags transient-key no-keytest"
                     " no-blinding use-x931) (rsa-use-e 1:0)))");
        ASSERT_NOT_NULL(key);
        e = param_mpi(key, "e");
        ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 41));
    }

    gcry_mpi_release(e);
    ASSERT_OK(gcry_pk_testkey(key));
    gcry_sexp_release(key);

    key = genkey(gcry_fips_mode_active()
                 ? "(genkey (rsa (nbits 4:2048) (rsa-use-e 1:1)))"
                 : "(genkey (rsa (nbits 4:1024) (rsa-use-e 1:1)))");
    ASSERT_NOT_NULL(key);
    e = param_mpi(key, "e");
    ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 65537));
    gcry_mpi_release(e);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* DSA parameters and data handling                                    */
/* ------------------------------------------------------------------ */

TEST(dsa_parameters)
{
    gcry_sexp_t key;
    gcry_sexp_t key2 = NULL;
    gcry_sexp_t parms;
    gcry_mpi_t p;
    gcry_mpi_t q;
    gcry_mpi_t g;
    gcry_mpi_t p2;

    if (gcry_fips_mode_active()) {
        /* Given domain parameters do not make DSA acceptable either. */
        key = sexp(key_grips[1].key);
        p = param_mpi(key, "p");
        q = param_mpi(key, "q");
        g = param_mpi(key, "g");
        ASSERT_OK(gcry_sexp_build(&parms, NULL,
                                  "(genkey (dsa (domain (p %m) (q %m) (g %m))))",
                                  p, q, g));
        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&key2, parms));
        ASSERT_NULL(key2);
        gcry_sexp_release(parms);
        gcry_mpi_release(p);
        gcry_mpi_release(q);
        gcry_mpi_release(g);
        gcry_sexp_release(key);
        return;
    }

    if (!dsa_available()) {
        printf("  (skipping: DSA not available)\n");
        return;
    }

    /* Default q size for 1024 bits. */
    key = genkey("(genkey (dsa (nbits 4:1024)))");
    ASSERT_NOT_NULL(key);
    q = param_mpi(key, "q");
    ASSERT_EQ(160, gcry_mpi_get_nbits(q));
    gcry_mpi_release(q);
    p = param_mpi(key, "p");
    g = param_mpi(key, "g");
    q = param_mpi(key, "q");
    gcry_sexp_release(key);

    /* Reusing domain parameters keeps p; nbits is then not allowed and a
     * missing parameter is reported. */
    ASSERT_OK(gcry_sexp_build(&parms, NULL,
                              "(genkey (dsa (domain (p %m) (q %m) (g %m))))",
                              p, q, g));
    ASSERT_OK(gcry_pk_genkey(&key2, parms));
    gcry_sexp_release(parms);
    p2 = param_mpi(key2, "p");
    ASSERT_EQ(0, gcry_mpi_cmp(p, p2));
    gcry_mpi_release(p2);
    ASSERT_OK(gcry_pk_testkey(key2));
    gcry_sexp_release(key2);
    key2 = NULL;
    ASSERT_OK(gcry_sexp_build(&parms, NULL,
                              "(genkey (dsa (nbits 4:1024)"
                              " (domain (p %m) (q %m) (g %m))))", p, q, g));
    ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&key2, parms));
    gcry_sexp_release(parms);
    ASSERT_OK(gcry_sexp_build(&parms, NULL,
                              "(genkey (dsa (domain (p %m) (q %m))))", p, q));
    ASSERT_ERR(GPG_ERR_MISSING_VALUE, gcry_pk_genkey(&key2, parms));
    gcry_sexp_release(parms);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);

    /* Explicit qbits and the FIPS 186-2 flag. */
    key = genkey("(genkey (dsa (nbits 4:1024) (qbits 3:224)))");
    ASSERT_NOT_NULL(key);
    q = param_mpi(key, "q");
    ASSERT_EQ(224, gcry_mpi_get_nbits(q));
    gcry_mpi_release(q);
    gcry_sexp_release(key);
    key = genkey("(genkey (dsa (nbits 4:1024) (flags use-fips186-2)))");
    ASSERT_NOT_NULL(key);
    gcry_sexp_release(key);

    /* Unsupported sizes. */
    parms = sexp("(genkey (dsa (nbits 4:1536)))");
    ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&key2, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (dsa (nbits 4:1024) (qbits 3:100)))");
    ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&key2, parms));
    gcry_sexp_release(parms);
    ASSERT_NULL(key2);
}

TEST(dsa_data_errors)
{
    /* The data and signature parsing is shared, so FIPS mode (or a strict
     * provider without DSA) runs the same checks with an ECDSA key. */
    int fips = gcry_fips_mode_active();
    int ecdsa = !dsa_available();
    const char *algo = ecdsa ? "ecdsa" : "dsa";
    gcry_sexp_t key = genkey(ecdsa ? "(genkey (ecc (curve \"NIST P-256\")))"
                             : "(genkey (dsa (nbits 4:1024)))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t bad;
    const char *data = "(data (flags raw) (hash sha256 #" D32 "#))";

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);

    /* Signature value checks. */
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_text(sigval_text(algo, "(r #00#) (s #01#)", 0), data, pub));
    ASSERT_ERR(GPG_ERR_NO_OBJ,
               verify_text(sigval_text(algo, "(r #01#)", 0), data, pub));
    ASSERT_ERR(GPG_ERR_NO_OBJ, verify_text("(sig-val)", data, pub));
    ASSERT_ERR(GPG_ERR_INV_OBJ, verify_text("(foo)", data, pub));
    ASSERT_ERR(GPG_ERR_INV_OBJ, verify_text("(sig-val ((a) b))", data, pub));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               verify_text("(sig-val (rsa (s #01#)))", data, pub));
    /* A flags list may precede the algorithm. */
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_text(sigval_text(algo, "(r #01#) (s #02#)", 1), data,
                           pub));
    ASSERT_ERR(GPG_ERR_INV_OBJ, verify_text("(sig-val (flags))", data, pub));

    /* Data element checks. */
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags raw) (hash sha256))", priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags raw) (hash \"\" #" D32 "#))", priv));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               sign_text(&sig, "(data (flags raw) (hash foo #" D32 "#))", priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags raw) (hash sha256 \"\"))", priv));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               sign_text(&sig, "(data (flags raw) (hash sha256 #" D32 "#)"
                         " (label \"\"))", priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags raw) (value))", priv));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               sign_text(&sig, "(data (flags rfc6979) (value #" D32 "#))", priv));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               sign_text(&sig, "(data (flags gost) (hash sha256 #" D32 "#))",
                         priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags eddsa) (hash sha512 #" D32 "#))",
                         priv));
    ASSERT_NULL(sig);

    /* Accepted variants: a label (the caller's nonce, which this library
     * ignores), prehashing, RIPEMD-160 under both names, a value next to
     * the hash, and pkcs1 which is treated as raw for DSA. */
    ASSERT_OK(sign_text(&sig, "(data (flags raw) (hash sha256 #" D32 "#)"
                        " (label #0102#))", priv));
    gcry_sexp_release(sig);
    ASSERT_OK(sign_text(&sig, "(data (flags rfc6979 prehash) (hash-algo sha256)"
                        " (value #0102#))", priv));
    {
        gcry_sexp_t d = sexp("(data (flags rfc6979 prehash) (hash-algo sha256)"
                             " (value #0102#))");

        ASSERT_OK(gcry_pk_verify(sig, d, pub));
        gcry_sexp_release(d);
    }
    gcry_sexp_release(sig);
    /* RIPEMD-160 is not FIPS-approved, so FIPS mode refuses it whether the
     * library hashes or the caller supplies the digest; a provider that
     * lacks the digest has the same effect. */
    ASSERT_OK_UNLESS(md_unavailable(GCRY_MD_RMD160), GPG_ERR_DIGEST_ALGO,
                     sign_text(&sig, "(data (flags raw prehash)"
                               " (hash-algo rmd160) (value #0102#))", priv));
    gcry_sexp_release(sig);
    ASSERT_OK_UNLESS(md_unavailable(GCRY_MD_RMD160), GPG_ERR_DIGEST_ALGO,
                     sign_text(&sig, "(data (flags raw)"
                               " (hash rmd160 #" D20 "#))", priv));
    gcry_sexp_release(sig);
    ASSERT_OK_UNLESS(md_unavailable(GCRY_MD_RMD160), GPG_ERR_DIGEST_ALGO,
                     sign_text(&sig, "(data (flags raw)"
                               " (hash ripemd160 #" D20 "#))", priv));
    gcry_sexp_release(sig);
    ASSERT_OK(sign_text(&sig, "(data (flags raw) (value #01#)"
                        " (hash sha256 #" D32 "#))", priv));
    gcry_sexp_release(sig);
    ASSERT_OK(sign_text(&sig, "(data (flags pkcs1) (hash sha256 #" D32 "#))",
                        priv));
    gcry_sexp_release(sig);

    /* A key whose y does not match x. */
    bad = sexp("(private-key (dsa (p #0b#) (q #05#) (g #02#) (y #04#) (x #03#)))");
    ASSERT_ERR(fips ? GPG_ERR_PUBKEY_ALGO : GPG_ERR_BAD_SECKEY,
               gcry_pk_testkey(bad));
    gcry_sexp_release(bad);

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

TEST(hash_sign_templates)
{
    /* The templates work the same for every signing algorithm; FIPS mode
     * (or a strict provider without DSA) uses ECDSA. */
    gcry_sexp_t key = genkey(dsa_available()
                             ? "(genkey (dsa (nbits 4:1024)))"
                             : "(genkey (ecc (curve \"NIST P-256\")))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t out = NULL;
    gcry_md_hd_t hd;
    gcry_ctx_t ctx = NULL;
    unsigned char nonce[20] = { 1, 2, 3 };

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    gcry_md_write(hd, "abc", 3);

    /* "%s" takes the handle's algorithm; a name selects it explicitly. */
    ASSERT_OK(gcry_pk_hash_sign(&sig, "(data(flags rfc6979)(hash %s %b))", priv,
                                hd, NULL));
    ASSERT_OK(gcry_pk_hash_verify(sig, "(data(flags rfc6979)(hash %s %b))", pub,
                                  hd, NULL));
    ASSERT_OK(gcry_pk_hash_verify(sig, "(data(flags rfc6979)(hash sha256 %b))",
                                  pub, hd, NULL));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_OK(gcry_pk_hash_sign(&sig, "(data(flags rfc6979)(hash sha256 %b))",
                                priv, hd, NULL));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_pk_hash_sign(&sig, "(data(flags rfc6979)(hash foo %b))", priv,
                                 hd, NULL));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_pk_hash_sign(&sig, "(data(flags rfc6979)(value %b))", priv,
                                 hd, NULL));
    ASSERT_ERR(GPG_ERR_EINVAL,
               gcry_pk_hash_sign(&sig, "(data(flags rfc6979)(hash sha256 %b))",
                                 priv, NULL, NULL));
    ASSERT_NULL(sig);

    /* An input data context supplies further "%b" arguments: with a
     * digest handle it follows the digest, without one it is the data. */
    ASSERT_OK(gcry_pk_random_override_new(&ctx, nonce, sizeof nonce));
    ASSERT_OK(gcry_pk_hash_sign(&sig, "(data(flags rfc6979)(hash %s %b)"
                                "(label %b))", priv, hd, ctx));
    ASSERT_OK(gcry_pk_hash_verify(sig, "(data(flags rfc6979)(hash %s %b)"
                                  "(label %b))", pub, hd, ctx));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_OK(gcry_pk_hash_sign(&sig, "(data(flags raw)(hash sha256 %b))", priv,
                                NULL, ctx));
    ASSERT_OK(gcry_pk_hash_verify(sig, "(data(flags raw)(hash sha256 %b))", pub,
                                  NULL, ctx));
    gcry_sexp_release(sig);

    /* gcry_pubkey_get_sexp needs an EC context. */
    ASSERT_ERR(GPG_ERR_WRONG_CRYPT_CTX, gcry_pubkey_get_sexp(&out, 0, ctx));
    ASSERT_ERR(GPG_ERR_NO_CRYPT_CTX, gcry_pubkey_get_sexp(&out, 0, NULL));
    ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pubkey_get_sexp(&out, 7, ctx));
    ASSERT_NULL(out);

    gcry_ctx_release(ctx);
    gcry_md_close(hd);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* RSA data handling                                                   */
/* ------------------------------------------------------------------ */

TEST(rsa_data_errors)
{
    gcry_sexp_t key = genkey(gcry_fips_mode_active()
                             ? "(genkey (rsa (nbits 4:2048)))"
                             : "(genkey (rsa (nbits 4:1024)))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t enc = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t data;
    gcry_sexp_t bad;
    gcry_mpi_t a;
    unsigned char grip[20];

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);

    /* Encoding versus operation conflicts. */
    ASSERT_ERR(GPG_ERR_CONFLICT,
               sign_text(&sig, "(data (flags pkcs1) (value #01#))", priv));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               sign_text(&sig, "(data (flags oaep) (hash sha256 #" D32 "#))",
                         priv));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               encrypt_text(&enc, "(data (flags pss) (value #01#))", pub));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               encrypt_text(&enc, "(data (flags pkcs1) (hash sha256 #" D32 "#))",
                            pub));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               encrypt_text(&enc, "(data (flags pkcs1-raw) (value #01#))", pub));
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags pkcs1-raw) (value #01# #02#))",
                         priv));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               sign_text(&sig, "(data (flags pkcs1) (hash-algo sha256)"
                         " (value #0102#))", priv));

    /* PSS salt handling. */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               sign_text(&sig, "(data (flags pss) (salt-length 2:32)"
                         " (random-override #0102#) (hash sha256 #" D32 "#))",
                         priv));
    ASSERT_OK(sign_text(&sig, "(data (flags pss) (salt-length 1:2)"
                        " (random-override #0102#) (hash sha256 #" D32 "#))",
                        priv));
    {
        gcry_sexp_t d = sexp("(data (flags pss) (salt-length 1:2)"
                             " (hash sha256 #" D32 "#))");

        ASSERT_OK(gcry_pk_verify(sig, d, pub));
        gcry_sexp_release(d);
    }
    gcry_sexp_release(sig);
    ASSERT_OK(sign_text(&sig, "(data (flags pss) (hash-algo sha256)"
                        " (value #0102#) (salt-length 2:32))", priv));
    gcry_sexp_release(sig);
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               sign_text(&sig, "(data (flags pss) (hash-algo md2) (value #0102#))",
                         priv));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               sign_text(&sig, "(data (flags pss) (hash md2"
                         " #0102030405060708091011121314151617#))", priv));

    /* PKCS#1 with other digests and with prehashing.  RIPEMD-160 is not
     * FIPS-approved and is refused in FIPS mode, or wherever the provider
     * lacks it. */
    ASSERT_OK_UNLESS(md_unavailable(GCRY_MD_RMD160), GPG_ERR_DIGEST_ALGO,
                     sign_text(&sig, "(data (flags pkcs1)"
                               " (hash rmd160 #" D20 "#))", priv));
    gcry_sexp_release(sig);
    ASSERT_OK(sign_text(&sig, "(data (flags pkcs1 prehash) (hash-algo sha256)"
                        " (value #0102#))", priv));
    {
        gcry_sexp_t d = sexp("(data (flags pkcs1 prehash) (hash-algo sha256)"
                             " (value #0102#))");

        ASSERT_OK(gcry_pk_verify(sig, d, pub));
        gcry_sexp_release(d);
    }
    gcry_sexp_release(sig);
    ASSERT_OK(sign_text(&sig, "(data (flags pkcs1 prehash) (value #0102#))", priv));
    gcry_sexp_release(sig);
    sig = NULL;

    /* OAEP: unsupported digest, label handling, and the enc-val parser. */
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               encrypt_text(&enc, "(data (flags oaep) (hash-algo md2)"
                            " (value #0102#))", pub));
    ASSERT_OK(encrypt_text(&enc, "(data (flags oaep) (hash-algo sha256)"
                           " (label #0102#) (value #0102#))", pub));
    a = param_mpi(enc, "a");
    ASSERT_NOT_NULL(a);
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_sexp_build(&enc, NULL,
                              "(enc-val (flags oaep) (hash-algo sha256)"
                              " (label #0102#) (rsa (a %m)))", a));
    ASSERT_OK(gcry_pk_decrypt(&plain, enc, priv));
    {
        size_t vlen;
        void *v = param_bytes(plain, "value", &vlen);

        ASSERT_EQ(2, vlen);
        ASSERT_TRUE(bytes_eq_hex(v, vlen, "0102"));
        gcry_free(v);
    }
    gcry_sexp_release(plain);
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_sexp_build(&enc, NULL,
                              "(enc-val (flags oaep) (hash-algo sha256)"
                              " (label #0103#) (rsa (a %m)))", a));
    ASSERT_ERR(GPG_ERR_ENCODING_PROBLEM, gcry_pk_decrypt(&plain, enc, priv));
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_sexp_build(&enc, NULL, "(enc-val (flags pss) (rsa (a %m)))", a));
    ASSERT_ERR(GPG_ERR_CONFLICT, gcry_pk_decrypt(&plain, enc, priv));
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_sexp_build(&enc, NULL,
                              "(enc-val (flags) (random-override #01#)"
                              " (label #01#) (rsa (a %m)))", a));
    /* Not OAEP, so the label is skipped and raw RSA decryption succeeds. */
    ASSERT_OK(gcry_pk_decrypt(&plain, enc, priv));
    gcry_sexp_release(plain);
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_sexp_build(&enc, NULL, "(enc-val (elg (a %m) (b %m)))", a, a));
    ASSERT_ERR(GPG_ERR_CONFLICT, gcry_pk_decrypt(&plain, enc, priv));
    gcry_sexp_release(enc);
    gcry_mpi_release(a);
    ASSERT_ERR(GPG_ERR_NO_OBJ,
               decrypt_text(&plain, "(enc-val (flags) (hash-algo sha256))", priv));
    ASSERT_ERR(GPG_ERR_NO_OBJ, decrypt_text(&plain, "(enc-val)", priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ, decrypt_text(&plain, "(foo)", priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ, decrypt_text(&plain, "(enc-val ((a) b))", priv));
    ASSERT_NULL(plain);

    /* Raw RSA of zero gives an empty MPI both ways. */
    ASSERT_OK(encrypt_text(&enc, "(data (flags raw) (value #00#))", pub));
    a = param_mpi(enc, "a");
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 0));
    gcry_mpi_release(a);
    ASSERT_OK(gcry_pk_decrypt(&plain, enc, priv));
    a = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
    ASSERT_NOT_NULL(a);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 0));
    gcry_mpi_release(a);
    gcry_sexp_release(plain);
    gcry_sexp_release(enc);

    /* Values beyond the modulus. */
    {
        gcry_mpi_t big = gcry_mpi_new(0);

        gcry_mpi_set_ui(big, 1);
        gcry_mpi_mul_2exp(big, big, gcry_pk_get_nbits(pub) + 6);
        ASSERT_OK(gcry_sexp_build(&enc, NULL, "(enc-val (rsa (a %m)))", big));
        ASSERT_OK(gcry_pk_decrypt(&plain, enc, priv));
        gcry_sexp_release(plain);
        gcry_sexp_release(enc);
        ASSERT_OK(gcry_sexp_build(&sig, NULL, "(sig-val (rsa (s %m)))", big));
        data = sexp("(data (flags raw) (value #01#))");
        ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pub));
        gcry_sexp_release(data);
        gcry_sexp_release(sig);
        gcry_mpi_release(big);
    }

    /* Incomplete secret keys. */
    bad = sexp("(private-key (rsa (n #0f#) (e #03#)))");
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (rsa (n #0f#) (e #03#) (d #03#) (p #03#) (q #05#)))");
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (rsa (n #0f#) (e #03#) (d #03#) (p #03#) (q #05#)"
               " (u #02#)))");
    ASSERT_OK(gcry_pk_testkey(bad));
    gcry_sexp_release(bad);

    /* Keygrip edge cases: the RSA grip only needs n; shadowed and
     * protected keys are accepted; broken lists are not. */
    bad = sexp("(public-key (rsa (n #0f#)))");
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    bad = sexp("(public-key (rsa (n) (e)))");
    ASSERT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    bad = sexp("(public-key ((x)))");
    ASSERT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    bad = sexp("(public-key (foo (n #01#)))");
    ASSERT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    bad = sexp("(foo (rsa (n #01#) (e #03#)))");
    ASSERT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    bad = sexp("(shadowed-private-key (rsa (n #0f#) (e #03#)"
               " (shadowed t1-v1 (#01# #02#))))");
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    bad = sexp("(protected-private-key (rsa (n #0f#) (e #03#)"
               " (protected x (y) z)))");
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    {
        unsigned char *g = gcry_pk_get_keygrip(pub, NULL);

        ASSERT_NOT_NULL(g);
        gcry_free(g);
    }
    ASSERT_NULL(gcry_pk_get_curve(pub, 0, NULL));

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* ElGamal edge cases                                                  */
/* ------------------------------------------------------------------ */

TEST(elgamal_edge_cases)
{
    gcry_sexp_t key;
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t enc = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t data;
    gcry_sexp_t bad;
    gcry_mpi_t big = gcry_mpi_new(0);

    if (gcry_fips_mode_active()) {
        /* Not even a malformed ElGamal key gets as far as a check. */
        bad = sexp("(private-key (elg (p #0b#) (g #02#) (y #04#) (x #03#)))");
        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_testkey(bad));
        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO,
                   encrypt_text(&enc, "(data (flags raw) (value #00#))", bad));
        ASSERT_NULL(enc);
        gcry_sexp_release(bad);
        gcry_mpi_release(big);
        return;
    }

    key = genkey("(genkey (elg (nbits 4:1024)))");
    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);

    /* Zero and out-of-range values are processed, not rejected. */
    ASSERT_OK(encrypt_text(&enc, "(data (flags raw) (value #00#))", pub));
    gcry_sexp_release(enc);
    gcry_mpi_set_ui(big, 1);
    gcry_mpi_mul_2exp(big, big, 1030);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", big));
    ASSERT_OK(gcry_pk_encrypt(&enc, data, pub));
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&enc, NULL, "(enc-val (elg (a %m) (b %m)))", big,
                              big));
    ASSERT_OK(gcry_pk_decrypt(&plain, enc, priv));
    gcry_sexp_release(plain);
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_sexp_build(&sig, NULL, "(sig-val (elg (r %m) (s %m)))", big,
                              big));
    data = sexp("(data (flags raw) (value #01#))");
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(data);
    gcry_sexp_release(sig);
    gcry_mpi_release(big);

    bad = sexp("(private-key (elg (p #0b#) (g #02#) (y #04#) (x #03#)))");
    ASSERT_ERR(GPG_ERR_BAD_SECKEY, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* ECC key generation variants and data handling                       */
/* ------------------------------------------------------------------ */

TEST(ecc_genkey_variants)
{
    gcry_sexp_t key = NULL;
    gcry_sexp_t parms;
    gcry_sexp_t l;
    size_t qlen = 0;
    const unsigned char *q;

    parms = sexp("(genkey (ecc (curve foo)))");
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (ecc (nbits 3:255)))");
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (ecc (nbits 3:200)))");
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    ASSERT_NULL(key);

    /* "comp" is accepted but the public point stays uncompressed. */
    key = genkey("(genkey (ecc (curve \"NIST P-256\") (flags comp)))");
    ASSERT_NOT_NULL(key);
    l = gcry_sexp_find_token(key, "q", 0);
    q = (const unsigned char *)gcry_sexp_nth_data(l, 1, &qlen);
    ASSERT_EQ(65, qlen);
    ASSERT_EQ(0x04, q[0]);
    gcry_sexp_release(l);
    gcry_sexp_release(key);

    key = genkey("(genkey (ecc (curve \"NIST P-256\")"
                 " (flags nocomp transient-key no-keytest)))");
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_pk_testkey(key));
    gcry_sexp_release(key);

    /* "param" puts the domain parameters into the key. */
    key = genkey("(genkey (ecc (curve \"NIST P-256\") (flags param)))");
    ASSERT_NOT_NULL(key);
    l = gcry_sexp_find_token(key, "p", 0);
    ASSERT_NOT_NULL(l);
    gcry_sexp_release(l);
    ASSERT_STR_EQ("NIST P-256", gcry_pk_get_curve(key, 0, NULL));
    gcry_sexp_release(key);

    /* The NIST curve is selected from nbits alone. */
    key = genkey("(genkey (ecc (nbits 3:256)))");
    ASSERT_NOT_NULL(key);
    ASSERT_STR_EQ("NIST P-256", gcry_pk_get_curve(key, 0, NULL));
    gcry_sexp_release(key);

    /* djb-tweak on a Weierstrass curve is accepted. */
    key = genkey("(genkey (ecc (curve \"NIST P-256\") (flags djb-tweak)))");
    ASSERT_NOT_NULL(key);
    gcry_sexp_release(key);
}

TEST(ecc_data_errors)
{
    gcry_sexp_t key = genkey("(genkey (ecc (curve \"NIST P-256\")))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t enc = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t data;
    gcry_sexp_t bad;
    gcry_mpi_t m = hex_mpi(D32);
    const char *hash = "(data (flags raw) (hash sha256 #" D32 "#))";

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);

    /* A bare (value) without flags is signed as a number. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (value %m))", m));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    sig = NULL;
    gcry_sexp_release(data);

    ASSERT_ERR(GPG_ERR_CONFLICT,
               sign_text(&sig, "(data (flags gost) (hash sha256 #" D32 "#))",
                         priv));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_text("(sig-val (ecdsa (r #00#) (s #01#)))", hash, pub));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               verify_text("(sig-val (eddsa (r #01#) (s #01#)))", hash, pub));
    ASSERT_ERR(GPG_ERR_NO_OBJ,
               verify_text("(sig-val (ecdsa (r #01#)))", hash, pub));

    /* Keys with problems. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", m));
    bad = sexp("(public-key (ecc (curve \"NIST P-256\")))");
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_encrypt(&enc, data, bad));
    ASSERT_EQ(256, gcry_pk_get_nbits(bad));
    gcry_sexp_release(bad);
    bad = sexp("(public-key (ecc (curve foo) (q #04#)))");
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_pk_encrypt(&enc, data, bad));
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE,
               verify_text("(sig-val (ecdsa (r #01#) (s #01#)))", hash, bad));
    ASSERT_EQ(0, gcry_pk_get_nbits(bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (ecc (curve foo) (q #04#) (d #01#)))");
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_pk_sign(&sig, data, bad));
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE,
               decrypt_text(&plain, "(enc-val (ecdh (e #04#)))", bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (ecc (curve \"NIST P-256\") (q #04#) (d #01#)))");
    ASSERT_ERR(GPG_ERR_BAD_SECKEY, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    /* Signing needs only d; testkey needs q as well. */
    bad = sexp("(private-key (ecc (curve \"NIST P-256\") (d #01#)))");
    ASSERT_OK(gcry_pk_sign(&sig, data, bad));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (ecc (curve \"NIST P-256\") (q #04"
               "0101010101010101010101010101010101010101010101010101010101010101"
               "0202020202020202020202020202020202020202020202020202020202020202"
               "#) (d #01#)))");
    ASSERT_ERR(GPG_ERR_BAD_SECKEY, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    bad = sexp("(public-key (ecc (curve \"NIST P-256\") (q #04"
               "0101010101010101010101010101010101010101010101010101010101010101"
               "0202020202020202020202020202020202020202020202020202020202020202"
               "#)))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    gcry_sexp_release(data);

    /* ECDH inputs. */
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               decrypt_text(&plain, "(enc-val (ecdh (e #0400#)))", priv));
    ASSERT_ERR(GPG_ERR_NO_OBJ,
               decrypt_text(&plain, "(enc-val (ecdh (s #01#)))", priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               decrypt_text(&plain, "(enc-val (flags) (ecdh (e #0400#)))", priv));
    ASSERT_ERR(GPG_ERR_INV_DATA,
               encrypt_text(&enc, "(data (flags raw) (value #00#))", pub));
    {
        gcry_mpi_t big = gcry_mpi_new(0);

        gcry_mpi_set_ui(big, 1);
        gcry_mpi_mul_2exp(big, big, 300);
        ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))",
                                  big));
        ASSERT_OK(gcry_pk_encrypt(&enc, data, pub));
        gcry_sexp_release(enc);
        gcry_sexp_release(data);
        gcry_mpi_release(big);
    }

    gcry_mpi_release(m);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

TEST(eddsa_data_errors)
{
    gcry_sexp_t key = genkey("(genkey (ecc (curve Ed25519) (flags eddsa)))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t data;
    gcry_sexp_t bad;
    const char *msg = "(data (flags eddsa) (value #0102#))";

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);

    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags eddsa) (hash sha512 #" D32 "#))",
                         priv));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               sign_text(&sig, "(data (flags eddsa) (hash-algo sha256)"
                         " (value #0102#))", priv));
    ASSERT_NULL(sig);

    /* The empty message is valid. */
    data = sexp("(data (flags eddsa) (value))");
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    ASSERT_ERR(GPG_ERR_INV_LENGTH,
               verify_text("(sig-val (eddsa (r #01#) (s #02#)))", msg, pub));
    ASSERT_ERR(GPG_ERR_CONFLICT,
               verify_text("(sig-val (ecdsa (r #01#) (s #02#)))", msg, pub));

    data = sexp(msg);
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    bad = sexp("(public-key (ecc (curve Ed25519) (flags eddsa) (q #4001#)))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_verify(sig, data, bad));
    gcry_sexp_release(bad);
    bad = sexp("(public-key (ecc (curve Ed25519) (flags eddsa) (q #04"
               "0101010101010101010101010101010101010101010101010101010101010101"
               "0202020202020202020202020202020202020202020202020202020202020202"
               "#)))");
    ASSERT_ERR(GPG_ERR_BROKEN_PUBKEY, gcry_pk_verify(sig, data, bad));
    gcry_sexp_release(bad);
    gcry_sexp_release(sig);
    sig = NULL;

    /* Short and zero padded secret scalars are usable; the public key is
     * needed for testkey. */
    bad = sexp("(private-key (ecc (curve Ed25519) (flags eddsa) (d #01#)))");
    ASSERT_OK(gcry_pk_sign(&sig, data, bad));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (ecc (curve Ed25519) (flags eddsa)"
               " (d #00" D32 "#)))");
    ASSERT_OK(gcry_pk_sign(&sig, data, bad));
    gcry_sexp_release(sig);
    sig = NULL;
    gcry_sexp_release(bad);
    bad = sexp("(private-key (ecc (curve Ed25519) (flags eddsa) (q #4001#)"
               " (d #" D32 "#)))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (ecc (curve Ed25519) (flags eddsa) (q #4001#)))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_sign(&sig, data, bad));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);
    gcry_sexp_release(data);

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

TEST(key_sexp_errors)
{
    gcry_sexp_t data = sexp("(data (flags raw) (value #01#))");
    gcry_sexp_t bad;
    gcry_sexp_t sig = NULL;
    unsigned char grip[20];

    bad = sexp("(private-key ((x) y))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_sign(&sig, data, bad));
    gcry_sexp_release(bad);
    bad = sexp("(private-key (foo (n #01#) (d #01#)))");
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_sign(&sig, data, bad));
    ASSERT_EQ(0, gcry_pk_get_nbits(bad));
    gcry_sexp_release(bad);
    ASSERT_NULL(sig);

    /* Keygrips need every element of the algorithm's grip list. */
    bad = sexp("(public-key (dsa (p #01#)))");
    ASSERT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    bad = sexp("(public-key (rsa (e #03#)))");
    ASSERT_NULL(gcry_pk_get_keygrip(bad, grip));
    gcry_sexp_release(bad);
    gcry_sexp_release(data);
}

TEST(genkey_flag_variants)
{
    gcry_sexp_t key = NULL;
    gcry_sexp_t parms;
    gcry_mpi_t q;

    /* 2048-bit DSA defaults to a 224-bit q, with or without the FIPS flag;
     * FIPS mode itself has no DSA at all, and a strict provider may lack
     * it, in which case the size check is skipped. */
    if (gcry_fips_mode_active()) {
        parms = sexp("(genkey (dsa (nbits 4:2048) (flags use-fips186)))");
        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
    } else if (dsa_available()) {
        key = genkey("(genkey (dsa (nbits 4:2048) (flags use-fips186)))");
        ASSERT_NOT_NULL(key);
        q = param_mpi(key, "q");
        ASSERT_EQ(224, gcry_mpi_get_nbits(q));
        gcry_mpi_release(q);
        gcry_sexp_release(key);
        key = NULL;
    }

    parms = sexp("(genkey (dsa (nbits 4:1024) (flags bogus)))");
    ASSERT_ERR(gcry_fips_mode_active() ? GPG_ERR_PUBKEY_ALGO : GPG_ERR_INV_FLAG,
               gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (rsa (nbits 4:1024) (rsa-use-e)))");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    ASSERT_NULL(key);

    key = genkey("(genkey (ecc (curve Ed25519) (flags eddsa no-prefix)))");
    ASSERT_NOT_NULL(key);
    gcry_sexp_release(key);
}

TEST(dsa_more_data_handling)
{
    int fips = gcry_fips_mode_active();
    int ecdsa = !dsa_available();
    gcry_sexp_t key = genkey(ecdsa ? "(genkey (ecc (curve \"NIST P-256\")))"
                             : "(genkey (dsa (nbits 4:1024)))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t bad;
    gcry_md_hd_t hd;
    gcry_ctx_t ctx = NULL;
    unsigned char nonce[20] = { 1 };

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    pub = gcry_sexp_find_token(key, "public-key", 0);

    /* The sm2 flag has no meaning for DSA and is ignored; ECDSA (used in
     * FIPS mode, or where the provider has no DSA) has no SM2 on its
     * curves. */
    if (ecdsa) {
        ASSERT_ERR(GPG_ERR_NOT_IMPLEMENTED,
                   sign_text(&sig, "(data (flags sm2) (hash sha256 #" D32 "#))",
                             priv));
    } else {
        ASSERT_OK(sign_text(&sig, "(data (flags sm2) (hash sha256 #" D32 "#))",
                            priv));
    }

    gcry_sexp_release(sig);
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               verify_text("(sig-val (flags) ((x)))",
                           "(data (flags raw) (hash sha256 #" D32 "#))", pub));
    bad = sexp("(private-key (dsa (p #0b#) (q #05#) (g #02#) (y #04#)))");
    ASSERT_ERR(fips ? GPG_ERR_PUBKEY_ALGO : GPG_ERR_NO_OBJ, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);

    /* Input data contexts: a named digest with a context, two contexts
     * without a digest handle, and the limit of two contexts. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    gcry_md_write(hd, "abc", 3);
    ASSERT_OK(gcry_pk_random_override_new(&ctx, nonce, sizeof nonce));
    ASSERT_OK(gcry_pk_hash_sign(&sig, "(data(flags rfc6979)(hash sha256 %b)"
                                "(label %b))", priv, hd, ctx));
    ASSERT_OK(gcry_pk_hash_verify(sig, "(data(flags rfc6979)(hash sha256 %b)"
                                  "(label %b))", pub, hd, ctx));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_OK(gcry_pk_random_override_new(&ctx, nonce, sizeof nonce));
    ASSERT_OK(gcry_pk_hash_sign(&sig, "(data(flags raw)(hash sha256 %b)"
                                "(label %b))", priv, NULL, ctx));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_OK(gcry_pk_random_override_new(&ctx, nonce, sizeof nonce));
    ASSERT_ERR(GPG_ERR_EINVAL,
               gcry_pk_hash_sign(&sig, "(data(flags raw)(hash sha256 %b)"
                                 "(label %b))", priv, NULL, ctx));
    ASSERT_NULL(sig);
    gcry_ctx_release(ctx);
    gcry_md_close(hd);

    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(key);
}

TEST(rsa_more_data_handling)
{
    gcry_sexp_t key = genkey(gcry_fips_mode_active()
                             ? "(genkey (rsa (nbits 4:2048)))"
                             : "(genkey (rsa (nbits 4:1024)))");
    gcry_sexp_t priv;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t bad;

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);

    ASSERT_ERR(GPG_ERR_NO_OBJ,
               sign_text(&sig, "(data (flags pss) (hash sha256 #" D32 "#)"
                         " (random-override))", priv));
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               sign_text(&sig, "(data (flags pkcs1-raw) (value))", priv));
    ASSERT_NULL(sig);
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               decrypt_text(&plain, "(enc-val (flags oaep) (hash-algo foo)"
                            " (rsa (a #01#)))", priv));
    ASSERT_ERR(GPG_ERR_NO_OBJ,
               decrypt_text(&plain, "(enc-val (flags oaep) (label)"
                            " (rsa (a #01#)))", priv));
    ASSERT_NULL(plain);

    bad = sexp("(private-key (rsa (n #10#) (e #03#) (d #03#) (p #03#) (q #05#)"
               " (u #02#)))");
    ASSERT_ERR(GPG_ERR_BAD_SECKEY, gcry_pk_testkey(bad));
    gcry_sexp_release(bad);

    gcry_sexp_release(priv);
    gcry_sexp_release(key);
}

TEST(ecc_more_data_handling)
{
    gcry_sexp_t key = genkey("(genkey (ecc (curve \"NIST P-256\")))");
    gcry_sexp_t bad;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t data;
    gcry_mpi_t q;
    const char *msg = "(data (flags eddsa) (value #0102#))";

    ASSERT_NOT_NULL(key);
    q = param_mpi(key, "q");
    ASSERT_OK(gcry_sexp_build(&bad, NULL,
                              "(private-key (ecc (curve \"NIST P-256\") (q %m)))",
                              q));
    gcry_mpi_release(q);
    data = sexp("(data (flags raw) (hash sha256 #" D32 "#))");
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_sign(&sig, data, bad));
    gcry_sexp_release(data);
    gcry_sexp_release(bad);
    gcry_sexp_release(key);

    /* Explicit parameters that match no known curve: nbits comes from p. */
    bad = sexp("(public-key (ecc (p #0b#) (a #01#) (q #04#)))");
    ASSERT_NULL(gcry_pk_get_curve(bad, 0, NULL));
    ASSERT_EQ(4, gcry_pk_get_nbits(bad));
    gcry_sexp_release(bad);
    bad = sexp("(public-key (ecc (p #0b#) (a #01#) (b #01#) (g #040102#)"
               " (n #0d#) (h #01#) (q #04#)))");
    ASSERT_NULL(gcry_pk_get_curve(bad, 0, NULL));
    ASSERT_EQ(4, gcry_pk_get_nbits(bad));
    gcry_sexp_release(bad);

    /* EdDSA public keys that decode to nothing and signatures of the
     * wrong shape. */
    key = genkey("(genkey (ecc (curve Ed25519) (flags eddsa)))");
    ASSERT_NOT_NULL(key);
    {
        gcry_sexp_t priv = gcry_sexp_find_token(key, "private-key", 0);
        gcry_sexp_t pub = gcry_sexp_find_token(key, "public-key", 0);

        data = sexp(msg);
        ASSERT_OK(gcry_pk_sign(&sig, data, priv));
        bad = sexp("(public-key (ecc (curve Ed25519) (flags eddsa) (q #"
                   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                   "#)))");
        ASSERT_ERR(GPG_ERR_BROKEN_PUBKEY, gcry_pk_verify(sig, data, bad));
        gcry_sexp_release(bad);
        bad = sexp("(public-key (ecc (curve Ed25519) (flags eddsa) (q #40"
                   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                   "#)))");
        ASSERT_ERR(GPG_ERR_BROKEN_PUBKEY, gcry_pk_verify(sig, data, bad));
        gcry_sexp_release(bad);
        gcry_sexp_release(sig);
        gcry_sexp_release(data);
        ASSERT_ERR(GPG_ERR_INV_LENGTH,
                   verify_text("(sig-val (eddsa (r #" D32 "#) (s #"
                               "01020304050607080910111213141516171819202122232425262728293031"
                               "#)))", msg, pub));
        ASSERT_ERR(GPG_ERR_INV_LENGTH,
                   verify_text("(sig-val (eddsa (r #" D32 "#) (s #00" D32 "#)))",
                               msg, pub));
        ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
                   verify_text("(sig-val (eddsa (r #" D32 "#) (s #" D32 "#)))",
                               msg, pub));
        gcry_sexp_release(priv);
        gcry_sexp_release(pub);
    }
    gcry_sexp_release(key);
}

/* Must run last: disabling an algorithm is permanent for the process. */
TEST(disable_algorithm)
{
    int algo = GCRY_PK_ELG;
    /* FIPS mode cannot generate the key, but refuses a given one the same
     * way as a disabled algorithm. */
    gcry_sexp_t key = gcry_fips_mode_active()
                      ? sexp("(private-key (elg (p #0b#) (g #02#) (y #04#) (x #03#)))")
                      : genkey("(genkey (elg (nbits 3:512)))");
    gcry_sexp_t priv;
    gcry_sexp_t parms;
    gcry_sexp_t data = sexp("(data (flags raw) (value #01#))");
    gcry_sexp_t sig = NULL;
    gcry_sexp_t key2 = NULL;
    unsigned char grip[20];

    ASSERT_NOT_NULL(key);
    priv = gcry_sexp_find_token(key, "private-key", 0);
    ASSERT_OK(gcry_pk_ctl(GCRYCTL_DISABLE_ALGO, &algo, sizeof algo));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_test_algo(GCRY_PK_ELG));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_test_algo(GCRY_PK_ELG_E));
    ASSERT_OK(gcry_pk_test_algo(GCRY_PK_RSA));
    /* The name stays known but no longer maps back. */
    ASSERT_STR_EQ("ELG", gcry_pk_algo_name(GCRY_PK_ELG));
    ASSERT_EQ(0, gcry_pk_map_name("elg"));
    parms = sexp("(genkey (elg (nbits 3:512)))");
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&key2, parms));
    gcry_sexp_release(parms);
    ASSERT_NULL(key2);
    ASSERT_EQ(0, gcry_pk_get_nbits(priv));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_sign(&sig, data, priv));
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_testkey(priv));
    /* Keygrips are a pure function of the key material. */
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(priv, grip));

    gcry_sexp_release(data);
    gcry_sexp_release(priv);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* Behaviour matched against the reference library                     */
/* ------------------------------------------------------------------ */

/* Deterministic outputs of libgcrypt 1.12 for the vector key: encodings
 * with a caller supplied random part ("random-override") and the PKCS#1
 * v1.5 decryption of an unpadded ciphertext (implicit rejection). */
#define RSA_PKCS1_CT \
    "4939D5D8467211A670B7F826FBA213C9E8D2627BE1A010E01042FEEC73AB9775F85DF3" \
    "9158D8F04D16AE1FCEC94259BB201EEDF62079B50EC12C840C2ADF4744A510258A2693" \
    "1A62961F62E65ED064FA64D4543E2B11B3F170810A9E62B819E27B92F97C109E1EBD45" \
    "0A1466A39FAA052438985FC208D4E2D33D6B15C87BD942BF365D9DAEAC8CB38F43649D" \
    "EDA02CC961B2DB180FEE9090015FE45B784BF88C3EF074C93F724AD82AA5552401000A" \
    "16AAD36F4A4FB0C56FFFBFF4D2CB6252AA98A93879864F7A4E73BD1C0ECA9BA3514A07" \
    "F07C0213620D674B16109562556F141A3AB5D9E3DD5D7786F115211B3FBB6909407B80" \
    "BA8FB427ABF4E507FD4F42"
#define RSA_OAEP1_CT \
    "201D52EED17C78C04001D608E80FA7EEE9EAE5A8941A31FA7677F08B66A93DF39B3A97" \
    "9978E6A00ED1CE53D0CF9CB4E776484F8FDB94C4CD29AD3BB2CF4D3760C810E41542F6" \
    "CE05CBC7885A32A6AA6A1600C5C017A0CFB219BD5DB30B644AA15B4E1E2FFAD03CEB19" \
    "68CC1DC34B1D88470A84B40625A96E1548A1BD0666E8D9B2A58F4D5E9E755BA2683193" \
    "FF77FE2B1261490B0F489E385155D8E1DF3394DF2C3C7121991896662136067512B3E2" \
    "36DC37196B327E80C55C37A14B43E1F3E035E450BC2612532D01013174416F2326EB0E" \
    "8D2FA976CE575137EF689738B4403D95D725F122D34F18A49544B293EB84572234F52F" \
    "78452DB4804B992D0F0504"
#define RSA_OAEP256_CT \
    "5AE5E122A2CD5A7148EAAF3CD88EE9CB69B21AA0CA4F7C8C95E556047A039F8B8C04AD" \
    "D4396C0A0DC01BCBDB684971F59E9A476CF013002007C1FB496A633F1D2B716A4434A0" \
    "FE4D7D14E6A3AD6678F4BB36465A703DA5711915D06F7B396F969F398DEC295FB919AC" \
    "68CE574FAE416699916910106A1E3AB073F00D7E5ED22F6FA54837F22C7714621D8781" \
    "1EDAB1FE847CCE18C046510EBBB2A4A745C8DA8B156EA5963AAE5A5B46CFB2E00F8CCC" \
    "D3B6D5AF77448D1F54AB37BE025421D82CBEB234FA5EBCB07DBA73E247C0838B258907" \
    "A82200D3C5CAA22F826675FE302635DF28B9D9F74673D3E98889030D294F3C2D5E9F91" \
    "D4D2178932114B7BB6A45F"
#define RSA_PSS256_SIG \
    "8AA5531ED78FB9EE717B7E5B2E5BCA7C9EB5C8DEEDA2D6CBF22996F2AC34F6096A3920" \
    "0B8D34ECC22DC57A285031DC0FDA6131362D2F508993D173689C9FD35AC5BEFF29CE6F" \
    "1C4183FF57DF4730F67552EC3FF3A98E7249843FA1D5E5D4017B30B6C3C74EA658FA54" \
    "DEB19B8800F770023EB23DC8026622F20973833E9D7D5938BFF9289F943DD05B332A7E" \
    "003A82320AA1E317623FC5E4469733ACA937233ECE1BF5BD13B2CC2640A46B8D699AF9" \
    "4CA7D4B25AB60CCF21FAA9661D23DDF3E00457595254A842AB2DA6E400694603D55A77" \
    "E22AC2108ABAD6515FC399814BCBD7A94E7FA1DEEF4D33C4E3576989E82A917E957776" \
    "DECF769B87FC384846FC99"
#define RSA_PSSSHAKE_SIG \
    "9284BB06E93952A6E625585D6AE499426079A315835DB98246CADF9559F797563825" \
    "539A3452F2E480C1830982D6F45889E58E065093A996A2A3D2D59D41B7945F918A1FBE" \
    "F0F6D154D9C29E9C8515EFE82180C65A3602EA6AB30CB7693984C53BA9EA74B118822C" \
    "0065F76683730040905195BFE87E01ADC00C6DCCBF211C8998C70D1653B2040473FB3F" \
    "0A6149F5B7BFC3A8E6E21CFA8A4965DD9A3EA34976349E5DE26240481823A19602F2DA" \
    "43D3C17FE2F67848AE1D64FCFAE3D5339280A2EDEF01CAAE088ED63BEED569E13B18BB" \
    "F096A9EE58584A37D4B40B84C8A43BB3B7A6374150D1E63BAED7E23202FB2A3D2A266D" \
    "DAE30DDE20A26ACA1B0E4835"
#define RSA_CRC32_SIG \
    "4B37E1EC24799584BE779E253814E58C99714D223794150EF229E0A5D8C7E8EB64FBA4" \
    "A83D81D128DA021FCFAEF33A7A6961DDB73A29896EDBD3F64A2F8B69AA140AB5603664" \
    "14B8E1A851AC837B7EA5B1404B28FF878912495768966C4DA5E3AF11BFBCF77C0FBC47" \
    "D076DB326583807929388C3D661A564E79602BA9E0B08BD3759EE732B1EC25ECC0C9F4" \
    "4C6866F82F1112F83D74A992A1D58BEC9D60849B89B6EE8B9CCB700DC2EF76E4D8F3B2" \
    "38C8D6164D4F41F15B9F831D54C3A5C3C624894BBFBA7EF0E593CE9ADEC9B60A1FD828" \
    "5CF4108B4D42603143A3E218E2EA0031A26B3A3F8EEFA0B5C4027F01321811CCD5EBA8" \
    "447D5AC19485A1F2EB7D52"
#define RSA_SHA3_SIG \
    "611A65B59E4A7F702714C46C4DDB4F8A4A5FB7E3A6F04B7DE5F45E68B7EAB3257BCBE0" \
    "92323059A93EF90E8590E555A3732ACBAF1C3D21710D3840F12AD725EAEDDEF913B49D" \
    "515723DB9EDED26C498E8875A2F268FE94A29907D34A2E4FB82AB8484FB8875AB91689" \
    "50ACAAC672BE850B51E0ACDAE0E5A94F714F02D20EE11EDB80379ECE5804BF07BA63E6" \
    "8F7003D0B7B26814E03B49DC8AD8AB60616F5A475516BDD6FEFCBBAA06A2D603CAE10A" \
    "9F28FF8459A1367FEB916D008BA871CEA094174E0D8C99F577C4EFCA43675C738FA6B2" \
    "2064A8AD518553972EC2F470337B2EBFCEAC98FC7813C650CF1DE4C14A688B8A494D3C" \
    "E20D88DF1A81A7E02B5399"
#define RSA_RAW1_SIG \
    "1A5A8D5524175EBEF8F5620B97DC96E08A2C6BF82BB350B938D04E9A8A6BA04E00640A" \
    "ECBFB74D0C51244DBC3177BA55234A07D0021055E8BA002C27FA635406968EE052E110" \
    "36CB31357E949ABEDA692C80A978F3CCB8DA5D0D1F52B0FE8695EEC25AE00EB2B0D852" \
    "F8F382CC4CC6FC202DC72B7FE069B15F899AF28B9D3677DD14D1AA988F9D7629D634F6" \
    "1A0A5345415C92262582E69A9DD465B399DA8A50239BC1A65EA92FE2571F94CBC2B02A" \
    "6C323A21BEE59E10B5DCA9EEF091B3A99BDCD0F46024D074A338971AD039184CF5DA74" \
    "C144042F75990B78B1DA77C10B7C55A5D4220BDC77BF592A008838F53870BB31127834" \
    "18CA61ED6EB5BA44CE3038"
#define RSA_IMPLICIT \
    "DAB0FDFB466C042B8E79AA6237200524F2BBA931039F1B9AD41E30B1400D616FF1F152" \
    "034F459C676CDD4F720052E8EC2F1543AD934D7ABC4ADF99666BE671604417F87F42C1" \
    "C27423F7433A"
#define RSA_RAW_CT5 \
    "38937EF3A1727FCA2F8BB000A77E39F5B589BF05B48B972F46D2AF8F1CD6EBE986EF69" \
    "5D1517119F0F81374FE2EE1F2A650330F334E7223C3C7E7E1F1CB664CE3CD26DF3541C" \
    "F23B879047D50E3FAE4FE531A173B6F31FB0D0FD072ABAB1EBE12A18DB684BCD11D094" \
    "F7BC68B0DE4FC19211C8FAA27D8965532C49AD05DB7390599A36B09D5DB18694EBC442" \
    "3E828CE5602CE0EE4F58155BEAC439BA9E8170B1F0E5DFB4420C9EEB71173958E1877E" \
    "C122161E465460B25C8F59C9A93324A6E349731ADEDA66878DFAC79034FAE27D5CE9C9" \
    "2F89E05EE69B9C6A09FA90139A9812C414E9B6262AF88C6CA50C317DD885BC72AF6DB2" \
    "31DBC02CEE50B9108A0429"

/* The full private key of the vector, with u computed. */
static gcry_sexp_t
rsa_full_vector_key(void)
{
    gcry_sexp_t key = NULL;
    gcry_mpi_t n = hex_mpi(RSA_N);
    gcry_mpi_t e = gcry_mpi_set_ui(NULL, RSA_E_DEC);
    gcry_mpi_t d = hex_mpi(RSA_D);
    gcry_mpi_t p = hex_mpi(RSA_P);
    gcry_mpi_t q = hex_mpi(RSA_Q);
    gcry_mpi_t u = gcry_mpi_new(0);

    if (gcry_mpi_cmp(p, q) > 0) {
        gcry_mpi_swap(p, q);
    }

    gcry_mpi_invm(u, p, q);
    gcry_sexp_build(&key, NULL,
                    "(private-key (rsa (n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                    n, e, d, p, q, u);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_mpi_release(d);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(u);
    return key;
}

/* Does the first element named NAME hold the bytes HEX? */
static int
param_is_hex(gcry_sexp_t s, const char *name, const char *hex)
{
    size_t len;
    void *buf = param_bytes(s, name, &len);
    int eq = buf && bytes_eq_hex(buf, len, hex);

    gcry_free(buf);
    return eq;
}

TEST(rsa_encoding_vectors)
{
    gcry_sexp_t skey = rsa_full_vector_key();
    gcry_sexp_t pkey = rsa_vector_key(0);
    gcry_sexp_t data;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t plain = NULL;
    unsigned char ov[256];
    unsigned char digest[32];
    gcry_mpi_t a;
    int i;

    ASSERT_NOT_NULL(skey);
    ASSERT_OK(gcry_pk_testkey(skey));

    for (i = 0; i < 256; i++) {
        ov[i] = (unsigned char)(i + 1);
    }

    for (i = 0; i < 32; i++) {
        unsigned int v;

        sscanf(&RSA_DIGEST[2 * i], "%2x", &v);
        digest[i] = (unsigned char)v;
    }

    /* PKCS#1 v1.5 encryption with the padding supplied by the caller. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1) (value 3:abc)"
                              " (random-override %b))", 250, ov));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    ASSERT_TRUE(param_is_hex(ciph, "a", RSA_PKCS1_CT));
    gcry_sexp_release(data);
    /* Unpadded only when the enc-val says so. */
    a = param_mpi(ciph, "a");
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(enc-val (flags pkcs1) (rsa (a %m)))",
                              a));
    gcry_mpi_release(a);
    ASSERT_OK(gcry_pk_decrypt(&plain, data, skey));
    ASSERT_TRUE(param_is_hex(plain, "value", "616263"));
    gcry_sexp_release(plain);
    gcry_sexp_release(data);
    gcry_sexp_release(ciph);

    /* The padding must fit exactly and contain no zero byte. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1) (value 3:abc)"
                              " (random-override %b))", 249, ov));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_encrypt(&ciph, data, pkey));
    gcry_sexp_release(data);
    ov[7] = 0;
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1) (value 3:abc)"
                              " (random-override %b))", 250, ov));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_encrypt(&ciph, data, pkey));
    gcry_sexp_release(data);
    ov[7] = 8;

    /* OAEP with the seed supplied by the caller.  The default digest is
     * SHA-1, but SHA-256 in FIPS mode (as in the reference library), so
     * the SHA-1 vector then needs the digest named and a 20 byte seed no
     * longer fits the default. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags oaep) (value 3:abc)"
                              " (random-override %b))", 20, ov));

    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_encrypt(&ciph, data, pkey));
        gcry_sexp_release(data);
        ASSERT_OK(gcry_sexp_build(&data, NULL,
                                  "(data (flags oaep) (hash-algo sha1) (value 3:abc)"
                                  " (random-override %b))", 20, ov));
    }

    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    ASSERT_TRUE(param_is_hex(ciph, "a", RSA_OAEP1_CT));
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags oaep) (hash-algo sha256)"
                              " (label 3:lbl) (value 3:abc)"
                              " (random-override %b))", 32, ov));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    ASSERT_TRUE(param_is_hex(ciph, "a", RSA_OAEP256_CT));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(enc-val (flags oaep) (hash-algo sha256)"
                              " (label 3:lbl) (rsa (a %m)))",
                              a = param_mpi(ciph, "a")));
    gcry_mpi_release(a);
    ASSERT_OK(gcry_pk_decrypt(&plain, data, skey));
    ASSERT_TRUE(param_is_hex(plain, "value", "616263"));
    gcry_sexp_release(plain);
    gcry_sexp_release(data);
    gcry_sexp_release(ciph);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags oaep) (value 3:abc)"
                              " (random-override %b))", 19, ov));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_encrypt(&ciph, data, pkey));
    gcry_sexp_release(data);

    /* PSS with a given salt, with SHA-256 and with SHAKE256 (RFC 8702). */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (random-override %b)"
                              " (hash sha256 %b))", 20, ov, 32, digest));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_TRUE(param_is_hex(sig, "s", RSA_PSS256_SIG));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (salt-length 2:32)"
                              " (random-override %b) (hash shake256 %b))",
                              32, ov, 64, ov));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_TRUE(param_is_hex(sig, "s", RSA_PSSSHAKE_SIG));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    /* Signatures with digests OpenSSL does not offer for PKCS#1.  CRC-32
     * is not an approved digest, so FIPS mode refuses it. */
    data = sexp("(data (flags pkcs1) (hash crc32 #01020304#))");

    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_pk_sign(&sig, data, skey));
    } else {
        ASSERT_OK(gcry_pk_sign(&sig, data, skey));
        ASSERT_TRUE(param_is_hex(sig, "s", RSA_CRC32_SIG));
        ASSERT_OK(gcry_pk_verify(sig, data, pkey));
        gcry_sexp_release(sig);
    }

    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1) (hash sha3-256 %b))", 32,
                              digest));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_TRUE(param_is_hex(sig, "s", RSA_SHA3_SIG));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    data = sexp("(data (flags pkcs1-raw) (value 5:hello))");
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_TRUE(param_is_hex(sig, "s", RSA_RAW1_SIG));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    /* A digest of the wrong size for its algorithm is a conflict. */
    data = sexp("(data (flags pkcs1) (hash sha256 #0102#))");
    ASSERT_ERR(GPG_ERR_CONFLICT, gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);

    /* Textbook RSA: encryption reduces the value, a signature of a value
     * not below the modulus cannot be made. */
    a = gcry_mpi_set_ui(NULL, 5);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))",
                              a));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    ASSERT_TRUE(param_is_hex(ciph, "a", RSA_RAW_CT5));
    gcry_sexp_release(ciph);
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    gcry_mpi_release(a);
    a = hex_mpi(RSA_N);
    gcry_mpi_add_ui(a, a, 1);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))",
                              a));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    ASSERT_TRUE(param_is_hex(ciph, "a", "01"));
    gcry_sexp_release(ciph);
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);
    gcry_mpi_release(a);

    /* PKCS#1 v1.5 decryption never reports bad padding: it yields the
     * same synthetic plaintext the reference library computes. */
    a = gcry_mpi_set_ui(NULL, 12345);
    ASSERT_OK(gcry_sexp_build(&ciph, NULL, "(enc-val (flags pkcs1) (rsa (a %m)))",
                              a));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, skey));
    ASSERT_TRUE(param_is_hex(plain, "value", RSA_IMPLICIT));
    gcry_sexp_release(plain);
    gcry_sexp_release(ciph);
    ASSERT_OK(gcry_sexp_build(&ciph, NULL, "(enc-val (flags oaep) (rsa (a %m)))",
                              a));
    ASSERT_ERR(GPG_ERR_ENCODING_PROBLEM, gcry_pk_decrypt(&plain, ciph, skey));
    gcry_sexp_release(ciph);
    ASSERT_OK(gcry_sexp_build(&ciph, NULL,
                              "(enc-val (flags) ((x)) (rsa (a %m)))", a));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_decrypt(&plain, ciph, skey));
    gcry_sexp_release(ciph);
    gcry_mpi_release(a);

    /* Length rules and odd parameters. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags pkcs1) (value %b))",
                              250, ov));
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_pk_encrypt(&ciph, data, pkey));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags pkcs1) (value %b))",
                              249, ov));
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pkey));
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (salt-length 3:223)"
                              " (hash sha256 %b))", 32, digest));
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (salt-length)"
                              " (hash sha256 %b))", 32, digest));
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (hash shake256 %b))", 32,
                              digest));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);
    data = sexp("(data (flags pss prehash) (hash-algo shake128) (value 3:msg))");
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
}

TEST(rsa_genkey_rules)
{
    gcry_sexp_t key;
    gcry_mpi_t e;

    if (gcry_fips_mode_active()) {
        /* FIPS mode: at least 2048 bits in steps of 512, and e >= 65537;
         * an even exponent is still made odd. */
        static const char *const refused[] = {
            "(genkey (rsa (nbits 3:512)))",
            "(genkey (rsa (nbits 3:767)))",
            "(genkey (rsa (nbits 3:256)))",
            "(genkey (rsa (nbits 4:2304)))",
            "(genkey (rsa (nbits 4:2048) (rsa-use-e 1:4)))",
            "(genkey (rsa (nbits 4:2048) (rsa-use-e 3:256)))",
            NULL
        };
        size_t i;

        for (i = 0; refused[i]; i++) {
            gcry_sexp_t parms = sexp(refused[i]);

            ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&key, parms));
            gcry_sexp_release(parms);
        }

        key = genkey("(genkey (rsa (nbits 4:2048) (rsa-use-e 5:65536)))");
        ASSERT_NOT_NULL(key);
        ASSERT_EQ(2048, gcry_pk_get_nbits(key));
        e = param_mpi(key, "e");
        ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 65537));
        gcry_mpi_release(e);
        gcry_sexp_release(key);
        return;
    }

    /* Odd sizes are rounded up; OpenSSL cannot go below 512 bits. */
    key = genkey("(genkey (rsa (nbits 3:512)))");
    ASSERT_NOT_NULL(key);
    ASSERT_EQ(512, gcry_pk_get_nbits(key));
    gcry_sexp_release(key);
    key = genkey("(genkey (rsa (nbits 3:767)))");
    ASSERT_NOT_NULL(key);
    ASSERT_EQ(768, gcry_pk_get_nbits(key));
    gcry_sexp_release(key);
    {
        gcry_sexp_t parms = sexp("(genkey (rsa (nbits 3:256)))");

        ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
    }

    /* Even exponents are made odd, 0 selects 41. */
    key = genkey("(genkey (rsa (nbits 3:512) (rsa-use-e 1:4)))");
    ASSERT_NOT_NULL(key);
    e = param_mpi(key, "e");
    ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 5));
    gcry_mpi_release(e);
    gcry_sexp_release(key);
    key = genkey("(genkey (rsa (nbits 3:512) (rsa-use-e 3:256)))");
    ASSERT_NOT_NULL(key);
    e = param_mpi(key, "e");
    ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 257));
    gcry_mpi_release(e);
    gcry_sexp_release(key);
}

TEST(elgamal_encodings)
{
    gcry_sexp_t key;
    gcry_sexp_t pub;
    gcry_sexp_t sec;
    gcry_sexp_t data;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t sig = NULL;
    gcry_mpi_t a;
    gcry_mpi_t b;
    gcry_mpi_t m;
    unsigned char digest[32];

    if (gcry_fips_mode_active()) {
        gcry_sexp_t parms = sexp("(genkey (elg (nbits 3:300)))");

        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
        parms = sexp("(genkey (elg (nbits 3:512) (xvalue #8000000000000000#)))");
        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
        return;
    }

    key = genkey("(genkey (elg (nbits 4:1024)))");
    ASSERT_NOT_NULL(key);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    sec = gcry_sexp_find_token(key, "private-key", 0);
    memset(digest, 0x11, sizeof digest);

    /* PKCS#1 v1.5 encryption; the result is unpadded only when the
     * enc-val carries the flag, else the frame comes back as a number. */
    data = sexp("(data (flags pkcs1) (value 3:abc))");
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pub));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, sec));
    m = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(1015, gcry_mpi_get_nbits(m) / 8 * 8 + 7);
    gcry_mpi_release(m);
    gcry_sexp_release(plain);
    a = param_mpi(ciph, "a");
    b = param_mpi(ciph, "b");
    gcry_sexp_release(ciph);
    ASSERT_OK(gcry_sexp_build(&ciph, NULL,
                              "(enc-val (flags pkcs1) (elg (a %m)(b %m)))", a,
                              b));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, sec));
    ASSERT_TRUE(param_is_hex(plain, "value", "616263"));
    gcry_sexp_release(plain);
    gcry_sexp_release(ciph);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_sexp_release(data);

    /* OAEP with a label. */
    data = sexp("(data (flags oaep) (hash-algo sha256) (label 3:lbl)"
                " (value 5:hello))");
    ASSERT_OK(gcry_pk_encrypt(&ciph, data, pub));
    a = param_mpi(ciph, "a");
    b = param_mpi(ciph, "b");
    gcry_sexp_release(ciph);
    ASSERT_OK(gcry_sexp_build(&ciph, NULL,
                              "(enc-val (flags oaep) (hash-algo sha256)"
                              " (label 3:lbl) (elg (a %m)(b %m)))", a, b));
    ASSERT_OK(gcry_pk_decrypt(&plain, ciph, sec));
    ASSERT_TRUE(param_is_hex(plain, "value", "68656c6c6f"));
    gcry_sexp_release(plain);
    gcry_sexp_release(ciph);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_sexp_release(data);
    data = sexp("(data (flags pkcs1-raw) (value 5:hello))");
    ASSERT_ERR(GPG_ERR_CONFLICT, gcry_pk_encrypt(&ciph, data, pub));
    gcry_sexp_release(data);

    /* Signatures over PKCS#1 frames. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1) (hash sha256 %b))", 32,
                              digest));
    ASSERT_OK(gcry_pk_sign(&sig, data, sec));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    data = sexp("(data (flags pkcs1) (value 5:hello))");
    ASSERT_ERR(GPG_ERR_CONFLICT, gcry_pk_sign(&sig, data, sec));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1-raw) (value %b))", 32,
                              digest));
    ASSERT_OK(gcry_pk_sign(&sig, data, sec));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (hash sha256 %b))", 32,
                              digest));
    ASSERT_OK(gcry_pk_sign(&sig, data, sec));
    ASSERT_ERR(GPG_ERR_INV_DATA, gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    gcry_sexp_release(pub);
    gcry_sexp_release(sec);
    gcry_sexp_release(key);

    /* Small groups are allowed; a given secret needs 64 bits. */
    key = genkey("(genkey (elg (nbits 3:300)))");
    ASSERT_NOT_NULL(key);
    ASSERT_EQ(300, gcry_pk_get_nbits(key));
    gcry_sexp_release(key);
    {
        gcry_sexp_t parms = sexp("(genkey (elg (nbits 3:512)"
                                 " (xvalue #7FFFFFFFFFFFFFFF#)))");

        ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
    }
    key = genkey("(genkey (elg (nbits 3:512) (xvalue #8000000000000000#)))");
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_pk_testkey(gcry_sexp_find_token(key, "private-key", 0)));
    gcry_sexp_release(key);
}

TEST(dsa_sizes)
{
    gcry_sexp_t key = NULL;
    gcry_sexp_t parms;
    /* In FIPS mode the algorithm is refused before any size is looked at. */
    gcry_err_code_t bad = gcry_fips_mode_active() ? GPG_ERR_PUBKEY_ALGO
                          : GPG_ERR_INV_VALUE;

    /* OpenSSL only knows the FIPS 186 sizes of q; the reference library
     * would accept 168 here. */
    parms = sexp("(genkey (dsa (nbits 4:1024) (qbits 3:168)))");
    ASSERT_ERR(bad, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);

    /* FIPS 186-3 only allows its three size pairs, 186-2 just one. */
    parms = sexp("(genkey (dsa (nbits 4:1024) (qbits 3:160)"
                 " (flags use-fips186)))");
    ASSERT_ERR(bad, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (dsa (nbits 4:1024) (qbits 3:224) (use-fips186)))");
    ASSERT_ERR(bad, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (dsa (nbits 4:2048) (qbits 3:224)"
                 " (flags use-fips186-2)))");
    ASSERT_ERR(bad, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);

    if (gcry_fips_mode_active()) {
        parms = sexp("(genkey (dsa (nbits 4:1024) (qbits 3:160)"
                     " (flags use-fips186-2)))");
        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
        ASSERT_NULL(key);
        return;
    }

    if (!dsa_available()) {
        printf("  (skipping: DSA not available)\n");
        return;
    }

    key = genkey("(genkey (dsa (nbits 4:1024) (qbits 3:160)"
                 " (flags use-fips186-2)))");
    ASSERT_NOT_NULL(key);
    gcry_sexp_release(key);
}

TEST(ecc_sm2_and_curve_rules)
{
    gcry_sexp_t key;
    gcry_sexp_t pub;
    gcry_sexp_t sec;
    gcry_sexp_t data;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t parms;
    unsigned char digest[32];
    size_t len;
    void *q;
    int i;
    const char *name;

    memset(digest, 0x33, sizeof digest);

    /* SM2 signatures on the SM2 curve, tagged "sm2"; the curve is not
     * approved, so FIPS mode refuses it. */
    if (gcry_fips_mode_active()) {
        parms = sexp("(genkey (ecc (curve sm2p256v1)))");
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_genkey(&key, parms));
        gcry_sexp_release(parms);
        sec = sexp("(private-key (ecc (curve sm2p256v1) (q #04#) (d #01#)))");
        ASSERT_OK(gcry_sexp_build(&data, NULL,
                                  "(data (flags sm2) (hash sha256 %b))", 32,
                                  digest));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_pk_sign(&sig, data, sec));
        ASSERT_NULL(gcry_pk_get_curve(sec, 0, NULL));
        gcry_sexp_release(data);
        gcry_sexp_release(sec);
    } else {
        gcry_error_t err;

        key = genkey("(genkey (ecc (curve sm2p256v1)))");
        ASSERT_NOT_NULL(key);
        pub = gcry_sexp_find_token(key, "public-key", 0);
        sec = gcry_sexp_find_token(key, "private-key", 0);
        ASSERT_OK(gcry_sexp_build(&data, NULL,
                                  "(data (flags sm2) (hash sha256 %b))", 32,
                                  digest));
        err = gcry_pk_sign(&sig, data, sec);

        /* A strict provider may know the curve but have no SM2 key type;
         * the library then reports the scheme as unsupported. */
        if (TEST_STRICT_PROVIDER
            && gcry_err_code(err) == GPG_ERR_NOT_SUPPORTED) {
            printf("  (skipping SM2 signatures: not available)\n");
        } else {
            ASSERT_OK(err);
            ASSERT_TRUE(has_token(sig, "sm2"));
            ASSERT_OK(gcry_pk_verify(sig, data, pub));
            gcry_sexp_release(data);
            digest[0] ^= 1;
            ASSERT_OK(gcry_sexp_build(&data, NULL,
                                      "(data (flags sm2) (hash sha256 %b))", 32,
                                      digest));
            ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pub));
            gcry_sexp_release(sig);
            digest[0] ^= 1;
        }

        gcry_sexp_release(data);
        gcry_sexp_release(pub);
        gcry_sexp_release(sec);
        gcry_sexp_release(key);
    }

    /* The sm2 and eddsa flags need their curves. */
    sec = sexp("(private-key (ecc (curve \"NIST P-256\")"
               " (q #04" P256_QX P256_QY "#) (d #" P256_D "#)))");
    pub = sexp("(public-key (ecc (curve \"NIST P-256\")"
               " (q #04" P256_QX P256_QY "#)))");
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags sm2) (hash sha256 %b))", 32,
                              digest));
    ASSERT_ERR(GPG_ERR_NOT_IMPLEMENTED, gcry_pk_sign(&sig, data, sec));
    gcry_sexp_release(data);
    data = sexp("(data (flags eddsa) (value 3:msg))");
    ASSERT_ERR(GPG_ERR_NOT_IMPLEMENTED, gcry_pk_sign(&sig, data, sec));
    gcry_sexp_release(data);
    parms = sexp("(genkey (ecc (curve \"NIST P-256\") (flags eddsa)))");
    ASSERT_ERR(GPG_ERR_NOT_IMPLEMENTED, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);
    parms = sexp("(genkey (ecc (curve secp256k1) (flags eddsa)))");
    ASSERT_ERR(gcry_fips_mode_active() ? GPG_ERR_NOT_SUPPORTED
               : GPG_ERR_NOT_IMPLEMENTED, gcry_pk_genkey(&key, parms));
    gcry_sexp_release(parms);

    /* Signatures of other schemes: certainly bad when out of range. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags raw) (hash sha256 %b))", 32,
                              digest));
    sig = sexp("(sig-val (gost (r #00#)(s #02#)))");
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    sig = sexp("(sig-val (sm2 (r #00#)(s #02#)))");
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);

    /* A public point off the curve is a broken key. */
    gcry_sexp_release(pub);
    pub = sexp("(public-key (ecc (curve \"NIST P-256\")"
               " (q #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A1"
               "3945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECE"
               "CBB6406837BF51F6#)))");
    sig = sexp("(sig-val (ecdsa (r #01#)(s #02#)))");
    ASSERT_ERR(GPG_ERR_BROKEN_PUBKEY, gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    gcry_sexp_release(pub);
    gcry_sexp_release(sec);

    /* Ed25519 without the eddsa flag: a plain key with a 32 byte point,
     * or the uncompressed point with nocomp. */
    key = genkey("(genkey (ecc (curve Ed25519)))");
    ASSERT_NOT_NULL(key);
    ASSERT_NULL(gcry_sexp_find_token(key, "flags", 0));
    q = param_bytes(key, "q", &len);
    ASSERT_EQ(32, len);
    gcry_free(q);
    gcry_sexp_release(key);
    key = genkey("(genkey (ecc (curve Ed25519) (flags nocomp)))");
    ASSERT_NOT_NULL(key);
    q = param_bytes(key, "q", &len);
    ASSERT_EQ(65, len);
    ASSERT_EQ(4, ((unsigned char *)q)[0]);
    gcry_free(q);
    gcry_sexp_release(key);

    /* X25519 of a low order point is all zero rather than an error. */
    {
        unsigned char scalar[32];
        unsigned char point[32];
        unsigned char result[32];
        unsigned char zero[32];

        memset(scalar, 9, sizeof scalar);
        memset(point, 0, sizeof point);
        memset(zero, 0, sizeof zero);
        memset(result, 1, sizeof result);
        ASSERT_OK_OR_FIPS_ERR(GPG_ERR_NOT_SUPPORTED,
                              gcry_ecc_mul_point(GCRY_ECC_CURVE25519, result,
                                                 scalar, point));

        if (!gcry_fips_mode_active()) {
            ASSERT_MEM_EQ(zero, result, 32);
        }
    }

    /* The curve table matches the reference library's list. */
    for (i = 0; (name = gcry_pk_get_curve(NULL, i, NULL)); i++) {
        ASSERT_TRUE(strcmp(name, "ietf25") != 0);
    }

    ASSERT_EQ(27, i);
}

TEST(null_arguments)
{
    gcry_sexp_t key = genkey("(genkey (ecc (curve \"Ed25519\")))");
    gcry_sexp_t data = sexp("(data (flags eddsa) (hash-algo sha512)"
                            " (value #616263#))");
    gcry_sexp_t probe = sexp("(foo)");
    gcry_sexp_t result = probe;
    gcry_ctx_t ctx = NULL;
    unsigned char grip[20];
    unsigned char byte = 1;
    unsigned int nbits = 1;
    size_t n;

    ASSERT_NOT_NULL(key);
    ASSERT_NOT_NULL(data);

    /* A missing result pointer. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_encrypt(NULL, data, key));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_decrypt(NULL, data, key));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_sign(NULL, data, key));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_genkey(NULL, data));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_pk_hash_sign(NULL, "(data (value %b))", key, NULL, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_hash_sign(&result, NULL, key, NULL,
                                                  NULL));
    ASSERT_TRUE(result == probe); /* Untouched: the template is checked first. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_pk_hash_verify(NULL, NULL, key, NULL,
                                                    NULL));
    ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pubkey_get_sexp(NULL, 0, NULL));
    ASSERT_ERR(GPG_ERR_EINVAL, gcry_pk_random_override_new(NULL, &byte, 1));
    ASSERT_ERR(GPG_ERR_EINVAL, gcry_pk_random_override_new(&ctx, NULL, 1));
    ASSERT_ERR(GPG_ERR_EINVAL, gcry_pk_random_override_new(&ctx, NULL, 0));
    ASSERT_NULL(ctx);
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_GET_ALGO_USAGE, NULL,
                                 NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_GET_ALGO_NPKEY, NULL,
                                 NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_pk_algo_info(GCRY_PK_RSA, GCRYCTL_TEST_ALGO, &n, NULL));

    /* A NULL S-expression is not a key or data object: the reference
     * library reports GPG_ERR_INV_OBJ, not GPG_ERR_INV_ARG. */
    /* RESULT starts out as a stale pointer to prove the calls clear it. */
    ASSERT_NOT_NULL(probe);
    result = probe;
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_encrypt(&result, data, NULL));
    ASSERT_NULL(result);
    result = probe;
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_decrypt(&result, data, NULL));
    ASSERT_NULL(result);
    result = probe;
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_sign(&result, data, NULL));
    ASSERT_NULL(result);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_sign(&result, NULL, key));
    ASSERT_NULL(result);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_verify(NULL, data, NULL));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_verify(NULL, data, key));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_verify(NULL, NULL, key));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_testkey(NULL));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_pk_genkey(&result, NULL));
    ASSERT_NULL(result);
    /* Without a digest handle or data context there is nothing to sign. */
    ASSERT_ERR(GPG_ERR_EINVAL,
               gcry_pk_hash_sign(&result, "(data (value %b))", NULL, NULL,
                                 NULL));
    ASSERT_EQ(0, gcry_pk_get_nbits(NULL));
    ASSERT_NULL(gcry_pk_get_keygrip(NULL, grip));
    ASSERT_NULL(gcry_pk_get_keygrip(NULL, NULL));
    ASSERT_NULL(gcry_pk_get_curve(NULL, -1, &nbits));
    ASSERT_EQ(0, nbits);
    ASSERT_NULL(gcry_pk_get_param(GCRY_PK_ECC, NULL));
    ASSERT_NULL(gcry_pk_get_param(GCRY_PK_ECDSA, NULL));
    ASSERT_EQ(0, gcry_pk_map_name(NULL));

    gcry_sexp_release(probe);
    gcry_sexp_release(data);
    gcry_sexp_release(key);
}

/* ------------------------------------------------------------------ */
/* Corrupted RSA frames, keys without CRT values, crafted ElGamal data */
/* ------------------------------------------------------------------ */

/* An RSA key with a 2049 bit modulus (a 1025 bit p and a 1024 bit q made
 * with "openssl prime -generate", d = e^-1 mod (p-1)(q-1)): the PSS
 * encoded message is one byte shorter than the modulus, so the verifier
 * has to strip a leading zero byte.  Test data only. */
#define RSA2049_N "1D5036B7DE47CA4283A2AAC3220FE5C20D8D3E8099EDE46F419AA44946F7DF47530CA19E1ECB63A927471381882A01D55A8B31768D2160286E4852136700CE13903AD4C07673E95F4F8132FB4D5E7170FAF3F5CC22A72E9FD59E6C34C63B5702411662A4B0512F32194E72D1C0A5D840B594D8297EDE10F6E001623AF459AD8B2BB389480C5589DBE9B6FADEA184D21A82BB6B2A96823CABCCA75485A8473146BCFFBE510D0A81F497323D954028997B7C0702CA9849CDB2041C64B93459D2E463775E9CFBC2842B0B625A2136D6D4D3F4C700EF9559A22CA572414AA332A13F13C763641A3B78650F1E39F4A2E7A6ECF6CA2D7A190FEF94C02E2027225710F6B"
#define RSA2049_D "836489E0A2FA2822FCE8A78503A93EB6150888A0E958EC17C678E4ED90AE80A5B41D6A52D8B5D482E30C34E2E8F562427518771E6E7CAC088E4C9D995A9AC11DEFE1C4C2EE31A261167E8986E7C5EDB7FF28891BFC3865450CC29143FD4AFF379B883BA0F8B2EE5A2215019631713164DC87D2662DC6374461D1D1FD704A8919FB080C5F8BA8FEDC765CD724C58E5F1566BB49FCDE6AC7E820AF09C704967CF5143A83955B0DA14209FFD831DB4751451A932073E5D9D62FCD9F653C3A21BAE2B2A3558107D7B1E6224FB7A53F1E43867240614FD7C99CB187B2B2A4E5E4950065FDE927DC100070062E66FEA732D0686CD9F5FB562C01E28EE94FE5B02EB541"
#define RSA2049_P "1EC5ED17355A15D7321C82C61A3DABFEFE7DF9296205D82933F56A447798AF52DAB0B960F033D0110A93CBD2DE842E7BD023604658699665A388D7B73FA3B087A1717B4457C260B4F508ADFFC88C3D1E9375A9EB2DFA6C112AE2CFBEF87BEAD74120B177F3FFE4E063FA4929C9C7F73C7309297422C26682D7293FC8B5D13A175"
#define RSA2049_Q "F3DB1BD974813A31F83DE7E919B72434727510CA8BD2AFDC3BB5C0A850A884CFEB62DEAE626743EDE5349ABB14AEB27BBFC91E3D6F43DFB960CC2062AD7627F770EEA90AAD6D0DCDC2FFCAD5190A4480472F448BB74BFFBC48A42F446C26DEC74D77BCA1136966B1E577DDC2022D1213C31D0A32D42DC9B1924237381965F15F"

/* An RSA private key (e = 65537) from hex parts.  WITH_PQ adds the
 * primes (ordered p < q as the reference library wants them), WITH_U the
 * CRT coefficient u = p^-1 mod q on top of them. */
static gcry_sexp_t
rsa_key_from_hex(const char *nhex, const char *dhex, const char *phex,
                 const char *qhex, int with_pq, int with_u)
{
    gcry_sexp_t key = NULL;
    gcry_mpi_t n = hex_mpi(nhex);
    gcry_mpi_t e = gcry_mpi_set_ui(NULL, 65537);
    gcry_mpi_t d = hex_mpi(dhex);
    gcry_mpi_t p = hex_mpi(phex);
    gcry_mpi_t q = hex_mpi(qhex);
    gcry_mpi_t u = gcry_mpi_new(0);

    if (gcry_mpi_cmp(p, q) > 0) {
        gcry_mpi_swap(p, q);
    }

    gcry_mpi_invm(u, p, q);

    if (!with_pq) {
        gcry_sexp_build(&key, NULL, "(private-key (rsa (n %m)(e %m)(d %m)))",
                        n, e, d);
    } else if (!with_u) {
        gcry_sexp_build(&key, NULL,
                        "(private-key (rsa (n %m)(e %m)(d %m)(p %m)(q %m)))",
                        n, e, d, p, q);
    } else {
        gcry_sexp_build(&key, NULL,
                        "(private-key (rsa (n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                        n, e, d, p, q, u);
    }

    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_mpi_release(d);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(u);
    return key;
}

/* The public key belonging to the RSA private key SKEY. */
static gcry_sexp_t
rsa_public_of(gcry_sexp_t skey)
{
    gcry_sexp_t key = NULL;
    gcry_mpi_t n = param_mpi(skey, "n");
    gcry_mpi_t e = param_mpi(skey, "e");

    if (n && e) {
        gcry_sexp_build(&key, NULL, "(public-key (rsa (n %m)(e %m)))", n, e);
    }

    gcry_mpi_release(n);
    gcry_mpi_release(e);
    return key;
}

/* M as a big endian number left padded with zeros to LEN bytes. */
static int
mpi_to_bytes(gcry_mpi_t m, unsigned char *buf, size_t len)
{
    size_t n = 0;

    if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &n, m) || n > len) {
        return 0;
    }

    memset(buf, 0, len - n);
    return !gcry_mpi_print(GCRYMPI_FMT_USG, buf + len - n, n, NULL, m);
}

/* Textbook RSA on the number M with the private key: s = M^d mod n. */
static gcry_error_t
raw_sign_mpi(gcry_sexp_t *r_sig, gcry_mpi_t m, gcry_sexp_t skey)
{
    gcry_sexp_t data = NULL;
    gcry_error_t err;

    *r_sig = NULL;
    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", m);

    if (!err) {
        err = gcry_pk_sign(r_sig, data, skey);
    }

    gcry_sexp_release(data);
    return err;
}

/* Verify the PSS data DATATEXT against a signature whose public
 * operation recovers exactly the EMLEN bytes EM: the raw private
 * operation on EM gives that signature, so the verifier decodes EM. */
static gcry_error_t
verify_pss_em(const unsigned char *em, size_t emlen, const char *datatext,
              gcry_sexp_t skey, gcry_sexp_t pkey)
{
    gcry_mpi_t m = NULL;
    gcry_sexp_t sig = NULL;
    gcry_sexp_t data = sexp(datatext);
    gcry_error_t err;

    if (!data) {
        return gcry_error(GPG_ERR_INTERNAL);
    }

    err = gcry_mpi_scan(&m, GCRYMPI_FMT_USG, em, emlen, NULL);

    if (!err) {
        err = raw_sign_mpi(&sig, m, skey);
    }

    if (!err) {
        err = gcry_pk_verify(sig, data, pkey);
    }

    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    gcry_mpi_release(m);
    return err;
}

#define PKCS1_SHA256_DATA "(data (flags pkcs1) (hash sha256 #" RSA_DIGEST "#))"
#define PSS_SHA256_DATA "(data (flags pss) (hash sha256 #" RSA_DIGEST "#))"
#define FOX "The quick brown fox jumps over the lazy dog"

TEST(rsa_pkcs1_verify_mismatch)
{
    gcry_sexp_t skey = rsa_vector_key(1);
    gcry_sexp_t pkey = rsa_vector_key(0);
    gcry_sexp_t good = sexp("(sig-val (rsa (s #" RSA_SIG "#)))");
    gcry_sexp_t sig = NULL;
    gcry_sexp_t data = NULL;
    gcry_mpi_t n = hex_mpi(RSA_N);
    gcry_mpi_t m = gcry_mpi_new(0);
    gcry_mpi_t s;
    char flipped[sizeof RSA_SIG];

    ASSERT_NOT_NULL(good);

    /* The frame recovered from the signature is compared with the one
     * the data describes: another digest, another digest algorithm (so
     * another DigestInfo) or the bare digest all make a different frame. */
    ASSERT_OK(gcry_pk_verify(good, data = sexp(PKCS1_SHA256_DATA), pkey));
    gcry_sexp_release(data);
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               gcry_pk_verify(good, data = sexp("(data (flags pkcs1)"
                                                " (hash sha256 #" D32 "#))"),
                              pkey));
    gcry_sexp_release(data);
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               gcry_pk_verify(good, data = sexp("(data (flags pkcs1)"
                                                " (hash sha512 #" D32 D32 "#))"),
                              pkey));
    gcry_sexp_release(data);
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               gcry_pk_verify(good, data = sexp("(data (flags pkcs1-raw)"
                                                " (value #" RSA_DIGEST "#))"),
                              pkey));
    gcry_sexp_release(data);

    /* The same with the message given for prehashing. */
    ASSERT_OK(gcry_pk_verify(good, data = sexp("(data (flags pkcs1 prehash)"
                                               " (hash-algo sha256)"
                                               " (value \"" FOX "\"))"),
                             pkey));
    gcry_sexp_release(data);
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               gcry_pk_verify(good, data = sexp("(data (flags pkcs1 prehash)"
                                                " (hash-algo sha256)"
                                                " (value \"" FOX ".\"))"),
                              pkey));
    gcry_sexp_release(data);
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               gcry_pk_verify(good, data = sexp("(data (flags pkcs1 prehash)"
                                                " (hash-algo sha512)"
                                                " (value \"" FOX "\"))"),
                              pkey));
    gcry_sexp_release(data);

    /* A flipped low bit keeps the signature below n: the public operation
     * runs and the recovered frame is garbage. */
    data = sexp(PKCS1_SHA256_DATA);
    memcpy(flipped, RSA_SIG, sizeof flipped);
    flipped[sizeof flipped - 2] = '5'; /* ...34 -> ...35 */
    s = hex_mpi(flipped);
    ASSERT_TRUE(gcry_mpi_cmp(s, n) < 0);
    ASSERT_OK(gcry_sexp_build(&sig, NULL, "(sig-val (rsa (s %m)))", s));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_mpi_release(s);

    /* A flipped top bit takes it above n and it is refused before that. */
    flipped[sizeof flipped - 2] = '4';
    flipped[0] = 'C'; /* 48... -> C8..., above n = B7... */
    s = hex_mpi(flipped);
    ASSERT_TRUE(gcry_mpi_cmp(s, n) > 0);
    ASSERT_OK(gcry_sexp_build(&sig, NULL, "(sig-val (rsa (s %m)))", s));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_mpi_release(s);
    ASSERT_OK(gcry_sexp_build(&sig, NULL, "(sig-val (rsa (s %m)))", n));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    /* Raw data must be below the modulus: 2^2048 does not even fit the
     * frame, n fits but is not below itself, n - 1 is the largest value
     * (and, as -1, its own signature). */
    gcry_mpi_set_ui(m, 1);
    gcry_mpi_mul_2exp(m, m, 2048);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", m));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_sign(&sig, data, skey));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(good, data, pkey));
    gcry_sexp_release(data);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", n));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_sign(&sig, data, skey));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(good, data, pkey));
    gcry_sexp_release(data);
    gcry_mpi_sub_ui(m, n, 1);
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", m));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    s = param_mpi(sig, "s");
    ASSERT_NOT_NULL(s);
    ASSERT_EQ(0, gcry_mpi_cmp(s, m));
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_mpi_release(s);
    gcry_sexp_release(sig);
    gcry_sexp_release(data);

    gcry_mpi_release(m);
    gcry_mpi_release(n);
    gcry_sexp_release(good);
    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
}

TEST(rsa_pss_verify_corruptions)
{
    /* The encoded message of a 2048 bit key with SHA-256 and the default
     * 20 byte salt: DB = 202 zero bytes, 0x01, the salt (masked), then
     * H and the 0xBC trailer. */
    enum {
        HLEN = 32, SALTLEN = 20, EMLEN = 256, DBLEN = EMLEN - HLEN - 1,
        SEP = DBLEN - SALTLEN - 1
    };
    gcry_sexp_t skey = rsa_vector_key(1);
    gcry_sexp_t pkey = rsa_vector_key(0);
    gcry_sexp_t data = NULL;
    gcry_sexp_t sig = NULL;
    gcry_mpi_t n = hex_mpi(RSA_N);
    gcry_mpi_t e = gcry_mpi_set_ui(NULL, RSA_E_DEC);
    gcry_mpi_t s;
    gcry_mpi_t em_mpi = gcry_mpi_new(0);
    unsigned char em[EMLEN];
    unsigned char bad[EMLEN];
    unsigned char salt[SALTLEN];

    memset(salt, 0x5a, sizeof salt);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (random-override %b)"
                              " (hash sha256 #" RSA_DIGEST "#))",
                              (int)sizeof salt, salt));
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    gcry_sexp_release(data);
    s = param_mpi(sig, "s");
    gcry_sexp_release(sig);
    ASSERT_NOT_NULL(s);

    /* The public operation recovers the encoded message; signing it
     * again with raw RSA gives back a valid signature. */
    gcry_mpi_powm(em_mpi, s, e, n);
    ASSERT_TRUE(mpi_to_bytes(em_mpi, em, sizeof em));
    ASSERT_EQ(0xbc, em[EMLEN - 1]);
    ASSERT_EQ(0, em[0] & 0x80);
    ASSERT_OK(verify_pss_em(em, sizeof em, PSS_SHA256_DATA, skey, pkey));

    /* Wrong trailer byte. */
    memcpy(bad, em, sizeof em);
    bad[EMLEN - 1] ^= 0x01;
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(bad, sizeof bad, PSS_SHA256_DATA, skey, pkey));

    /* The high bit must be clear (0x80... is still below n = 0xB7...). */
    memcpy(bad, em, sizeof em);
    bad[0] = 0x80;
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(bad, sizeof bad, PSS_SHA256_DATA, skey, pkey));

    /* A flipped bit in the masked DB flips the same bit of PS. */
    memcpy(bad, em, sizeof em);
    bad[100] ^= 0x01;
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(bad, sizeof bad, PSS_SHA256_DATA, skey, pkey));

    /* The 0x01 separator turned into 0x00. */
    memcpy(bad, em, sizeof em);
    bad[SEP] ^= 0x01;
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(bad, sizeof bad, PSS_SHA256_DATA, skey, pkey));

    /* A changed salt byte gives another H. */
    memcpy(bad, em, sizeof em);
    bad[SEP + 1] ^= 0x01;
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(bad, sizeof bad, PSS_SHA256_DATA, skey, pkey));

    /* A changed H byte changes the mask, so PS is no longer zero. */
    memcpy(bad, em, sizeof em);
    bad[DBLEN] ^= 0x01;
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(bad, sizeof bad, PSS_SHA256_DATA, skey, pkey));

    /* A salt length other than the one signed with: the separator is
     * looked for in the salt (32) or found inside the padding (8). */
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(em, sizeof em,
                             "(data (flags pss) (salt-length 2:32)"
                             " (hash sha256 #" RSA_DIGEST "#))", skey, pkey));
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
               verify_pss_em(em, sizeof em,
                             "(data (flags pss) (salt-length 1:8)"
                             " (hash sha256 #" RSA_DIGEST "#))", skey, pkey));

    /* Parameters that cannot describe any frame of this size. */
    ASSERT_ERR(GPG_ERR_TOO_SHORT,
               verify_pss_em(em, sizeof em,
                             "(data (flags pss) (salt-length 3:300)"
                             " (hash sha256 #" RSA_DIGEST "#))", skey, pkey));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               verify_pss_em(em, sizeof em,
                             "(data (flags pss) (hash sha256 #0102#))", skey,
                             pkey));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               verify_pss_em(em, sizeof em,
                             "(data (flags pss) (hash md2 #" D20 "#))", skey,
                             pkey));

    gcry_mpi_release(s);
    gcry_mpi_release(em_mpi);
    gcry_mpi_release(e);
    gcry_mpi_release(n);
    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);

    /* With a 2049 bit modulus the frame has 257 bytes but the encoded
     * message only 256, so a leading zero byte is stripped on
     * verification; a frame with that byte set is too long. */
    skey = rsa_key_from_hex(RSA2049_N, RSA2049_D, RSA2049_P, RSA2049_Q, 1, 1);
    pkey = rsa_public_of(skey);
    ASSERT_NOT_NULL(pkey);
    ASSERT_EQ(2049, gcry_pk_get_nbits(skey));
    ASSERT_OK(gcry_pk_testkey(skey));
    data = sexp(PSS_SHA256_DATA);
    ASSERT_OK(gcry_pk_sign(&sig, data, skey));
    {
        size_t slen;
        void *sbuf = param_bytes(sig, "s", &slen);

        ASSERT_EQ(257, slen);
        gcry_free(sbuf);
    }
    ASSERT_OK(gcry_pk_verify(sig, data, pkey));
    gcry_sexp_release(sig);
    gcry_sexp_release(data);
    {
        unsigned char top[257];

        memset(top, 0, sizeof top);
        top[0] = 0x01; /* 2^2048, below n but longer than EM. */
        ASSERT_ERR(GPG_ERR_BAD_SIGNATURE,
                   verify_pss_em(top, sizeof top, PSS_SHA256_DATA, skey, pkey));
    }
    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
}

TEST(rsa_key_without_crt_values)
{
    gcry_sexp_t full = rsa_vector_key(1);
    gcry_sexp_t pub = rsa_vector_key(0);
    gcry_sexp_t no_u = rsa_key_from_hex(RSA_N, RSA_D, RSA_P, RSA_Q, 1, 0);
    gcry_sexp_t no_pq = rsa_key_from_hex(RSA_N, RSA_D, RSA_P, RSA_Q, 0, 0);
    gcry_sexp_t data = sexp(PKCS1_SHA256_DATA);
    gcry_sexp_t sig = NULL;
    gcry_sexp_t enc = NULL;
    gcry_sexp_t plain = NULL;
    gcry_mpi_t a;
    unsigned char grip_full[20];
    unsigned char grip[20];

    ASSERT_NOT_NULL(no_u);
    ASSERT_NOT_NULL(no_pq);
    ASSERT_FALSE(has_token(no_u, "u"));
    ASSERT_FALSE(has_token(no_pq, "p"));

    /* Without u the CRT coefficient is derived from p and q; without the
     * primes the plain private exponent is used.  Both give the known
     * signature. */
    ASSERT_OK(gcry_pk_sign(&sig, data, no_u));
    ASSERT_TRUE(param_is_hex(sig, "s", RSA_SIG));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);
    ASSERT_OK(gcry_pk_sign(&sig, data, no_pq));
    ASSERT_TRUE(param_is_hex(sig, "s", RSA_SIG));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
    gcry_sexp_release(sig);

    /* Decryption of the same ciphertext gives the message with every
     * form of the key. */
    ASSERT_OK(encrypt_text(&enc, "(data (flags pkcs1) (value 5:hello))", pub));
    a = param_mpi(enc, "a");
    ASSERT_NOT_NULL(a);
    gcry_sexp_release(enc);
    ASSERT_OK(gcry_sexp_build(&enc, NULL, "(enc-val (flags pkcs1) (rsa (a %m)))",
                              a));
    ASSERT_OK(gcry_pk_decrypt(&plain, enc, full));
    ASSERT_TRUE(param_is_hex(plain, "value", "68656c6c6f"));
    gcry_sexp_release(plain);
    ASSERT_OK(gcry_pk_decrypt(&plain, enc, no_u));
    ASSERT_TRUE(param_is_hex(plain, "value", "68656c6c6f"));
    gcry_sexp_release(plain);
    ASSERT_OK(gcry_pk_decrypt(&plain, enc, no_pq));
    ASSERT_TRUE(param_is_hex(plain, "value", "68656c6c6f"));
    gcry_sexp_release(plain);
    gcry_sexp_release(enc);
    gcry_mpi_release(a);

    /* The key check wants all of n, e, d, p, q and u, as in the reference
     * library; size and keygrip only depend on the public part. */
    ASSERT_OK(gcry_pk_testkey(full));
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_testkey(no_u));
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_pk_testkey(no_pq));
    ASSERT_EQ(2048, gcry_pk_get_nbits(no_u));
    ASSERT_EQ(2048, gcry_pk_get_nbits(no_pq));
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(full, grip_full));
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(no_u, grip));
    ASSERT_MEM_EQ(grip_full, grip, sizeof grip);
    ASSERT_NOT_NULL(gcry_pk_get_keygrip(no_pq, grip));
    ASSERT_MEM_EQ(grip_full, grip, sizeof grip);

    gcry_sexp_release(data);
    gcry_sexp_release(full);
    gcry_sexp_release(pub);
    gcry_sexp_release(no_u);
    gcry_sexp_release(no_pq);
}

/* Encrypt the number FRAME with raw ElGamal and decrypt the result as a
 * PKCS#1 block, which hands exactly FRAME (left padded to the key size)
 * to the block decoder. */
static gcry_error_t
elg_pkcs1_decrypt_frame(gcry_sexp_t *r_plain, const unsigned char *frame,
                        size_t framelen, gcry_sexp_t pub, gcry_sexp_t sec)
{
    gcry_mpi_t m = NULL;
    gcry_mpi_t a = NULL;
    gcry_mpi_t b = NULL;
    gcry_sexp_t data = NULL;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t enc = NULL;
    gcry_error_t err;

    *r_plain = NULL;
    err = gcry_mpi_scan(&m, GCRYMPI_FMT_USG, frame, framelen, NULL);

    if (!err) {
        err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", m);
    }

    if (!err) {
        err = gcry_pk_encrypt(&ciph, data, pub);
    }

    if (!err) {
        a = param_mpi(ciph, "a");
        b = param_mpi(ciph, "b");
        err = gcry_sexp_build(&enc, NULL,
                              "(enc-val (flags pkcs1) (elg (a %m) (b %m)))", a,
                              b);
    }

    if (!err) {
        err = gcry_pk_decrypt(r_plain, enc, sec);
    }

    gcry_sexp_release(enc);
    gcry_sexp_release(ciph);
    gcry_sexp_release(data);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(m);
    return err;
}

TEST(elgamal_crafted_ciphertexts)
{
    gcry_sexp_t key;
    gcry_sexp_t pub;
    gcry_sexp_t sec;
    gcry_sexp_t enc = NULL;
    gcry_sexp_t plain = NULL;
    gcry_mpi_t p;
    unsigned char frame[128];
    void *v;
    size_t vlen;

    if (gcry_fips_mode_active()) {
        /* ElGamal is refused before any ciphertext is looked at. */
        gcry_sexp_t bad = sexp("(private-key (elg (p #0b#) (g #02#) (y #04#)"
                               " (x #03#)))");

        ASSERT_ERR(GPG_ERR_PUBKEY_ALGO,
                   decrypt_text(&plain, "(enc-val (flags pkcs1)"
                                " (elg (a #00#) (b #05#)))", bad));
        ASSERT_NULL(plain);
        gcry_sexp_release(bad);
        return;
    }

    key = genkey("(genkey (elg (nbits 4:1024)))");
    ASSERT_NOT_NULL(key);
    pub = gcry_sexp_find_token(key, "public-key", 0);
    sec = gcry_sexp_find_token(key, "private-key", 0);
    p = param_mpi(sec, "p");
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(1024, gcry_mpi_get_nbits(p));

    /* A well formed block: 00 02, eight non-zero padding bytes, 00 and
     * the message. */
    memset(frame, 0xaa, sizeof frame);
    frame[0] = 0x00;
    frame[1] = 0x02;
    frame[10] = 0x00;
    memset(frame + 11, 'm', sizeof frame - 11);
    ASSERT_OK(elg_pkcs1_decrypt_frame(&plain, frame, sizeof frame, pub, sec));
    v = param_bytes(plain, "value", &vlen);
    ASSERT_EQ(sizeof frame - 11, vlen);
    ASSERT_MEM_EQ(frame + 11, v, vlen);
    gcry_free(v);
    gcry_sexp_release(plain);

    /* The number may have lost its leading zero byte, so a block that
     * starts with the type byte is accepted too. */
    frame[0] = 0x02;
    frame[1] = 0xaa;
    ASSERT_OK(elg_pkcs1_decrypt_frame(&plain, frame, sizeof frame, pub, sec));
    v = param_bytes(plain, "value", &vlen);
    ASSERT_EQ(sizeof frame - 11, vlen);
    ASSERT_MEM_EQ(frame + 11, v, vlen);
    gcry_free(v);
    gcry_sexp_release(plain);

    /* Block type 1 (a signature block) is not an encryption block. */
    frame[0] = 0x00;
    frame[1] = 0x01;
    ASSERT_ERR(GPG_ERR_ENCODING_PROBLEM,
               elg_pkcs1_decrypt_frame(&plain, frame, sizeof frame, pub, sec));
    ASSERT_NULL(plain);

    /* Only seven padding bytes before the separator. */
    frame[1] = 0x02;
    frame[9] = 0x00;
    frame[10] = 0xaa;
    ASSERT_ERR(GPG_ERR_ENCODING_PROBLEM,
               elg_pkcs1_decrypt_frame(&plain, frame, sizeof frame, pub, sec));

    /* No separator at all. */
    memset(frame + 2, 0xaa, sizeof frame - 2);
    ASSERT_ERR(GPG_ERR_ENCODING_PROBLEM,
               elg_pkcs1_decrypt_frame(&plain, frame, sizeof frame, pub, sec));

    /* a = 0 and a = p have no inverse modulo p, whatever the encoding. */
    ASSERT_ERR(GPG_ERR_INV_DATA,
               decrypt_text(&plain, "(enc-val (flags pkcs1)"
                            " (elg (a #00#) (b #05#)))", sec));
    ASSERT_ERR(GPG_ERR_INV_DATA,
               decrypt_text(&plain, "(enc-val (elg (a #00#) (b #05#)))", sec));
    ASSERT_OK(gcry_sexp_build(&enc, NULL,
                              "(enc-val (flags pkcs1) (elg (a %m) (b #05#)))",
                              p));
    ASSERT_ERR(GPG_ERR_INV_DATA, gcry_pk_decrypt(&plain, enc, sec));
    ASSERT_NULL(plain);
    gcry_sexp_release(enc);

    gcry_mpi_release(p);
    gcry_sexp_release(pub);
    gcry_sexp_release(sec);
    gcry_sexp_release(key);
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(keygrips);
    RUN_TEST(rsa_known_signature);
    RUN_TEST(rsa_sign_modes);
    RUN_TEST(rsa_encrypt_decrypt);
    RUN_TEST(rsa_keygen);
    RUN_TEST(rsa_testkey_detects_corruption);
    RUN_TEST(dsa);
    RUN_TEST(elgamal);
    RUN_TEST(ecdsa_rfc6979_vector);
    RUN_TEST(ecc_keygen_and_ecdh);
    RUN_TEST(ed25519_vectors);
    RUN_TEST(ed25519_keygen_and_ed448);
    RUN_TEST(curve25519);
    RUN_TEST(names_and_info);
    RUN_TEST(curve_queries);
    RUN_TEST(algo_info_and_ctl);
    RUN_TEST(rsa_genkey_flags);
    RUN_TEST(dsa_parameters);
    RUN_TEST(dsa_data_errors);
    RUN_TEST(hash_sign_templates);
    RUN_TEST(rsa_data_errors);
    RUN_TEST(elgamal_edge_cases);
    RUN_TEST(ecc_genkey_variants);
    RUN_TEST(ecc_data_errors);
    RUN_TEST(eddsa_data_errors);
    RUN_TEST(key_sexp_errors);
    RUN_TEST(genkey_flag_variants);
    RUN_TEST(dsa_more_data_handling);
    RUN_TEST(rsa_more_data_handling);
    RUN_TEST(ecc_more_data_handling);
    RUN_TEST(rsa_encoding_vectors);
    RUN_TEST(rsa_genkey_rules);
    RUN_TEST(elgamal_encodings);
    RUN_TEST(dsa_sizes);
    RUN_TEST(ecc_sm2_and_curve_rules);
    RUN_TEST(rsa_pkcs1_verify_mismatch);
    RUN_TEST(rsa_pss_verify_corruptions);
    RUN_TEST(rsa_key_without_crt_values);
    RUN_TEST(elgamal_crafted_ciphertexts);
    RUN_TEST(disable_algorithm);
    RUN_TEST(null_arguments);
    return TEST_RESULT();
}
