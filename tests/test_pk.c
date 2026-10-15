/* Tests of the public key API (gcry_pk_*). */
#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"
#include "test_pk_rsa_vector.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

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
    ASSERT_ERR(GPG_ERR_BAD_SIGNATURE, gcry_pk_verify(sig, bad, pkey));
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
    gcry_sexp_t key = genkey("(genkey (rsa (nbits 4:2048) (rsa-use-e 1:3)))");
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
    ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 3));
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
    gcry_sexp_t key = genkey("(genkey (dsa (nbits 4:2048) (qbits 3:256)))");
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
    gcry_sexp_t key = genkey("(genkey (elg (nbits 4:1024)))");
    gcry_sexp_t priv;
    gcry_sexp_t pub;
    gcry_sexp_t data = NULL;
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t sig = NULL;
    gcry_mpi_t m;
    gcry_mpi_t p;
    gcry_mpi_t factor;

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
    ASSERT_NOT_NULL(gcry_sexp_find_token(ciph, "elg", 0));
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
    ASSERT_NOT_NULL(gcry_sexp_find_token(sig, "elg", 0));
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
    ASSERT_NOT_NULL(gcry_sexp_find_token(sig, "ecdsa", 0));
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
    gcry_sexp_release(pub);
    gcry_sexp_release(key);

    /* A GOST curve has no OpenSSL NID but works from explicit params. */
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
        ASSERT_NOT_NULL(gcry_sexp_find_token(sig, "eddsa", 0));
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

    /* Ed25519ctx and Ed25519ph. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags eddsa) (label %s) (value %s))", "ctx", "msg"));
    ASSERT_OK(gcry_pk_sign(&sig, data, priv));
    ASSERT_OK(gcry_pk_verify(sig, data, pub));
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
    ASSERT_NOT_NULL(gcry_sexp_find_token(sig, "eddsa", 0));
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
    ASSERT_OK(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, result, scalar, point));
    ASSERT_TRUE(bytes_eq_hex(result, 32, X25519_V1_OUT));
    hex_to_bytes(X25519_ALICE_SK, scalar);
    ASSERT_OK(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, result, scalar, NULL));
    ASSERT_TRUE(bytes_eq_hex(result, 32, X25519_ALICE_PK));
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_ecc_mul_point(7, result, scalar, NULL));

    /* ECDH through gcry_pk_encrypt: Alice's scalar against Bob's key. */
    pkey = sexp("(public-key (ecc (curve Curve25519) (flags djb-tweak)"
                " (q #40" X25519_BOB_PK "#)))");
    skey = sexp("(private-key (ecc (curve Curve25519) (flags djb-tweak)"
                " (q #40" X25519_BOB_PK "#) (d #" X25519_BOB_SK "#)))");
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
    hex_to_bytes(X25519_BOB_SK, scalar);

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
    ASSERT_EQ(GCRY_PK_DSA, gcry_pk_map_name("dsa"));
    ASSERT_EQ(GCRY_PK_ELG, gcry_pk_map_name("elg"));
    ASSERT_EQ(GCRY_PK_ELG, gcry_pk_map_name("openpgp-elg-sig"));
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
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_test_algo(4711));
    n = GCRY_PK_USAGE_ENCR;
    ASSERT_ERR(GPG_ERR_PUBKEY_ALGO, gcry_pk_algo_info(GCRY_PK_DSA,
                                                      GCRYCTL_TEST_ALGO, NULL, &n));
    n = GCRY_PK_USAGE_SIGN;
    ASSERT_OK(gcry_pk_algo_info(GCRY_PK_DSA, GCRYCTL_TEST_ALGO, NULL, &n));
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
    ASSERT_STR_EQ("brainpoolP256r1", gcry_pk_get_curve(key, 0, NULL));
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
    return TEST_RESULT();
}
