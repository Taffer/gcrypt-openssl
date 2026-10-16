/*
 * ecc-curves.c - Table of the elliptic curves known to the gcrypt API.
 *
 * The domain parameters are the public constants from the respective
 * standards (NIST FIPS 186, RFC 5639, RFC 7748/8032, GOST R 34.10, SEC 2,
 * GB/T 32918).  Weierstrass curves are handed to OpenSSL as EC_GROUPs,
 * either by their well known NID or built from the explicit parameters.
 */
#include "gcrypt-int.h"

#include <string.h>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static const struct gcry_ecc_curve curves[] = {
    {
        "Ed25519", 255, 1, GCRY_ECC_MODEL_EDWARDS,
        GCRY_ECC_DIALECT_ED25519, NID_undef, "ED25519",
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "ED",
        "-0x01",
        "-0x2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA68"
        "74A",
        "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3"
        "ED",
        "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D5"
        "1A",
        "0x66666666666666666666666666666666666666666666666666666666666666"
        "58",
        8
    },
    {
        "Curve25519", 255, 0, GCRY_ECC_MODEL_MONTGOMERY,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, "X25519",
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "ED",
        "0x01DB41",
        "0x01",
        "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3"
        "ED",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "09",
        "0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3"
        "D9",
        8
    },
    {
        "Ed448", 448, 1, GCRY_ECC_MODEL_EDWARDS,
        GCRY_ECC_DIALECT_SAFECURVE, NID_undef, "ED448",
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "0x01",
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756",
        "0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23"
        "E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3",
        "0x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A4"
        "6412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E",
        "0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2"
        "D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14",
        4
    },
    {
        "X448", 448, 0, GCRY_ECC_MODEL_MONTGOMERY,
        GCRY_ECC_DIALECT_SAFECURVE, NID_undef, "X448",
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "0x98A9",
        "0x01",
        "0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23"
        "E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000005",
        "0x7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC28DF3F6"
        "EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A",
        4
    },
    {
        "NIST P-192", 192, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_X9_62_prime192v1, NULL,
        "0xfffffffffffffffffffffffffffffffeffffffffffffffff",
        "0xfffffffffffffffffffffffffffffffefffffffffffffffc",
        "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
        "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",
        "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
        "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
        1
    },
    {
        "NIST P-224", 224, 1, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_secp224r1, NULL,
        "0xffffffffffffffffffffffffffffffff000000000000000000000001",
        "0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
        "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
        "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
        1
    },
    {
        "NIST P-256", 256, 1, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_X9_62_prime256v1, NULL,
        "0xffffffff00000001000000000000000000000000ffffffffffffffffffffff"
        "ff",
        "0xffffffff00000001000000000000000000000000ffffffffffffffffffffff"
        "fc",
        "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d260"
        "4b",
        "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325"
        "51",
        "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2"
        "96",
        "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51"
        "f5",
        1
    },
    {
        "NIST P-384", 384, 1, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_secp384r1, NULL,
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "feffffffff0000000000000000ffffffff",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "feffffffff0000000000000000fffffffc",
        "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f501387"
        "5ac656398d8a2ed19d2a85c8edd3ec2aef",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372d"
        "df581a0db248b0a77aecec196accc52973",
        "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a"
        "385502f25dbf55296c3a545e3872760ab7",
        "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8"
        "c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        1
    },
    {
        "NIST P-521", 521, 1, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_secp521r1, NULL,
        "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffff",
        "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffc",
        "0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef"
        "109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b5"
        "03f00",
        "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91"
        "386409",
        "0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b"
        "4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2"
        "e5bd66",
        "0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd1727"
        "3e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769f"
        "d16650",
        1
    },
    {
        "brainpoolP160r1", 160, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_brainpoolP160r1, NULL,
        "0xe95e4a5f737059dc60dfc7ad95b3d8139515620f",
        "0x340e7be2a280eb74e2be61bada745d97e8f7c300",
        "0x1e589a8595423412134faa2dbdec95c8d8675e58",
        "0xe95e4a5f737059dc60df5991d45029409e60fc09",
        "0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3",
        "0x1667cb477a1a8ec338f94741669c976316da6321",
        1
    },
    {
        "brainpoolP192r1", 192, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_brainpoolP192r1, NULL,
        "0xc302f41d932a36cda7a3463093d18db78fce476de1a86297",
        "0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
        "0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
        "0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
        "0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
        "0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
        1
    },
    {
        "brainpoolP224r1", 224, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_brainpoolP224r1, NULL,
        "0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
        "0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
        "0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
        "0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
        "0x0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
        "0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
        1
    },
    {
        "brainpoolP256r1", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_brainpoolP256r1, NULL,
        "0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e53"
        "77",
        "0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5"
        "d9",
        "0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07"
        "b6",
        "0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856"
        "a7",
        "0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace32"
        "62",
        "0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f0469"
        "97",
        1
    },
    {
        "brainpoolP320r1", 320, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_brainpoolP320r1, NULL,
        "0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec"
        "28fcd412b1f1b32e27",
        "0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9"
        "f492f375a97d860eb4",
        "0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539"
        "816f5eb4ac8fb1f1a6",
        "0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658"
        "e98691555b44c59311",
        "0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599"
        "c710af8d0d39e20611",
        "0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6a"
        "c7d35245d1692e8ee1",
        1
    },
    {
        "brainpoolP384r1", 384, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_brainpoolP384r1, NULL,
        "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb711"
        "23acd3a729901d1a71874700133107ec53",
        "0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f9"
        "0f8aa5814a503ad4eb04a8c7dd22ce2826",
        "0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62"
        "d57cb4390295dbc9943ab78696fa504c11",
        "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425"
        "a7cf3ab6af6b7fc3103b883202e9046565",
        "0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10"
        "e8e826e03436d646aaef87b2e247d4af1e",
        "0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129"
        "280e4646217791811142820341263c5315",
        1
    },
    {
        "brainpoolP512r1", 512, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_brainpoolP512r1, NULL,
        "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308"
        "717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48"
        "f3",
        "0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863"
        "bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94"
        "ca",
        "0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117"
        "a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f7"
        "23",
        "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308"
        "70553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca900"
        "69",
        "0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d009"
        "8eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f8"
        "22",
        "0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f81"
        "11b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad808"
        "92",
        1
    },
    {
        "GOST2001-test", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0x80000000000000000000000000000000000000000000000000000000000004"
        "31",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "07",
        "0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b"
        "7e",
        "0x8000000000000000000000000000000150fe8a1892976154c59cfc193accf5"
        "b3",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "02",
        "0x08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8f"
        "c8",
        1
    },
    {
        "GOST2001-CryptoPro-A", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"
        "97",
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"
        "94",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "a6",
        "0xffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b8"
        "93",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "01",
        "0x8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e"
        "14",
        1
    },
    {
        "GOST2001-CryptoPro-B", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0x8000000000000000000000000000000000000000000000000000000000000c"
        "99",
        "0x8000000000000000000000000000000000000000000000000000000000000c"
        "96",
        "0x3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc"
        "8b",
        "0x800000000000000000000000000000015f700cfff1a624e5e497161bcc8a19"
        "8f",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "01",
        "0x3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717e"
        "fc",
        1
    },
    {
        "GOST2001-CryptoPro-C", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d75"
        "9b",
        "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d75"
        "98",
        "0x00000000000000000000000000000000000000000000000000000000000080"
        "5a",
        "0x9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980b"
        "b9",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "00",
        "0x41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb"
        "67",
        1
    },
    {
        "GOST2012-256-A", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"
        "97",
        "0xc2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e73"
        "35",
        "0x295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae95"
        "13",
        "0x400000000000000000000000000000000fd8cddfc87b6635c115af556c360c"
        "67",
        "0x91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa"
        "28",
        "0x32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e"
        "5c",
        4
    },
    {
        "GOST2012-512-test", 511, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0x4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d1"
        "5df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be63"
        "73",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "07",
        "0x1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac"
        "4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302a"
        "dc",
        "0x4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d1"
        "5da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6"
        "df",
        "0x24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd7"
        "62fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a"
        "9a",
        "0x2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b"
        "2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add37"
        "1e",
        1
    },
    {
        "GOST2012-512-tc26-A", 512, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"
        "c7",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"
        "c4",
        "0xe8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b62"
        "65ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c7"
        "60",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b2"
        "75",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "03",
        "0x7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa9"
        "21df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2"
        "a4",
        1
    },
    {
        "GOST2012-512-tc26-B", 512, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0x80000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "6f",
        "0x80000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "6c",
        "0x687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b28"
        "9f3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c51401"
        "16",
        "0x80000000000000000000000000000000000000000000000000000000000000"
        "0149a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25"
        "bd",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "02",
        "0x1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec73"
        "35dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41"
        "bd",
        1
    },
    {
        "GOST2012-512-tc26-C", 512, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_undef, NULL,
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"
        "c7",
        "0xdc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e14306"
        "4546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689b"
        "d3",
        "0xb4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ad"
        "e038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557"
        "e1",
        "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023"
        "ed",
        "0xe2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea04"
        "3aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c19501"
        "48",
        "0xf5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff"
        "9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc4"
        "0f",
        4
    },
    {
        "secp256k1", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_secp256k1, NULL,
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC"
        "2F",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "00",
        "0x00000000000000000000000000000000000000000000000000000000000000"
        "07",
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD03641"
        "41",
        "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817"
        "98",
        "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4"
        "B8",
        1
    },
    {
        "sm2p256v1", 256, 0, GCRY_ECC_MODEL_WEIERSTRASS,
        GCRY_ECC_DIALECT_STANDARD, NID_sm2, NULL,
        "0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffff"
        "ff",
        "0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffff"
        "fc",
        "0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e"
        "93",
        "0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d541"
        "23",
        "0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74"
        "c7",
        "0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0"
        "a0",
        1
    },
};

static const struct {
    const char *name;
    const char *other;
} curve_aliases[] = {
    { "Ed25519", "1.3.6.1.4.1.11591.15.1" },
    { "Ed25519", "1.3.101.112" },
    { "Curve25519", "1.3.6.1.4.1.3029.1.5.1" },
    { "Curve25519", "1.3.101.110" },
    { "Curve25519", "X25519" },
    { "Ed448", "1.3.101.113" },
    { "X448", "1.3.101.111" },
    { "NIST P-192", "1.2.840.10045.3.1.1" },
    { "NIST P-192", "prime192v1" },
    { "NIST P-192", "secp192r1" },
    { "NIST P-192", "nistp192" },
    { "NIST P-224", "secp224r1" },
    { "NIST P-224", "1.3.132.0.33" },
    { "NIST P-224", "nistp224" },
    { "NIST P-256", "1.2.840.10045.3.1.7" },
    { "NIST P-256", "prime256v1" },
    { "NIST P-256", "secp256r1" },
    { "NIST P-256", "nistp256" },
    { "NIST P-384", "secp384r1" },
    { "NIST P-384", "1.3.132.0.34" },
    { "NIST P-384", "nistp384" },
    { "NIST P-521", "secp521r1" },
    { "NIST P-521", "1.3.132.0.35" },
    { "NIST P-521", "nistp521" },
    { "brainpoolP160r1", "1.3.36.3.3.2.8.1.1.1" },
    { "brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3" },
    { "brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5" },
    { "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7" },
    { "brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9" },
    { "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11" },
    { "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13" },
    { "brainpoolP256r1", "bp256" },
    { "brainpoolP384r1", "bp384" },
    { "brainpoolP512r1", "bp512" },
    { "GOST2001-test", "1.2.643.2.2.35.0" },
    { "GOST2001-CryptoPro-A", "1.2.643.2.2.35.1" },
    { "GOST2001-CryptoPro-B", "1.2.643.2.2.35.2" },
    { "GOST2001-CryptoPro-C", "1.2.643.2.2.35.3" },
    { "GOST2001-CryptoPro-A", "GOST2001-CryptoPro-XchA" },
    { "GOST2001-CryptoPro-C", "GOST2001-CryptoPro-XchB" },
    { "GOST2001-CryptoPro-A", "1.2.643.2.2.36.0" },
    { "GOST2001-CryptoPro-C", "1.2.643.2.2.36.1" },
    { "GOST2012-256-tc26-A", "1.2.643.7.1.2.1.1.1" },
    { "GOST2001-CryptoPro-A", "1.2.643.7.1.2.1.1.2" },
    { "GOST2001-CryptoPro-A", "GOST2012-256-tc26-B" },
    { "GOST2001-CryptoPro-B", "1.2.643.7.1.2.1.1.3" },
    { "GOST2001-CryptoPro-B", "GOST2012-256-tc26-C" },
    { "GOST2001-CryptoPro-C", "1.2.643.7.1.2.1.1.4" },
    { "GOST2001-CryptoPro-C", "GOST2012-256-tc26-D" },
    { "GOST2012-512-test", "GOST2012-test" },
    { "GOST2012-512-test", "1.2.643.7.1.2.1.2.0" },
    { "GOST2012-512-tc26-A", "GOST2012-tc26-A" },
    { "GOST2012-512-tc26-B", "GOST2012-tc26-B" },
    { "GOST2012-512-tc26-A", "1.2.643.7.1.2.1.2.1" },
    { "GOST2012-512-tc26-B", "1.2.643.7.1.2.1.2.2" },
    { "GOST2012-512-tc26-C", "1.2.643.7.1.2.1.2.3" },
    { "secp256k1", "1.3.132.0.10" },
    { "sm2p256v1", "1.2.156.10197.1.301" },
};

size_t
_gcry_ecc_curve_count(void)
{
    return DIM(curves);
}

const struct gcry_ecc_curve *
_gcry_ecc_curve_by_index(size_t idx)
{
    return idx < DIM(curves) ? &curves[idx] : NULL;
}

/* Find a curve by its canonical name or one of its aliases (names, OIDs).
 * Returns NULL if unknown. */
const struct gcry_ecc_curve *
_gcry_ecc_curve_find(const char *name)
{
    size_t i;

    if (!name) {
        return NULL;
    }

    for (i = 0; i < DIM(curves); i++) {
        if (!strcmp(curves[i].name, name)) {
            return &curves[i];
        }
    }

    for (i = 0; i < DIM(curve_aliases); i++) {
        if (!strcmp(curve_aliases[i].other, name)) {
            return _gcry_ecc_curve_find(curve_aliases[i].name);
        }
    }

    return NULL;
}

/* Find a curve by the size of its field: used when only "nbits" is given
 * to genkey.  Only NIST curves are considered, like upstream. */
const struct gcry_ecc_curve *
_gcry_ecc_curve_by_nbits(unsigned int nbits)
{
    size_t i;

    for (i = 0; i < DIM(curves); i++) {
        if (curves[i].nbits == nbits
            && !strncmp(curves[i].name, "NIST P-", 7)) {
            return &curves[i];
        }
    }

    return NULL;
}

static BIGNUM *
bn_from_hex(const char *s)
{
    BIGNUM *bn = NULL;
    int negative = 0;

    if (*s == '-') {
        negative = 1;
        s++;
    }

    if (s[0] == '0' && s[1] == 'x') {
        s += 2;
    }

    if (BN_hex2bn(&bn, s) <= 0) {
        BN_free(bn);
        return NULL;
    }

    BN_set_negative(bn, negative);
    return bn;
}

/* The domain parameter NAME ("p", "a", "b", "n", "h", "g.x", "g.y") of
 * CURVE as a new MPI.  Negative constants (Ed25519's a = -1) are
 * reduced modulo p. */
gcry_mpi_t
_gcry_ecc_curve_param(const struct gcry_ecc_curve *curve, const char *name)
{
    const char *hex = NULL;
    BIGNUM *bn;

    if (!strcmp(name, "p")) {
        hex = curve->p;
    } else if (!strcmp(name, "a")) {
        hex = curve->a;
    } else if (!strcmp(name, "b")) {
        hex = curve->b;
    } else if (!strcmp(name, "n")) {
        hex = curve->n;
    } else if (!strcmp(name, "g.x")) {
        hex = curve->gx;
    } else if (!strcmp(name, "g.y")) {
        hex = curve->gy;
    } else if (!strcmp(name, "h")) {
        gcry_mpi_t m = _gcry_mpi_alloc(0);

        gcry_mpi_set_ui(m, curve->h);
        return m;
    } else {
        return NULL;
    }

    bn = bn_from_hex(hex);

    if (!bn) {
        ERR_clear_error();
        return NULL;
    }

    if (BN_is_negative(bn)) {
        BIGNUM *p = bn_from_hex(curve->p);
        BN_CTX *ctx = BN_CTX_new_ex(_gcry_libctx());

        if (!p || !ctx || !BN_nnmod(bn, bn, p, ctx)) {
            ERR_clear_error();
            BN_free(p);
            BN_CTX_free(ctx);
            BN_free(bn);
            return NULL;
        }

        BN_free(p);
        BN_CTX_free(ctx);
    }

    return _gcry_mpi_new_from_bn(bn, 0);
}

/* A new EC_GROUP for a Weierstrass curve, or NULL (with the OpenSSL error
 * queue cleared) for curves OpenSSL cannot represent this way. */
EC_GROUP *
_gcry_ecc_curve_group(const struct gcry_ecc_curve *curve)
{
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *n = NULL;
    BIGNUM *gx = NULL;
    BIGNUM *gy = NULL;
    BIGNUM *h = NULL;
    EC_POINT *g = NULL;

    if (curve->model != GCRY_ECC_MODEL_WEIERSTRASS) {
        return NULL;
    }

    if (curve->nid != NID_undef) {
        group = EC_GROUP_new_by_curve_name_ex(_gcry_libctx(), _gcry_propq(),
                                              curve->nid);

        if (group) {
            return group;
        }

        ERR_clear_error();
    }

    ctx = BN_CTX_new_ex(_gcry_libctx());
    p = bn_from_hex(curve->p);
    a = bn_from_hex(curve->a);
    b = bn_from_hex(curve->b);
    n = bn_from_hex(curve->n);
    gx = bn_from_hex(curve->gx);
    gy = bn_from_hex(curve->gy);
    h = BN_new();

    if (!ctx || !p || !a || !b || !n || !gx || !gy || !h
        || !BN_set_word(h, curve->h)) {
        goto leave;
    }

    group = EC_GROUP_new_curve_GFp(p, a, b, ctx);

    if (!group) {
        goto leave;
    }

    g = EC_POINT_new(group);

    if (!g || !EC_POINT_set_affine_coordinates(group, g, gx, gy, ctx)
        || !EC_GROUP_set_generator(group, g, n, h)) {
        EC_GROUP_free(group);
        group = NULL;
        goto leave;
    }

    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);

leave:
    ERR_clear_error();
    EC_POINT_free(g);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(n);
    BN_free(gx);
    BN_free(gy);
    BN_free(h);
    BN_CTX_free(ctx);
    return group;
}

/* Identify the curve of an existing EC_GROUP by its domain parameters.
 * Returns NULL if no known Weierstrass curve has them.  The parameters are
 * compared as numbers: EC_GROUP_cmp cannot compare the generators of
 * groups with different internal representations, which OpenSSL's
 * optimised implementations of the NIST curves have. */
const struct gcry_ecc_curve *
_gcry_ecc_curve_from_group(const EC_GROUP *group)
{
    static const char *const names[] = {
        "p", "a", "b", "g.x", "g.y", "n", "h"
    };
    const struct gcry_ecc_curve *found = NULL;
    const EC_POINT *g;
    BIGNUM *values[DIM(names)];
    BN_CTX *ctx;
    size_t i;
    size_t j;
    int nid;

    if (!group) {
        return NULL;
    }

    nid = EC_GROUP_get_curve_name(group);

    if (nid != NID_undef) {
        for (i = 0; i < DIM(curves); i++) {
            if (curves[i].nid == nid) {
                return &curves[i];
            }
        }
    }

    ctx = BN_CTX_new_ex(_gcry_libctx());

    if (!ctx) {
        return NULL;
    }

    BN_CTX_start(ctx);

    for (i = 0; i < DIM(values); i++) {
        values[i] = BN_CTX_get(ctx);
    }

    g = EC_GROUP_get0_generator(group);

    if (!values[DIM(values) - 1] || !g
        || !EC_GROUP_get_curve(group, values[0], values[1], values[2], ctx)
        || !EC_POINT_get_affine_coordinates(group, g, values[3], values[4],
                                            ctx)
        || !BN_copy(values[5], EC_GROUP_get0_order(group))
        || !BN_copy(values[6], EC_GROUP_get0_cofactor(group))) {
        goto leave;
    }

    for (i = 0; i < DIM(curves) && !found; i++) {
        int same = curves[i].model == GCRY_ECC_MODEL_WEIERSTRASS;

        for (j = 0; same && j < DIM(names); j++) {
            gcry_mpi_t t = _gcry_ecc_curve_param(&curves[i], names[j]);

            same = t && !BN_cmp(_gcry_mpi_bn(t), values[j]);
            gcry_mpi_release(t);
        }

        if (same) {
            found = &curves[i];
        }
    }

leave:
    ERR_clear_error();
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return found;
}
