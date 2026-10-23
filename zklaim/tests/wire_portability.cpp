// Cross-architecture protocol fixture. The RFC 8032 key and nonce below are
// public test material and must never be used to issue or request real credentials.
#include <fstream>
#include <iterator>
#include <memory>
#include <vector>
#include <cstring>
extern "C" {
#include <zklaim/zklaim.h>
}

static unsigned char test_key[64] = {
    0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
    0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a,
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
    0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
};
static const zklaim_predicate policy = {
    {UINT64_C(0x0102030405060708), UINT64_C(0x8877665544332211), UINT64_MAX,
     UINT64_C(0x8000000000000000), 42},
    {zklaim_eq, zklaim_eq, zklaim_eq, zklaim_eq, zklaim_eq}
};
// Every byte differs and the top and bottom bits are set, so byte-order or
// bit-order mistakes in the public input change the statement.
static const unsigned char test_nonce[ZKLAIM_NONCE_SIZE] = {
    0x80,0x01,0xfe,0x7f,0x02,0xfd,0x40,0xbf,0x03,0xfc,0x20,0xdf,0x04,0xfb,0x10,0xef,
    0x05,0xfa,0x08,0xf7,0x06,0xf9,0x55,0xaa,0x07,0xf8,0x33,0xcc,0x09,0xf6,0x0f,0xf1
};

static std::vector<unsigned char> read_file(const char *path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), {});
}

static bool write_file(const char *path, const unsigned char *data, size_t size) {
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char *>(data), size);
    return file.good();
}

// usage: wire_portability issue|verify <presentation> <verification key>
int main(int argc, char **argv) {
    if (argc != 4) return 1;
    gcry_check_version(GCRYPT_VERSION);
    std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)> ctx(zklaim_context_new(), zklaim_ctx_free);
    if (!ctx) return 2;
    if (strcmp(argv[1], "issue") == 0) {
        gcry_sexp_t priv = nullptr;
        if (zklaim_buf2pk(test_key, sizeof(test_key), &priv)) return 3;
        zklaim_payload pl = {};
        memcpy(pl.data_ref, policy.data_ref, sizeof(pl.data_ref));
        memcpy(pl.data_op, policy.data_op, sizeof(pl.data_op));
        for (uint8_t i = 0; i < 5; ++i) zklaim_set_attr(&pl, policy.data_ref[i], i);
        memcpy(ctx->pub_key, test_key, 32);
        zklaim_add_pl(ctx.get(), pl);
        zklaim_hash_ctx(ctx.get());
        unsigned char *pk = nullptr, *vk = nullptr;
        size_t pk_size = 0, vk_size = 0;
        const int result = zklaim_trusted_setup(1, &pk, &pk_size, &vk, &vk_size) ||
                           zklaim_ctx_sign(ctx.get(), priv) ||
                           zklaim_proof_generate(ctx.get(), pk, pk_size, test_nonce);
        std::unique_ptr<unsigned char, decltype(&free)> pk_storage(pk, free), vk_storage(vk, free);
        gcry_sexp_release(priv);
        if (result) return 4;
        unsigned char *data = nullptr;
        const size_t size = zklaim_ctx_serialize(ctx.get(), &data);
        std::unique_ptr<unsigned char, decltype(&free)> storage(data, free);
        if (size == 0) return 5;
        return write_file(argv[2], data, size) && write_file(argv[3], vk, vk_size) ? 0 : 6;
    }
    if (strcmp(argv[1], "verify") == 0) {
        auto data = read_file(argv[2]);
        const auto vk = read_file(argv[3]);
        if (data.empty() || vk.empty()) return 7;
        if (zklaim_ctx_deserialize(ctx.get(), data.data(), data.size()) ||
            zklaim_ctx_verify(ctx.get(), test_key, vk.data(), vk.size(), &policy, 1, test_nonce)) return 8;
        unsigned char *encoded = nullptr;
        const size_t size = zklaim_ctx_serialize(ctx.get(), &encoded);
        std::unique_ptr<unsigned char, decltype(&free)> storage(encoded, free);
        if (size != data.size() || encoded == nullptr || memcmp(data.data(), encoded, size) != 0) return 9;
        return 0;
    }
    return 10;
}
