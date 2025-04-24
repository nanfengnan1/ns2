// threshold_rsa.cc
#include "threshold_rsa.h"
#include "tclcl.h"
#include <vector>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include<address.h>
#include<cmu-trace.h>
// 兼容OpenSSL 1.1.1及以下版本
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/rsa.h>
// 添加包头注册代码
int hdr_threshold_rsa::offset_;
static int EVP_PKEY_get_bn_param(const EVP_PKEY* pkey, const char* param, BIGNUM** bn) {
    const RSA* rsa = EVP_PKEY_get0_RSA((EVP_PKEY*)pkey);
    if (!rsa) return 0;
    if (strcmp(param, "n") == 0) {
        *bn = BN_dup(RSA_get0_n(rsa));
    } else if (strcmp(param, "e") == 0) {
        *bn = BN_dup(RSA_get0_e(rsa));
    } else {
        return 0;
    }
    return *bn != NULL;
}
#endif
static class ThresholdRSA_AgentClass : public TclClass {
public:
    ThresholdRSA_AgentClass() : TclClass("Agent/ThresholdRSA") {}
    TclObject* create(int, const char*const*) {
        return new ThresholdRSA_Agent();
    }
} class_threshold_rsa_agent;

ThresholdRSA_Agent::ThresholdRSA_Agent() : Agent(PT_UDP),
    node_id_(0), N_(0), T_(0), pkey_(NULL), bn_ctx_(BN_CTX_new()) {
    bind("node_id_", &node_id_);
    bind("N_", &N_);
    bind("T_", &T_);
    bind("packetSize_",&size_);
    if (!bn_ctx_) {
        fprintf(stderr, "BN_CTX_new() failed\n");
        exit(EXIT_FAILURE);
    }
}

ThresholdRSA_Agent::~ThresholdRSA_Agent() {
    if (pkey_) {
        EVP_PKEY_free(pkey_);
    }
    if (bn_ctx_) {
        BN_CTX_free(bn_ctx_);
    }
}
int ThresholdRSA_Agent::command(int argc, const char*const* argv) {
    if (argc == 5 && !strcmp(argv[1], "init")) {
        init(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        return TCL_OK;
    }
    if (argc == 3 && !strcmp(argv[1], "sign")) {
        generate_partial_signature(argv[2]);
        return TCL_OK;
    }
    return Agent::command(argc, argv);
}

void ThresholdRSA_Agent::init(int node_id, int N, int T) {
    node_id_ = node_id;
    N_ = N;
    T_ = T;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        Tcl::instance().result("Key context creation failed");
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        Tcl::instance().result("Set key bits failed");
        return;
    }

    if (EVP_PKEY_keygen(ctx, &pkey_) <= 0) {
                                                          EVP_PKEY_CTX_free(ctx);
        Tcl::instance().result("Key generation failed");
        return;
    }
    EVP_PKEY_CTX_free(ctx);
}
// 在任意函数外添加包头注册
static class ThresholdRSAHeaderClass : public PacketHeaderClass {
public:
    ThresholdRSAHeaderClass() : PacketHeaderClass("PacketHeader/ThresholdRSA",
                                                 sizeof(hdr_threshold_rsa)) {
        bind_offset(&hdr_threshold_rsa::offset_);
    }
} class_threshold_rsa_hdr;
void ThresholdRSA_Agent::generate_partial_signature(const char* message) {
    // 输入验证
    if (!message || strlen(message) == 0) {
        Tcl::instance().result("Invalid message");
        return;
    }
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        Tcl::instance().result("Failed to create EVP context");
        return;
    }

    // 初始化签名上下文
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey_) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        Tcl::instance().result("Sign init failed");
 return;
    }

    // 更新消息内容
    size_t msg_len = strlen(message);
    if (EVP_DigestSignUpdate(md_ctx, message, msg_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        Tcl::instance().result("Sign update failed");
        return;
    }

    // 获取签名长度
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        Tcl::instance().result("Sign length check failed");
        return;
    }

    // 分配签名缓冲区（使用OpenSSL安全分配）
    unsigned char* sig = (unsigned char*)OPENSSL_malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(md_ctx);
        Tcl::instance().result("Memory allocation failed");
        return;
    }

    // 生成最终签名
    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) {
        OPENSSL_free(sig);
EVP_MD_CTX_free(md_ctx);
        Tcl::instance().result("Signing failed");
        return;
    }

    // 验证签名长度
    if (sig_len > sizeof(hdr_threshold_rsa::payload)) {
        OPENSSL_free(sig);
        EVP_MD_CTX_free(md_ctx);
        Tcl::instance().resultf("Signature too large (%lu > %lu)",
                              sig_len, sizeof(hdr_threshold_rsa::payload));
        return;
    }

    // 封装数据包
    Packet* pkt=allocpkt();
    hdr_threshold_rsa* hdr=HDR_THRESHOLD_RSA(pkt);  // 使用预定义宏
    if (!pkt) {
        OPENSSL_free(sig);
        EVP_MD_CTX_free(md_ctx);
        Tcl::instance().result("Packet allocation failed");
        return;
    }

    hdr=hdr_threshold_rsa::access(pkt);
    hdr->type = PARTIAL_SIG;
    hdr->sender_id = node_id_;
    memset(hdr->payload, 0, sizeof(hdr->payload));  // 安全清零
    memcpy(hdr->payload, sig, sig_len);
 // 发送并清理
    send(pkt, (Handler*)0);
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md_ctx);
}
void ThresholdRSA_Agent::aggregate_signatures(const std::vector<BIGNUM*>& shares) {
    BIGNUM* product = BN_new();
    BN_one(product);
    BIGNUM* modulus = NULL;
    EVP_PKEY_get_bn_param(pkey_,"n",&modulus);
    std::vector<BIGNUM*> lambdas(T_);
    compute_lagrange_coeff(lambdas);
    size_t i;
    for (i=0;i<shares.size();++i){
        BIGNUM* temp=BN_new();
        BN_mod_exp(temp,shares[i],lambdas[i],modulus,bn_ctx_);
        BN_mod_mul(product,product,temp,modulus,bn_ctx_);
        BN_free(temp);
    }
    Packet* pkt=allocpkt();
    hdr_threshold_rsa* hdr=hdr_threshold_rsa::access(pkt);
    hdr->type=FULL_SIG;
    BN_bn2bin(product,(unsigned char*)hdr->payload);
    hdr_cmn* ch=hdr_cmn::access(pkt);
    ch->addr_type()=NS_AF_INET;       // 设置地址类型
    send(pkt, (Handler*)0);
    BN_free(product);
       BN_free(modulus);
    for(std::vector<BIGNUM*>::const_iterator it = lambdas.begin();
        it != lambdas.end();
        ++it)
    {
        BN_free(*it);
    }
}

void ThresholdRSA_Agent::compute_lagrange_coeff(std::vector<BIGNUM*>& lambdas) {
    BIGNUM* modulus=NULL;
    EVP_PKEY_get_bn_param(pkey_,"n", &modulus);
    BIGNUM* numerator = BN_new();
    BIGNUM* denominator = BN_new();
    BIGNUM* tmp = BN_new();
    int i,j;
    for (i = 0; i < T_; ++i) {
        lambdas[i] = BN_new();
        BN_one(lambdas[i]);
        for (j=0;j<T_;++j){
            if (i == j) continue;
            BN_set_word(numerator,-j);
            BN_set_word(denominator,i-j);
            BN_mod_inverse(denominator,denominator,modulus,bn_ctx_);
            BN_mod_mul(tmp, numerator,denominator,modulus,bn_ctx_);
            BN_mod_mul(lambdas[i],lambdas[i],tmp,modulus,bn_ctx_);
        }
    }
BN_free(numerator);
    BN_free(denominator);
    BN_free(tmp);
    BN_free(modulus);
}
