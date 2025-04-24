#ifndef THRESHOLD_RSA_H
#define THRESHOLD_RSA_H

#include "agent.h"
#include"packet.h"
#include<vector>
#include <openssl/evp.h>

#define PARTIAL_SIG 0x01
#define FULL_SIG   0x02
#define HDR_THRESHOLD_RSA(p) hdr_threshold_rsa::access(p)  // 定义包头访问宏

struct hdr_threshold_rsa {
   static int offset_;

    // 包头访问方法
    inline static hdr_threshold_rsa* access(const Packet* p) {
        return (hdr_threshold_rsa*)p->access(offset_);
    }
    u_int8_t type;
    int sender_id;
    char payload[512];  // 存储签名数据
    u_int16_t sig_len;
};

class ThresholdRSA_Agent : public Agent {
public:
    ThresholdRSA_Agent();
    virtual ~ThresholdRSA_Agent();
    virtual int command(int argc, const char*const* argv);
    void aggregate_signatures(const std::vector<BIGNUM*>& shares);

protected:
    void init(int node_id, int N, int T);
    void generate_partial_signature(const char* message);
    void compute_lagrange_coeff(std::vector<BIGNUM*>& lambdas);

private:
    int node_id_;
    int N_;
    int T_;
    EVP_PKEY* pkey_;
    BN_CTX* bn_ctx_;
};

#endif /* THRESHOLD_RSA_H */
