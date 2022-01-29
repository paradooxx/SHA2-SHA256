#include "sha256.h"

void sha256_transform(sha256_ctx *ctx, uchar *data)
{
    uint x[8], t1, t2, i, j, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; i++)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    /*the above line can be writen as 
    m[i] = (m[i - 2] >> 17) ^ (m[i - 2] >> 19) ^ (m[i - 2] >> 10) + m[i - 7] + (m[i - 15] >> 7) ^ (m[i - 15] >> 18) ^ (m[i - 15] >> 3) + m[i - 16];
    but it's too long*/

    for (i = 0; i < 8; ++i)
        x[i] = ctx->state[i];

    for(i = 0 ; i < 64 ; ++i)
    {
        t1 = h + EP1(x[4]) + CH(x[4], x[5], x[6]) + k[i] + m[i];
        t2 = EP0(x[0]) + MAJ(x[0], x[1], x[2]);
        x[7] = x[6];
        x[6] = x[5];
        x[5] = x[4];
        x[4] = x[3] + t1;
        x[3] = x[2];
        x[2] = x[1];
        x[1] = t1 + t2;
    }

    for(i = 0; i < 8; ++i)
        ctx->state[i] += x[i];
}

void sha256_init(sha256_ctx *ctx)
{
    ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx *ctx, uchar *data, uint len)
{
    for(uint i = 0; i < len; ++i)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if(ctx->datalen == 64)
        {
            sha256_transform(ctx, ctx->data);
            ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
            ctx->datalen = 0;
        }
    }
}

void sha256_final(sha256_ctx *ctx, uchar *hash)
{
    uint i = ctx->datalen;
    if(ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while(i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
    ctx->data[63] = ctx->bitlen[0];
	ctx->data[62] = ctx->bitlen[0] >> 8;
	ctx->data[61] = ctx->bitlen[0] >> 16;
	ctx->data[60] = ctx->bitlen[0] >> 24;
	ctx->data[59] = ctx->bitlen[1];
	ctx->data[58] = ctx->bitlen[1] >> 8;
	ctx->data[57] = ctx->bitlen[1] >> 16;
	ctx->data[56] = ctx->bitlen[1] >> 24;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) 
    {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

char* sha256(char* data)
{
    int strlength = strlen(data);
    sha256_ctx ctx;
    unsigned char hash[32];
    char* hashString = malloc(65);
    strcpy(hashString, "");

    sha256_init(&ctx);
    sha256_update(&ctx, data, strlength);
    sha256_final(&ctx, hash);

    char s[3];
    for(int i = 0; i < 32; i++)
    {
        sprintf(s, "%02x", hash[i]);
        strcat(hashString, s);
    }
    return hashString;
}

int main()
{
    char* string = "Paras";
    //printf("Enter the string to be hashed: ");
    //fgets(string, sizeof(string), stdin);
    printf("The hashed value is: %s", sha256(string));
    return 0;
}