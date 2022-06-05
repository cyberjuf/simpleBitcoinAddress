
#include "applog.h"
#include "base58.h"
#include "hash.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include "openssl/sha.h"
#include "segwit_addr.h"
#include "utility.h"
#include <assert.h>
#include <bits/getopt_core.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <errno.h>
#include <getopt.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
// #include <libkeccak.h>
#define BITCOIN_ADDRESS_SIZE 21
#define BITCOIN_PRIVATEKEY_WIF_SIZE 34
#define BITCOIN_PRIVATEKEY_SIZE 32
#define BITCOIN_PUBLICKEY_COMMPRESSED_SIZE 33
enum CNETWORK { mainnet, testnet, doge };
CNETWORK network;
struct privatekeyST {
  std::string privatekeyHex;
  std::string WIFHex;
  std::string WIFbase58;
};
privatekeyST CreateWIFCommpressed(const BIGNUM *);
void *HexDecode(const char *inputhex, size_t size);
std::string EncodeHex(unsigned char *rawdata, size_t _datasize);
std::string encodeBase58check(void *data, size_t _datasize);
BitcoinRIPEMD160 sha256ripemd160encode(void *_data, size_t _datasize);
std::string makeLagacyAddress(void *pubkey_raw);
std::string makeSegwitAddress(void *pubkey_raw);
std::string makeBech32Address(void *pubkey_raw);

int main(int argc, char **argv) {
  EC_KEY *key_pair_obj = nullptr;
  int ret_error;
  BIGNUM *priv_key = NULL;
  EC_POINT *pub_key;
  EC_GROUP *secp256k1_group;
  char *pub_key_char;
  unsigned char buffer_digest[SHA256_DIGEST_LENGTH];
  uint8_t *digest;
  BIGNUM *bn;
  EC_KEY *imported_key_pair = nullptr;
  EC_GROUP *curve_group;
  EC_POINT *public_point;
  int char_read;
  std::string option_str;

  int option;
  while ((option = getopt(argc, argv, "b:k:n:")) != -1) {
    switch (option) {
    case 'n':
      option_str = std::string(optarg);
      if (option_str == std::string("mainnet"))
        network = CNETWORK::mainnet;
      else if (option_str == std::string("testnet"))
        network = CNETWORK::testnet;
      else if (option_str == std::string("doge"))
        network = CNETWORK::doge;
      else {
        printf("NETWORK ERR!!!\n");
        exit(1);
      }
      break;
    case 'k':
      if (strlen(optarg) != 64) {
        applog(APPLOG_ERROR, __func__,
               "Invalid Input HEX must 64 Char long: %s", optarg);
        return BITCOIN_ERROR_PRIVATE_KEY_INVALID_FORMAT;
      }
      BN_hex2bn(&priv_key, optarg);

      break;
    case 'b':
      printf("Open binary Private Key : %s\n", optarg);
      unsigned char buffer[32];
      FILE *ptr;
      ptr = NULL;
      ptr = fopen(optarg, "rb"); // r for read, b for binary
      if (ptr == NULL) {
        applog(APPLOG_ERROR, __func__, "Invalid Input binary: %s", optarg);
        return BITCOIN_ERROR_PRIVATE_KEY_INVALID_FORMAT;
      }
      fread(buffer, sizeof(buffer), 1, ptr); // read 10 bytes to our buffer
      fclose(ptr);
      priv_key = BN_bin2bn(buffer, 32, NULL);
      break;
    case '?':
      applog(APPLOG_ERROR, __func__, "Invalid format: %s", "ERROR!!!");
      return BITCOIN_ERROR_INVALID_FORMAT;
      break;
    default:
      network = CNETWORK::mainnet;
      break;
    }
  } // getopt
  switch (network) {
  case CNETWORK::mainnet:
    printf("NETWORK  : mainnet\n");
    break;
  case CNETWORK::testnet:
    printf("NETWORK  : testnet\n");
    break;
  case CNETWORK::doge:
    printf("NETWORK  : doge\n");
    break;
  }

  if (priv_key != NULL) {
    printf("Private key Set\n");
    key_pair_obj = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key_pair_obj) {
      applog(APPLOG_ERROR, __func__, "EC_KEY_new_by_curve_name failed: %s",
             "ERROR!!!");
      return BITCOIN_ERROR_LIBRARY_FAILURE; // BITCOIN_ERROR_INVALID_FORMAT
    }
    secp256k1_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    pub_key = EC_POINT_new(secp256k1_group);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_mul(secp256k1_group, pub_key, priv_key, NULL, NULL, ctx);
    EC_KEY_set_private_key(key_pair_obj, priv_key);
    EC_KEY_set_public_key(key_pair_obj, pub_key);
    BN_CTX_free(ctx);
    EC_POINT_free(pub_key);
    // EC_GROUP_free(secp256k1_group);

  } else {
    key_pair_obj = EC_KEY_new_by_curve_name(NID_secp256k1);
    ret_error = EC_KEY_generate_key(key_pair_obj);
    priv_key = (BIGNUM *)EC_KEY_get0_private_key(key_pair_obj);
  }

  privatekeyST privkey;
  privkey = CreateWIFCommpressed(priv_key);

  // Get public key
  pub_key = (EC_POINT *)EC_KEY_get0_public_key(key_pair_obj);
  secp256k1_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  pub_key_char = EC_POINT_point2hex(secp256k1_group, pub_key,
                                    POINT_CONVERSION_COMPRESSED, nullptr);
  unsigned char *pubkey_raw = nullptr;
  EC_POINT_point2buf(secp256k1_group, pub_key, POINT_CONVERSION_COMPRESSED,
                     &pubkey_raw, nullptr);
  std::string bitcoinAddress = makeLagacyAddress(pubkey_raw);
  std::string segwitAddress = makeSegwitAddress(pubkey_raw);
  std::string bech32Address = makeBech32Address(pubkey_raw);
  free(pubkey_raw);
  printf("Private key HEX: 0x%s\n", privkey.privatekeyHex.c_str());
  printf("Private key WIF HEX: 0x%s\n", privkey.WIFHex.c_str());
  printf("Private key WIF BASE58CHECK : %s\n", privkey.WIFbase58.c_str());
  printf("Public key Commpressed: 0x%s\n", pub_key_char);
  printf("Bitcoin Lagacy Address  : %s\n", bitcoinAddress.c_str());
  printf("Bitcoin Segwit Address  : %s\n", segwitAddress.c_str());
  printf("Bitcoin Bech32 Address  : %s\n", bech32Address.c_str());
  EC_KEY_free(key_pair_obj);
  EC_GROUP_free(secp256k1_group);
  free(pub_key_char);
  return 0;
}

privatekeyST CreateWIFCommpressed(const BIGNUM *_BNprivatekey) {
  unsigned char *WIF_privatekey, *rawPrivatekey;
  unsigned char prefix, postfix;
  WIF_privatekey = (unsigned char *)malloc(BITCOIN_PRIVATEKEY_WIF_SIZE);
  memset(WIF_privatekey, 0, BITCOIN_PRIVATEKEY_WIF_SIZE);
  rawPrivatekey = (unsigned char *)malloc(BITCOIN_PRIVATEKEY_SIZE);
  BN_bn2bin(_BNprivatekey, rawPrivatekey);
  switch (network) {
  case CNETWORK::mainnet:
    prefix = 0x80;
    postfix = 0x01;
    memcpy(WIF_privatekey, &prefix, 1);
    memcpy(WIF_privatekey + 1, rawPrivatekey, BITCOIN_PRIVATEKEY_SIZE);
    memcpy(WIF_privatekey + BITCOIN_PRIVATEKEY_SIZE + 1, &postfix, 1);
    break;
  case CNETWORK::testnet:
    prefix = 0xef;
    postfix = 0x01;
    memcpy(WIF_privatekey, &prefix, 1);
    memcpy(WIF_privatekey + 1, rawPrivatekey, BITCOIN_PRIVATEKEY_SIZE);
    memcpy(WIF_privatekey + BITCOIN_PRIVATEKEY_SIZE + 1, &postfix, 1);
    break;
  case CNETWORK::doge:
    prefix = 0x9e;
    postfix = 0x01;
    memcpy(WIF_privatekey, &prefix, 1);
    memcpy(WIF_privatekey + 1, rawPrivatekey, BITCOIN_PRIVATEKEY_SIZE);
    memcpy(WIF_privatekey + BITCOIN_PRIVATEKEY_SIZE + 1, &postfix, 1);
    break;
  }
  privatekeyST result;
  result.WIFHex = EncodeHex(WIF_privatekey, BITCOIN_PRIVATEKEY_WIF_SIZE);
  result.WIFbase58 =
      encodeBase58check(WIF_privatekey, BITCOIN_PRIVATEKEY_WIF_SIZE);
  result.privatekeyHex = EncodeHex(rawPrivatekey, 32);
  free(WIF_privatekey);
  free(rawPrivatekey);
  return result;
}

void *HexDecode(const char *inputhex, size_t size) {
  void *result = malloc(256);
  size_t output_buffer_size = sizeof(result);
  BitcoinResult format_result = BITCOIN_ERROR;
  memset(result, 0, output_buffer_size);
  format_result = Bitcoin_DecodeHex(result, output_buffer_size,
                                    &output_buffer_size, inputhex, size);
  assert(format_result == BITCOIN_SUCCESS);
  return result;
}

std::string EncodeHex(unsigned char *rawdata, size_t _datasize) {
  char output_buffer[256];
  size_t output_buffer_size = sizeof(output_buffer);
  BitcoinResult format_result = BITCOIN_ERROR;
  memset(&output_buffer, 0, sizeof(output_buffer));
  format_result =
      Bitcoin_EncodeHex(output_buffer, output_buffer_size, &output_buffer_size,
                        rawdata, _datasize, false);
  return std::string(output_buffer);
}

std::string encodeBase58check(void *data, size_t _datasize) {
  char output_raw[256]; /* raw input type converted to raw output type */
  size_t output_raw_size = sizeof(output_raw);
  memset(&output_raw, 0, output_raw_size);
  BitcoinResult format_result = BITCOIN_ERROR;
  format_result = Bitcoin_EncodeBase58Check(output_raw, output_raw_size,
                                            &output_raw_size, data, _datasize);
  assert(format_result == BITCOIN_SUCCESS);
  return std::string(output_raw);
}

BitcoinRIPEMD160 sha256ripemd160encode(void *_data, size_t _datasize) {
  BitcoinSHA256 pubkeyhash;
  BitcoinRIPEMD160 pubkeyhashripemd160;
  Bitcoin_SHA256(&pubkeyhash, _data, _datasize);
  Bitcoin_RIPEMD160(&pubkeyhashripemd160, pubkeyhash.data, BITCOIN_SHA256_SIZE);
  return pubkeyhashripemd160;
}
void *makeRawLagacyAddress(void *pubkey_raw);

std::string makeLagacyAddress(void *pubkey_raw) {
  void *lagacyRawAddress = makeRawLagacyAddress(pubkey_raw);
  return encodeBase58check(lagacyRawAddress, BITCOIN_ADDRESS_SIZE);
}
std::string makeBech32Address(void *pubkey_raw) {
  void *lagacyRawAddress = makeRawLagacyAddress(pubkey_raw);
  char outputbuffer[256];
  std::string hrp;
  memset(outputbuffer, 0, sizeof(outputbuffer));
  switch (network) {
  case mainnet:
    hrp = std::string("bc");
    break;
  case testnet:
    hrp = std::string("tb");
    break;
  case doge:
    hrp = std::string("dc");
    break;
  }
  segwit_addr_encode(outputbuffer, hrp.c_str(), 0,
                     (const uint8_t *)lagacyRawAddress + 1,
                     BITCOIN_RIPEMD160_SIZE);
  return std::string(outputbuffer);
}
void *makeRawLagacyAddress(void *pubkey_raw) {
  BitcoinRIPEMD160 pubkeyhashripemd160 =
      sha256ripemd160encode(pubkey_raw, BITCOIN_PUBLICKEY_COMMPRESSED_SIZE);
  char *bitcoinAddress = (char *)malloc(BITCOIN_ADDRESS_SIZE);

  std::string bitcoinaddress_hex;
  char prefix;
  switch (network) {
  case CNETWORK::mainnet:    
    prefix = 0;
    memcpy(bitcoinAddress, &prefix, 1);
    memcpy(bitcoinAddress + 1, pubkeyhashripemd160.data,
           BITCOIN_RIPEMD160_SIZE);
    break;
  case CNETWORK::testnet:   
    prefix = 0x6f;
    memcpy(bitcoinAddress, &prefix, 1);
    memcpy(bitcoinAddress + 1, pubkeyhashripemd160.data,
           BITCOIN_RIPEMD160_SIZE);
    break;
  case CNETWORK::doge:    
    prefix = 0x1e;
    memcpy(bitcoinAddress, &prefix, 1);
    memcpy(bitcoinAddress + 1, pubkeyhashripemd160.data,
           BITCOIN_RIPEMD160_SIZE);
    break;
  default:    
    prefix = 0;
    memcpy(bitcoinAddress, &prefix, 1);
    memcpy(bitcoinAddress + 1, pubkeyhashripemd160.data,
           BITCOIN_RIPEMD160_SIZE);
    break;
  }

  return bitcoinAddress;
}

std::string makeSegwitAddress(void *pubkey_raw) {
  char *result, *prefixRipemd160;
  prefixRipemd160 = (char *)malloc(BITCOIN_RIPEMD160_SIZE + 2);
  memset(prefixRipemd160, 0, BITCOIN_RIPEMD160_SIZE + 2);
  BitcoinRIPEMD160 pubkeyhashripemd160 =
      sha256ripemd160encode(pubkey_raw, BITCOIN_PUBLICKEY_COMMPRESSED_SIZE);  
  unsigned char prefix = 0x14;
  memcpy(prefixRipemd160 + 1, &prefix, 1);
  memcpy(prefixRipemd160 + 2, pubkeyhashripemd160.data, BITCOIN_RIPEMD160_SIZE);

  BitcoinRIPEMD160 pubkeyhashripemd160_2 =
      sha256ripemd160encode(prefixRipemd160, BITCOIN_RIPEMD160_SIZE + 2);
  free(prefixRipemd160);
  result = (char *)malloc(BITCOIN_ADDRESS_SIZE);
  memset(result, 0, BITCOIN_ADDRESS_SIZE);
  switch (network) {
  case CNETWORK::mainnet:    
    prefix = 0x05;
    memcpy(result, &prefix, 1);
    memcpy(result + 1, pubkeyhashripemd160_2.data, BITCOIN_RIPEMD160_SIZE);
    break;
  case CNETWORK::testnet:    
    prefix = 0xc4;
    memcpy(result, &prefix, 1);
    memcpy(result + 1, pubkeyhashripemd160_2.data, BITCOIN_RIPEMD160_SIZE);
    break;
  case CNETWORK::doge:   
    prefix = 0x16;
    memcpy(result, &prefix, 1);
    memcpy(result + 1, pubkeyhashripemd160_2.data, BITCOIN_RIPEMD160_SIZE);
    break;
  default:    
    prefix = 0x05;
    memcpy(result, &prefix, 1);
    memcpy(result + 1, pubkeyhashripemd160_2.data, BITCOIN_RIPEMD160_SIZE);
    break;
  }
  std::string resutstr =
      encodeBase58check((void *)result, BITCOIN_ADDRESS_SIZE);
  free(result);
  return resutstr;
}