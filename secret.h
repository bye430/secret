#ifndef _SECRET_H_
#define _SECRET_H_
#include<openssl/bio.h>
#include<openssl/ssl.h>
#include<openssl/err.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<stdio.h>
#include<string>
#include<cassert>
#include<iostream>
using namespace std;
 /*使用已有公钥文件加密数据
 @return 密文长度+1(缓冲区的大小)
 @param  
 _strPemFileName:公钥文件路径,strData:待加密内容,buffer:存放密文结果的缓冲区,length:buffer的大小*/
int EncodeRSAKeyFile(const char * _strPemFileName , const char * _strData , unsigned char * buffer , int length){
    std::string strPemFileName = _strPemFileName;
    std::string strData = _strData ;
    if(strPemFileName.empty() || strData.empty()){
        assert(false);
        return 0 ;
    }
     
    FILE * hPubKeyFile = fopen(strPemFileName.c_str() , "rb");
    if(hPubKeyFile == NULL){
        assert(false);
        return 0;
    }
 
    std::string strRet;
    RSA * pRSAPublicKey = RSA_new();
    if(PEM_read_RSA_PUBKEY(hPubKeyFile , &pRSAPublicKey , 0 , 0) == NULL){
        assert(false);
        return 0;
    }
 
    int nLen = RSA_size(pRSAPublicKey);
    char * pEncode = new char[nLen + 1] ;
    int ret = RSA_public_encrypt(strData.length() , (const unsigned char *)strData.c_str() , (unsigned char * ) pEncode , pRSAPublicKey , RSA_PKCS1_PADDING);
    if(ret >= 0){
        strRet = std::string(pEncode , ret) ;
    }
 
    delete[] pEncode;
    RSA_free(pRSAPublicKey);
    fclose(hPubKeyFile);
    CRYPTO_cleanup_all_ex_data();
     
    if(strRet.length() + 1 > length){
        return 0;
    }
 
    memset(buffer , 0 , strRet.length() + 1) ;
    memcpy(buffer , &strRet[0] ,strRet.length());
 
    return strRet.length() + 1;
}
/*使用已有的私钥文件解密
@return 明文长度
@param
strPemFileName 私钥文件,_strData:密文,buffer:明文结果的缓冲区,length:缓冲区的大小*/
 
int DecodeRSAKeyFile(const char * _strPemfileName , const char * _strData , unsigned char * buffer ,  int length){
    std::string strPemFileName = _strPemfileName;
    std::string strData = _strData ;
    if(strPemFileName.empty() || strData.empty()){
        assert(false);
        return 0;
    }
 
    FILE* hPriKeyFile = NULL;
    hPriKeyFile =  fopen(strPemFileName.c_str() , "rb");
    if(hPriKeyFile == NULL){
        assert(false);
        return 0;
    }
 
    std::string strRet;
    RSA* pRSAPriKey = RSA_new();
    if(PEM_read_RSAPrivateKey(hPriKeyFile , &pRSAPriKey , 0 , 0) == NULL ){
        assert(false);
        return 0;
    }
 
    int nLen = RSA_size(pRSAPriKey);
    char * pDecode = new char[nLen + 1];
 
    int ret = RSA_private_decrypt(strData.length() , (const unsigned char *)strData.c_str() , (unsigned char *)pDecode , pRSAPriKey , RSA_PKCS1_PADDING);
 
    if(ret >= 0){
        strRet = std::string((char *)pDecode , ret);
    }
 
    delete [] pDecode;
    RSA_free(pRSAPriKey);
    fclose(hPriKeyFile);
    CRYPTO_cleanup_all_ex_data();
 
    if(strRet.length() + 1 > length){
        return 0 ;
    } else {
        memset(buffer , 0 , strRet.length() + 1);
        memcpy(buffer , &strRet[0] , strRet.length());
    }
 
    return strRet.length() + 1 ;
 
}
#endif 
