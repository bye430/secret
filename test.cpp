#include"secret.h"
#include<iostream>
int main(){
    //jia mi
    const std::string one = "abcdeF";
    std::string strPubKey = "/root/test_2018_pub.key";
    const char * char1 = strPubKey.c_str();
    const char * char2 = one.c_str();
    unsigned char buffer[512] , buffer1[512];
    int length = EncodeRSAKeyFile(char1 , char2 , buffer , 512);
    std::string strResult = std::string((char *)buffer , length);
    //cout << "pwdtxt:" << strResult << endl;
    //cout << length << endl;
    //return 0;
 
    //jiemi
    std::string strPriKey = "/root/test_2018.key";
    length = DecodeRSAKeyFile(strPriKey.c_str() , strResult.c_str() , buffer1 , 512 );
    std::string strOrgTxt = std::string((char *)buffer1 , length);
    cout << "orgTxtLength:" << length << endl <<  "orgTxt:" << strOrgTxt << endl ;
 
    return 0;
}
