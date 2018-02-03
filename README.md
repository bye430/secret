在使用openssl 库前，需检测是否安装openssl , shell 窗口输入:openssl version 
生成公私钥步骤:
openssl genrsa -out test_2048.key 2048 //私钥
openssl rsa -in test_2048.key -pubout -out test_2048_pub.key //公钥

gcc 编译指令:
gcc test.cpp -o test  -lcrypto -ldl -lstdc++
