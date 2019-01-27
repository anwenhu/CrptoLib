import RSA

if __name__ == "__main__":
    rsa = RSA.RSA()
    pubkey = rsa.generatePubKey()
    privkey = rsa.generatePrivKey()

    plain = int(input("请输入要进行RSA加密的明文: "))

    print('RSA公钥为: ', pubkey)
    crpt = rsa.encrypt(plain)
    print('使用RSA公钥加密的结果为: ',crpt)

    print('RSA私钥为: ', privkey)
    plain = rsa.decrypt(crpt)
    print('使用RSA私钥解密的结果为: ',plain)