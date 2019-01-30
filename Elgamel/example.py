import Elgamel as El

if __name__ == "__main__":
    #接收方B初始化
    B = El.Elgamel()
    q, a, Y = B.receiveClient()

    #发送方A初始化
    A = El.Elgamel()
    A.sendClient(q,a,Y)
    print("共享参数q = ",q)
    print("共享参数a = ",a)
    print("共享参数Y = ",Y)

    #发送方进行加密
    plain = int(input("请输入明文(以十进制形式数字输入):"))
    crpt = A.encrypt(plain)
    print("发送方A加密得到的密文为: ", crpt)

    #接收方进行解密
    plain = B.decipher(crpt)
    print("接收方B解密得到的明文为: ", plain[0])
    print("发送方加密所使用的密钥为:", plain[1])
