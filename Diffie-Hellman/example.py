import DH

if __name__ == "__main__":
    # 1. 初始化密钥交换的双方A和B
    A = DH.DeffieHellman()
    B = DH.DeffieHellman()

    # 2. 密钥交换双方的其中一方A生成共享参数——素数q及其本原根a
    q, a = A.generateArg()

    # 3. 密钥交换的双方A,B利用上述素数q和本原根a生成各自的公钥和私钥，并共享A,B各自的公钥Ya，Yb
    Ya = A.generateKey(q,a)
    Yb = B.generateKey(q,a)

    # 4. 输出双方的共享参数q, a，以及双方各自的公钥Ya，Yb
    (qa, aa, Ya) = A.publish()
    (qb, ab, Yb) = B.publish()
    print("A的公开参数q = ",qa)
    print("A的公开参数a = ",aa)
    print("A的公钥Ya = ",Ya)
    print("B的公开参数q = ",qb)
    print("B的公开参数a = ",ab)
    print("B的公钥Yb = ",Yb)

    # 5. A根据公钥Yb计算出共享密钥并输出
    keya=A.getKey(Yb)
    print("A计算出的共享密钥为: ",keya)

    # 6. B根据公钥Ya计算出共享密钥并输出
    keyb=B.getKey(Ya)
    print("B计算出的共享密钥为: ",keyb)