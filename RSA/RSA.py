import math
import random

import os

class RSA:

    # private object members
    __p, __q, __n, __f, __e, __d = [0 for i in range(6)]

    # public function members
    def __init__(self):
        '''
        : __init: RSA类的初始化，生成并初始化公钥和私钥参数n, e, d
        '''
        self.__n, self.__e, self.__d=self.__keyGenerate() 
        return
    
    def generatePubKey(self):
        '''
        : generatePubKey: 返回RSA公钥(n, e)
        : Return: RSA公钥(n, e)
        '''
        return (self.__n, self.__e)
        
    def generatePrivKey(self):
        '''
        : generatePrivKey: 返回RSA私钥(n, d)
        : Return: RSA私钥(n, d)
        '''
        return (self.__n, self.__d)
    
    def encrypt(self, plain):
        '''
        : encrypt: 进行RSA加密
        : Param: plain--明文
        : Return: RSA加密密文结果
        '''
        return self.__RSA(plain, (self.__n, self.__e))
    
    def decrypt(self, crpt):
        '''
        : decrypt: 进行RSA解密
        : Param: crpt--密文
        : Return: RSA解密明文结果
        '''
        return self.__deRSA(crpt, (self.__n, self.__d))
    

    #private functions members
    def __fastExpMod(self, b, e, m):
        '''
        : __fastExpMod: 快速幂取模算法
        : Param: b,e,m--对应于幂取模运算式b^e mod m中对应参数
        : Return: 幂取模运算式b^e mod m的计算结果
        '''
        result = 1
        while e != 0:
            if (e&1) == 1:
                result = (result * b) % m
            e >>= 1
            b = (b*b) % m    
        return result

    def __primeArray(self, r):
        '''
        : __primeArray:该方法生成范围在[0,r]内的素数表
        : Param: r--素数表上界
        : Return: 范围在[0,r]内的素数表
        '''
        prime=[0 for i in range(r+1)]
        lis=[]
        for i in range(2,r+1):
            if prime[i]==0:
                lis.append(i)
            for j in lis:
                if i*j>r:
                    break
                prime[i*j]=1
                if i%j==0:
                    break
        return lis
    
    def __prime(self, n, test_divisor):
        '''
        : __prime: 判断是否为素数
        '''
        if math.sqrt(n) < test_divisor:
            return True #为素数时返回True
        if n % test_divisor==0:
            return False #不为素数时返回Fasle
        else:
            return self.__prime(n, test_divisor+1)

    def __findCoPrime(self, s):
        '''
        : __findCoPrime: 筛选出符合条件的数e满足gcd(e,(p-1,q-1))==1
        : Param: s--(p-1)*(q-1)
        : Return: 符合条件的值e
        : comment: 因为两个随机数互质的概率为0.6，因此只需要随机选取一个数e，然后测试是否满足gcd(e,(p-1,q-1))==1即可
        '''
        while True:
            e = random.choice(range(10000))
            x = self.__gcd(e,s)
            if x==1:
                break
        return e
    
    def __gcd(self, a,b):
        '''
        : __gcd: 求两个数的最大公约数
        : Param: a,b--数a，数b
        : Return: 数a，b的最大公约数
        '''
        if b==0:
            return a
        else:
            return self.__gcd(b, a%b)
    
    def __inV(self, a,b):
        '''
        : __inV:扩展欧几里得算法求解乘法逆元
        '''
        if b == 0:
            return (1,0,a)
        (x, y, r) = self.__inV(b,a%b)
        temp = x
        x = y
        y = temp - int(a / b) * y
        return (x,y,r) 
    
    def __searchD(self, e,s):
        '''
        : __searchD: 筛选出符合条件的参数d的值
        : Param: e--RSA加密参数e，s--(p-1)*(q-1)
        '''
        x=0
        y=0
        r=0
        (x,y,r)=self.__inV(e,s)
        d=(x+s)%s
        return d
    
    def __keyGenerate(self):
        '''
        : __keyGenerate: 生成RSA加密的关键变量n,e,d
        : Return: (n,e,d)的三元组
        '''
        a= self.__primeArray(10000)                   #生成素数表
        #print("范围在[0,10000]的素数表为:",a)
        p = random.choice(a)                   #随机从素数表中筛选出p
        q = random.choice(a)                   #随机从素数表中筛选出q
        #print("随机筛选出的素数p，q分别为:",p,q)
        n=p*q
        s=(p-1)*(q-1)
        e = self.__findCoPrime(s)
        #print("根据gcd(e,(p-1)*(q-1))==1得到e的值为: e=", e)
        d = self.__searchD(e,s)
        #print("根据(e*d)%((p-1)*(q-1))==1得到d的值为: d=", d)
        #print("公钥为: n=",n," e=",e)
        #print("私钥为: n=",n," d=",d)
        res=(n,e,d)
        return res
    
    def __RSA(self, plain, ned):
        '''
        : __RSA:进行RSA加密
        : Param: plain--明文，ned--公钥
        : Return: 密文
        '''
        crpt = self.__fastExpMod(plain,ned[1],ned[0])
        return crpt
    
    def __deRSA(self, crpt, ned):
        '''
        : __deRSA: 进行RSA解密
        : Param: crpt--明文，ned--私钥
        : Return: 明文
        '''
        plain = self.__fastExpMod(crpt,ned[1],ned[0])
        return plain
    
    
    
    
    
    
    


