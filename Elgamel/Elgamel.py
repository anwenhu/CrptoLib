import math
import random

class Elgamel:
	def __init__(self):
		self.q=0      #公开参数：所选择的素数
		self.a=0      #公开参数：本原根
		self.Y=0      #公开参数：公钥Y
		self.__X=0    #私密参数：私钥X
		self.__key=0  #私密参数：密钥key
		self.__plain=0  #私密参数：明文
		self.__crpt=(0,0)     #私密参数：密文

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

	def __primeArray(self,r):
		'''
		: __primeArray: 该方法生成范围在[0,r]内的素数表
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

	def __primeGenerate(self,limits):
		'''
		: __primeGenerate: 该方法从生成的素数表中随机筛选一个素数
		: Param: limits--随机筛选素数的素数表上界
		: Return: p--随机筛选的在上界内的素数
		'''
		a= self.__primeArray(limits)                  #生成一定范围内的素数表
		p = random.choice(a)                   #随机从素数表中筛选出一个素数
		return p

	def __getPrimitive(self,p):
		'''
		: __getPrimitive: 该方法计算给定的素数的随机的一个本原根
		: Param: p--给定的素数
	    : Return: res--给定的素数的一个随机筛选出的本原根
		'''
		testset=set([i for i in range(1,p)])
		res=[]
		for i in range(1,p):
			tempset=[]
			for k in range(1,p):
				tempset.append(self.__fastExpMod(i,k,p))
			if set(tempset)==testset:
				res.append(i)
		return random.choice(res)
	
	def __ext_euclid(self,a, b):
		'''
		: __ext_euclid: 扩展欧几里得算法
		'''
		a1 = max(a, b)
		b1 = min(a, b)
		return self.__ext_algorithm(a1, b1)

	def __ext_algorithm(self,a, b):
		'''
		: __ext_algorithm: 扩展欧几里得算法
		'''
		if b == 0:
			return (1, 0, a)
		x2, y2, gcd = self.__ext_euclid(b, a % b)
		tmp = x2
		x1 = y2
		y1 = tmp - int(a/b)*y2
		return (x1, y1, gcd)

	def sendClient(self,q,a,Y):
		'''
		: sendClient: 发送方A初始化
		: Param: 接收方B的公开参数——素数q，本原根a，公钥Y
		: Return: 无
		: Comment: 本方法为发送方，作用为初始化发送方A——设置从接收方获得的基本公开参数q,a,Y
		'''
		#1. 发送方设置基本公共参数
		self.q=q
		self.a=a
		self.Y=Y
		return 

	def receiveClient(self):
		'''
		: receiveClient: 接收方B初始化
		: Param: 无
		: Return: 公开参数(q,a,Y)
		: Comment: 本方法为接收方操作，作用为初始化接收方B——选定素数q以及本原根a，并选定私钥X，从而计算出收发双方共享公钥Y，并返回公开参数(q,a,Y)给发送方
		'''
		#1. 密钥接收方首先随机选定一个素数q，并且计算出该素数的本原根a
		self.q=self.__primeGenerate(1000)
		self.a=self.__getPrimitive(self.q)
		#2. 密钥发送方随机选择一个小于q的随机数X作为私钥
		self.__X=random.randint(0,self.q-1)
		#3. 密钥发送方计算出Ya作为公钥
		self.Y=self.__fastExpMod(self.a,self.__X,self.q)
		return (self.q,self.a,self.Y)

	def publish(self):
		'''
		: publish: 发送方A/接收方B公开公开参数——素数q，本原根a，以及公钥Y
		: Param: 无
		: Return: 素数q，本原根a，以及公钥Y
		'''
		return (self.q,self.a,self.Y)

	def encrypt(self,plain):
		'''
		: encrypt: 发送方A加密信息
		: Param: plain--明文信息
		: Return: 加密后的密文对
		: Comment: 本方法为发送方操作
		'''
		#1. 随机选定整数k<q-1
		k=random.randint(0,self.q-1)
		#2.发送方A计算出密钥
		self.__key=self.__fastExpMod(self.Y,k,self.q)
		#3. 根据接收方的公开参数和明文计算密文对
		self.__plain=plain
		self.__crpt=(self.__fastExpMod(self.a,k,self.q),self.__fastExpMod(self.__key*self.__plain,1,self.q))
		return self.__crpt
	
	def decipher(self,crpt):
		'''
		: decipher: 接收方B解密信息
		: Param: crpt--密文对
		: Return: 解密后的明文M和密钥key的元组(M, key)
		: Comment: 本方法为接收方操作
		'''
		#1. 根据接收方自身的私钥X解密明文并求解出密钥key
		self.__crpt=crpt
		self.__key=self.__fastExpMod(crpt[0],self.__X,self.q)
		(x1,y1,gcd)=self.__ext_euclid(self.__key,self.q)
		y1=(y1+self.q)%self.q
		self.__plain=self.__fastExpMod(crpt[1]*y1,1,self.q)     
		return (self.__plain, self.__key)







