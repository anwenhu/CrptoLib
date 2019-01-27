import math
import random

class DeffieHellman:
	def __init__(self):
		self.q=0      #公开参数：所选择的素数
		self.a=0      #公开参数：本原根
		self.Y=0      #公开参数：公钥Y
		self.__X=0    #私密参数：私钥X

	
	# private function
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
	
	# public functions
	def generateArg(self):
		'''
		: generateArg: 随机生成共享参数——素数q和素数q的本原根a
		: Param: 无
		: Return: 密钥交换共享参数(q,a)——素数q和素数q的一个本原根a
		'''
		#1. 首先随机选定一个素数q，并且计算出该素数的本原根a
		self.q=self.__primeGenerate(1000)
		self.a=self.__getPrimitive(self.q)
		return (self.q, self.a)

	def generateKey(self,q,a):
		'''
		: generateKey: 根据密钥双方的共享参数q和a，随机生成自己的私钥X，并计算出自己的公钥Y
		: Param: q, a--密钥交换双方的共享参数q和a
		: Return: X--密钥交换中自己一方的公钥
		'''
		#1. 随机选择一个小于q的随机数X作为密钥交换中自己一方的私钥
		self.q=q
		self.a=a
		self.__X=random.randint(0,self.q-1)
		#2. 根据私钥X，共享参数a和q，计算出Y作为密钥交换中自己一方的公钥
		self.Y=self.__fastExpMod(self.a,self.__X,self.q)
		return self.Y

	def publish(self):
		'''
		: publish: 公开自己一方的素数q，本原根a，以及公钥Y
		: Param: 无
		: Return: 素数q，本原根a，以及公钥Y
		'''
		return (self.q,self.a,self.Y)

	def getKey(self,Y):
		'''
		: getKey: 计算真实的共享密钥key
		: Param: 密钥交换中另一方的公钥Y
		: Return: 共享密钥key
		'''
		key=self.__fastExpMod(Y,self.__X,self.q)
		return key
	
	
	




