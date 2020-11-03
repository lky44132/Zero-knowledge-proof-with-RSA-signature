import random  # used to generate random number
import hashlib  # used to generate hash
import time  # used to generate time so that RSA can become nondeterministic
import sympy as sympy  # used to calculate the inverse


# Prover class
class Prover:

    def __init__(self, id):
        self.ranNums = [0] * 1000  # list that contains random number
        self.r = [0] * 1000  # list that contains results = ranNum^e mod n
        self.verification = [0] * 1000  # which is p in my slide
        self.id = id  # prover's id
        self.sign = ""  # signature got from authoritative third party
        self.Pkey = (0, 0)  # third party public key which contain e and N
        self.TR = 0  # time of signature
        self.TRV = 0  # duration of signature
        self.x = 0  # number of verifications that require from verifier

    # we assume public key from Authoritative third party
    def setPublicKey(self, e, n):
        self.Pkey = (e, n)

    def generateRandomr(self, x):  # generate x random number and calculate its encrypted r using RSA
        self.x = x
        for i in range(x):
            self.ranNums[i] = random.randint(0, 9999)
            self.r[i] = (self.ranNums[i]**self.Pkey[0]) % self.Pkey[1]

    def setSign(self, SKey):  # set the signature by the secret key and current time
        md5 = hashlib.md5()
        self.TR = time.time()
        self.TRV = 2000
        string = str(self.id) + str(self.TR) + str(self.TRV)
        md5.update(string.encode('utf-8'))
        hash = int(md5.hexdigest(), 16)  # convert hex to int
        self.sign = ((hash**SKey) % self.Pkey[1])  # sign = ((𝐇(𝒊𝒅|𝑻𝑹|𝑻𝑹𝒗)))^𝒅 𝒎𝒐𝒅 𝒏

    def getSign(self):  # getter method of signature
        return self.sign

    def getHashCombindnation(self):  # compute the hash of the combination of id and time and duration and all rssssthat we calculate
        c = str(self.id) + str(self.TR) + str(self.TRV)  # get (𝑖𝑑|𝑇𝑅|𝑇𝑅𝑣|r0|𝑟1|r2|r....|rx-1)
        for i in range(self.x):
            c += str(self.r[i])
        md5 = hashlib.md5()
        md5.update(c.encode('utf-8'))
        hash = md5.hexdigest()
        return hash

    def selfVerification(self):  # compute x times verifications
        c = self.getHashCombindnation()
        hex_as_int = int(c, 16)
        hex_as_binary = bin(hex_as_int)
        for i in range(self.x):
            # the reason why I used binary_string[i+2] is because python shows 0b at the beginning of a binary number
            # and it violate the randomness for choosing bit so I start the loop by add 2 to it.
            if hex_as_binary[i+2] == '0':
                self.verification[i] = self.ranNums[i] % self.Pkey[1]
            if hex_as_binary[i+2] == '1':
                self.verification[i] = (self.ranNums[i] * self.getSign()) % self.Pkey[1]


    def sendXverification(self):
        return self.id, self.TR, self.TRV, self.verification, self.getHashCombindnation()


class Verifier:
    def __init__(self):
        self.Pkey = (0, 0)  # e and N
        self.x = 20  # require 20 time verification
        self.verification = [0]*1000

    # again, we assume public key from Authoritative third party
    def setPublicKey(self, e, n):
        self.Pkey = (e, n)  # we assume e is 5 and mod-N is  which is a prime number

    def numOfverification(self):
        return self.x

    # Pverification is prover's verifications
    def verify(self, id, TR, TRV, Pverification, hashCombination):
        # Pverification is prover's verifications
        if id > 20:  # firstly, verify id
            hex_as_int = int(hashCombination, 16)  # convert to decimal
            hex_as_binary = bin(hex_as_int)  # convert to binary form
            for i in range(self.x):
                # the reason why I used binary_string[i+2] is because python shows 0b at the beginning of a binary
                # number and it violate the randomness for choosing bit so I start the loop by add 2 to it.
                if hex_as_binary[i+2] == '0':
                    #  we take it and calculate it to the power of e mod n so that it would equal to ---
                    self.verification[i] = (Pverification[i] ** self.Pkey[0]) % self.Pkey[1]
                else:
                    md5 = hashlib.md5()
                    c = str(id) + str(TR) + str(TRV)
                    md5.update(c.encode('utf-8'))
                    hash = int(md5.hexdigest(), 16)
                    modular_inverse = sympy.mod_inverse(hash, self.Pkey[1])
                    self.verification[i] = ((Pverification[i] ** self.Pkey[0]) * modular_inverse) % self.Pkey[1]
            newCombination = str(id) + str(TR) + str(TRV)
            for i in range(self.x):
                newCombination += str(self.verification[i])
            md5 = hashlib.md5()
            md5.update(newCombination.encode('utf-8'))
            newhashCombination = md5.hexdigest()
            print("Hash combination from verifier: ", newhashCombination)
            if newhashCombination == hashCombination:
                return True
            else:
                return False

# no third part class since one of my group member is responsible for the key generation of RSA

prover1 = Prover(21)  # set up a prover with id 21
prover1.setPublicKey(17, 3233)  # assume we get public key from Authoritative third party which pq = 3233 and e = 17

verifier1 = Verifier()
verifier1.setPublicKey(17, 3233)  # assume we get public key from Authoritative third party

prover1.setSign(2753)  # Assume we got sign from Authoritative third party with x = 2753

x = verifier1.numOfverification()  # prompt prover that we need x verifications
prover1.generateRandomr(x)  # generate random number and encrypted r using RSA
prover1.selfVerification()

id, TR, TRV, verification, HashCombindnation = prover1.sendXverification()

print("Verifier only see: ")
print("prover's id: ", id)
print("prover's time when signature got sign: ", TR)  # Return the time in seconds since the epoch as a floating point number.
print("Hash combination from prover: ", HashCombindnation)
print("self verification from prover: ", verification)

if verifier1.verify(id, TR, TRV, verification, HashCombindnation):
    print("verification passed")
else:
    print("Fail the verification")
