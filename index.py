import numpy as np
# Initial Permutation table
import tables
import sBoxs
import random

BLOCK_LENGTH = 64
KEY_LENGTH = 64
HALF_BLOCK = round(BLOCK_LENGTH/2)

sBoxTable = sBoxs.generate_sboxes()


# def addBitesToBlock(block):
# 	if(len(block) != 56):
# 		raise Exception("Length of block less than 56!")

# 	increasedBlock = ['']*64
# 	numberOfOne = 0;
# 	j=0
# 	indexOfElem = 1
# 	for i in range(len(increasedBlock)):
# 		if(indexOfElem%8 == 0):
# 			if(numberOfOne%2 == 0 and numberOfOne != 0):
# 				increasedBlock[i] = '1'
# 			else:
# 				increasedBlock[i] = '0'
# 			numberOfOne = 0
# 			indexOfElem = 1
# 			continue
# 		increasedBlock[i] = block[j]
# 		indexOfElem += 1
# 		j += 1
# 		if(increasedBlock[i] == '1'):
# 			numberOfOne += 1
	
# 	return ''.join(char for char in increasedBlock)



# # function which permutates block
# def permutate(block, table):
# 	permutatedBlock = ['']*len(block)

# 	for i, pos in enumerate(table):
# 		permutatedBlock[i] = block[pos-1]

# 	return ''.join(elem for elem in permutatedBlock)

# # додавання по модулю 2


# # Основна функція шифрування (функція Фейстеля)
# def addBytes(rightSide, key):
# 	if(len(rightSide) != len(key)):
# 		extendedRightSide = ['']*48
# 		for i, pos in enumerate(tables.extendsE_table):
# 			extendedRightSide[i] = rightSide[pos-1]

# 		addedKey = xorBinOperation(extendedRightSide, key)
# 		bBlocks = [0]*8
# 		for i in range(8):
# 			index1 = int(addedKey[i:i+6][0] + addedKey[i:i+6][5], 2)
# 			index2 = int(addedKey[i:i+6][1:5], 2)
# 			if((index1 >= 0 and index1 <= 3) and (index2 >= 0 and index2 <= 15)):
# 				bBlocks[i] = tables.sBoxs[i][index1][index2]
		
# 		result = ''.join(format(block, '04b') for block in bBlocks)
# 		return result

# #generateKey 
# def generateKey(key, index):
# 	keyParts = [[0]*28 for _ in range(2)]
# 	for i in range(len(keyParts)):
# 		for j, pos in enumerate(tables.keyPermutation_table[i]):
# 			keyParts[i][j] = key[pos-1]


# 	offset = 0 #this variable used to set offset which will be performed to parts of key
# 	if(index == 1 or index == 2 or index == 9 or index == 16):
# 		offset = 1
# 	else:
# 		offset = 2

# 	for i in range(len(keyParts)):
# 		for j in range(offset, len(keyParts[i])+offset):
# 			keyParts[i][j-offset] = keyParts[i][j] if j < len(keyParts[i]) else '0'
	

# 	stringKey = ''
# 	for part in keyParts:
# 		for char in part:
# 			stringKey += char


# 	finalKey = ''
# 	for i, pos in enumerate(tables.keyPermutateShrinkMatrix):
# 		finalKey += stringKey[pos-1]

# 	return finalKey


	


# # Раунди шифрування
# def encrypt(block, key, index = 16):
# 	if(len(block) != 64):
# 		raise Exception("Error: func 'encrypt' -> len of block is not 64 bites")
	
# 	leftSide = block[0:len(block)//2]
# 	rightSide = block[len(block)//2:len(block)]

# 	newLeftSide = rightSide
# 	newRightSide = xorBinOperation(leftSide, addBytes(rightSide, generateKey(key, 17-index)))

# 	newBlock = newLeftSide + newRightSide
# 	# print(newBlock)
# 	if(index == 0):
# 		return  newBlock
# 	return encrypt(newBlock, key, index-1)





# rgr

# basic function to work with text
def textToBin(text):
	return ''.join(bin(int(ord(char)))[2:] for char in text)

def binToText(binary):
    # Split the binary string into 8-bit chunks
    chunks = [binary[i:i+7] for i in range(0, len(binary), 7)]

    # Convert each 8-bit chunk back to a character and join them
    text = ''.join(chr(int(chunk, 2)) for chunk in chunks)
    return text

def chunk_into_64_bits(input_data):
    # Split the input data into 64-bit blocks
    blocks = [input_data[i:i + 64] if len(input_data[i:i + 64]) ==64 else zero_pad(input_data[i:i + 64]) for i in range(0, len(input_data), 64)]
    return blocks

def zero_pad(input_block):
    # Ensure the input is exactly 64 bits by zero-padding if necessary
    while len(input_block) < 64:
        input_block += "0"
    return input_block


# xorOperation
def xorBinOperation(text, key):
	if(len(text) != len(key)):
		raise Exception(f"Length of key and text is different!\nText length is {len(text)}\nKey length is {len(key)}")
	
	encryptedText = ''
	for i in range(len(text)):
		# encryptedText += str(0) if text[i] == key[i] else str(1)
		encryptedText += str(int(text[i]) ^ int(key[i]))

	return encryptedText

def cyclic_left_shift(bits, shift_amount):
    return bits[shift_amount:] + bits[:shift_amount]

# function to devide one block into sub-blocks
def divideBlockBy2(block):
	if(round(len(block)) != BLOCK_LENGTH):
		raise Exception("Error: func 'divideBlockBy2' -> len of block is not 64 bites")
	
	resultBlock = [block[i:i+HALF_BLOCK] for i in range(0, round(len(block)), HALF_BLOCK)]
	# for i in range(0, round(len(block)), HALF_BLOCK):
	# 	resultBlock.append([block[i:i+HALF_BLOCK]])

	return resultBlock

def process_left_block(last_8_bits, octet_index):
	# for each iteration used different sBox table
	selected_sbox = sBoxTable[octet_index]
	output_bits = []
	for i in range(0, len(last_8_bits), round(len(last_8_bits)/4)):
		sbox_row = last_8_bits[i:i+3] 
		sbox_col = last_8_bits[i+3:i+8] 
		print(f"rowIndex: {int(sbox_row, 2)}\ncolIndex: {int(sbox_col, 2)}")
		output_bits.extend(bin(int(selected_sbox[int(sbox_row, 2)][int(sbox_col, 2)], 16))[2:].zfill(8))
	returnedBlock = ''.join(output_bits)
	# print(len(returnedBlock))
	return returnedBlock

def binTextToString(block):
	resultedString = ''
	if isinstance(block[0], list):
		for subBlock in block:
			for part in subBlock:
				resultedString += binToText(part)
	elif isinstance(block[0], str):
		for part in block:
				resultedString += binToText(part)
	
	return resultedString





def enterValue():
	# textToEncrypt = str(input('Enter text to encrypt:'))
	# key = str(input('Enter key:'))
	# roundsOfEncryption = str(input('Enter number of encrypting rounds:'))
	roundsOfEncryption = 1
	textToEncrypt = "Oleksii"
	key = "Shevchenko"
	print("Text:", textToEncrypt)
	print("Key:", key)
	binText = textToBin(textToEncrypt)
	binKey = textToBin(key)
	print("\nbinText:", binText, len(binText))
	print("binKey:", binKey, len(binKey))

	# here we entered value to exact length
	if(len(binText) > 64):
		binText = chunk_into_64_bits(binText)
	else:
		binText = [zero_pad(binText)]
	if(len(binKey) > 64):
		binKey = [chunk_into_64_bits(binKey)[0]]
	else:
		binKey = [zero_pad(binKey)]

	print("\n\nFinal text:", binText , len(binText[0]))
	print("\n\nFinal key:", binKey , len(binKey[0]))
	
	# next loop divides text with 64 bites length to two 32 length blocks
	resultBinText = []
	for binPart in binText:
		resultBinText.append(divideBlockBy2(binPart))
	
	resultBinKey = divideBlockBy2(binKey[0])

	print(resultBinText, len(resultBinText[0]))
	print(resultBinKey, len(resultBinText[0]))

	return resultBinText, resultBinKey, roundsOfEncryption

def khafreEncryption(block, round = 8):
	roundNumber = 8 - round
	changedLeftBlock = process_left_block(block[0], roundNumber)
	xorRightAndChangedLeft = xorBinOperation(changedLeftBlock, block[1])
	shiftAmount = 0

	if roundNumber == 2 or roundNumber == 3:
		shiftAmount = 8
	elif roundNumber == 6 or roundNumber == 7:
		shiftAmount = 24
	else: 
		shiftAmount = 16

	leftBlock = cyclic_left_shift(block[0], shiftAmount)
	
	resultedBlock = [xorRightAndChangedLeft, leftBlock]
	if(roundNumber == 1):
		return resultedBlock
	return khafreEncryption(resultedBlock, round-1)



def KhafreCipher():
	binTextToEncrypt, binKey, rounds = enterValue()
	print(f"Text: {binTextToEncrypt}\n\nKey: {binKey}")

	for i in range(len(binTextToEncrypt)):
		for j in range(len(binTextToEncrypt[i])):
			binTextToEncrypt[i][j] = xorBinOperation(binTextToEncrypt[i][j], binKey[j])

	print(binTextToEncrypt)

	for _ in range(rounds):
		for i in range(len(binTextToEncrypt)):
			binTextToEncrypt[i] = khafreEncryption(binTextToEncrypt[i])
			for j in range(len(binTextToEncrypt[i])):
				binTextToEncrypt[i][j] = xorBinOperation(binTextToEncrypt[i][j], binKey[j])
	
	encryptedString = binTextToString(binTextToEncrypt)

	return encryptedString
	






# enterValue()
result = KhafreCipher()
print(result)		

	
# openedText = 'ORIGINAL'

# Key = ''.join(str(random.randint(0,1)) for i in range(64))

# binOpenedText = ''.join(bin(int(ord(char)))[2:] for char in openedText)

# print(f"\nOpenede text -> {openedText}\n")
# print(f"text in binary -> {binOpenedText}\nblock len -> {len(binOpenedText)}\n")

# block = addBitesToBlock(binOpenedText)
# print(f"block -> {block}\nblock len -> {len(block)}\n")
# permutatedBlock = permutate(block, tables.IP_table)

# print(f"permutated block -> {permutatedBlock}\nblock len -> {len(permutatedBlock)}\n")
# encryptedBlock = encrypt(permutatedBlock, Key)

# print(f"encrypted block -> {encryptedBlock}\nblock len -> {len(encryptedBlock)}\n")

# finallyPermutatedBlock = permutate(encryptedBlock, tables.finalIP_table)

# print(f"finally permutated block -> {finallyPermutatedBlock}\nblock len -> {len(finallyPermutatedBlock)}\n")


