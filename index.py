import numpy as np
# Initial Permutation table
import tables
import sBoxs
import random

BLOCK_LENGTH = 64
KEY_LENGTH = 64
HALF_BLOCK = round(BLOCK_LENGTH/2)

sBoxTable = tables.sBoxs

# rgr

# basic function to work with text
def textToBin(text):
	return ''.join(format(ord(char), '08b') for char in text)

def binToText(binary):
    # Split the binary string into 8-bit chunks
	while len(binary) >= 8 and binary[-4:] == '0000':
		binary = binary[:-4]

	chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]

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
		encryptedText += str(int(text[i]) ^ int(key[i]))

	return encryptedText

def cyclic_left_shift(bits, shift_amount):
    return bits[shift_amount:] + bits[:shift_amount]

def cyclic_left_shift_revers(bits, shift_amount):
    return bits[round(len(bits)-shift_amount):] + bits[:round(len(bits)-shift_amount)]

# function to devide one block into sub-blocks
def divideBlockBy2(block):
	if(round(len(block)) != BLOCK_LENGTH):
		raise Exception("Error: func 'divideBlockBy2' -> len of block is not 64 bites")
	
	resultBlock = [block[i:i+HALF_BLOCK] for i in range(0, round(len(block)), HALF_BLOCK)]
	return resultBlock

def process_left_block(last_8_bits, octet_index):
	# for each iteration used different sBox table
	selected_sbox = sBoxTable[octet_index]
	output_bits = []
	for i in range(0, len(last_8_bits), round(len(last_8_bits)/4)):
		sbox_row = last_8_bits[i:i+3] 
		sbox_col = last_8_bits[i+3:i+8] 
		output_bits.extend(bin(int(selected_sbox[int(sbox_row, 2)][int(sbox_col, 2)], 16))[2:].zfill(8))
	returnedBlock = ''.join(output_bits)

	return returnedBlock

def reverse_process_left_block(value, octet_index):
	selected_sbox = sBoxTable[octet_index]
	output_bits = []

	for i in range(0, len(value), round(len(value)/4)):
		searchedValue = value[i:i+8] 

		for row_index, row in enumerate(selected_sbox):
			for col_index, element in enumerate(row):
				if element == hex(int(searchedValue, 2))[2:]:
					output_bits.append(format(row_index, '03b')+format(col_index, '05b'))
	
	returnedBlock = ''.join(output_bits)

	return returnedBlock



def binTextToString(blocks):
	# Concatenate all the blocks and remove any trailing zeroes
	concatenated = ''
	 
	for block in blocks:
		for part in block:
			concatenated += ''.join(part)
	# Trim excess bits if the length is not a multiple of 8
	concatenated = concatenated[:-(len(concatenated) % 8)] if len(concatenated) % 8 != 0 else concatenated
	# Convert the concatenated binary string back to text
	return binToText(concatenated)

def binTextToHex(block):
    resultedHex = ''
    if isinstance(block[0], list):
        for subBlock in block:
            for part in subBlock:
                resultedHex += hex(int(part, 2))[2:]
    elif isinstance(block[0], str):
        for part in block:
            resultedHex += hex(int(part, 2))[2:]
    
    return resultedHex

def hexToBinText(hexString):
    binText = ''
    for hexChar in hexString:
        binText += bin(int(hexChar, 16))[2:].zfill(4)
    return binText







def enterValue(isHexInputValue = False):
	# textToEncrypt = str(input('Enter text to encrypt:'))
	# key = str(input('Enter key:'))
	# roundsOfEncryption = str(input('Enter number of encrypting rounds:'))
	roundsOfEncryption = 1
	textToEncrypt = "Oleksii" if not(isHexInputValue) else "fbfc5201adca1ef5"
	key = "Shevchenko"
	
	print("Text:", textToEncrypt)
	print("Key:", key)

	if not(isHexInputValue):
		binText = textToBin(textToEncrypt)
		binKey = textToBin(key)
	else:
		binText = hexToBinText(textToEncrypt)
		binKey = textToBin(key)

	print("\nbinText:", binText, len(binText))
	print("binKey:", binKey, len(binKey))

	# here we entered value to exact length
	if(len(binText) > 64):
		binText = chunk_into_64_bits(binText)
	elif len(binText) < 64:
		binText = [zero_pad(binText)]
	else:
		binText = [binText]
	if(len(binKey) > 64):
		binKey = [chunk_into_64_bits(binKey)[0]]
	elif len(binKey) < 64:
		binKey = [zero_pad(binKey)]
	else:
		binKey = [binKey]

	# next loop divides text with 64 bites length to two 32 length blocks
	resultBinText = []
	for binPart in binText:
		resultBinText.append(divideBlockBy2(binPart))
	
	resultBinKey = divideBlockBy2(binKey[0])

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
	if(round == 1):
		return resultedBlock
	return khafreEncryption(resultedBlock, round-1)



def KhafreCipher():
	binTextToEncrypt, binKey, rounds = enterValue()

	print(binTextToEncrypt)

	for i in range(len(binTextToEncrypt)):
		for j in range(len(binTextToEncrypt[i])):
			binTextToEncrypt[i][j] = xorBinOperation(binTextToEncrypt[i][j], binKey[j])

	print(f"After Xor: {binTextToEncrypt}")

	for _ in range(rounds):
		for i in range(len(binTextToEncrypt)):
			binTextToEncrypt[i] = khafreEncryption(binTextToEncrypt[i])
			for j in range(len(binTextToEncrypt[i])):
				binTextToEncrypt[i][j] = xorBinOperation(binTextToEncrypt[i][j], binKey[j])
	
	encryptedString = binTextToHex(binTextToEncrypt)

	return encryptedString
	






# enterValue()
result = KhafreCipher()
print(result,"\n\n")		

def khafreDecryption(block, round=0):
	roundNumber = 7-round
	shiftAmount = 0

	if roundNumber == 2 or roundNumber == 3:
		shiftAmount = 8
	elif roundNumber == 6 or roundNumber == 7:
		shiftAmount = 24
	else:
		shiftAmount = 16

	xoredRightAndChangedLeft = block[0]
	reversedShiftedLeftBlock = cyclic_left_shift(block[1], -shiftAmount)

    

	changedLeftBlock = process_left_block(reversedShiftedLeftBlock, roundNumber)

	# Perform the reverse XOR operation
	rightBlock = xorBinOperation(xoredRightAndChangedLeft, changedLeftBlock)

	if round == 7:
		return [reversedShiftedLeftBlock, rightBlock]

	resultedBlock = [reversedShiftedLeftBlock, rightBlock]
	return khafreDecryption(resultedBlock, round + 1)


def khafreDecipher():
	binTextToDecrypt, binKey, rounds = enterValue(True)
	print(f"\n\nbinTExt: {binTextToDecrypt}\nbinKey: {binKey}")
	# Perform steps to retrieve binTextToEncrypt and binKey
	# ...
	# Reverse the encryption process

	for _ in range(rounds):
		for i in range(len(binTextToDecrypt)):
			for j in range(len(binTextToDecrypt[i])):
				binTextToDecrypt[i][j] = xorBinOperation(binTextToDecrypt[i][j], binKey[j])
			binTextToDecrypt[i] = khafreDecryption(binTextToDecrypt[i])

		print(f"before xor: {binTextToDecrypt}")



	for i in range(len(binTextToDecrypt)):
		for j in range(len(binTextToDecrypt[i])):
			binTextToDecrypt[i][j] = xorBinOperation(binTextToDecrypt[i][j], binKey[j])

	# Convert the decrypted binary text back to a string
	print(binTextToDecrypt)
	decryptedString = binTextToString(binTextToDecrypt)
	return decryptedString


decryptedResult = khafreDecipher()
print(decryptedResult)	