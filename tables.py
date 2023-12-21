IP_table = [
	58, 50, 42, 34, 26, 18, 10, 2,
   60, 52, 44, 36, 28, 20, 12, 4,
   62, 54, 46, 38, 30, 22, 14, 6,
   64, 56, 48, 40, 32, 24, 16, 8,
   57, 49, 41, 33, 25, 17, 9, 1,
   59, 51, 43, 35, 27, 19, 11, 3,
   61, 53, 45, 37, 29, 21, 13, 5,
   63, 55, 47, 39, 31, 23, 15, 7
]

finalIP_table = [
	40, 8, 48, 16, 56, 24, 64, 32,
   39, 7, 47, 15, 55, 23, 63, 31,
   38, 6, 46, 14, 54, 22, 62, 30,
   37, 5, 45, 13, 53, 21, 61, 29,
   36, 4, 44, 12, 52, 20, 60, 28,
   35, 3, 43, 11, 51, 19, 59, 27,
   34, 2, 42, 10, 50, 18, 58, 26,
   33, 1, 41, 9, 49, 17, 57, 25
]

extendsE_table = [
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17, 
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
]

sBoxs = [
	[['48', 'a3', '17', '1a', '47', '64', 'b7', 'd9', '21', 'cf', '53', '23', 'c2', 'e3', 'bc', 'ac', '37', 'bb', 'c5', 'f4', '31', 'a8', '16', 'f2', '75', '5f', 'd2', '3d', '63', '1e', '33', '14'],
   ['55', '7b', '76', 'de', '5a', '7d', 'e2', 'd1', 'b3', 'd', 'a0', '65', '68', '8d', '96', '60', '3f', 'e1', '72', '3b', 'b6', 'd6', 'ad', '5d', 'f9', '69', 'd5', '26', '5e', '3', '70', 'cc'],
	['25', 'e7', '41', '79', 'ce', 'fa', 'dd', 'b5', '5b', 'f0', 'd0', '67', 'f7', 'fd', 'ca', 'b9', '3e', '32', '2', '4d', 'a5', '57', '6f', 'bf', '94', 'c1', '49', 'be', 'd8', '6c', 'e9', '62'],
	['83', '8a', 'fb', '7a', '61', 'c4', 'ec', '18', '9c', '22', 'b0', 'e', '85', '8c', '39', 'c6', 'a6', 'e4', '0', '66', 'a7', 'a2', '2f', '42', 'db', 'f3', 'c8', '98', '34', '13', '8b', '93'],
	['e0', '1c', '87', '54', '7e', '9b', 'f6', '74', '19', 'a9', '1b', '29', '44', '80', 'ea', '3c', '4f', 'ef', '7', '9e', '6d', '3a', 'fe', '11', 'eb', '73', '84', '1d', '20', 'f', '1f', '38'],
	['f8', 'c0', '46', '24', 'e8', 'bd', '6e', '45', '4c', '7c', 'a1', 'd7', '71', '78', '9', '6b', '9f', '9d', '2e', '59', 'f1', '89', 'e5', '2b', '12', '7f', '95', '56', 'c', '8f', 'cd', '5c'],
	['58', '10', '90', '35', 'dc', '2d', 'a4', '97', 'c3', '1', '77', 'ab', '99', '4e', 'f5', 'b1', 'ba', 'ee', 'ff', '92', 'c9', 'da', 'd3', 'fc', '86', '52', '40', 'ed', 'af', '8', 'df', '43'],
	['51', '2c', '4b', '5', '91', 'e6', '2a', '8e', '36', '4', 'cb', 'd4', 'a', '50', '15', 'b8', '30', '28', '6a', 'b2', 'b', 'aa', 'c7', '6', '4a', '88', '81', '82', '9a', 'b4', '27', 'ae']],
	[['a8', '13', '85', '78', 'c8', '1f', 'ff', '63', 'ed', '1d', 'e4', '55', 'ba', '35', 'd8', 'ea', '96', '77', '10', '60', 'e1', 'b3', '57', '30', 'a6', '84', 'cb', 'a4', '4', '8d', '93', '32'],
  ['3d', '31', '62', 'e2', 'ef', '45', '8a', 'b', '8e', '2f', 'e5', '51', 'b1', 'f8', 'c2', '65', '94', '8c', '11', '38', '83', '44', '3c', '2', '36', '5e', '2e', '66', '8', '33', 'e3', 'a1'],
  ['ab', '50', 'c1', '24', '26', '46', '5a', '91', '76', 'f2', '61', 'd3', '5c', '9a', '2d', 'b7', 'ca', 'e', '37', '90', '17', '99', '64', '9c', '7a', '87', '14', 'b2', '54', '7e', 'd0', '29'],
  ['ec', '58', '97', '5d', 'da', '42', 'fd', '82', '48', '88', '9', 'af', 'e8', '2a', 'b0', '18', '71', 'd5', 'c7', '39', 'f', 'a', '8f', '2b', '9d', 'b6', '15', '3f', '1a', '0', 'd4', '1'],
  ['f5', 'd7', '89', 'fe', '5', 'b4', 'be', '69', '74', '4b', 'b9', 'cc', '16', '81', '4e', '2c', '47', '25', '56', 'fb', '73', 'c3', 'bb', '6f', '9f', '9b', '12', 'e6', '3e', 'f0', '27', '6a'],
  ['68', 'b8', 'a3', 'e7', '7', 'aa', 'f1', '3a', 'e9', '75', 'f4', '52', 'b5', '1e', '28', '59', '72', 'a2', 'c4', 'f7', '22', 'e0', 'a9', 'f6', 'df', '9e', 'c9', 'd9', 'cd', '98', '80', 'bc'],
  ['1c', '4f', 'bf', 'eb', '4a', '43', 'f9', '3b', '19', 'fa', '53', 'a5', '6e', '3', '7f', 'd1', 'ad', '5f', '7b', 'c0', 'ae', '7c', '4d', '4c', '70', '40', '6', 'ac', '20', '21', 'c', 'de'],
  ['79', 'db', '34', 'd', '86', '23', '8b', '6d', '95', 'f3', '7d', '67', 'ce', '49', '1b', 'a7', '6c', '92', 'dd', 'a0', 'ee', 'c5', '6b', 'dc', 'c6', 'd2', 'cf', '5b', 'd6', 'bd', '41', 'fc']],
  [['3a', 'd1', '61', '22', '3f', 'a2', '66', '49', '71', '74', '75', '4f', '1e', '1c', 'de', 'eb', 'bd', 'f8', 'f1', '7e', '79', '46', '83', '7f', '91', '8c', 'b8', '3c', '9c', '55', '29', 'd3'],
	['aa', 'ce', '77', 'd5', 'fa', '48', '0', 'dc', '9b', 'c9', '7', '9a', 'd0', 'fc', '42', '93', '2e', '14', 'ec', 'fe', 'e9', 'fd', '4', '58', 'd4', '4e', '92', 'c5', '2', 'd9', '36', '9'],
	['e7', 'b2', '54', 'ab', '1d', 'c7', '13', '4c', 'c4', 'c2', 'a1', 'af', '50', 'e1', 'a9', '3', '38', 'cb', '43', '7b', '7d', '76', '23', 'b', 'f3', 'bb', '82', 'b1', '98', 'f0', 'e8', '7c'],
	['ad', '15', '2a', '18', 'd', '41', '10', '25', '5b', 'a5', '99', 'e6', '96', 'f7', '8d', '32', 'a8', '85', '70', '89', '40', '52', 'a7', 'f4', '88', '68', 'db', '2d', '8a', '86', 'a6', 'ea'],
	['73', '90', '4a', 'ba', '27', 'e0', '2f', 'f2', 'df', '81', '11', '62', '5e', '6f', 'f', '69', 'ff', '2c', '7a', 'd6', 'ed', '2b', '34', '17', '30', '72', '78', 'ac', 'a', 'ee', '87', 'd2'],
	['24', 'c', '31', '45', '63', '26', 'b4', '3d', 'a3', 'b7', 'c8', 'b5', '80', '5d', '5', '1b', 'e2', 'c6', '1f', '6e', 'a4', '94', '39', '5c', '6c', 'b3', '3b', 'be', 'e5', '84', 'c3', 'b9'],
	['b6', '47', '9e', '8f', '53', '44', '59', '56', 'cf', '97', 'cd', 'f6', 'da', 'b0', 'fb', 'ca', '19', '4d', '8b', '6d', 'f5', '12', 'ef', '9f', '9d', '37', '1a', '4b', '5a', 'ae', 'd8', '5f'],
	['6a', '60', '67', 'd7', '35', '33', '8', 'c1', 'bc', '16', '21', 'f9', 'dd', '3e', 'a0', '57', '65', '51', 'e', '95', '1', 'c0', '6', 'e4', 'bf', 'e3', '64', '28', '20', '8e', '6b', 'cc']],
	[['30', '8f', '80', '99', '7a', '4a', '54', '18', '13', 'ec', '15', 'f4', '98', '33', 'd9', '19', 'cd', 'c4', 'c5', '64', '8', '59', '90', 'a', 'f', '8b', '12', '38', 'c6', 'eb', '28', '1e'],
  ['2e', 'f2', '68', '17', 'f5', 'ad', '41', '53', 'c8', 'c9', '4b', '9e', 'ca', '23', 'bf', 'b5', '9b', 'a5', '47', 'c3', '56', 'af', '88', 'b8', '1a', 'd0', '4c', 'bd', '11', 'a6', '4d', 'cc'],
  ['2b', 'dc', '84', 'b0', '60', '78', '24', '73', '3e', 'e5', '50', '67', 'f3', 'fa', 'd', 'e8', '32', '79', '69', '89', 'db', '65', 'c0', '55', '66', '10', 'b7', 'ee', 'bb', 'aa', '87', 'a9'],
  ['da', 'c1', '1f', 'c2', 'b3', '70', 'f9', '40', '51', '26', 'b6', '85', '52', '76', '3', '49', 'f0', 'be', 'ff', '20', '36', '9', '2f', '2c', 'ed', 'a0', '77', '7e', '7', '6f', 'a4', '94'],
  ['58', 'd8', '97', '74', '9d', 'fb', 'e4', 'bc', '8c', '35', '37', '29', '3f', 'dd', 'cb', '86', '2a', '1', '27', '2d', 'c', '1c', '3d', '25', 'd3', '91', '63', 'd7', '9a', '2', '5e', 'b1'],
  ['5c', '5f', '95', 'ba', '7d', '62', 'a2', '4f', 'c7', 'e2', 'f8', 'ae', '82', '1d', '6b', '6e', '7c', 'cf', '5d', 'fd', '43', 'a3', '96', '8d', 'b4', 'e1', '48', '3c', 'a8', '5b', 'ac', '3b'],
  ['92', 'd5', '14', '6a', 'd4', 'e0', 'd6', '7b', 'b9', '39', 'd1', 'a1', '0', 'b2', '45', '5', 'e9', '61', '46', '72', '6c', '81', '6d', '57', 'e7', 'f6', '8e', 'fc', '5a', '4e', '9f', '8a'],
  ['df', '16', '44', 'ce', '21', '83', 'e3', '75', '34', '31', 'ef', '42', 'f7', '7f', 'b', 'e6', '22', 'ea', 'e', '9c', 'fe', 'a7', 'de', '4', 'd2', '93', 'f1', '3a', '1b', 'ab', '71', '6']],
  [['ad', '94', '75', '17', '68', 'd1', '7e', 'aa', 'd3', 'c', '34', 'e7', 'c3', '95', '83', 'c6', '5', '5b', '2d', '14', '30', '1e', '48', '88', '1d', '52', '1b', 'a5', 'ec', '4a', 'e4', 'b6'],
	['fa', 'da', 'fc', 'b7', '4b', '74', 'f7', 'a3', 'cb', '97', 'c7', '54', '19', '53', '2b', '5a', '3b', 'fd', 'f1', '26', '77', '47', '21', '3d', '8', 'cd', 'ab', 'd8', '2f', 'a2', 'bd', '84'],
	['93', '89', '73', '45', 'e5', '3', '23', '31', 'f9', '85', '7c', 'df', '91', '41', '13', 'c9', 'a8', '5e', '1f', 'e8', 'cc', '25', '8f', '3f', 'b2', 'd2', 'e2', 'fe', 'd0', '6a', '1a', '44'],
	['9e', '98', '76', '64', 'a7', '46', 'ef', '43', '4f', 'a6', '65', '9a', '29', '1c', '8e', '10', 'a1', '90', '4c', 'b', '2e', 'd', '6b', 'c5', 'ba', 'c2', 'b9', 'be', 'ac', 'a4', '51', '8c'],
	['32', '7b', '6d', 'cf', 'd7', '16', '9b', '3c', '62', 'de', '67', 'd4', 'e3', '40', 'f6', '56', '2', '60', '55', 'f3', '92', '50', 'db', '49', '12', '6e', '9', 'c0', '0', 'f0', '1', '5d'],
	['7a', '6f', '37', '96', 'd5', 'fb', '7', '2c', 'e9', 'bf', 'ae', '59', '72', '2a', '70', 'e6', '58', 'e0', 'c8', '9d', 'ca', 'c4', '99', '5c', '15', '33', 'af', 'b8', 'bc', 'ed', 'f2', '11'],
	['38', 'e1', 'a', '71', '27', 'dc', '22', '3e', '66', '6', 'f5', 'ea', 'c1', 'a0', 'ee', 'f', 'b0', '18', '4d', 'f8', '80', 'b1', '8a', '87', '3a', '28', '69', '9f', '8d', '63', 'dd', 'b4'],
	['f4', '7f', '24', 'bb', '20', '79', '61', 'ff', '4e', 'a9', '81', '6c', '39', '4', '8b', 'ce', '42', 'e', '82', 'b5', '57', '36', '5f', '78', 'd9', '7d', 'b3', '9c', 'eb', '35', '86', 'd6']],
	[['e9', '56', 'cb', '7b', '4c', '32', 'ba', 'e6', 'b5', 'f1', 'ab', 'bf', 'ee', '30', '6b', '72', 'ed', 'e1', '51', 'c1', 'a6', 'a1', 'd', 'fd', '86', 'eb', '35', 'd4', 'e4', 'b6', '7c', '46'],
  ['1a', 'c7', '7f', '40', 'c2', '95', 'ce', '8c', '0', '5b', '19', 'ef', 'bc', 'f2', '11', '6', 'f5', '48', 'e2', '73', '59', '94', 'd7', '66', '64', '45', '2d', '39', '3f', '9a', '5c', '60'],
  ['d1', '12', 'f4', '25', 'c5', '3e', '53', 'd2', '81', 'fc', 'b9', '6e', '68', 'd9', '96', '1d', 'cf', '36', '10', 'fe', 'db', '14', 'fb', '27', 'ea', '9b', '74', '9d', '87', 'dc', '54', '90'],
  ['15', 'c6', '6d', '93', 'a8', 'b7', 'd3', 'a4', '4b', 'a3', '83', 'd6', '82', 'c9', 'a', '61', 'a7', 'cc', '3b', '8', '18', '8f', 'c0', '31', 'e0', '88', 'f8', '91', '2b', 'c4', 'a9', 'ae'],
  ['97', '1', 'ec', '3a', '78', 'e', 'a0', '3c', 'd0', 'a5', 'ac', 'e3', '4', '6c', '50', 'c', 'cd', '2e', '8a', '41', 'b4', '85', '2', 'dd', '1c', '33', '34', '98', '80', 'af', '29', '79'],
  ['62', '2a', '9', 'c8', 'de', 'b0', 'f7', 'bb', '58', '8e', '5a', '5d', '75', '24', '84', '4d', '17', '13', '49', 'aa', 'be', '43', 'd8', '22', '1e', 'da', 'ad', 'fa', '44', '69', '8b', '7e'],
  ['70', '76', 'b', 'b2', '57', 'b8', 'b3', '2f', 'e8', '4e', '9e', '3', '92', '77', '16', 'df', '65', '63', 'e5', '9c', '21', '1f', '37', 'c3', '99', 'f0', '89', '6f', '7', 'd5', '28', 'ff'],
  ['a2', '42', '55', '2c', '38', '6a', '4a', '8d', '52', 'f', 'b1', '47', '5', '5f', '5e', 'ca', '23', '67', '7a', '7d', 'f6', '3d', '1b', '71', 'e7', 'bd', '26', 'f9', '9f', '20', 'f3', '4f']],
  [['ad', 'e4', '6f', 'b4', '90', '50', '9e', '62', '64', 'a2', '1d', 'b1', 'de', 'c4', '60', 'fc', 'f4', 'c3', 'b3', 'fe', '92', 'ea', '42', '4f', 'e0', '5c', 'e2', '1', '7f', '2d', 'c2', 'ba'],
	['0', '3e', '32', 'd2', 'e', 'a6', '9c', 'df', '11', '13', '24', 'a4', '5d', '88', '55', 'a', 'ab', '2f', '70', '25', '39', 'a7', '43', 'ee', '2', 'fb', '86', '93', '47', '78', '76', 'd8'],
	['6b', '8', '30', 'a8', '27', '59', '1c', '26', '6d', 'c5', 'cb', '14', 'f9', 'e8', '7a', '20', 'b5', '1f', '10', '9', 'c8', '1a', 'bd', '35', '41', 'e1', '7b', 'd5', 'c1', 'eb', '52', '6a'],
	['2c', '4d', 'bb', '73', '67', '16', 'ce', '2b', '4e', '8b', 'd4', 'f1', 'a5', '40', '77', '5f', '18', '7d', '8c', '81', 'ed', '29', 'a1', 'd', '6e', 'e6', 'd1', '72', 'af', '5', 'ec', '15'],
	['69', '19', 'ac', 'c', '9d', '84', 'f3', '87', '89', 'fd', '8e', 'b2', 'ff', '7e', '4c', 'f0', 'a0', 'b6', '4', 'd6', 'f6', 'b0', '95', '8d', '68', 'b', '7c', 'f5', '56', '46', '2e', '17'],
	['28', 'c0', '63', 'da', '37', 'c9', '8a', '34', 'f', '80', '66', '6c', 'd0', '12', 'f2', '91', 'db', '3d', '9b', 'b7', '75', 'd7', 'ef', 'dd', 'a3', '36', '2a', '3c', 'e7', '79', '5b', 'b9'],
	['83', 'cc', 'a9', '6', '22', '57', '71', '31', 'e9', '8f', '53', '4a', 'c7', '58', '1b', 'd3', '48', '38', '3f', '5a', '99', 'c6', '51', '49', '7', '44', '9a', 'f8', 'f7', '33', 'bf', 'bc'],
	['96', 'ae', 'be', '9f', '85', 'cf', '65', '5e', '1e', '4b', 'aa', '98', '3', '21', '45', 'e5', 'ca', '74', 'd9', '61', '54', 'b8', '3a', '82', '3b', 'dc', '94', '97', '23', 'fa', 'cd', 'e3']],
	[['9', 'be', '6c', 'ab', '87', 'e6', '89', '1e', '77', '57', 'a0', '62', '68', '9c', '59', 'fb', '24', '2e', '7b', 'b8', '2f', '88', 'aa', 'a7', '7d', '76', 'fc', '8d', '94', 'd5', '92', '96'],
  ['a4', '6a', '48', 'c', '83', '98', 'f7', 'ca', '69', 'e', 'c7', '2a', '4d', 'dd', 'fe', '5', 'e7', 'a', '22', '99', 'b2', '9d', '1a', '23', '75', '8b', '5a', '15', '46', 'bc', '70', '2c'], ['e2', '93', '49', '63', '8e', '67', '2b', 'ef', '41', '30', 'fd', '7f', 'f3', '9f', '65', '6f', '8c', 'bd', '26', '1c', '3e', '4b', 'b6', 'cf', '51', 'f6', 'b1', '5f', 'f5', '61', '9b', '60'], ['e1', '4e', '97', '3', '86', 'b4', '64', 'd3', 'a3', 'dc', '2d', 'd7', '42', '11', '5d', '71', 'fa', '6d', '7', 'd2', '3d', '54', 'b0', '13', '29', '78', '74', 'b7', '81', '1', '7e', '27'], ['55', 'b', 'c8', '50', '90', '79', '28', '4', '17', 'ad', 'b5', '66', '1b', 'e0', 'bf', 'f0', '25', 'cb', '19', '52', 'ff', 'd9', '5b', 'd6', 'a6', 'f8', '16', '45', 'b3', '34', 'd1', '6b'], ['43', '58', 'f2', 'c1', '4a', '12', 'a2', '5e', 'ae', '73', 'a5', 'ea', 'e5', '7c', '4c', 'a1', '72', 'da', '4f', '8a', '1d', 'ac', '38', 'f', '31', 'db', '44', '47', '33', 'f9', 'ce', 'c0'], ['80', 'b9', '14', '32', '9e', '3a', 'ed', 'f1', 'c6', '39', '6', 'd8', 'cc', 'c2', '82', 'a9', '9a', '21', '8f', 'eb', 'f4', '3c', 'd4', 'af', 'e8', 'bb', '8', '20', '7a', '53', 'd0', 'de'], ['c3', '18', 'e3', 'e9', 'd', 'df', '95', '35', '3f', '1f', 'e4', 'c4', '85', 'a8', '5c', '36', '91', '10', '40', 'c9', '3b', 'ee', '2', '6e', '37', 'ec', 'c5', '84', '56', 'ba', '0', 'cd']]
]

keyPermutation_table = [
	[57, 49, 41, 33, 25, 17, 9,
	 1, 58, 50, 42, 34, 26, 18,
	 10, 2, 59, 51, 43, 35, 27,
	 19, 11, 3, 60, 52, 44, 36
  	 ],
	[63, 55, 47, 39, 31, 23, 15,
  	 7, 62, 54, 46, 38, 30, 22,
	 14, 6, 61, 53, 45, 37, 29,
	 21, 13, 5, 28, 20, 12, 4]
]


keyPermutateShrinkMatrix = [
	14, 17, 11, 24, 1, 5, 
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
]