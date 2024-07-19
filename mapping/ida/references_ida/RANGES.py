

img_base = 0x00400000
code_min_rva = 0x00001000
code_max_rva = 0x0026C000  # data start
data_max_rva = 0x003B3000


def in_data(va):
  data_min = img_base + code_max_rva
  data_max = img_base + data_max_rva
  return data_min <= va < data_max


def in_code(va):
  code_min = img_base + code_min_rva
  code_max = img_base + code_max_rva
  return code_min <= va < code_max

