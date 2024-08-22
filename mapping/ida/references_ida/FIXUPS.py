from . import RANGES


NOT_RELOCS = {
  0x004C014E,
  0x00509A6A,
  0x00566C80,
  0x005908FF,
  0x00647D17,
  0x00647F27,

  0x00664ABA,
  0x00664ABE,
  0x00664AC2,
  0x00664AC6,
  0x00664ACA,
  0x00664ACE,
  0x00664AD2,

  0x00675D45,
  0x00675D85,
  0x00675FC5,
  0x00675FD1,
  0x00676005,
  0x00676011,
  0x0067616D,
  0x006761AD,
  0x006761CD,
  0x0067620D,
  0x00678943,
  0x00679F37,
  0x0067A043,
  0x0067A14F,
  0x0067B283,
  0x0067B287,

  0x0068E564,

  0x00691552,
  0x00694078,
  0x0069412A,
  0x00694150,
  0x006941EA,
  0x00694258,
  0x006942C2,
  0x00694330,

  0x0069E4A6,

  0x006A6D40,
  0x006A74F6,
  0x006A99F6,
  0x006AB255,
  0x006AD200,
  0x006AE278,

  0x006AFD52,
  0x006B0032,
  0x006B0386,
  0x006B0666,

  0x006B2A2C,
  0x006B2EC0,
  0x006B3230,
  0x006B5938,
  0x006B854E,
  0x006B85C2,
  0x006B87A6,
  0x006B881A,
  0x006B89FE,
  0x006B8C56,
  0x006B8CCA,

  0x006BAE44,
  0x006BAE48,
  0x006BAE54,
  0x006BAE58,
  0x006BAE64,
  0x006BAE68,
  0x006BAE74,
  0x006BAE78,

  0x006BD276,
  0x006BD2A6,
  0x006BDEB0,
  0x006BF138,

  0x006BF756,
  0x006BF9C6,
  0x006BFB02,

  0x006C161B,
  0x006C167F,
  0x006C168F,
  0x006C16A7,
  0x006C16AB,
  0x006C16BB,
  0x006C2253,
  0x006C2263,
  0x006C2267,
  0x006C227F,
  0x006C228F,
  0x006C22F3,
  0x006C361B,
  0x006C367F,
  0x006C368F,
  0x006C36A7,
  0x006C36AB,
  0x006C36BB,

  0x006C3FFA,
  0x006C5662,

  0x006C5B1B,
  0x006C5BB7,
  0x006C5C3F,
  0x006C5C6B,
  0x006C60D2,
  0x006C60EA,
  0x006C616A,
  0x006C68D2,
  0x006C68EA,
  0x006C696A,

  0x006C97F6,
  0x006C9A82,
  0x006CBD0C,
  0x006CBD2C,

}


FORCE_RELOCS = {
  0x00519968,
  0x00531EDC,
  0x0053B730,
  0x0053C394,
  0x0057BE44,
  0x0057BFC5,
  0x0057C11F,
  0x00635AC4,
  0x00635C4C,

  0x00635CD4,
  0x00635CD8,
  0x00635CDC,
  0x00635CE0,
  0x00635CE4,
  0x00635CE8,
  0x00635CEC,

  # 0x0063A98D,
  # 0x0063A9A4,
  # 0x0063A9D6,

  0x0063BA0C,
  0x0063BA24,

  0x00655298,

}


def is_known_custom_code(va, val):
  if (val & 0xFFFFFF00) == 0:
    return True
  if (val & 0xFFFFFF00) == 0x66666600:
    return True
  if (val & 0xFFFFFF00) == 0x55555500:
    return True
  if (val & 0x0FFFFFFF) == 0x0149F2CA:
    return True
  if (val & 0xFFFF0000) == 0:
    return True
  if (val & 0xFFF00000) == 0x3E400000:
    return True
  if (val & 0xFFF00000) == 0x3F400000:
    return True
  if (val & 0xFFF00000) == 0x3D400000:
    return True
  if (val & 0xFFFF0000) == 0x88760000:  # DDERR_??????
    return True
  if (val & 0x0000FFFF) == 0:
    return True
  if (val & 0x0000FFFF) == 0x00004642:  # '??FB'
    return True
  if val == 0xE06D7363:  # '\xE0msc'  EXTERNAL_EXCEPTION
    return True
  if val == 0x56433230:  # 'VC20'
    return True
  if val == 0x5641524D:  # 'VARM'
    return True
  if val == 0x42465350:  # 'BFSP'
    return True
  if val == 0x42465744:  # 'BFWD'
    return True
  if val == 0x42463446:  # 'BF4F'
    return True
  if val == 0x5A4C4942:  # 'ZLIB'
    return True
  if val == 0x54534642:  # 'TSFB'
    return True
  if val == 0x49524642:  # 'IRFB'
    return True
  if val == 0x4D554642:  # 'MUFB'
    return True
  if val == 0x4147FFFF:
    return True
  if val == 0x4150017E:
    return True
  if val == 0x10624DD3:
    return True
  if val == 0x1B4E81B5:
    return True
  if val == 0x92492493:
    return True
  if val == 0x71625345:
    return True
  if val == 0x326496C9:
    return True
  if val == 0x32595559:
    return True
  if val == 0x3C6EF35F:
    return True
  if val == 0x07861F80:  # time const __loctotime_t
    return True
  if val == 0x7C558180:  # mul const gmtime
    return True
  if val == 0xF879E080:  # mul const gmtime
    return True
  if val in [
    0x6C434353,
    0x6C444353,
    0x6C454353,
    0x6C484353,
    0x6C4C4353,
    0x6B564754,
    0x684E5331,
    0x6D44414D,
    0x6B44414D,
    0x66564754,
    0x6656554D,
    0x654E5331,
    0x644E5331,
    0x6544414D,
    0x5447566B,
    0x54514970,
    0x54475170,
    0x54475666,
    0x53434C6C,
    0x534E4443,
    0x5343446C,
    0x5343486C,
    0x4D41446B,
    0x5343436C,
    0x444E4553,
    0x4D414465,
    0x43444E53,
    0x44414553,
    0x684E5331,
    0x6C484353,
    0x5041554C,
    0x00405008,  # dx caps
  ]:
    return True
  return True  # all data is known?

trusted_suspicious_data_ref = {
  0x00519968,
  0x00655298,
  0x0066D5B4,
  0x0066E6B0,
  0x0066ECD0,
  0x0066EE20,
  0x0066F0A4,
  0x0066F3A0,
  0x0066F3D8,
  0x00671B33,
  0x0067B790,
  0x0067B7F0,
  0x0067BB48,
  0x0067CF90,
  0x0067CFD4,
  0x0067E1E0,
  0x0067E22C,
  0x0067F178,
  0x0067F1C4,
  0x00686FE8,
  0x0068E040,
  0x0068E218,
  0x0069106E,
  0x006A1EFA,
  0x006A2134,
  0x006A213C,

  0x006AD906,
  0x006AD956,
  0x006AD9A6,
  0x006AD9F6,
  0x006ADA46,
  0x006ADB36,
  0x006ADB86,
  0x006ADBD6,
  0x006ADC26,
  0x006AE278,

  0x006B220E,
  0x006B2EC0,
  0x006B3230,
  0x006B5938,
  0x006B5CEE,
  0x006B854E,
  0x006B85C2,
  0x006B87A6,
  0x006B881A,
  0x006B89FE,
  0x006B8C56,
  0x006B8CCA,

  0x006BD276,
  0x006BD2A6,

  0x006C9924,


}

TRUSTED_REFS = {
  0x0066F0A4,  # g_empty_string
  0x00698688,  # g_empty_string

  0x006A1488,  # missing struct
  0x006A148C,  # missing struct
  0x006A1490,  # missing struct
  0x006A1494,  # missing struct
  0x006A1498,  # missing struct
  0x006A149C,  # missing struct
  0x006A14A0,  # missing struct
  0x006A14A4,  # missing struct

  0x006BBFDC,  # missing struct
  0x006BBFE4,  # missing struct
  0x006BBFEC,  # missing struct
  0x006BBFF4,  # missing struct

  0x006BC204,  # missing struct
  0x006BC210,  # missing struct
  0x006BC21C,  # missing struct
  0x006BC228,  # missing struct

  0x006C57D0,  # g_empty_string
  0x006C57EC,  # g_empty_string

  0x006C6F18,  # missing struct

  0x006C6F20,  # missing struct
  0x006C6F24,  # missing struct
  0x006C6F38,  # missing struct
  0x006C6F3C,  # missing struct
  0x006C6F54,  # missing struct
  0x006C6FC8,  # missing struct
  0x006C6FCC,  # missing struct
  0x006C6FD0,  # missing struct

  0x006C7D44,  # missing struct
  0x006C7D4C,  # missing struct
  0x006C7D5C,  # missing struct
  0x006C7D60,  # missing struct
  0x006C7D64,  # missing struct
  0x006C7D68,  # missing struct
  0x006C7D6C,  # missing struct
  0x006C7D70,  # missing struct

  0x006C8EA8,  # missing struct
  0x006C8EAC,  # missing struct
  0x006C8EB0,  # missing struct
  0x006C8EB4,  # missing struct
  0x006C8EB8,  # missing struct

  0x006C8FB8,  # missing struct
  0x006C8FC0,  # missing struct

  0x006C923C,  # missing struct
  0x006C925C,  # missing struct
  0x006C926C,  # missing struct
  0x006C927C,  # missing struct

  0x006C9340,  # missing struct
  0x006C934C,  # missing struct
  0x006C9358,  # missing struct
  0x006C9364,  # missing struct
  0x006C9370,  # missing struct

  0x006C9488,  # missing struct
  0x006C948C,  # missing struct

  0x006C96EA,  # missing struct
  0x006C96EE,  # missing struct

  0x006C9AB0,  # missing struct
  0x006C9AB4,  # missing struct
  0x006C9AB8,  # missing struct
  0x006C9ABC,  # missing struct
  0x006CBAD0,  # missing struct

  0x006CC71C,  # missing struct

  0x006CC728,  # missing struct
  0x006CC72C,  # missing struct
  0x006CC730,  # missing struct
  0x006CC734,  # missing struct
  0x006CC738,  # missing struct
  0x006CC73C,  # missing struct
  0x006CC740,  # missing struct
  0x006CC744,  # missing struct
  0x006CC748,  # missing struct
  0x006CC74C,  # missing struct

  0x006CC758,  # missing struct

  0x007A76F0,  # missing struct
  0x007A76F4,  # missing struct
  0x007A76F8,  # missing struct
  0x007A76FC,  # missing struct
  0x007A7700,  # missing struct
  0x007A7704,  # missing struct
  0x007A7708,  # missing struct
  0x007A770C,  # missing struct

}
