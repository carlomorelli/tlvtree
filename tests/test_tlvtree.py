'''
(c) 2016 Carlo Morelli
Relased under MIT License
'''

from tlvtree import TLVTree

tlv_n1     = "\x11\x0f\x33\x05\x66\x03\xa3\xa2\xa1\x44\x01\xbb\x55\x03\x77\x01\xc3\x22\x01\xa7" 

#   LEVEL1    T11 L15 --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  T22 L01 --
#   LEVEL2            T33 L05 --  --  --  --  --  T44 L01 --  T55 L03 --  --  -- 
#   LEVEL3                    T66 L03 --  --  --                      T77 L01 --

tlv_n2     = "\x00\x11\x00\x19\x00\x33\x00\x07\x00\x66\x00\x03\xa3\xa2\xa1\x00\x44\x00\x01\xbb\x00\x55\x00\x05\x00\x77\x00\x01\xc3\x00\x22\x00\x01\xa7" 

#   LEVEL1    T11 --  --  L25 --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  T22 --  --  L01 --
#   LEVEL2                    T33 --  --  L07 --  --  --  --  --  --  --  T44 --  --  L01 --  T55 --  --  L05 --  --  --  --  --  --
#   LEVEL3                                    T66 --  --  L03 --  --  --                                      T77 --  --  L01 --

my_tag_map = {
              0x11: "AAAA",
              0x22: "BBBB",
              0x33: "CCCC",
              0x44: "DDDD",
              0x55: "EEEE",
              0x66: "FFFF",
              0x77: "GGGG"
              }


def test_tlv_default():
    p = TLVTree(tlv_n1)
    print "== Normal structure for tlv_n1 =="
    print p.get_struct()
    p.set_tag_map(my_tag_map)
    print "== Formatted structure for tlv_n1 =="
    print p.get_struct()
    assert p.get_dict()[0x22]             == "\xa7"
    assert p.get_dict()[0x11][0x55][0x77] == "\xc3"

def test_tlv_2bytes():
    q = TLVTree(tlv_n2, tag_size=2)
    print "== Normal structure for tlv_n2 =="
    print q.get_struct()
    q.set_tag_map(my_tag_map)
    print "== Formatted structure for tlv_n2 =="
    print q.get_struct()
    assert q.get_dict()[0x22]             == "\xa7"
    assert q.get_dict()[0x11][0x55][0x77] == "\xc3"
