'''
(c) 2016 Carlo Morelli
Relased under MIT License
'''

import struct
import binascii

TAG_L = 1  #bytes
LEN_L = 1  #bytes

INDENT = "    "
def parse_tlv(raw_data, tag_size):
    HEAD = 2 * tag_size
    while raw_data:
        try:
            tag, length = struct.unpack(get_mask(tag_size), raw_data[:HEAD])
            value = struct.unpack("!%is"%length, raw_data[HEAD:(HEAD+length)])[0]
        except:
            raise Exception("No TLV structure found.")
            break
        yield tag, value
        raw_data = raw_data[(HEAD+length):]

def get_tlv_structure(raw_data, tag_size, debug=False):
    if debug:
        print "Decoding %s..." % binascii.hexlify(raw_data)
    d = {}
    for tag, value in parse_tlv(raw_data, tag_size):
        d[tag] = value
    if len(d) == 0:
        return raw_data
    for tag in d:
        try:
            new_dict = get_tlv_structure(d[tag], tag_size)
        except:
            new_dict = d[tag]
        finally:
            d[tag]=new_dict
    return d

def get_mask(tag_size):
    if tag_size == 1:
        return "!BB"
    elif tag_size == 2:
        return "!HH"
    elif tag_size == 4:
        return "!II"    
    elif tag_size == 8:
        return "!QQ"
    return None


class TLVObject(object):

    _tlv_dict = {}
    _raw_data = ""

    def __init__(self, raw_data, tag_size=1, debug=False):
        self._raw_data = raw_data
        self._tag_size = tag_size

        if not get_mask(tag_size):
            print "Warning: unrecognized tag size. Going to default to 1 byte length."
            self._tag_size = 1
        self._tlv_dict = get_tlv_structure(raw_data, self._tag_size, debug)
        
    def print_tree_struct(self):
        def recursive_dict_output(d, rec_level=0):
            if not isinstance(d, dict):  
                return INDENT*rec_level + "Raw data: %s" % binascii.hexlify(d)
            string_array = []
            for item in d:
                string_array.append(INDENT*rec_level + "[Tag: %s]" % hex(item))
                string_array.append(recursive_dict_output(d[item], rec_level=rec_level+1))
            return "\n".join(string_array)
        print recursive_dict_output(self._tlv_dict)
 
     
if __name__ == '__main__':
    
    tlv_n1 = "\x11\x0f\x33\x05\x66\x03\xa3\xa2\xa1\x44\x01\xbb\x55\x03\x77\x01\xc3\x22\x01\xa7" 

#   LEVEL1    T11 L15 --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  T22 L01 --
#   LEVEL2            T33 L05 --  --  --  --  --  T44 L01 --  T55 L03 --  --  -- 
#   LEVEL3                    T66 L03 --  --  --                      T77 L01 --

    tlv_n2 = "\x00\x11\x00\x19\x00\x33\x00\x07\x00\x66\x00\x03\xa3\xa2\xa1\x00\x44\x00\x01\xbb\x00\x55\x00\x05\x00\x77\x00\x01\xc3\x00\x22\x00\x01\xa7" 

#   LEVEL1    T11 --  --  L25 --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  T22 --  --  L01 --
#   LEVEL2                    T33 --  --  L07 --  --  --  --  --  --  --  T44 --  --  L01 --  T55 --  --  L05 --  --  --  --  --  --
#   LEVEL3                                    T66 --  --  L03 --  --  --                                      T77 --  --  L01 --


    p = TLVObject(tlv_n1)
    p.print_tree_struct()



    q = TLVObject(tlv_n2, tag_size=2)
    q.print_tree_struct()
