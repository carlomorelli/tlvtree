'''
(c) 2016 Carlo Morelli
Relased under MIT License
'''

import struct
import binascii

TAG_L = 1  #bytes
LEN_L = 1  #bytes

def parse_tlv(raw_data):
    HEAD = TAG_L + LEN_L
    while raw_data:
        try:
            tag, length = struct.unpack("!BB", raw_data[:HEAD])
            value = struct.unpack("!%is"%length, raw_data[HEAD:(HEAD+length)])[0]
        except:
            raise Exception("No TLV structure found.")
            break
        yield tag, value
        raw_data = raw_data[(HEAD+length):]

def get_tlv_structure(raw_data):
    print "decoding %s..." % binascii.hexlify(raw_data)
    d = {}
    for tag, value in parse_tlv(raw_data):
        d[tag] = value
    if len(d) == 0:
        return raw_data
    for tag in d:
        try:
            new_dict = get_tlv_structure(d[tag])
        except:
            new_dict = d[tag]
        finally:
            d[tag]=new_dict
    return d


class TLVObject(object):

    _tlv_dict = {}
    _raw_data = ""

    def __init__(self, raw_data):
        self._raw_data = raw_data
        self._tlv_dict = get_tlv_structure(raw_data)
        
    def print_tree_struct(self):
        def recursive_dict_output(d, rec_level=0):
            if not isinstance(d, dict):  
                return "  "*rec_level + "Raw data: %s" % d
            string_array = []
            for item in d:
                string_array.append("  "*rec_level + "[%s]" % item)
                string_array.append(recursive_dict_output(d[item], rec_level=rec_level+1))
            return "\n".join(string_array)
        print recursive_dict_output(self._tlv_dict)
 
     
if __name__ == '__main__':
    
    my_tlv = "\x01\x0f\x03\x05\x05\x03\xa3\xa2\xa1\x04\x01\xbb\x05\x03\x06\x01\xc3\x02\x01\xa7" 

#   LEVEL1    T01 L15 --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  T02 L1
#   LEVEL2            T03 L05 --  --  --  --  --  T04 L01 --  T05 L03 --  --  -- 
#   LEVEL3                    T55 L03 --  --  --                      T66 L01 --
    
    q = TLVObject(my_tlv)
    q.print_tree_struct()
