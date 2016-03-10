import binascii
import struct

L_TAG=1
L_LEN=1

def parse_tlv(data):
    HEAD = L_TAG + L_LEN
    while data:
        try:
            tag, length = struct.unpack("!BB", data[:HEAD])
            value = struct.unpack("!%is"%length, data[HEAD:(HEAD+length)])
        except:
            raise Exception("Improper TLV structure found.")
            break
        yield tag, value
        data = data[(HEAD+length):]
		
def get_tlv_structure(data):
    data_hex = binascii.hexlify(data)
    print "decoding %s" % data_hex 
    d = {}
    for tag, value in parse_tlv(data):
        d[tag] = value
    if len(d) == 0:
        return data
    else:
        for tag in d:
            d[tag] = get_tlv_structure(d[tag])
        return d
	
class TLV(object):
    _dict = {}
    _data = ""
    def __init__(self, data):
        self._data = data
        self._dict = get_tlv_structure(data)


if __name__ == "__main__":
	
	mytlv = "\x11\x01\xff\x22\x01\xff" #4\xff\xff\xff\xff"
	
	z = TLV(mytlv)
	
	print z._dict
