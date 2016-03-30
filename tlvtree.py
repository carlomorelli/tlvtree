'''
(c) 2016 Carlo Morelli
Relased under MIT License
'''

import struct
import binascii

INDENT = "    "


def parse_tlv(raw_data, tag_size):
    '''
    Unpacks sequential raw data in string format to sequential TLV.
    Yields an iteration of Tag/Value pairs found.
    '''
    HEAD = 2 * tag_size
    while raw_data:
        try:
            tag, length = struct.unpack(_get_mask(tag_size), raw_data[:HEAD])
            value = struct.unpack("!%is"%length, raw_data[HEAD:(HEAD+length)])[0]
        except:
            raise Exception("No TLV structure found.")
            break
        yield tag, value
        raw_data = raw_data[(HEAD+length):]

def get_tlv_structure(raw_data, tag_size, debug=False):
    '''
    Returns a dictionary containing nested Tag/Value structure.
    '''

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


def _get_mask(tag_size):
    if tag_size == 1:
        return "!BB"
    elif tag_size == 2:
        return "!HH"
    elif tag_size == 4:
        return "!II"    
    elif tag_size == 8:
        return "!QQ"
    return None


class TLVTree(object):
    '''
    Object representing a structured TLV data.
    Usage:
       mytlv = TLVTree(myrawdata, tag_size=1, debug=False)
    '''

    _tlv_dict = {}
    _raw_data = ""
    _tag_map_dict = {}

    def __init__(self, raw_data, tag_size=1, debug=False):
        self._raw_data = raw_data
        self._tag_size = tag_size

        if not _get_mask(tag_size):
            print "Warning: unrecognized tag size. Going to default to 1 byte length."
            self._tag_size = 1
        self._tlv_dict = get_tlv_structure(raw_data, self._tag_size, debug)

    def get_struct(self):
        '''
        Returns a string containing a formatted structure of the object in Tag/Value hierarchy.
        '''
        def recursive_dict_output(d, rec_level=0):
            if not isinstance(d, dict):  
                return INDENT*rec_level + "Raw data: %s" % binascii.hexlify(d)
            string_array = []
            for item in d:
                string_array.append(INDENT*rec_level + "[Tag: %s]" % self._tag_map_dict.get(item, hex(item)))
                string_array.append(recursive_dict_output(d[item], rec_level=rec_level+1))
            return "\n".join(string_array)
        return recursive_dict_output(self._tlv_dict)

    def get_dict(self):
        '''
        Returns a nested dictionary representing the formatted structure of the object in Tag/Value hierarchy.
        '''
        return self._tlv_dict

    def set_tag_map(self, tag_map_dictionary):
        '''
        Applies a known map {Tag value: Tag symbolic name} to the created TLVObject, so that new get_struct()
        and get_dict() calls can return a more meaningful formatted structure.
        '''
        self._tag_map_dict = tag_map_dictionary

    def reset_tag_map(self):
        '''
        Removes any previous {Tag: symname} map configuration from the TLVObject, so that new calls from 
        get_struct() and get_dict() return a numeric tag in formatted structure.
        '''
        self.set_tag_map(tag_map_dictionary={})



     
