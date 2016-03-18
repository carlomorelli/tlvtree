# tlvtree
Simple TLV structure analyzer in Python
https://travis-ci.org/carlomorelli/tlvtree.svg?branch=master

## About
_tlvtree_ is a recursive parser of bytestrings, which in Python 2.7.x are the default binary output format for file operations.
The usage of _tlvtree_ is very simple: just create the object by instantiating class *TLVTree()*, with the original raw string as input. 

### Basic use
The following snippet shows the main logic in using _tlvtree_:

```python
from tlvtree import TLVTree
myrawdata = "\xff\x04\xaa\xbb\xcc\xdd"
z = TLVTree(myrawdata)
print z.get_struct()
```

Default size for tag & length fields is 1 byte. To configure for example 2 bytes, call the object like this:

```python
z = TLVTree(myrawdata, tag_size=2)
```

Also a debug flag (default is False) is supported that shows what the parser is trying to decode, in hexadecimal format. This is most useful when analyzing packets or payload of packets carrying TLV structured information.

```python
z = TLVTree(myrawdata, debug=True)
```

### As dictionary
The call 
```python
mydict = z.get_dict()
```
returns a dictionary, possibly a nested dictionary, containing the TLVTree object hierarchy according to the Tag/Value scheme.

### Using symbolic names for tags
Consider the following:

```python
tags = {
		0x01: "The tag 1",
		0x63: "The tag 63"
		}
z.set_tag_map(tags)
print z.get_struct()
```
The printed output will be the same structure as in the main example, but the printed numeric tag values will now be substituted according to what the input dictionary "tags" carries to the object.

### More info
Check out also more complex examples in the code where nested TLV levels can be found.

## Changelog
#### Release 0.1
- Initial release. Basic support of multilevel TLVs and pretty printer

#### Release 0.2
- Support of multibyte tags (+ length fields) is added; supported sizes: 1, 2, 4 or 8 bytes
- Fixed tab spacing for pretty printer

#### Release 0.3
- Added documentation in code
- Added get_dict() method
- Added support for symbolic {tag value: tag name} mapping in TLVTree() object
- Renaming old class name to TLVTree()
