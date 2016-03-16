# tlvtree
Simple TLV structure analyzer in Python

## About
_tlvtree_ is a recursive parser of bytestrings, which in Python 2.7.x are the default binary output format for file operations.
The usage of _tlvtree_ is very simple: just create the object by instantiating class *TLVObject()*, with the original raw string as input. 

```python
import tlvtree
myrawdata = "\xff\x04\xaa\xbb\xcc\xdd"
z = TLVObject(myrawdata)
z.print_tree_struct()
```

Default size for tag & length fields is 1 byte. To configure for example 2 bytes, call the object like this:

```python
z = TLVObject(myrawdata, tag_size=2)
```

Also a debug flag (default is False) is supported that shows what the parser is trying to decode, in hexadecimal format. This is most useful when analyzing packets or payload of packets carrying TLV structured information.

```python
 = TLVObject(myrawdata, debug=True)
```

Check out also more complex examples in the code where nested TLV levels can be found.

## Changelog
####Release 0.1
Initial release. Basic support of multilevel TLVs and pretty printer

####Release 0.2
Support of multibyte tags (+ length fields) is added; supported sizes: 1, 2, 4 or 8 bytes
Fixed tab spacing for pretty printer
