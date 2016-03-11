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

Check out also more complex examples in the code where nested TLV levels can be found.

## Changelog
####Release 0.1
Initial release. Basic support of multilevel TLVs and pretty printer

