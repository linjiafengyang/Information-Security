import hashlib
def md5(str):
    import hashlib
    import types
    if type(str) is types.StringType:
        m = hashlib.md5()   
        m.update(str)
        return m.hexdigest()
    else:
        return ''

print md5('123456')