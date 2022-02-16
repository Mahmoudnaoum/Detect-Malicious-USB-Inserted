import hashlib
f = open("effcf2912529b5b90091778125d63abc.jpg", "rb")
bytes = f.read()
hash_object = hashlib.md5(bytes).hexdigest()
print(hash_object)