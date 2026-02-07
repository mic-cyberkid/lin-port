def encrypt_w(s, key=[0x4B, 0x1F, 0x8C, 0x3E]):
    res = []
    for i, c in enumerate(s):
        res.append(f"'{c}'^0x{key[i % 4]:02X}")
    return ", ".join(res)

print("// {21EC2020-3AEA-1069-A2DD-08002B30309D}")
print(encrypt_w("{21EC2020-3AEA-1069-A2DD-08002B30309D}"))
print()
print("// MicrosoftEdgeUpdateTaskMachineCore")
print(encrypt_w("MicrosoftEdgeUpdateTaskMachineCore"))
print()
print("// LocalServer32")
print(encrypt_w("LocalServer32"))
