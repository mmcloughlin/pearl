

def output(name, s):
    print '\t"{name}": {num},'.format(
        name=name,
        shift=s,
        num=1<<s,
        )


prefixes = ['kilo', 'mega', 'giga', 'tera']

output('bytes', 3)
output('bits', 0)

for i, prefix in enumerate(prefixes):
    bit_unit = 10*(i+1)
    byte_unit = bit_unit + 3
    f = prefix[0]
    output(f + 'b', byte_unit)
    output(f + 'bytes', byte_unit)
    output(prefix + 'bytes', byte_unit)
    output(f + 'bits', bit_unit)
    output(prefix + 'bits', bit_unit)
