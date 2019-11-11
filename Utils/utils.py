import struct

# convert HEX to int
def Convert(character):
    if character == 'A' or character == 'a':
        return 10
    else:
        if character == 'B' or character == 'b':
            return 11
        else:
            if character == 'C' or character == 'c':
                return 12
            else:
                if character == 'D' or character == 'd':
                    return 13
                else:
                    if character == 'E' or character == 'e':
                        return 14
                    else:
                        if character == 'F' or character == 'f':
                            return 15
                        else:
                            if '0' <= character <= '9':
                                return int(character)


# convert string to bytes
def Str2Bytes(data):
    length = int(len(data) / 2)
    result = b''
    for i in range(length):
        substr = data[i * 2: (i + 1) * 2]
        num_1 = Convert(substr[0])
        num_2 = Convert(substr[1])
        num = num_1 * 16 + num_2
        result += struct.pack("!B", num)
    return result