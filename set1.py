from collections import Counter
from utils import EXPECTED_FREQ

import codecs
import sys


def hex_to_base64(hex):
    decoded = codecs.decode(hex, "hex")
    return codecs.encode(decoded, "base64")

input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
expected = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n"
output = hex_to_base64(input)
print("Challenge 1:", output)
assert(output == expected), "Challenge 1"



def xor(hex_a, hex_b):
    hex_a_decoded = codecs.decode(hex_a, "hex")
    hex_b_decoded = codecs.decode(hex_b, "hex")
    bytes_xor = bytes(a ^ b for a, b in zip(hex_a_decoded, hex_b_decoded))
    return codecs.encode(bytes_xor, "hex")

hex_a = b"1c0111001f010100061a024b53535009181c"
hex_b = b"686974207468652062756c6c277320657965"
expected_2 = b"746865206b696420646f6e277420706c6179"
output_2 = xor(hex_a, hex_b)
print("Challenge 2:", output_2)
assert(output_2 == expected_2), "Challenge 2"



def how_gibberish(input):
    count = Counter(input)
    total = len(input)
    freq = {k: v/total for k, v in count.items()}
    sum_squares = 0

    for ord, actual in freq.items():
        expected = EXPECTED_FREQ[ord] if ord in EXPECTED_FREQ else 0
        sum_squares += pow(actual - expected, 2)
        
    return sum_squares

def caeser_cypher(input):
    input_decoded = codecs.decode(input, "hex")
    min_score = sys.maxsize
    least_gibberish = input

    for i in range(256):
        decoded = bytes(i ^ x for x in input_decoded)
        giberishness = how_gibberish(decoded)

        if giberishness < min_score:
            min_score = giberishness
            least_gibberish = decoded
        
    return least_gibberish

input_3 = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
print("Challenge 3:", caeser_cypher(input_3))