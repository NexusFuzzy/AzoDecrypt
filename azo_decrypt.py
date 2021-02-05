import sys
import urllib.parse
import os.path

input_file = ""
output_file = ""


''' This function removes the part of the POST request which is not part of the payload itsself '''
def extract_payload(data):
    # We are searching for a specific byte sequence which marks the start of our payload
    found = data.find(b'\x3c\x69\x6e\x66\x6f')
    print("Found payload at position " + str(found))
    return data[found:]


''' Inside the payload there is a ZIP file containint text files with stolen credentials, cookies etc. so we extract it'''
def ExtractZipFiles(startpos, data):
    zip_begin = b"\x50\x4b\x03\x04"
    zip_end = b"\x50\x4b\x05\x06"
    start = data.find(zip_begin)
    print("Found ZIP begin @ " + str(start))
    end = data.find(zip_end)
    print("Found ZIP end @ " + str(end))

    zip_file = data[start:end]

    file = open(os.path.dirname(output_file) + "/" + str(start) + "_" + str(end) + ".zip", "wb")

    file.write(zip_file)
    file.close()


''' This function was found in index.php of AzoRult panel which does the decryption of the paylod '''
def xor(data, key):
    l = len(key)
    return bytearray((
        (data[i] ^ key[i % l]) for i in range(0,len(data))
    ))


''' Self explanatory I guess '''
def WriteToDisk(value, filename):
    file = open(filename, "w")
    for v in value:
        file.write(v)
    file.close()
    print("File was written to disk: " + filename)


def decrypt():
    # This key was found in index.php and is used to decrypt the content
    # Since this key is also hard coded into the client it is highly unlikely that this will ever change
    # since no one will put the effort into changing the client I guess
    # If you want to detect the key, use https://github.com/hariomenkel/AzoBrute
    xor_key = b'\x0a\xc8\x0d'
    input_byte = open(input_file, 'rb').read()

    decrypted = xor(input_byte, xor_key)
    # We strip the POST data from the payload
    data_sanitized = extract_payload(decrypted)
    size = len(data_sanitized)

    # Finally we decrypt the data using the XOR key

    #decrypted = xor(input_byte, xor_key)

    # The payload either starts with "G" which contains just a unique system id...
    if "G" in chr(data_sanitized[0]):
        print("Content started with G")
        substring = str(decrypted)[1:]
        payload = urllib.parse.unquote(substring)
        WriteToDisk(payload, output_file)
        ExtractZipFiles(str(decrypted)[1:])

    # ... or it starts with "<" which indicates that this POST contains the stolen data
    elif "<" in chr(data_sanitized[0]):
        print("Content started with <")
        substring = str(decrypted)
        payload = urllib.parse.unquote(substring, "utf-8")
        WriteToDisk(payload, output_file)
        print("Extracting ZIP file(s)")
        ExtractZipFiles(0, decrypted)


def print_header():
    print("                    _____                             _")
    print("    /\             |  __ \                           | |")
    print("   /  \    _______ | |  | | ___  ___ _ __ _   _ _ __ | |_")
    print("  / /\ \  |_  / _ \| |  | |/ _ \/ __| '__| | | | '_ \| __|")
    print(" / ____ \  / / (_) | |__| |  __/ (__| |  | |_| | |_) | |_")
    print("/_/    \_\/___\___/|_____/ \___|\___|_|   \__, | .__/ \__|")
    print("                                         __/ | |")
    print("                                        |___/|_|")
    print("")


if len(sys.argv) < 3:
    print_header()
    print("Usage: " + sys.argv[0] + " <POST Data File> <Output File>")
else:
    print_header()
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if os.path.isfile(input_file):
        print("Using file '" + input_file + "' as input.")
        print("Writing output to '" + output_file + "'")
        decrypt()
    else:
        print("[!] Couldn't find input file; Aborting.")





