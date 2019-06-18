import sys
from urllib import unquote
import os.path

input_file = ""
output_file = ""

''' This function removes the part of the POST request which is not part of the payload itsself '''
def extract_payload(data):
	# We are searching for a specific byte sequence which marks the start of our payload
	found = data.find('\x0d\x0a\x0d\x0a')
	payload = data[found + 4:]
	return data[found + 4:]

''' This function was found in index.php of AzoRult panel which does the decryption of the paylod '''
''' Since we want to be able to manipuate the content we first have to decrypt it '''
def CB_XORm(data, key, max):
	datalen=len(data);
	keylen=len(key);
	if (datalen >= max):
		datalen=max;
		
	j = 0;
	i = 0;
	
	while i < datalen:
		data[i] = chr(data[i]^ord(key[j]));
		j = j + 1;
		if( j > (keylen-1)):
			j=0;
		i = i + 1;
	return data;
	
def WriteToDisk(value, filename):
	file = open(filename, "w")
	file.write(value)
	file.close
	print "File was written to disk: " + filename

def decrypt():
	xor_key = chr(13) + chr(10) + chr(200)
	print "<Key>" + xor_key + "</Key>"

	input_byte = bytearray(open(input_file, 'rb').read())

	data_sanitized = extract_payload(input_byte)

	size = len(data_sanitized)

	decrypted = CB_XORm(data_sanitized, xor_key, 1024*512)

	if "G" in str(decrypted)[0]:
		print "Content started with G"
		substring = str(decrypted)[1:]
		payload = unquote(substring)
		WriteToDisk(payload, output_file)
	elif "<" in str(decrypted)[0]:
		print "Content started with <"
		substring = str(decrypted)
		payload = unquote(substring)
		WriteToDisk(payload, output_file)
	
if len(sys.argv) < 3:
	print "AzoDecrypt"
	print "**********"
	print ""
	print "Usage: " + sys.argv[0] + " <POST Data File> <Output File>"
else:
	print "AzoDecrypt"
	print "**********"
	print ""
	input_file = sys.argv[1]
	output_file = sys.argv[2]
	
	if os.path.isfile(input_file):
		print "Using file '" + input_file + "' as input."
		print "Writing output to '" + output_file + "'"
		decrypt()
	else:
		print "[!] Couldn't find input file; Aborting."
	
	
	
	

