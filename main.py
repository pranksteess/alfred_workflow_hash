from workflow import Workflow3
from _pysha3 import keccak_256
import sys, hashlib, re

def hash_result(hash_alg, src):
	hash_alg.update(bytes(src, "utf8"))
	strHash = hash_alg.hexdigest()

	hexHash = "The payload is not a hex str"
	if src.startswith("0x"):
		src = src[2:]
	hexformat = re.match(r'^[0-9a-f]*$', src)
	hexstr = hexformat and (len(src) % 2 == 0)
	if hexstr:
		hash_alg.update(bytes.fromhex(src))
		hexHash = hash_alg.hexdigest()
		
	return strHash, hexHash

def main(wf):
	msg = sys.argv[1]
	alg_list = [
		("md5", hashlib.md5()),
		("sha1", hashlib.sha1()),
		("sha256", hashlib.sha256()),
		("sha512", hashlib.sha512()),
		("keccak256", keccak_256()),
		("blake2b_ckb", hashlib.blake2b(digest_size=32, person=b'ckb-default-hash'))
	]
	res_list = []
	for alg in alg_list:
		digest, digest4hex = hash_result(alg[1], msg)
		res_list.append((alg[0], digest, digest4hex))

	for r in res_list:
		wf.add_item(r[0], r[1], r[1], valid=True).add_modifier("cmd", r[2], r[2])

	wf.send_feedback()

if __name__ == '__main__':
	wf = Workflow3()
	log = wf.logger
	sys.exit(wf.run(main))
