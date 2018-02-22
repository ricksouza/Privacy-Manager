/*
 * Cipher.h
 *
 *  Created on: Sep 23, 2013
 *      Author: rick
 */

#ifndef CIPHER_H_
#define CIPHER_H_

#include "Common.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <PBC/G1.h>
#include <PBC/Pairing.h>
#include "systemparam.h"
#include "io.h"
#include "SecretSharer.h"
#include "lagrange.h"


class Cipher {
public:
	Cipher();
	virtual ~Cipher();
	void Encrypt(char *file_path, char *ID, int M, int N);
	void Decrypt(char *file_path, char *ID, int N);

private:
	void generate_symmetric_key(int sym_key_size, unsigned char** sym_key);
	void generate_iv(int iv_size, unsigned char **iv);
	void gen_random(int num_bytes, unsigned char **data);
	void sym_encrypt(unsigned char *open_data, int open_data_size, unsigned char **encrypted_data, int *encrypted_data_size,
			unsigned char *key, unsigned char *iv, char *file_path, char *encrypted_file_path);

	void sym_decrypt(unsigned char *open_data, int open_data_size, unsigned char **encrypted_data, int *encrypted_data_size,
				unsigned char *key, unsigned char *iv, int NID);

	void encrypt_key(char *id, char *encryptedFilePath, unsigned char *key, unsigned char *iv, int size, int M, int N);
	G1 openPublicKey (char *filePath, const Pairing& e);
	G2 openPublicKeyG2 (char *filePath, const Pairing& e);
	G1 openPrivateKeyG1 (char *filePath, const Pairing& e);
	Zr openPrivateKeyZr (char *filePath, const Pairing& e);
	Zr openShare(char *filePath, const Pairing& e);
	void sign_hash(unsigned char *hash, char *share_path, Zr private_key, G1 Qid);
	void generate_signing_keys(char *file_path);
	void generate_private_key(int N, char *id);
	void generate_shares_paths (char *file_path, int N, vector<vector<char *> >& vector_paths);
	int verify_signatures(vector<vector<char *> > paths, int N, char *g_path, char *pub_key_path);
	unsigned char * decrypt_key(char *encrypted_key_path, char *final_U_path);

};

#endif /* CIPHER_H_ */
