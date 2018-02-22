/*
 * Cipher.cpp
 *
 *  Created on: Sep 23, 2013
 *      Author: rick
 */

#include "Cipher.h"


Cipher::Cipher() {
	// TODO Auto-generated constructor stub

}

Cipher::~Cipher() {
	// TODO Auto-generated destructor stub
}

G1 Cipher::openPublicKey (char *filePath, const Pairing& e){

	char *buffer;
	int size;
	Common com;

	com.openFile(filePath, &buffer, &size);

	//char *tok;

	//tok = strtok(buffer, ":");
	//if(tok != NULL)
	//		tok = strtok(NULL, ":");

	return G1(e, (unsigned char *)buffer, (size_t)size, false, 10);

}

G2 Cipher::openPublicKeyG2 (char *filePath, const Pairing& e){

	char *buffer;
	int size;
	Common com;

	com.openFile(filePath, &buffer, &size);

	//char *tok;

	//tok = strtok(buffer, ":");
	//if(tok != NULL)
	//		tok = strtok(NULL, ":");

	return G2(e, (unsigned char *)buffer, (size_t)size, false, 10);

}

G1 Cipher::openPrivateKeyG1 (char *filePath, const Pairing& e){

	char *buffer;
	int size;
	Common com;

	com.openFile(filePath, &buffer, &size);

	//char *tok;

	//tok = strtok(buffer, ":");
	//if(tok != NULL)
	//		tok = strtok(NULL, ":");

	return G1(e, (unsigned char *)buffer, (size_t)size, false, 10);

}

Zr Cipher::openPrivateKeyZr (char *filePath, const Pairing& e){

	char *buffer;
	int size;
	Common com;

	com.openFile(filePath, &buffer, &size);

	//char *tok;

	//tok = strtok(buffer, ":");
	//if(tok != NULL)
	//		tok = strtok(NULL, ":");

	//Zr(e, (unsigned char *)buffer, size, 10);

	return Zr(e, (unsigned char *)buffer, (size_t)size, 10);

}

Zr Cipher::openShare(char *filePath, const Pairing& e){

	char *buffer;
	int size;

	Common com;

	com.openFile(filePath, &buffer, &size);

	char *tok;

	tok = strtok(buffer, ": \n");
	//if(tok != NULL)
	//	tok = strtok(NULL, ":");

	return Zr (e, (unsigned char *)tok, (size_t)size, 10);

}

void Cipher::gen_random(int num_bytes, unsigned char **data){

	*data = (unsigned char *) calloc(num_bytes + 1, sizeof(unsigned char));
	RAND_bytes(*data, num_bytes);

}

void Cipher::generate_symmetric_key(int sym_key_size, unsigned char** sym_key) {
	this->gen_random(sym_key_size, sym_key);
}

void Cipher::generate_iv(int iv_size, unsigned char **iv){
	this->gen_random(iv_size, iv);
}

void Cipher::sym_encrypt(unsigned char *open_data, int open_data_size, unsigned char **encrypted_data, int *encrypted_data_size,
		unsigned char *key, unsigned char *iv, char *file_path, char *encrypted_file_path){

	int block_size = 8192;
	int ilen, olen;
	int ret = 0;
	timeval t1, t2;

	unsigned char *ibuf, *obuf;

	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	FILE *in, *out;

	cipher = EVP_aes_128_cbc();

	ibuf = (unsigned char *)malloc(block_size);
	obuf = (unsigned char *)malloc(block_size + EVP_CIPHER_block_size(cipher));
	printf("Cipher block size: %d \n", EVP_CIPHER_block_size(cipher));

	in = fopen(file_path, "rb");
	out = fopen(encrypted_file_path, "wb");

	int data_alloc;
	int final_encrypted_block_size = 0;
	double elapsed = 0;

	   /*
	 * Init the memory used for EVP_CIPHER_CTX and set the key and
	 * ivec.
	 */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, 1);

	while ((ilen = fread(ibuf, 1, block_size, in)) > 0) {
		/* encrypto/decrypt */
		ret = EVP_CipherUpdate(&ctx, obuf, &olen, ibuf, ilen);
		if (ret != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			//errx(1, "EVP_CipherUpdate failed");
		}
		/* write out to output file */
		gettimeofday(&t1, NULL);
		fwrite(obuf, 1, olen, out);
		gettimeofday(&t2, NULL);

		elapsed += (t2.tv_sec - t1.tv_sec) * 1000.0;
		elapsed += (t2.tv_usec - t1.tv_usec) / 1000.0;
	}
	/* done reading */
	fclose(in);

	ret = EVP_CipherFinal_ex(&ctx, obuf, &olen);
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (ret != 1)
		//errx(1, "EVP_CipherFinal_ex failed");

	/* write the last bytes out and close */
	gettimeofday(&t1, NULL);
	fwrite(obuf, 1, olen, out);
	fclose(out);
	gettimeofday(&t2, NULL);
	elapsed += (t2.tv_sec - t1.tv_sec) * 1000.0;
	elapsed += (t2.tv_usec - t1.tv_usec) / 1000.0;

	cout << "Writing file: " << elapsed << "ms. \n";


//	printf("Writing encrypted file ... \n");
//	com.writeFile(finalEncryptedFilePath, encrypted_data, encrypted_size);
//	printf("Finished. \n");










//	data_alloc = open_data_size + (16 - (open_data_size % (cipher->block_size)));
//	*encrypted_data = (unsigned char *)calloc(data_alloc, sizeof(unsigned char));
//
//	EVP_CIPHER_CTX_init(&ctx);
//	EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, 1);
//	EVP_CipherUpdate(&ctx, *encrypted_data, encrypted_data_size, open_data, open_data_size);
//	EVP_CipherFinal_ex(&ctx, *encrypted_data + *encrypted_data_size, &final_encrypted_block_size);
//
//	*encrypted_data_size = *encrypted_data_size + final_encrypted_block_size;

}

void Cipher::sym_decrypt(unsigned char *encrypted_data, int encrypted_data_size, unsigned char **decrypted_data, int *decrypted_data_size,
		unsigned char *key, unsigned char *iv, int NID){

	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;

	int data_alloc;
	int final_decrypted_block_size = 0;

	cipher = EVP_aes_128_cbc();

	data_alloc = encrypted_data_size;
	*decrypted_data = (unsigned char *)calloc(data_alloc - 5, sizeof(unsigned char));

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, cipher, NULL, key, iv);
	EVP_DecryptUpdate(&ctx, *decrypted_data, decrypted_data_size, encrypted_data, encrypted_data_size);
	EVP_DecryptFinal_ex(&ctx, *decrypted_data + *decrypted_data_size, &final_decrypted_block_size);

	*decrypted_data_size = *decrypted_data_size + final_decrypted_block_size;

}

void Cipher::generate_private_key(int N, char *id){


	SystemParam sysparam("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	char *priv_key_share_path = "shares/priv%d";

	int i;

	vector<G1> sharesG1;
	vector<Zr> indices;

	G1 g1_publicKey;

	G1 msgHashG1;

	//hash_msg(msgHashG1, id, e);

	unsigned char *id_hash;
	id_hash = (unsigned char *)malloc(SHA_DIGEST_LENGTH);

	SHA1((unsigned char *)id, strlen(id), id_hash);

	msgHashG1 = G1(e, (void*)id_hash, SHA_DIGEST_LENGTH);

	msgHashG1.dump(stderr, "", 10);
	printf("\n");
	printf(id);
	printf("\n");

	G1 share1 = this->openPublicKey("share1", e);

	sharesG1.push_back(share1);

	int indice_f = 1;

	Zr indice_zr_f(e, (long) indice_f);

	indices.push_back(indice_zr_f);

	for (i = 2; i <= N; i++) {
		char *final_priv_key_share_path;
		final_priv_key_share_path = (char *) calloc(strlen(priv_key_share_path) + 5, sizeof(char));
		sprintf(final_priv_key_share_path, priv_key_share_path, i);

		if (access(final_priv_key_share_path, F_OK) == 0) {

			Zr share_zr;
			G1 share_g1;
			share_zr = this->openShare(final_priv_key_share_path, e);
			share_g1 = msgHashG1 ^ share_zr;

			sharesG1.push_back(share_g1);

			int indice = final_priv_key_share_path[strlen(final_priv_key_share_path) - 1] - '0';

			Zr indice_zr(e, (long) indice);

			indices.push_back(indice_zr);

		}
	}

	Zr alpha(e, (long) 0);
	vector<Zr> coeffs = lagrange_coeffs(indices, alpha);
	G1 g1_priv_key = lagrange_apply(coeffs, sharesG1);

	g1_publicKey = openPublicKey("pubsys1", e);

	if (e(sysparam.get_U(), g1_priv_key) == e(g1_publicKey, msgHashG1)) {
		cerr << "\n*** CORRECT!\n\n";
	} else {
		cerr << "\n*** DIFFERENT!\n\n";
		//Send a Wrong Signatures Message
	}

	FILE *priv;
	priv = fopen("priv_key", "wb");
	g1_priv_key.dump(priv, "teste", 10);
	fclose(priv);

}

void Cipher::generate_signing_keys(char *file_path){

	SystemParam sysparam("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	Zr private_key = Zr(e, true);

	FILE *f_priv;
	f_priv = fopen("priv_sign_key", "w");
	private_key.dump(f_priv, "", 10);
	fclose(f_priv);

	G2 g = G2(e, false);
	//g.dump(stderr, "", 10);
	//private_key.dump(stderr, "", 10);
	G2 public_key = g^private_key;

	char *final_pub_key_path;
	char *final_g_path;
	final_pub_key_path = (char *)calloc( strlen(file_path) + strlen("%s.shares.pub_key") + 1, sizeof(char));
	final_g_path = (char *)calloc( strlen(file_path) + strlen("%s.shares.g") + 1, sizeof(char));

	sprintf(final_pub_key_path, "%s.shares.pub_key", file_path);
	sprintf(final_g_path, "%s.shares.g", file_path);

	FILE *f_g;
	f_g = fopen(final_g_path, "w");
	g.dump(f_g, "", 10);
	fclose(f_g);

	FILE *pub_key;
	pub_key = fopen(final_pub_key_path, "w");
	public_key.dump(pub_key, "", 10);
	fclose(pub_key);

	free(final_pub_key_path);
	free(final_g_path);


//	SystemParam sysparam ("pairing.param", "system.param");
//
//	const Pairing& e = sysparam.get_Pairing();
//
//	char *priv_key_share_path = "shares/priv%d";
//
//	int i;
//
//	vector<G1> sharesG1;
//	vector <Zr> indices;
//
//	G1 g1_publicKey;
//
//	G1 msgHashG1;
//
//	hash_msg(msgHashG1, id,e);
//
//	for (i = 1; i <= N; i++){
//		char *final_priv_key_share_path;
//		final_priv_key_share_path = (char *)calloc(strlen(priv_key_share_path) + 5, sizeof(char));
//		sprintf(final_priv_key_share_path, priv_key_share_path, i);
//
//		if(access(final_priv_key_share_path, F_OK) == 0){
//
//			Zr share_zr;
//			G1 share_g1;
//			share_zr = this->openShare(final_priv_key_share_path, e);
//			share_g1 = msgHashG1^share_zr;
//
//			sharesG1.push_back(share_g1);
//
//			int indice = final_priv_key_share_path[strlen(final_priv_key_share_path) - 1] - '0';
//
//			Zr indice_zr(e, (long)indice);
//
//			indices.push_back(indice_zr);
//
//		}
//	}
//
//	Zr alpha(e,(long)0);
//	vector<Zr> coeffs = lagrange_coeffs(indices, alpha);
//	G1 g1_priv_key = lagrange_apply(coeffs, sharesG1);
//
//	g1_publicKey = openPublicKey("pubsys1", e);
//
//	if (e(sysparam.get_U(), g1_priv_key) == e(g1_publicKey, msgHashG1)) {
//		cerr << "\n*** CORRECT!\n\n";
//	} else {
//		cerr << "\n*** DIFFERENT!\n\n";
//		//Send a Wrong Signatures Message
//	}
//
//	FILE *priv;
//	priv = fopen("priv_key", "wb");
//	g1_priv_key.dump(priv, "teste", 10);
//	fclose(priv);

}

void Cipher::sign_hash(unsigned char *hash, char *share_path, Zr private_key, G1 Qid){

	SystemParam sysparam("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	G1 msgHashG1;
	//hash_msg(msgHashG1, id, e);

	Common com;

	msgHashG1 = G1(e, (void*)hash, SHA_DIGEST_LENGTH);

	G1 sig = msgHashG1^private_key;
	//sig.dump(stderr, "", 10);

	char *share_signed_hash_path;
	share_signed_hash_path = (char *)calloc(strlen(share_path) + strlen("%s.signedhash") + 1, sizeof(char));
	sprintf(share_signed_hash_path, "%s.signed_hash", share_path);

	FILE *final_signed_share;
	final_signed_share = fopen(share_signed_hash_path, "w");
	sig.dump(final_signed_share, "", 10);
	fclose(final_signed_share);

	free(share_signed_hash_path);

	//******************************************** Hess Signature BEGIN **************************************//

	printf("//****************************   Hess Signature BEGIN *******************************//");
	printf("\n");

	G1 priv_key = this->openPrivateKeyG1("priv_key", e);

	mpz_t t2;
	element_t t3;
	element_t v;
	element_t t4;
	element_t t5;
	element_t u;
	pairing_t pairing;

	FILE * pFile;
	long lSize;
	char * buffer;
	size_t result;

	pFile = fopen("pairing.param", "r");
	if (pFile == NULL) {
		fputs("File error", stderr);
		exit(1);
	}

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	buffer = (char*) malloc(sizeof(char) * lSize);
	if (buffer == NULL) {
		fputs("Memory error", stderr);
		exit(2);
	}

	// copy the file into the buffer:
	result = fread(buffer, 1, lSize, pFile);
	fclose(pFile);

	if (!result)
		pbc_die("input error");

	pairing_init_set_buf(pairing, buffer, result);

	G1 P1 = G1(e, true);
	Zr k = Zr(e, true);
	GT t1 = GT(e);
	GT r = GT(e);

	mpz_init(t2);
	element_init_Zr(v, pairing);
	element_init_Zr(t3, pairing);
	element_init_G1(t4, pairing);
	element_init_G1(t5, pairing);
	element_init_G1(u, pairing);

	t1 = e(sysparam.get_U(), P1);
	r = t1^k;

	element_to_mpz(t2, (element_s *)r.getElement());

	element_from_hash(t3, hash, SHA_DIGEST_LENGTH);



	element_mul_mpz(v, t3, t2);
	element_mul_zn(t4, (element_s *)priv_key.getElement(), v);
	element_mul_zn(t5, (element_s *)P1.getElement(), (element_s *)k.getElement());
	element_add(u, t4, t5);

	element_printf("u = %B\n", u);
	element_printf("v = %B\n", v);

	printf("//****************************   Hess Signature END *******************************//");
	printf("\n");

	printf("//****************************   Hess Signature VERIFY BEGIN *******************************//");
	printf("\n");

	element_t r2;
	element_t t6;
	element_t t7;
	element_t t8;
	element_t Ppub;


	element_init_GT(t6, pairing);
	element_init_GT(t7, pairing);
	element_init_G1(Ppub, pairing);
	element_init_GT(r2, pairing);
	element_init_Zr(t8, pairing);

	G1 publicKey = openPublicKey("pubsys1", e);

	element_pairing(t6, u, (element_s *)sysparam.get_U().getElement());
	element_neg(Ppub, (element_s *)publicKey.getElement());
	element_pairing(t7, (element_s *)Qid.getElement(), Ppub);
	element_pow_zn(t7, t7, v);
	element_mul(r2, t6, t7);
	element_to_mpz(t2, r2);
	element_from_hash(t3, hash, SHA_DIGEST_LENGTH);
	element_mul_mpz(t8, t3, t2);

	element_printf("h3(m,r) = %B\n", t8);
	element_printf("v = %B\n", v);

	if (!element_cmp(t8, v)) {
		printf("Signature is valid!\n");
	} else {
		printf("Signature is invalid!\n");
	}

	printf("//****************************   Hess Signature VERIFY END *******************************//");
	printf("\n");


	//******************************************** Hess Signature END **************************************//


	//************ Begin Verificacao de assinatura
//	GT temp1, temp2;
//
//	temp1 = e(sig, g);
//	temp2 = e(msgHashG1, public_key);
//
//	temp1.dump(stderr, "", 10);
//	temp2.dump(stderr, "", 10);

	//************ End Verificacao de assinatura

//	pairing_apply(temp1, sig, g, pairing);
//	pairing_apply(temp2, h, public_key, pairing);

	//free(share_hash);

//	GT gid = e(private_key, msgHashG1);
//	Zr r(e, true);
//	GT gidr = gid ^ r;
//
//	unsigned char *u_gidr;
//	int size_gidr;
//
//	size_gidr = element_length_in_bytes(*(element_t*) &gidr.getElement());
//	u_gidr = (unsigned char *) calloc(size_gidr, sizeof(unsigned char));
//	element_to_bytes(u_gidr, *(element_t*) &gidr.getElement());
//
//	unsigned char hash_gidr[SHA_DIGEST_LENGTH] = { 0 };
//	SHA1(u_gidr, size_gidr, hash_gidr);
//
//	unsigned char *signed_hash;
//	signed_hash = (unsigned char *) calloc(SHA_DIGEST_LENGTH + 1, sizeof(unsigned char));
//
//	int i;
//	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
//		signed_hash[i] = hash[i] ^ hash_gidr[i % SHA_DIGEST_LENGTH];
//	}
//
//	G1 U = sysparam.get_U() ^ r;
//
//
//
//	//********************************************//
//
//	G1 pub_key = this->openPublicKey("pubsys1", e);
//
//	GT xt = e(pub_key, U);
//
//	unsigned char *u_xt;
//	int size_xt;
//
//	size_xt = element_length_in_bytes(*(element_t*)&xt.getElement());
//	u_xt = (unsigned char *)calloc( size_xt, sizeof(unsigned char));
//	element_to_bytes(u_xt, *(element_t*)&xt.getElement());
//
//	unsigned char hash_xt[SHA_DIGEST_LENGTH]={0};
//	SHA1(u_xt, size_xt, hash_xt);
//
//	unsigned char *decrypted_data;
//	decrypted_data = (unsigned char *)calloc( SHA_DIGEST_LENGTH, sizeof(unsigned char));
//
//	for(i = 0; i < SHA_DIGEST_LENGTH; i++)
//	{
//		decrypted_data[i] = signed_hash[i]^ hash_xt[i % SHA_DIGEST_LENGTH];
//	}
//
//	//********************************************//
//
//
//
//	char *share_signed_hash_path;
//	share_signed_hash_path = (char *)calloc(strlen(share_path) + strlen("%s.signedhash") + 1, sizeof(char));
//	sprintf(share_signed_hash_path, "%s.signed_hash", share_path);
//
//	char *share_U_signed_hash_path;
//	share_U_signed_hash_path = (char *)calloc(strlen(share_path) + strlen("%s.U.signedhash") + 1, sizeof(char));
//	sprintf(share_U_signed_hash_path, "%s.U.signed_hash", share_path);
//
//	com.writeFile(share_signed_hash_path, signed_hash, SHA_DIGEST_LENGTH);
//
//	FILE *f_U;
//	f_U = fopen(share_U_signed_hash_path, "w");
//	U.dump(f_U, "", 10);
//	fclose(f_U);
//
//	free(signed_hash);
//	free(share_signed_hash_path);
//	free(share_U_signed_hash_path);
//	free(u_gidr);
}

unsigned char * Cipher::decrypt_key(char *encrypted_key_path, char *final_U_path){

	SystemParam sysparam("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	int i = 0;

	Common com;

	unsigned char *encrypted_key;
	int encrypted_key_size = 0;

	com.openFile(encrypted_key_path, (char **)&encrypted_key, &encrypted_key_size);

	//G1 pub_key = this->openPublicKey("pubsys1", e);
	G1 priv_key = this->openPrivateKeyG1("priv_key", e);

	G1 U = this->openPublicKey(final_U_path, e);

	GT xt = e(priv_key, U);

	unsigned char *u_xt;
	int size_xt;

	size_xt = element_length_in_bytes(*(element_t*) &xt.getElement());
	u_xt = (unsigned char *) calloc(size_xt, sizeof(unsigned char));
	element_to_bytes(u_xt, *(element_t*) &xt.getElement());

	unsigned char hash_xt[SHA_DIGEST_LENGTH] = { 0 };
	SHA1(u_xt, size_xt, hash_xt);

	unsigned char *decrypted_data;
	decrypted_data = (unsigned char *) calloc( SHA_DIGEST_LENGTH,
			sizeof(unsigned char));

	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		decrypted_data[i] = encrypted_key[i] ^ hash_xt[i % SHA_DIGEST_LENGTH];
	}

	return decrypted_data;

}

void Cipher::encrypt_key(char *id, char *encryptedFilePath, unsigned char *iv, unsigned char *key, int size, int M, int N){

	SystemParam sysparam("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	G1 publicKey = openPublicKey("pubsys1", e);

	printf(id);
	printf("\n");

	G1 msgHashG1;
	//hash_msg(msgHashG1, id, e);

	unsigned char *id_hash;
	id_hash = (unsigned char *)malloc(SHA_DIGEST_LENGTH);

	SHA1((unsigned char *)id, strlen(id), id_hash);

	msgHashG1 = G1(e, (void*)id_hash, SHA_DIGEST_LENGTH);

	free(id_hash);

	msgHashG1.dump(stderr, "", 10);

	GT gid = e(publicKey, msgHashG1);
	Zr r(e, true);
	GT gidr = gid ^ r;

	unsigned char *u_gidr;
	int size_gidr;

	size_gidr = element_length_in_bytes(*(element_t*) &gidr.getElement());
	u_gidr = (unsigned char *) calloc(size_gidr, sizeof(unsigned char));
	element_to_bytes(u_gidr, *(element_t*) &gidr.getElement());

	unsigned char hash_gidr[SHA_DIGEST_LENGTH] = { 0 };
	SHA1(u_gidr, size_gidr, hash_gidr);

	unsigned char *encrypted_key;
	//unsigned char *encrypted_iv;
	encrypted_key = (unsigned char *) calloc(size + 1, sizeof(unsigned char));
	//encrypted_iv = (unsigned char *) calloc(size + 1, sizeof(unsigned char));

	int i;
	for (i = 0; i < size; i++) {
		encrypted_key[i] = key[i] ^ hash_gidr[i % SHA_DIGEST_LENGTH];
		//encrypted_iv[i] = iv[i] ^ hash_gidr[i % SHA_DIGEST_LENGTH];
	}

	G1 U = sysparam.get_U() ^ r;


	char *caminho_chave_cifrada, *caminho_iv_cifrado, *caminho_U;

	char *temp_chave_cif = ".key.cif";
	char *temp_iv_cif = ".iv.cif";
	char *temp_u = ".U";

	caminho_chave_cifrada = (char *) calloc(strlen(temp_chave_cif) + strlen(encryptedFilePath)	+ 1, sizeof(char));
	caminho_iv_cifrado = (char *) calloc(strlen(temp_iv_cif) + strlen(encryptedFilePath) + 1, sizeof(char));
	caminho_U = (char *) calloc(strlen(temp_u) + strlen(encryptedFilePath) + 1,sizeof(char));

	sprintf(caminho_chave_cifrada, "%s%s",  encryptedFilePath, temp_chave_cif);
	sprintf(caminho_iv_cifrado, "%s%s", encryptedFilePath,	temp_iv_cif);
	sprintf(caminho_U, "%s%s",  encryptedFilePath, temp_u);

	Common com;

	com.writeFile(caminho_chave_cifrada, encrypted_key, size);
	com.writeFile(caminho_iv_cifrado, iv, size);

	FILE *f_U;
	f_U = fopen(caminho_U, "w");
	U.dump(f_U, "", 10);
	fclose(f_U);

	FILE *file;
	long lSize;

	file = fopen(caminho_U, "rb");

	fseek(file, 0, SEEK_END);
	lSize = ftell(file);
	rewind(file);
	fclose(file);

	Secret_Sharer sec;
	sec.split(caminho_chave_cifrada, 16, M, N);
	sec.split(caminho_iv_cifrado, 16, M, N);
	sec.split(caminho_U, lSize, M, N);

	free(u_gidr);
	free(encrypted_key);
	//free(encrypted_iv);



	this->generate_signing_keys(encryptedFilePath);
	this->generate_private_key(N, id);
	Zr private_key;
	private_key = this->openPrivateKeyZr("priv_sign_key", e);

	//G1 private_key = this->openPrivateKey("priv_key", e);
	//private_key.dump(stderr, "", 10);

	//private_key.dump(stderr, "teste", 10);

	printf("Splitting the encrypted key ... \n");

	//private_key.dump(stderr, "", 10);

	for(i = 0; i < N; i++){
		char *chave_cifrada_share_path;
		unsigned char *chave_cifrada;
		unsigned char *chave_cifrada_hash;
		int chave_cifrada_size = 0;
		chave_cifrada_share_path = (char *)calloc(strlen(caminho_chave_cifrada) + strlen("-%d_share") + 1, sizeof(char));
		sprintf(chave_cifrada_share_path, "%s-%d_share", caminho_chave_cifrada, i);
		com.openFile(chave_cifrada_share_path, (char **)&chave_cifrada, &chave_cifrada_size);
		chave_cifrada_hash = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
		SHA1(chave_cifrada, chave_cifrada_size, chave_cifrada_hash);
		this->sign_hash(chave_cifrada_hash, chave_cifrada_share_path, private_key, msgHashG1);
		free(chave_cifrada_share_path);
		free(chave_cifrada);
		free(chave_cifrada_hash);

		char *iv_cifrada_share_path;
		unsigned char *iv_cifrado;
		unsigned char *iv_cifrado_hash;
		int iv_cifrado_size = 0;
		iv_cifrada_share_path = (char *)calloc(strlen(caminho_iv_cifrado) + strlen("-%d_share") + 1, sizeof(char));
		sprintf(iv_cifrada_share_path, "%s-%d_share", caminho_iv_cifrado, i);
		com.openFile(iv_cifrada_share_path, (char **)&iv_cifrado, &iv_cifrado_size);
		iv_cifrado_hash = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
		SHA1(iv_cifrado, iv_cifrado_size, iv_cifrado_hash);
		this->sign_hash(iv_cifrado_hash, iv_cifrada_share_path, private_key, msgHashG1);
		free(iv_cifrada_share_path);
		free(iv_cifrado);
		free(iv_cifrado_hash);

		char *U_share_path;
		unsigned char *U_share;
		unsigned char *U_share_hash;
		int U_share_size = 0;
		U_share_path = (char *)calloc(strlen(caminho_U) + strlen("-%d_share") + 1, sizeof(char));
		sprintf(U_share_path, "%s-%d_share", caminho_U, i);
		com.openFile(U_share_path, (char **)&U_share, &U_share_size);
		U_share_hash = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
		SHA1(U_share, U_share_size, U_share_hash);
		this->sign_hash(U_share_hash, U_share_path, private_key, msgHashG1);
		free(U_share_path);
		free(U_share);
		free(U_share_hash);
	}

	free(caminho_chave_cifrada);
	free(caminho_iv_cifrado);
	free(caminho_U);

}


void Cipher::Encrypt(char *file_path, char *ID, int M, int N){

	int sym_key_size = 16; //(bytes)
	int iv_size = 16; //(bytes)

	unsigned char *sym_key;
	unsigned char *iv;

	char *buffer;
	char *encryptedFilePath;
	char *finalEncryptedFilePath;
	char *encrypted_string = ".enc";
	unsigned char *encrypted_data;
	int encrypted_size;
	int size;

	SystemParam sysparam("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	timeval t1, t2, t3, t4;

	gettimeofday(&t1, NULL);

	Common com;

	//com.openFile(file_path, &buffer, &size);

	printf("Generating Symmetric Key and Initialization Vector ... \n");
	this->generate_symmetric_key(sym_key_size, &sym_key);
	this->generate_iv(iv_size, &iv);

	struct stat st = {0};
	char *folder;

	folder = (char *)calloc( strlen("/tmp/%s") + strlen(file_path) + 1, sizeof(char));
	sprintf(folder, "/tmp/%s", file_path);

	if (stat(folder, &st) == -1) {
	    mkdir(folder, 0700);
	}

	encryptedFilePath = (char *)calloc(strlen(folder) + strlen(file_path) + strlen(encrypted_string) + 1, sizeof(char));
	finalEncryptedFilePath = (char *)calloc(strlen(file_path) + strlen(encrypted_string) + 1, sizeof(char));

	sprintf(encryptedFilePath, "%s/%s%s", folder, file_path, encrypted_string);
	sprintf(finalEncryptedFilePath, "%s%s", file_path, encrypted_string);

	printf("Encrypting file ... \n");
	gettimeofday(&t3, NULL);
	this->sym_encrypt((unsigned char*)buffer, size, &encrypted_data, &encrypted_size, sym_key, iv, file_path, finalEncryptedFilePath);
	gettimeofday(&t4, NULL);
	printf("Finished. \n");


//	printf("Writing encrypted file ... \n");
//	com.writeFile(finalEncryptedFilePath, encrypted_data, encrypted_size);
//	printf("Finished. \n");


	double elapsed2;

	elapsed2 = (t4.tv_sec - t3.tv_sec) * 1000.0;
	elapsed2 += (t4.tv_usec - t3.tv_usec) / 1000.0;

	cout << "Writing file: " << elapsed2 << "ms. \n";

//	if(buffer)
//		free(buffer);
//	if(encrypted_data)
//		free(encrypted_data);

	printf("Encrypting Symmetric Key ... \n");
	this->encrypt_key(ID, encryptedFilePath, iv, sym_key, 16, M, N);
	int i;
//	for(i = 0; i < 16; i++){
//		printf("%02X", *sym_key);
//		sym_key++;
//	}
//	printf("\n");
//
//	for(i = 0; i < 16; i++){
//		printf("%02X", *iv);
//		iv++;
//	}
//	printf("\n");

//	sym_key = sym_key - i;
//	iv = iv - i;
//
	if(sym_key)
		free(sym_key);
	if(iv)
		free(iv);

	printf("Encoding the encrypted file ... \n");
	char *encode_cmd = "./encoder %s %d %d reed_sol_van 8 1 0";
	char *final_encode_cmd;

	final_encode_cmd = (char *)calloc( strlen(encode_cmd) + strlen(finalEncryptedFilePath) + strlen(folder) + 10, sizeof(char));
	sprintf(final_encode_cmd, encode_cmd, finalEncryptedFilePath, N-M, M);

	system(final_encode_cmd);

//	unsigned char *enc1;
//	unsigned char *enc1_hash;
//	int enc1_size = 0;
//	com.openFile("Coding/ubuntu_k1.iso.enc", (char **)&enc1, &enc1_size);
//
//	enc1_hash = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
//	SHA1(enc1, enc1_size, enc1_hash);
//	Zr private_key;
//	private_key = this->openPrivateKeyZr("priv_sign_key", e);
//	this->sign_hash(enc1_hash, "Coding/ubuntu_k1.iso.enc", private_key);


	gettimeofday(&t2, NULL);

	double elapsed;
	elapsed = (t2.tv_sec - t1.tv_sec) * 1000.0;
	//elapsed = 0;
	elapsed += (t2.tv_usec - t1.tv_usec) / 1000.0;

	cout << elapsed << "ms. \n";

	FILE *filePtr;
	char *elapsed_file_path = "encrypt_time.txt";
	char fileContents;
	char *elapsed_char;

	elapsed_char = (char *)calloc( strlen("%f \n") + 20, sizeof(char));
	sprintf(elapsed_char, "%8.2f\n", elapsed);

	//elapsed_file_path = (char *)calloc( strlen(finalEncryptedFilePath) + strlen("%s.time") + 1, sizeof(char));
	//sprintf(elapsed_file_path, "%s.time", finalEncryptedFilePath);

	filePtr = fopen(elapsed_file_path, "r");

	if (filePtr == NULL) {
		printf("Error opening file. \n");
	} else {
		while ((fileContents = fgetc(filePtr)) != EOF) {
			putchar (fileContents);

		}
		fclose (filePtr);
	}


	filePtr = fopen(elapsed_file_path, "a");

	if (filePtr == NULL) {
		printf("Error opening file, to write to it.");
	} else {
		fwrite(elapsed_char, sizeof(char), strlen(elapsed_char), filePtr);
	}

	fclose(filePtr);

	printf("End. \n");

	free(elapsed_char);
	//free(elapsed_file_path);
	free(folder);
	free(final_encode_cmd);
	free(encryptedFilePath);

}

void Cipher::generate_shares_paths (char *file_path, int N, vector<vector<char *> >& vector_paths){

	vector<char *> share_paths;
	vector<char *> share_signed_paths;

	vector<vector<char *> > paths;

	int i;

	for (i = 0; i < N; i++){

		char *key_share_path;
		char *key_share_signed_path;

		key_share_path = (char *)calloc( strlen(file_path) + strlen("%s-%d_share") + 1, sizeof(char));
		sprintf(key_share_path, "%s-%d_share", file_path, i);

		//printf("%s \n", key_share_path);

		share_paths.push_back(key_share_path);

		key_share_signed_path = (char *)calloc(strlen (key_share_path) + strlen("%s.signed_hash") + 1, sizeof(char));
		sprintf(key_share_signed_path, "%s.signed_hash", key_share_path);

		share_signed_paths.push_back(key_share_signed_path);

		//printf("%s \n", key_share_signed_path);

		//free(key_share_path);
		//free(key_share_signed_path);

	}

	vector_paths.push_back(share_paths);
	vector_paths.push_back(share_signed_paths);

	//printf("%s \n", share_paths.at(0));
	//printf("%s \n", share_signed_paths.at(0));

}

int Cipher::verify_signatures(vector<vector<char *> > paths, int N, char *g_path, char *pub_key_path){

	int rt = 1;
	int i = 0;

	SystemParam sysparam("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	G2 g = this->openPublicKeyG2(g_path, e);
	G2 pub_key = this->openPublicKeyG2(pub_key_path, e);

	Common com;

	for(i = 0; i < N; i++){

		//printf("%s \n", paths.at(0).at(i));
		//printf("%s \n", paths.at(1).at(i));

		if( access( paths.at(0).at(i), F_OK ) != -1 ) {
			if( access( paths.at(1).at(i), F_OK ) != -1 ) {

				unsigned char *key_share;
				unsigned char *key_share_hash;
				int key_share_size = 0;
				com.openFile(paths.at(0).at(i), (char **)&key_share, &key_share_size);

				key_share_hash = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
				SHA1(key_share, key_share_size, key_share_hash);

				G1 msgHashG1;

				msgHashG1 = G1(e, (void*)key_share_hash, SHA_DIGEST_LENGTH);

				G1 sig = this->openPublicKey(paths.at(1).at(i), e);

				GT temp1, temp2;

				temp1 = e(sig, g);
				temp2 = e(msgHashG1, pub_key);

				//temp1.dump(stderr, "", 10);
				//temp2.dump(stderr, "", 10);

				if(temp1 == temp2){
					//printf("Share %d integro \n", i);
				}else{
					printf("Share %d nao integro \n", i);
					rt = 0;
					break;
				}

			} else {
				printf("Arquivo %s nao existe. \n", paths.at(1).at(i));
			}
		} else {
			printf("Arquivo %s nao existe. \n", paths.at(0).at(i));
		}

	}

	return rt;

}

void Cipher::Decrypt(char *file_path, char *id, int N){

	char *final_encrypted_file_path;
	char *encrypted_file_path;
	char *final_encrypted_sym_key_path;
	char *final_iv_path;
	char *final_U_path;
	char *final_g_path;
	char *final_pub_key_path;
	int rt1;
	int rt2;
	int rt3;

	vector<vector<char *> > sym_key_shares_path;
	vector<vector<char *> > iv_shares_path;
	vector<vector<char *> > U_shares_path;

	Common com;

	timeval t1, t2, t3, t4, t5, t6;

	gettimeofday(&t1, NULL);

	encrypted_file_path = (char *)calloc(strlen(file_path) + strlen("%s.enc") + 1, sizeof(char));
	sprintf(encrypted_file_path, "%s.enc", file_path);

	final_encrypted_file_path = (char *)calloc( (strlen(file_path)*2) + strlen("/tmp/%s/%s.enc") + 1, sizeof(char));
	sprintf(final_encrypted_file_path, "/tmp/%s/%s.enc", file_path, file_path);

	final_encrypted_sym_key_path = (char *)calloc(strlen(final_encrypted_file_path) + strlen("%s.key.cif") + 1, sizeof(char));
	sprintf(final_encrypted_sym_key_path, "%s.key.cif", final_encrypted_file_path);

	this->generate_shares_paths(final_encrypted_sym_key_path, N, sym_key_shares_path);

	final_iv_path = (char *)calloc(strlen(final_encrypted_file_path) + strlen("%s.iv.cif") + 1, sizeof(char));
	sprintf(final_iv_path, "%s.iv.cif", final_encrypted_file_path);

	this->generate_shares_paths(final_iv_path, N, iv_shares_path);

	final_U_path = (char *)calloc(strlen(final_encrypted_file_path) + strlen("%s.U") + 1, sizeof(char));
	sprintf(final_U_path, "%s.U", final_encrypted_file_path);

	this->generate_shares_paths(final_U_path, N, U_shares_path);

	final_g_path = (char *)calloc( strlen(final_encrypted_file_path) + strlen("%s.shares.g") + 1, sizeof(char));
	sprintf(final_g_path, "%s.shares.g", final_encrypted_file_path);

	final_pub_key_path = (char *)calloc( strlen(final_encrypted_file_path) + strlen("%s.shares.pub_key") + 1, sizeof(char));
	sprintf(final_pub_key_path, "%s.shares.pub_key", final_encrypted_file_path);

	//printf("%s \n", sym_key_shares_path.at(0).at(0));
	//printf("%s \n", sym_key_shares_path.at(1).at(0));

	rt1 = this->verify_signatures(sym_key_shares_path, N, final_g_path, final_pub_key_path);
	rt2 = this->verify_signatures(iv_shares_path, N, final_g_path, final_pub_key_path);
	rt3 = this->verify_signatures(U_shares_path, N, final_g_path, final_pub_key_path);

	if(rt1 && rt2 && rt3){

		printf("Decoding the encrypted file ... \n");
		char *encode_cmd = "./decoder %s.enc";
		char *final_encode_cmd;

		gettimeofday(&t3, NULL);
		final_encode_cmd = (char *)calloc( strlen(encode_cmd) + strlen(file_path) + 1, sizeof(char));
		sprintf(final_encode_cmd, encode_cmd, file_path);

		system(final_encode_cmd);
		gettimeofday(&t4, NULL);

		double elapsed2;
		elapsed2 = (t4.tv_sec - t3.tv_sec) * 1000.0;
		//elapsed = 0;
		elapsed2 += (t4.tv_usec - t3.tv_usec) / 1000.0;

		cout << elapsed2 << "ms. \n";

		printf("Combine the key shares ... \n");

		//Combinar os shares Chave cifrada, U, IV
		char *key_shares_paths;
		char *iv_shares_paths;
		char *u_shares_paths;
		int key_shares_path_size = 1;
		int iv_shares_path_size = 1;
		int u_shares_path_size = 1;

		int i;

		for(i = 0; i < sym_key_shares_path.at(0).size(); i++){
			key_shares_path_size += strlen(sym_key_shares_path.at(0).at(i)) + 1;
			iv_shares_path_size += strlen(iv_shares_path.at(0).at(i)) + 1;
			u_shares_path_size += strlen(U_shares_path.at(0).at(i)) + 1;
		}

		key_shares_paths = (char *)calloc(key_shares_path_size, sizeof(char));
		sprintf(key_shares_paths, sym_key_shares_path.at(0).at(0));

		iv_shares_paths = (char *)calloc(iv_shares_path_size, sizeof(char));
		sprintf(iv_shares_paths, iv_shares_path.at(0).at(0));

		u_shares_paths = (char *)calloc(u_shares_path_size, sizeof(char));
		sprintf(u_shares_paths, U_shares_path.at(0).at(0));

		int sizes = sym_key_shares_path.at(0).size();

		for(i = 1; i < sizes; i++){
			strcat(key_shares_paths, ",");
			strcat(key_shares_paths, sym_key_shares_path.at(0).at(i));

			strcat(iv_shares_paths, ",");
			strcat(iv_shares_paths, iv_shares_path.at(0).at(i));

			strcat(u_shares_paths, ",");
			strcat(u_shares_paths, U_shares_path.at(0).at(i));
		}

		//-func combine -file metodos.pdf.enc.key.cif-0_share,metodos.pdf.enc.key.cif-1_share -N 4 -size 16

		char *comand_combine_shares = "./SecretSharer -func combine -file %s -N %d -size %d";
		char *final_comand_combine_key_shares;
		char *final_comand_combine_iv_shares;
		char *final_comand_combine_u_shares;

		final_comand_combine_key_shares = (char *)calloc(strlen(comand_combine_shares) + key_shares_path_size + 10, sizeof(char));
		final_comand_combine_iv_shares = (char *)calloc(strlen(comand_combine_shares) + iv_shares_path_size + 10, sizeof(char));
		final_comand_combine_u_shares = (char *)calloc(strlen(comand_combine_shares) + u_shares_path_size + 10, sizeof(char));

		unsigned char *key_share;
		int k_share_size;
		com.openFile(sym_key_shares_path.at(0).at(0), (char **)&key_share, &k_share_size);

		unsigned char *iv_share;
		int iv_share_size;
		com.openFile(iv_shares_path.at(0).at(0), (char **)&iv_share, &iv_share_size);

		unsigned char *u_share;
		int u_share_size;
		com.openFile(U_shares_path.at(0).at(0), (char **)&u_share, &u_share_size);

		free(key_share);
		free(iv_share);
		free(u_share);

		sprintf(final_comand_combine_key_shares, comand_combine_shares, key_shares_paths, N, k_share_size);
		sprintf(final_comand_combine_iv_shares, comand_combine_shares, iv_shares_paths, N, iv_share_size);
		sprintf(final_comand_combine_u_shares, comand_combine_shares, u_shares_paths, N, u_share_size);

		system(final_comand_combine_key_shares);
		system(final_comand_combine_iv_shares);
		system(final_comand_combine_u_shares);

		free(final_comand_combine_key_shares);
		free(final_comand_combine_iv_shares);
		free(final_comand_combine_u_shares);

		this->generate_private_key(N, id);
		printf(id);
		printf("\n");
		unsigned char *sym_key = this->decrypt_key(final_encrypted_sym_key_path, final_U_path);

		unsigned char *iv;
		int iv_size = 0;
		com.openFile(final_iv_path, (char **)&iv, &iv_size);



		unsigned char *encrypted_file;
		int encrypted_file_size = 0;
		char *encoded_file_path;
		encoded_file_path = (char *)calloc( strlen(encrypted_file_path) + strlen("Coding/%s") + 1, sizeof(char));
		sprintf(encoded_file_path, "Coding/%s", encrypted_file_path);

		double elapsed3;

		printf("Opening file ... \n");
		gettimeofday(&t5, NULL);
		com.openFile(encrypted_file_path, (char **)&encrypted_file, &encrypted_file_size);
		gettimeofday(&t6, NULL);
		printf("End. \n");

		elapsed3 = (t6.tv_sec - t5.tv_sec) * 1000.0;
		//elapsed = 0;
		elapsed3 += (t6.tv_usec - t5.tv_usec) / 1000.0;

		cout << elapsed3 << "ms. \n";

		unsigned char *decrypted_data;
		int decrypted_data_size = 0;

		printf("Decrypting file ... \n");
		this->sym_decrypt(encrypted_file, encrypted_file_size, &decrypted_data, &decrypted_data_size, sym_key, iv, NID_aes_128_cbc);
		printf("End. \n");

		//int i;
//		for (i = 0; i < 16; i++) {
//			printf("%02X", *sym_key);
//			sym_key++;
//		}
//		printf("\n");
//
//		for (i = 0; i < 16; i++) {
//			printf("%02X", *iv);
//			iv++;
//		}
//		printf("\n");

		sym_key = sym_key - i;
		iv = iv - i;

		char *final_decrypted_file_path;
		final_decrypted_file_path = (char *)calloc(strlen("decoded_%s") + strlen(file_path) + 1, sizeof(char));
		sprintf(final_decrypted_file_path, "decoded_%s", file_path);

		printf("Writing file ... \n");
		com.writeFile(final_decrypted_file_path, decrypted_data, decrypted_data_size);
		printf("End \n");

		gettimeofday(&t2, NULL);

		double elapsed;
		elapsed = (t2.tv_sec - t1.tv_sec) * 1000.0;
		//elapsed = 0;
		elapsed += (t2.tv_usec - t1.tv_usec) / 1000.0;

		cout << elapsed << "ms. \n";

		free(final_decrypted_file_path);

		free(final_encode_cmd);
		free(key_shares_paths);


	}

	free(encrypted_file_path);
	free(final_encrypted_file_path);
	free(final_encrypted_sym_key_path);
	free(final_iv_path);
	free(final_U_path);
	free(final_g_path);
	free(final_pub_key_path);

}
