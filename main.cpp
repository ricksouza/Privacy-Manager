/*
 * main.cpp
 *
 *  Created on: Sep 23, 2013
 *      Author: rick
 */

#include "Cipher.h"

//-func encrypt -data metodos.pdf -ID metodos/grupo1/1.0 -M 2 -N 4
//-func decrypt -data metodos.pdf -ID metodos/grupo1/1.0 -N 4

// -func encrypt -data ControleDeAcesso.flv -ID desenho/grupo1/1.0 -M 2 -N 4
// -func decrypt -data ControleDeAcesso.flv -ID desenho/grupo1/1.0 -N 4

int main(int argc, char **argv){

	//TODO Filtrar comandos:
	/**
	 * cifrar:     -func encrypt -data file_path -ID id(docName + group + version) -M m -N n
	 * decifrar:   -func decrypt -data file_path -ID id(docName + group + version)
	 */

	int rc = 0;
	char *func;
	char *file_path;
	char *ID;
	int M;
	int N;

	optarg = NULL;
	optopt = 0;
	opterr = 0; /* 0 disables stderror errors msg */
	optind = 0;

	static struct option long_options[] = {
		  {"func", required_argument, NULL, 0},
		  {"data", required_argument, NULL, 1},
		  {"M", required_argument, NULL, 2},
		  {"N", required_argument, NULL, 3},
		  {"ID", required_argument, NULL, 4},
		  {0, 0, 0, 0}
	};

	printf("Starting Privacy Manager... \n");

	while ((rc = getopt_long_only(argc, argv, "f:d:m:n:", long_options, NULL)) != -1) {
		switch (rc) {
		case 0:

			func = (char *) calloc(strlen(optarg) + 1, sizeof(char));
			sprintf(func, "%s", optarg);
			break;
		case 1:
			file_path = (char *) calloc(strlen(optarg) + 1, sizeof(char));
			sprintf(file_path, "%s", optarg);
			break;
		case 2:

			M = atoi(optarg);
			break;
		case 3:
			N = atoi(optarg);
			break;
		case 4:
			ID = (char *)calloc(strlen(optarg) + 1, sizeof(char));
			sprintf(ID, "%s", optarg);
			break;
		default:
			if (optopt) {
				//A variável optopt vem num inteiro representável e representa a opcao invalida
				printf("Opcao invalida. \n");
				optopt = 0;
			} else {
				printf("Opcao nao reconhecida. \n");
			}
			break;
		}
	}

	Cipher ciph;

	if(strcmp(func, "encrypt") == 0){
		printf("Encrypting File %s using M: %d and N: %d \n", file_path, M, N);
		ciph.Encrypt(file_path, ID, M, N);
	}else if(strcmp(func, "decrypt") == 0){
		ciph.Decrypt(file_path, ID, N);
	}else{
		printf("Funcao nao reconhecida. \n");
	}

	return 0;
}
