/*
 * SecretSharer.cpp
 *
 *  Created on: Sep 23, 2013
 *      Author: rick
 */

#include "SecretSharer.h"

#include "libgfshare.h"

Secret_Sharer::Secret_Sharer() {
	// TODO Auto-generated constructor stub

}

Secret_Sharer::~Secret_Sharer() {
	// TODO Auto-generated destructor stub
}

void Secret_Sharer::split(char *file_path, int size, int M, int N){

	char *final_cmd;
	char *cmd = "./SecretSharer -func split -file %s -M %d -N %d -size %d";

	final_cmd = (char *)calloc(strlen(cmd) + strlen(file_path) + 15, sizeof(char));
	sprintf(final_cmd, cmd, file_path, M, N, size);

	system(final_cmd);


}
