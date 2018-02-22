/*
 * Common.cpp
 *
 *  Created on: Sep 23, 2013
 *      Author: rick
 */

#include "Common.h"

Common::Common() {
	// TODO Auto-generated constructor stub

}

Common::~Common() {
	// TODO Auto-generated destructor stub
}

void Common::openFile(char *filePath, char **buffer, int *size){

	FILE *file;
	long lSize;

	file = fopen(filePath, "rb");

	fseek(file, 0, SEEK_END);
	lSize = ftell(file);
	rewind(file);
	// allocate memory to contain the whole file:
	*buffer = (char*) (malloc(sizeof(char) * lSize));
	if (*buffer == NULL) {
		fputs("Memory error", stderr);
		exit(2);
	}
	// copy the file into the share_buffer:
	*size = fread(*buffer, 1, lSize, file);

	fclose(file);
}

void Common::writeFile(char *filePath, unsigned char *buffer, int size){

	FILE *file;
	file = fopen(filePath, "wb");

	fwrite(buffer, sizeof(unsigned char), size, file);
	fclose(file);

}
