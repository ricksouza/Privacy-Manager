/*
 * Common.h
 *
 *  Created on: Sep 23, 2013
 *      Author: rick
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

class Common {
public:
	Common();
	virtual ~Common();
	void openFile(char *filePath, char **buffer, int *size);
	void writeFile(char *filePath, unsigned char *buffer, int size);
};

#endif /* COMMON_H_ */
