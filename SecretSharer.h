/*
 * SecretSharer.h
 *
 *  Created on: Sep 23, 2013
 *      Author: rick
 */

#ifndef SECRETSHARER_H_
#define SECRETSHARER_H_

#include "Common.h"

class Secret_Sharer {
public:
	Secret_Sharer();
	virtual ~Secret_Sharer();
	void split(char *file_path, int size, int M, int N);

};

#endif /* SECRETSHARER_H_ */
