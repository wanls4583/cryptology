#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file.h"
#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

unsigned char* load_file(char* filename, int* buffer_length) {
	int file;
	struct stat file_stat;
	unsigned char* buffer;
	unsigned char* bufptr;
	int buffer_size;
	int bytes_read;

	if ((file = open(filename, O_RDONLY)) == -1) {
		perror("Unable to open file");
		return NULL;
	}

	if (fstat(file, &file_stat)) {
		perror("Unable to stat certificate file");
		return NULL;
	}

	buffer_size = file_stat.st_size;
	buffer = (unsigned char*)malloc(buffer_size);

	if (!buffer) {
		perror("Not enough memory");
		return NULL;
	}

	bufptr = buffer;
	while ((bytes_read = read(file, (void*)bufptr, buffer_size))) {
		bufptr += bytes_read;
	}

	close(file);

	if (buffer_length != NULL) {
		*buffer_length = buffer_size;
	}

	return buffer;
}
