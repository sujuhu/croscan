#pragma warning(disable:4996)
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <string.h>
#include <pipe.h>
#include <windows.h>

int main(int argc, char* argv[])
{
	char* pipename = "croscan";
	int p = open_pipe(pipename);
	if (p == INVALID_PIPE) {
		printf("open pipe %s fail\n", pipename);
		exit(0);
	}

	char* input_file = "file.list";
	FILE* f = fopen(input_file, "r");
	char sample_file[520] = {0};
	while(EOF != fscanf(f, "%[^\n]", &sample_file)) {
		fgetc(f);
		printf("Sample: %s\n", sample_file);
		int nb = write_pipe(p, sample_file, strlen(sample_file));
		if (nb < 0) {
			//管道可能已经关闭， 发送失败
			printf("send sample path failed\n");
			break;
		}
	}
	fclose(f);

	//查询队列是否已经完成
	const char* request = "is finished?";
	while(true) {
		Sleep(2000);
		int nb = write_pipe(p, (void*)request, strlen(request));
		if (nb < 0) {
			printf("query failed\n");
			break;
		}

		char response[32] = {0};
		nb = read_pipe(p, response, sizeof(response) -1);
		if (nb < 0) {
			printf("read response failed\n");
			break;
		}

		if (0 == strncmp(response, "true", strlen("true"))) {
			printf("scan all finished\n");
			break;
		} else {
			continue;
		}
	}

	close_pipe(p);
}