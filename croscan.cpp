#pragma warning( disable:4996 )
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <direct.h>
#include <windows.h>
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include "typedef.h"
#include <slist.h>
#include <hashtable.h>
#include <getopt.h>
#include <termctrl.h>
#include <pipe.h>
#include "debug.h"
#include "avctrl.h"

typedef struct _av_t
{
	snode_t  node;
	char name[64];
	char cmdline[512];
	char path[512];
	int  flush;
	int  fd;
}av_t;

typedef struct _result_t
{
	snode_t node;
	char name[64];
	char output[4096];
}result_t;

bool g_interactive = false;
char * g_input_pipe = NULL;

void usage()
{
	printf("Multi-Antivirus Scanner, ");
	printf("console version (c) Kim Zhang  analyst004@gmail.com");
	printf("Usage: croscan [options]\n");
	printf("    options : optional parameters described in [Options] section\n");
	printf("Options\n");
	printf("    -p <pipe name>, --pipe: get sample path from pipe\n");
	printf("    -i, --interactive: get sample path from console\n");
	printf("	-d, --debug: display debug information\n");
	printf("    -h, --help: this message\n");
}

#define OPT "p:f:ih"

int parse_cmdline(int argc, char *argv[])
{
	while (1) {
		static struct option long_options[] = {
			{ "--pipe", 1, 0, 'p' },
			{ "--interactive", 0, 0, 'i' },
			{ "--debug", 0, 0, 'd' },
			{ "--help", 0, 0, 'h' },
		};	

		static int optidx;
		int c = getopt_long(argc, argv, OPT, long_options, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			if (g_interactive ) {
				usage();
			} else {
				printf("Pipe Mode: %s\n", optarg);
				g_input_pipe = optarg;
			}
			break;
		case 'd':
			g_debug = true;
			break;
		case 'i':
			if ( g_input_pipe != NULL) {
				usage();
			} else {
				printf("Interactive Mode\n");
				g_interactive = true;	
			}
			break;
		case 'h':
			usage();
			return 1;
		default:
			usage();
			return -1;
		}
	}

	/*
	if (optind == argc) {
		usage();
		return -1;
	}
	*/

	return 0;
}

/*
void output_report(slist_t* report)
{
	snode_t* pos = NULL;
	slist_for_each(pos, report->first) {
		result_t* result = slist_entry(pos, result_t, node);
		printf("Scanner: %s\n", result->name);
		printf("-----------------------------------------------------------\n");
		printf("%s\n", result->output);
		printf("-----------------------------------------------------------\n");
	}
}
*/

bool parse_scanner(xmlDocPtr doc, xmlNodePtr node, av_t* av)
{
	node = node->xmlChildrenNode;
	while(node != NULL) {
		if (!xmlStrcmp(node->name, (const xmlChar*)"name")) {
			xmlChar* name = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			_snprintf(av->name, sizeof(av->name) - 1, "%s", name);
			//xmlFree(name);
		} else if (!xmlStrcmp(node->name, (const xmlChar*)"cmdline")) {
			xmlChar* cmdline = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			_snprintf(av->cmdline, sizeof(av->cmdline) - 1, "%s", cmdline);
			//xmlFree(cmdline);
		} else if (!xmlStrcmp(node->name, (const xmlChar*)"flush")) {
			xmlChar* flush = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
			av->flush = atoi((const char*)flush);
			//xmlFree(flush);
		} else if (!xmlStrcmp(node->name, (const xmlChar*)"path")) {
			xmlChar* path = xmlNodeListGetString(doc, node->xmlChildrenNode,1);
			_snprintf(av->path, sizeof(av->path) - 1, "%s", path);
		} else {
		
		}

		node = node->next;
	}

	if (strlen(av->name) <= 0) {
		return false;
	}

	if (strlen(av->cmdline) <= 0) {
		return false;
	}

	return true;
}

void scan(slist_t* scanners, const char* sample_file)
{
	printf("%-10s%-45s%-5s", "Checking", sample_file, "...");
	if ( -1 == access(sample_file, 0)) {
		//file not exist
		setforecolor(CLR_RED);
		printf("FAIL\n");
		setforecolor(CLR_WHITE);
		return;
	} else {
		setforecolor(CLR_GREEN);
		printf("OK\n");
		setforecolor(CLR_WHITE);
	}

	//发送给各个引擎
	snode_t* pos = NULL;
	slist_for_each(pos, scanners->first) {
		av_t* av = slist_entry(pos, av_t, node);
		result_t* result = (result_t*)malloc(sizeof(result_t));
		memset(result, 0, sizeof(result_t));
		strncpy(result->name, av->name, sizeof(result->name) - 1);
		if (av->fd != INVALID_SCANNER)
			scan_file(av->fd, sample_file);
	}
}

bool parse_setting(const char* xml_file, slist_t* scanners)
{
	if (0 != access(xml_file, 0)) {
		dprintf("scanner.xml not found\n");
		return false;
	}

	xmlDocPtr doc = xmlParseFile(xml_file);
	if (doc == NULL) {
		dprintf("open xml file failed\n");
		return false;
	}

	xmlNodePtr root = xmlDocGetRootElement(doc);
	if (root == NULL) {
		xmlFreeDoc(doc);
		dprintf("get xml root failed");
		return false;
	}

	if (xmlStrcmp(root->name, (const xmlChar*)"scanners")) {
		xmlFreeDoc(doc);
		dprintf("wrong xml\n");
		return false;
	}
 
 	xmlNodePtr cur = root->xmlChildrenNode;
 	while(cur != NULL) {
 		if (!xmlStrcmp(cur->name, (const xmlChar*)"scanner")) {
			av_t* av = (av_t*)malloc(sizeof(av_t));
			if (av == NULL) {	
				errno = ENOMEM;
				return NULL;
			}
			memset(av, 0, sizeof(av_t));

 			if (!parse_scanner(doc, cur, av)){
 				free(av);
 				av = NULL;
 			} else {
 				slist_add(scanners, &av->node);	
 			}
 			
 		}
 		cur = cur->next;
 	}

	xmlCleanupParser();
	return true;
}

void parse_scanner_cmdline(const char* name, char* cmdline, int max)
{
	char vir_dir[520] = {0};
	_getcwd(vir_dir, sizeof(vir_dir) - 1);
	strcat(vir_dir, "\\__CROSCAN_SAMPLE__");
	//printf("%s\n", vir_dir);
	if (0!=access(vir_dir,0)) {
		mkdir(vir_dir);
	}

	char env[1024] = {0};
	_snprintf(env, sizeof(env) - 1, "VIRUS_DIR=%s", vir_dir);
	_putenv(env);

	char log_file[520] = {0};
	char cwd[520] = {0};
	_getcwd(cwd, sizeof(cwd) - 1);
	strcat(cwd, "\\log");
	if ( 0 != access(cwd, 0)) {
		mkdir(cwd);
	}
	_snprintf(log_file, sizeof(log_file) - 1, "%s\\%s.log", cwd, name);

	memset(env, 0, sizeof(env) - 1);
	_snprintf(env, sizeof(env) - 1, "LOG_FILE=%s", log_file);
	_putenv(env);

	char expand_cmdline[2048] = {0};
	ExpandEnvironmentStrings(cmdline, expand_cmdline, sizeof(expand_cmdline) - 1);
	memset(cmdline, 0, max);
	strncpy(cmdline, expand_cmdline, max);
}

int main(int argc, char* argv[])
{
	setforecolor(CLR_WHITE);
	//read argrument
	if (-1 == parse_cmdline(argc, argv)) {
		return 0;
	}

	//read config
	printf("%-60s", "Loading scanner.xml ...");
	slist_t scanners;
	slist_init(&scanners);
	if (!parse_setting("scanner.xml", &scanners) ) {
		setforecolor(CLR_RED);
		printf("FAIL\n");
		setforecolor(CLR_WHITE);
		return 0;
	} else {
		setforecolor(CLR_GREEN);
		printf("OK\n");
		setforecolor(CLR_WHITE);
	}

	//load antivirus
	snode_t* pos = NULL;
	slist_for_each(pos, scanners.first) {
		av_t* av = slist_entry(pos, av_t, node);
		printf("%-8s%-12s%-40s", "Loading", av->name, "...");
		parse_scanner_cmdline(av->name, av->cmdline, sizeof(av->cmdline) - 1);
		//printf("%s\n", av->name);
		//printf("%s\n", av->cmdline);
		//printf("%d\n", av->flush);

		//atach
		char vir_dir[520] = {0};
		_getcwd(vir_dir, sizeof(vir_dir) - 1);
		strcat(vir_dir, "\\__CROSCAN_SAMPLE__");
		av->fd = create_scanner(av->name, av->cmdline, av->path, vir_dir);
		if (av->fd == INVALID_SCANNER) {
			setforecolor(CLR_RED);
			printf("%s\n", "FAIL");
			setforecolor(CLR_WHITE);
			continue;
		} else {
			setforecolor(CLR_GREEN);
			printf("%s\n", "OK");
			setforecolor(CLR_WHITE);
		}
	}

	//从控制台接收请求
	if (g_interactive) {
		while(true) {
			setforecolor(CLR_YELLOW);
			printf("Please Enter Sample Full Path:(Press Ctrl-C to Exit)\n");
			setforecolor(CLR_WHITE);
			char sample_file[520] = {0};
			scanf("%s", sample_file);
			scan(&scanners, sample_file);
		}
	}

	//从文件列表中接受请求
	/* 不支持从文件中来读取MD5列表， 因为不知道文件何时会全部扫完
	if (g_input_file) {
		FILE* f = fopen(g_input_file, "r");
		char sample_file[520] = {0};
		while(true) {
			if ( fscanf(f, "%[^\n]s", &sample_file) <= 0){
				break;
			}
			if (-1 == access(sample_file, 0)) {
				printf("%s: No such file\n");
				continue;
			}
			printf("sample file = %s", sample_file);
			//scan(&scanners, sample_file);
		}
		fclose(f);
	}
	*/

	//从进程管道中接收请求
	if (g_input_pipe) {
		while(true) {
			printf("%-60s", "Create Process Pipe ...");
			int p = create_pipe(g_input_pipe);
			if (p == INVALID_PIPE) {
				setforecolor(CLR_RED);
				printf("FAIL\n");
				setforecolor(CLR_WHITE);
				exit(0);
			} else {
				setforecolor(CLR_GREEN);
				printf("OK\n");
				setforecolor(CLR_WHITE);
			}

			printf("%-60s", "Listening Process Pipe ...");
			if (!listen_pipe(p)) {
				setforecolor(CLR_RED);
				printf("FAIL\n");
				setforecolor(CLR_WHITE);
				exit(0);
			} else {
				setforecolor(CLR_GREEN);
				printf("OK\n");
				setforecolor(CLR_WHITE);
			}

			for(;;) {
				char sample_file[520] = {0};
				int nb = read_pipe(p, sample_file, sizeof(sample_file));
				if (nb < 0) {
					break;
				}

				scan(&scanners, sample_file);
			}
			close_pipe(p);
			p = NULL;
		}
	}

	/*
	av_t* av = NULL;
	slist_for_each_safe(av, &scanners, av_t, node) {
		close_scanner(av->fd);
		av->fd = 0;
		free(av);
		av = NULL;
	}
	*/

	return 0;
}