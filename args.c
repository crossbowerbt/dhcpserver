#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "args.h"
#include "options.h"

void usage(char *msg, int exit_status)
{
    fprintf(exit_status == 0 ? stdout : stderr,
	    "%s", usage_txt);
    
    if (msg) {
	fprintf(exit_status == 0 ? stdout : stderr,
		"\n%s\n", msg);
    }
    
    exit(exit_status);
}
 
void parse_args(int argc, char *argv[], address_pool *pool)
{
    int aflag = 0;
    int bflag = 0;
    char *cvalue = NULL;
    int index;
    int c;

    opterr = 0;
  
    while ((c = getopt (argc, argv, "a:l:m:o:p:")) != -1)
	switch (c) {
	case 'a':
	    char *opt = strdup(optarg);
	    
	    char *first = opt;
	    char *last = strchr(opt, ',');
	    
	    if (last == NULL) usage("Error: comma not present in option -a.", 1);
	    last++;
	    
	    pool->

	    free(opt);
	    break;
	case 'b':
	    bflag = 1;
	    break;
	case 'c':
	    cvalue = optarg;
	    break;
	case '?':
	    if (optopt == 'c')
		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	    else if (isprint (optopt))
		fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	    else
		fprintf (stderr,
			 "Unknown option character `\\x%x'.\n",
			 optopt);
	    return 1;
	default:
	    abort ();
	}
    
    printf ("aflag = %d, bflag = %d, cvalue = %s\n",
	    aflag, bflag, cvalue);
    
    for (index = optind; index < argc; index++)
	printf ("Non-option argument %s\n", argv[index]);

}
