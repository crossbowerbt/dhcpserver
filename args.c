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
    int index;
    int c;

    opterr = 0;
  
    while ((c = getopt (argc, argv, "a:l:m:o:p:")) != -1)
	switch (c) {

	case 'a': // parse IP address pool
	    char *opt    = strdup(optarg);
	    char *sfirst = opt;
	    char *slast  = strchr(opt, ',');
	    
	    if (slast == NULL)
		usage("error: comma not present in option -a.", 1);
	    slast++;
	    
	    uint32_t *first, *last;

	    if (parse_ip(sfirst, &first) != 4)
		usage("error: invalid first ip in address pool.", 1);


	    if (parse_ip(slast, &last) != 4)
		usage("error: invalid last ip in address pool.", 1);

	    pool->first   = *first;
	    pool->last    = *last;
	    pool->current = *first;

	    free(first);
	    free(last);
	    free(opt);

	    break;

	case 'l': // parse default lease time
	    time_t *t;

	    if(parse_long(optarg, &t) != 4)
		usage("error: invalid default lease time.", 1);

	    pool->lease_time = *t;
	    free(t);
	    break;

	case 'm': // parse max lease time
	    time_t *t;

	    if(parse_long(optarg, &t) != 4)
		usage("error: invalid max lease time.", 1);

	    pool->max_lease_time = *t;
	    free(t);
	    break;

	case 'o': // parse dhcp option
	    dhcp_option option;
	    uint8_t id;

	    char *opt   = strdup(optarg);
	    char *name  = opt;
	    char *value = strchr(opt, ',');
	    
	    if (value == NULL)
		usage("error: comma not present in option -o.", 1);
	    value++;

	    if((id = parse_option(&option, name, value)) == 0)
		usage("error: invalid dhcp option specified.", 1);

	    copy_option(&pool->options[id], &option);

	    free(opt);

	case 'p': // parse pending time
	    time_t *t;

	    if(parse_long(optarg, &t) != 4)
		usage("error: invalid pending time.", 1);

	    pool->pending_time = *t;
	    free(t);
	    break;

	case '?':
	    usage(NULL, 1);

	default:
	    usage(NULL, 1);
	}
    
    for (index = optind; index < argc; index++)
	printf ("Non-option argument %s\n", argv[index]);

}
