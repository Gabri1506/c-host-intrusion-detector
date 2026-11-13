#ifndef LOG_H
#define LOG_H

#include <stdio.h>

typedef struct {
    FILE *flog;
    char lasthash[65];
} idslog;

idslog* startlog(const char *filename);
int logger(const char *msg, idslog *logstru);
int closelog(idslog *logstru);

#endif