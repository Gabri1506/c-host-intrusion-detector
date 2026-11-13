//Realized by Gabri1506
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include "log.h"


static void hash(const char * msg, const char * hashin, char * hashout ){ 
    char combined[2048];
    unsigned char rawhash[SHA256_DIGEST_LENGTH];

    snprintf(combined, sizeof(combined), "%s%s", msg, hashin);
    SHA256((unsigned char*)combined, strlen(combined), rawhash);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashout + (i * 2), "%02x", rawhash[i]);
    }
    hashout[64] = '\0';
}

idslog * startlog(const char * filename){
    FILE * flog = fopen(filename, "a");



    if (flog == NULL) {
        perror("Error opening log file");
        return NULL;
    }


    idslog *logstru = malloc(sizeof(idslog));
    if (logstru == NULL) {
        perror("Log memory allocation error");
        fclose(flog);
        return NULL;
    }

    logstru->flog = flog;

    memset(logstru->lasthash, 0, sizeof(logstru->lasthash));
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char t_str[20];
    strftime(t_str, sizeof(t_str), "%Y-%m-%d %H:%M:%S", t);


    if(fprintf(logstru->flog, "[%s] Session start...\n", t_str) == EOF){
        perror("fprintf logging error");
        free(logstru);
        return NULL;
    }
    
    fflush(logstru->flog); 
    return logstru;

}

int logger(const char * msg, idslog *logstru){ 

    if (logstru == NULL || logstru->flog == NULL) {
        perror("Log error");
        return -1;
    }

    

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char t_str[20];
    strftime(t_str, sizeof(t_str), "%Y-%m-%d %H:%M:%S", t);

    char hashnow[65];
    hash(msg, logstru->lasthash, hashnow);
    
    memcpy(logstru->lasthash, hashnow, sizeof(logstru->lasthash));

    if(fprintf(logstru->flog, "[%s] %s | HASH: %s\n", t_str, msg, hashnow) == EOF){
        perror("Log write error");
        return -1;
    }
    fflush(logstru->flog);
    return 0;

}


int closelog(idslog *logstru) {

    int good = 0;

    if (logstru == NULL) {
        return -1;
    }


    if (logstru->flog) {
        
        
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char t_str[20];
        strftime(t_str, sizeof(t_str), "%Y-%m-%d %H:%M:%S", t);



        if(fprintf(logstru->flog, "[%s] Session end...\n", t_str) == EOF){
            perror("fprintf logging error");
            good = -1;
        }

        fclose(logstru->flog);
    }else{
        good = -1;
    }

    free(logstru);
    return good;
}
