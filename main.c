//realized by Gabri1506
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <signal.h>
#include <errno.h>

#include <dirent.h>
#include <sys/stat.h>

#include <pthread.h> 
#include "log.h"

#define ERROR -1
#define EVENT_SIZE  (sizeof (struct inotify_event))
#define BUF_LEN (1024*(EVENT_SIZE +16))
#define MAX_EVENTS 32768
#define MAX_DYNAMIC 100


volatile sig_atomic_t eseguo = 1;

void stop_handler(int sig) {
    eseguo = 0;
}

typedef struct {
    int wd;
    char *path;
} watchmap;


int watcher(int fd, int fdpoll){

    struct epoll_event evento;
    evento.events = EPOLLIN;    
    evento.data.fd = fd;


    if(epoll_ctl(fdpoll, EPOLL_CTL_ADD, fd, &evento) == ERROR){
        perror("epoll_ctl");
        return ERROR;
    }
    return 0;
}

int checker(int fd, const char * file, watchmap ** map, int *index, int * max){

    if (*index >= *max) {
        int newmax = (*max) * 2; 
        watchmap *newmap = realloc(*map, newmax * sizeof(watchmap));
        if(newmap == NULL){
            printf("reallocation error\n");
            return ERROR;
        }
        *map = newmap;
        *max = newmax;
    }

    int wd = inotify_add_watch (fd,file, IN_MODIFY | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF);

    if(wd == ERROR){
        if(errno == ENOSPC){
            printf("[!]the kernel has reached its limit, the next watches will be skipped\n");
            return 1;
        }
        perror("inotify_add_watch");
        return ERROR;
    }
    printf("[*]watch started\n");
    (*map)[*index].wd= wd;

    char *cpath = realpath(file, NULL);

    if (cpath != NULL) { 

        (*map)[*index].path = cpath;
    }else{

        (*map)[*index].path = strdup(file);
    }
    (*index)++;
    
    return 1;
}


int scan(int fd, const char *base_path, watchmap **map, int *index, int *max, int dynamic) {

    static int dynamicwatch = 0;

    if (dynamic && dynamicwatch >= MAX_DYNAMIC){
        printf("[!] DYNAMIC LIMIT REACHED (%d). Ignoring folder: %s\n", MAX_DYNAMIC, base_path);
        return 1;
    }


    if (checker(fd, base_path, map, index, max) == ERROR) {
        printf("[*]error while adding a watcher, skipping and moving on to the next one\n");
        return ERROR; 
    }
    
    if(dynamic){
        dynamicwatch++;
    }

    DIR *dir = opendir(base_path);
    if (dir != NULL) { 
        struct dirent *entry;
        struct stat st;

        while ((entry = readdir(dir)) != NULL) {
            
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                
                size_t req_len = strlen(base_path) + strlen(entry->d_name) + 2;
                char *full_path = malloc(req_len);
                
                if (full_path != NULL) {
                    snprintf(full_path, req_len, "%s/%s", base_path, entry->d_name);

                    if (lstat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                        scan(fd, full_path, map, index, max,dynamic); 
                    }
                    free(full_path);
                }else{
                perror("malloc error in scan");
                }
            }
        }
        closedir(dir);
        return 0;
    }else{
        return ERROR;
    }

}




int main(int argc, char *argv[]){

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);

    int fd, watchs = 0, maxwatchs = 10;
    watchmap *map = malloc(maxwatchs * sizeof(watchmap));
    if (map == NULL) {
        printf("malloc failed\n");
        return 1;
    }
    char *home = getenv("HOME");

    const char *dir[] = { 
        "/etc/",
        "/tmp/",
        "/bin/",
        NULL
    };

    const char *fromhome[] = {
    ".ssh/",
    ".bash_history",
    "Downloads/",
    ".config/",
    NULL
    };


    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if(fd == ERROR){
        perror("inotify_init");
        return ERROR;
    }else{
        printf("[*]instance initiated\n");
    }


    idslog *log1 = startlog("integrity.log");
    if(log1 == NULL){
        perror("error opening log file");
        eseguo = 0;
    }

    extern void* mainet1(void* arg); 
    pthread_t net_thread;
    if(pthread_create(&net_thread, NULL, mainet1, NULL) != 0) {
        perror("Error creating network thread");
        return 1;
    }

    for(int i = 1; i < argc; i++){
        if(scan(fd,argv[i], &map, &watchs, &maxwatchs,0) == ERROR){
                    printf("[*]error while scanning the folder\n");
                    
                }
    }

    for(int i = 0; dir[i] != NULL; i++){
        if(scan(fd,dir[i], &map, &watchs, &maxwatchs,0) == ERROR){
                    printf("[*]error while scanning the folder\n");
                }
        
    }




    if(home){
        for (int i = 0; fromhome[i] != NULL; i++) {
            size_t hlen = strlen(home) + strlen(fromhome[i]) + 2;
            char *fullpath = malloc(hlen);

            if (fullpath != NULL) {
                snprintf(fullpath, hlen, "%s/%s", home, fromhome[i]);

                if(scan(fd, fullpath, &map, &watchs, &maxwatchs,0) == ERROR){
                    printf("[*] error while scanning: %s\n", fullpath);
                }
                
                free(fullpath);
            }else{
                printf("malloc error for home paths\n");
                
            }
            
        }
    }


    
    int fdpoll = epoll_create1(EPOLL_CLOEXEC);
    if(fdpoll != ERROR){
        watcher(fd,fdpoll);

        printf("[*] IDS started. Press Ctrl+C to exit\n");
    }else{
        perror("epoll_create1");
        eseguo = 0;
    }

    int maxevent = 64;
    struct epoll_event *eventi = malloc(maxevent*sizeof(struct epoll_event ));
    
    if(eventi == NULL){
        perror("malloc eventi");
        eseguo = 0;
    }

    while(eseguo){

        int n = epoll_wait(fdpoll,eventi,maxevent,500);
        if(n>0){

            for (int i = 0; i < n; i++) {

                    char buffer[BUF_LEN];
                    ssize_t length = read(fd, buffer, BUF_LEN);

                    if(length > 0){

                        size_t pos = 0;
                        while (pos < length) {
                            struct inotify_event *event = (struct inotify_event *) &buffer[pos];
                            char * alertpath = "unknown";
                            char logmsg[2048];
                            if (event->mask & IN_Q_OVERFLOW) {
                                printf("[!] event queue full, some changes may not be recorded\n");
                            }else if(event->wd != ERROR){ 
                                int find = 0;
                                for (int j = 0; j < watchs && !find; j++) {
                                    if (map[j].wd == event->wd) {
                                        alertpath = map[j].path;
                                        find = 1;
                                    }
                                }
                            }
                            
                            if (event->len > 0) {
                                
                                if (event->mask & IN_CREATE){

                                    printf("[!] CREATED: %s/%s\n", alertpath, event->name);

                                    snprintf(logmsg, sizeof(logmsg), "CREATED: %s/%s", alertpath, event->name);
                                    logger(logmsg, log1);

                                    if (event->mask & IN_ISDIR) {

                                        size_t nlen = strlen(alertpath) + strlen(event->name) + 2;
                                        char *new_path = malloc(nlen);


                                        if (new_path) {
                                            snprintf(new_path, nlen, "%s/%s", alertpath, event->name);
                                            printf("[*] New dynamic subfolder: %s\n", new_path);

                                            snprintf(logmsg, sizeof(logmsg), "New watch added for: %s", new_path);
                                            logger(logmsg, log1); 

                                            scan(fd, new_path, &map, &watchs, &maxwatchs,1);
                                            free(new_path);
                                        }
                                    }

                                }else if (event->mask & IN_DELETE){
                                    printf("[!] DELETED: %s/%s\n", alertpath,event->name);
                                    snprintf(logmsg, sizeof(logmsg), "DELETED: %s/%s", alertpath, event->name);
                                    logger(logmsg, log1);
                                }else if (event->mask & IN_MODIFY){
                                    printf("[!] MODIFIED: %s/%s\n", alertpath, event->name);
                                    snprintf(logmsg, sizeof(logmsg), "MODIFIED: %s/%s", alertpath, event->name);
                                    logger(logmsg, log1);
                                }else if (event->mask & IN_MOVED_FROM) {
                                    printf("[!] MOVED (FROM): %s/%s\n", alertpath, event->name);
                                    snprintf(logmsg, sizeof(logmsg), "MOVED (FROM): %s/%s", alertpath, event->name);
                                    logger(logmsg, log1);
                                }else if (event->mask & IN_MOVED_TO) {
                                    printf("[!] MOVED (TO): %s/%s\n", alertpath, event->name);
                                    snprintf(logmsg, sizeof(logmsg), "MOVED (TO): %s/%s", alertpath, event->name);
                                    logger(logmsg, log1);

                                    if (event->mask & IN_ISDIR) {

                                        size_t nlen = strlen(alertpath) + strlen(event->name) + 2;
                                        char *new_path = malloc(nlen);


                                        if (new_path) {
                                            snprintf(new_path, nlen, "%s/%s", alertpath, event->name);
                                            printf("[*] New dynamic subfolder: %s\n", new_path);

                                            snprintf(logmsg, sizeof(logmsg), "New watch added for: %s", new_path);
                                            logger(logmsg, log1); 

                                            scan(fd, new_path, &map, &watchs, &maxwatchs,1);
                                            free(new_path);
                                        }
                                    }

                                }
                            }else if(event->len == 0){
                                if (event->mask & IN_MODIFY) {
                                    printf("[!] DIRECTORY MODIFIED: %s\n", alertpath);
                                    snprintf(logmsg, sizeof(logmsg), "DIRECTORY MODIFIED: %s", alertpath);
                                    logger(logmsg, log1);
                                }else if (event->mask & IN_DELETE_SELF) {
                                    printf("[!] DIRECTORY DELETED %s\n", alertpath);
                                    snprintf(logmsg, sizeof(logmsg), "DIRECTORY DELETED: %s", alertpath);
                                    logger(logmsg,log1);
                                }else if (event->mask & IN_MOVE_SELF) {
                                    printf("[!] WARNING: The monitored directory has been moved/renamed: %s\n", alertpath);
                                    snprintf(logmsg, sizeof(logmsg), "MOVE_SELF: %s", alertpath);
                                    logger(logmsg, log1);
                                }
                            }

                            pos += sizeof(struct inotify_event) + event->len;
                        }
                    }else if(length < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            perror("Critical inotify read error");
                            eseguo = 0; 
                    }
                
            }

            if(n == maxevent && maxevent < MAX_EVENTS){
                int newmaxevent = maxevent*2;

                if (newmaxevent > MAX_EVENTS){
                    newmaxevent = MAX_EVENTS;
                }

                struct epoll_event *neweventi = realloc(eventi, newmaxevent* sizeof(struct epoll_event));
                if(neweventi){
                    eventi = neweventi;
                    maxevent=newmaxevent;
                    printf("[*]epoll expanded to %d events\n",maxevent);
                }else{
                    printf("epoll realloc failed\n");
                }
            }



        }else if(n < 0) {   
            if(errno != EINTR){ 
                perror("epoll_wait failed");
                eseguo = 0;
            }

        }
    }

    printf("\n[*] Shutting down...\n"); 

    pthread_join(net_thread, NULL); 

    for (int i = 0; i < watchs; i++) {
        free(map[i].path);
    }
    closelog(log1);
    close(fd);
    close(fdpoll);
    free(map);
    free(eventi);
    return 0;
}
