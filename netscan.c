//Realized by g4lb1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "log.h"
#include <unistd.h>
#include <signal.h>
#define LUNG_RIGA 13
#define LUNG_NUMERI 10
#define LUNG_LETTERE 6
#define LUNG_MAX_LINEA 256
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define RESET   "\033[0m"
#define LUNG_IP 5
#define COMPONENT_IP 4
#define LUNG_INDIRIZZO_PORTA 9
extern volatile sig_atomic_t eseguo;

int conversione(char x);
void invertiArray(int arr[], int dimensione);
int check_whitelist(int* indirizzo, idslog * log2, FILE* whitelist, int k);
void parsing(char* rem_addr, int* risultato_finale);
int analisi_indirizzo(const char* proc_net_path, const char* whitelist_path, idslog* log2, int k);
void* mainet(void*);

void * mainet1(void* arg) {
    const char* proc_net_path[] = {
    "/proc/net/tcp",
    "/proc/net/udp"
    };

    const char* whitelist_path[] = {
    "whitelist_tcp.txt",
    "whitelist_udp.txt"
    };

    idslog *log2 = startlog("socket.log");
    if(log2 == NULL){
        perror("Error opening log file");
    }

    while(eseguo){
        for (int k = 0; k < 2; k++) {
            analisi_indirizzo(proc_net_path[k], whitelist_path[k], log2, k);
        }
        sleep(3);
    }
    

    closelog(log2);
    return NULL;
}


int analisi_indirizzo(const char* proc_net_path, const char* whitelist_path, idslog* log2, int k) {
    char riga[LUNG_MAX_LINEA];
    int indirizzo_finale[LUNG_IP];
    
    FILE* fp = fopen(proc_net_path, "r");
    if (fp == NULL) {
        perror("Error opening /proc/net/tcp");
        return 1;
    }
    
    FILE *whitelist = fopen(whitelist_path, "r");
    if (whitelist == NULL) {
        perror("Error opening whitelist");
        fclose(fp);
        return 1;
    }

    if (fgets(riga, sizeof(riga), fp) == NULL) {
        fclose(fp);
        fclose(whitelist);
        return 1;
    }
    
    while (fgets(riga, sizeof(riga), fp)) {
        char sl[10], local_addr[64], rem_addr[64];
        if (sscanf(riga, "%9s %63s %63s", sl, local_addr, rem_addr) == 3) {
            parsing(rem_addr, indirizzo_finale);
            printf("Checking: %d.%d.%d.%d:%d -> ", 
                   indirizzo_finale[0], indirizzo_finale[1], 
                   indirizzo_finale[2], indirizzo_finale[3], indirizzo_finale[4]);
            
            check_whitelist(indirizzo_finale, log2, whitelist, k);
            printf("\n");
        }
    }

    fclose(fp);
    fclose(whitelist);
    
    return 0;
}


void parsing(char* rem_addr, int* risultato_finale) {
    int indirizzo_salvato[LUNG_RIGA];
    int indirizzo[LUNG_INDIRIZZO_PORTA];    
    bool flag = false;
    char numeri[LUNG_NUMERI] = {'0','1','2','3','4','5','6','7','8','9'}; 
    char lettere[LUNG_LETTERE] = {'A','B','C','D','E','F'}; 

    for(int i = 0; i < LUNG_RIGA; i++) {
        indirizzo_salvato[i] = 0;
        flag = false;
        for(int j = 0; j < LUNG_NUMERI; j++) {
            if(rem_addr[i] == numeri[j] && flag == false){       
                indirizzo_salvato[i] = rem_addr[i] - '0';
                flag = true;
            }
        }
        if(rem_addr[i] == ':' && flag == false){
            indirizzo_salvato[i] = -58;
            flag = true;
        }
        if(flag == false){
            for(int h = 0; h < LUNG_LETTERE; h++){
                if(rem_addr[i] == lettere[h]){
                    indirizzo_salvato[i] = conversione(rem_addr[i]);
                    flag = true;
                }
            }
        }
    }      

    for(int i = 0; i < COMPONENT_IP; i++) {
        indirizzo[i] = (indirizzo_salvato[i*2] * 16) + indirizzo_salvato[i*2 + 1];
    }
    invertiArray(indirizzo, COMPONENT_IP);

    
    for(int i = 4; i < LUNG_INDIRIZZO_PORTA; i++){
        indirizzo[i] = indirizzo_salvato[i+4];
    }

    int porta = (indirizzo[5]*4096) + (indirizzo[6]*256) + (indirizzo[7]*16) + (indirizzo[8]*1);
    
    
    for(int i = 0; i < COMPONENT_IP; i++) {
        risultato_finale[i] = indirizzo[i];
    }
    risultato_finale[4] = porta;    
}


int conversione(char x) {
    switch (x) {
        case 'A': return 10;
        case 'B': return 11;
        case 'C': return 12;
        case 'D': return 13;
        case 'E': return 14;
        case 'F': return 15;
        default:  return 0;
    }
}


void invertiArray(int arr[], int dimensione){
    int temp;
    for (int i = 0; i < dimensione / 2; i++) {
        temp = arr[i];
        arr[i] = arr[dimensione - 1 - i];
        arr[dimensione - 1 - i] = temp;
    }
}

int check_whitelist(int* indirizzo, idslog* log2, FILE* whitelist, int k){
    char riga_testo[LUNG_MAX_LINEA];
    int array_dati[5];
    rewind(whitelist); 

    bool trovato = false;
    while (fgets(riga_testo, sizeof(riga_testo), whitelist)) {
        if (sscanf(riga_testo, "%d.%d.%d.%d:%d", 
                   &array_dati[0], &array_dati[1], &array_dati[2], 
                   &array_dati[3], &array_dati[4]) == 5) {
            
            int match = 0;
            for(int i = 0; i < LUNG_IP; i++) {
                if(indirizzo[i] == array_dati[i]) match++;
            }
            if (match == 5) {
                trovato = true;
                break;
            }
        }   
    }

    if (trovato) {
        if(k==0){
            printf(GREEN "TCP IP approved" RESET);
        }else{
            printf(GREEN "UDP IP approved" RESET);
        }
        
    } else {
        if(k==0){
            printf(RED "TCP IP NOT approved" RESET);
            char stringa_ip[128];
            snprintf(stringa_ip, sizeof(stringa_ip), "TCP IP NOT APPROVED: %d.%d.%d.%d:%d",  
            indirizzo[0], indirizzo[1], indirizzo[2], indirizzo[3], indirizzo[4]);
            logger(stringa_ip, log2);
        }else{
            printf(RED "UDP IP NOT approved" RESET);
            char stringa_ip[128];
            snprintf(stringa_ip, sizeof(stringa_ip), "UDP IP NOT APPROVED: %d.%d.%d.%d:%d",  
            indirizzo[0], indirizzo[1], indirizzo[2], indirizzo[3], indirizzo[4]);
            logger(stringa_ip, log2);
        }
        
    }
    return 0;
}
