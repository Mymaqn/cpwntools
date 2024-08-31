#ifndef __CPWN_H__
#define __CPWN_H__


#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

/*

Start header

*/

typedef struct{
    int stdin;
    int stdout;
}proc;

typedef struct{
    size_t size;
    unsigned char str[];
}bStr;


proc process(char* filename);
 
/*
Bytestring implementation
All bstr functions allocate buffers on the heap (yes, all strings are treated as immutable)

The user is expected to free() them whenever they are done using them.
*/
bStr* bstr_from_cstr(char* cstr);
bStr* bstr_from_bytes(void* ptr, size_t size);
bStr* bstr_append_bstr(bStr* to, bStr* append);
bStr* bstr_append_cstr(bStr* to, unsigned char* cstr);
bStr* bstr_append_bytes(bStr* to, unsigned char* bytes, size_t len);

void bprint(bStr* bstr);

//Receiving
bStr* precv(proc proc, size_t amount);
bStr* precvuntil(proc proc, bStr* until);

//Sending
void psend(proc proc, bStr* str);
void psendline(proc proc, bStr* str);
void psendafter(proc proc, bStr* str, bStr* after);


/*

End header

*/
#ifdef CPWN_IMPLEMENTATION

proc process(char* filename){
    int read_fd[2];
    int write_fd[2];
    
    if(pipe(read_fd)){
        perror("pipe");
        exit(1);
    }
    if(pipe(write_fd)){
        perror("pipe");
        exit(1);
    }
    int pid = fork();
    if(pid < 0){
        perror("fork");
        exit(1);
    }
    //Child
    if(pid == 0){
        char buf[256];
        close(read_fd[1]);
        close(write_fd[0]);

        dup2(read_fd[0], 0);
        dup2(write_fd[1], 1);
        dup2(write_fd[1], 2);

        char* argv[] = {filename, (char *)0};
        char* envp[] = {NULL};
        execve(filename, argv , envp);
        perror("execve");
        exit(1);

    }
    // Parent
    else{
        close(read_fd[0]);
        close(write_fd[1]);
        proc pipes = {
            .stdin = read_fd[1],
            .stdout = write_fd[0],
        };

        return pipes;
    }


}

void bprint(bStr* bstr){
    for(size_t i = 0; i < bstr->size; i++){
        if(isprint(bstr->str[i])){
            printf("%c",bstr->str[i]);
        }
        else{
            printf("\\x%02x",bstr->str[i]);
        }
    }
}

bStr* bstr_alloc(size_t size){
    bStr* new_bstr = malloc(size + sizeof(bStr));

    if(new_bstr == NULL){
        perror("malloc");
        exit(1);
    }

    new_bstr->size = size;

    return new_bstr;
}


bStr* bstr_from_cstr(char* cstr){
    size_t cstr_len = strlen(cstr);
    bStr* new_bstr = bstr_alloc(cstr_len);

    memcpy(&new_bstr->str, cstr, cstr_len);

    return new_bstr;
}

bStr* bstr_from_bytes(void* ptr, size_t size){
    bStr* new_bstr = bstr_alloc(size);
    
    memcpy(&new_bstr->str, ptr, size);

    return new_bstr;
}

bStr* bstr_append_bstr(bStr* to, bStr* append){
    size_t new_size = to->size + append->size;

    bStr* new_bstr = bstr_alloc(new_size);

    memcpy(&new_bstr->str, &to->str, to->size);
    memcpy((unsigned char*)(&new_bstr->str) + to->size, &append->str, append->size);

    return new_bstr;
}

bStr* bstr_append_cstr(bStr* to, unsigned char* cstr){
    size_t cstr_len = strlen(cstr);
    size_t new_size = to->size + cstr_len;
    bStr* new_bstr = bstr_alloc(new_size);

    memcpy(&new_bstr->str, &to->str, to->size);
    memcpy((unsigned char*)(&new_bstr->str) + to->size, cstr, cstr_len);

    return new_bstr;
}

bStr* bstr_append_bytes(bStr* to, unsigned char* bytes, size_t len){
    size_t new_size = to->size + len;
    bStr* new_str = bstr_alloc(new_size);

    memcpy(&new_str->str, &to->str, to->size);
    memcpy((unsigned char*)(&new_str->str) + to->size, bytes, len);

    return new_str;
}


bStr* precv(proc proc, size_t amount){
    bStr* new_bstr = bstr_alloc(amount);

    int read_bytes = read(proc.stdout, new_bstr->str, amount);
    if(read_bytes < 0){
        perror("read");
        exit(1);
    }
    new_bstr->size = read_bytes;

    return new_bstr;
}

void psend(proc proc, bStr* str){
    int written_bytes = write(proc.stdin, str->str, str->size);

    if(written_bytes < str->size){
        perror("write");
        exit(1);
    }
    return;
}




#endif


#endif