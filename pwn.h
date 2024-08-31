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


/*
Spawns a process and set up pipes for the given filename
*/
proc process(char* filename);


/*
The following are helper functions to grab values from the bStr* object.

It is encouraged to use the bStr structure directly instead of calling these and mainly 
exist in case a "getter" interface is preferred
*/
size_t bstr_get_size(bStr* bstr);
unsigned char* bstr_get_str(bStr* bstr);
void bprint(bStr* bstr);

/*
Bytestring implementation
All bstr functions below this comment allocate buffers on the heap (yes, all strings are treated as immutable)

The user is expected to free() them whenever they are done using them.
*/
bStr* bstr_from_cstr(char* cstr);
bStr* bstr_from_bytes(void* ptr, size_t size);

#ifndef CPWN_DISABLE_TINY_MACRO
    #define b(s) bstr_from_bytes(s, sizeof(s)-1)
#endif

bStr* bstr_append_bstr(bStr* to, bStr* append);
bStr* bstr_append_cstr(bStr* to, unsigned char* cstr);
bStr* bstr_append_bytes(bStr* to, unsigned char* bytes, size_t len);


//Receiving
bStr* precv(proc proc, size_t amount);
bStr* precvline(proc proc);
bStr* precvuntil(proc proc, bStr* until);


//Sending
void psend(proc proc, bStr* str);
void psendline(proc proc, bStr* str);


/*

End header

*/

#define RECV_CHUNK_SIZE 0x100
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

size_t bstr_get_size(bStr* bstr){
    return bstr->size;
}
unsigned char* bstr_get_str(bStr* bstr){
    return bstr->str;
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
bStr* bstr_realloc(bStr* bstr, size_t size){
    bstr = realloc(bstr, size + sizeof(bStr));

    if(bstr == NULL){
        perror("realloc");
        exit(1);
    }

    return bstr;

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

bStr* precvline(proc proc){
    bStr* new_bstr = bstr_alloc(RECV_CHUNK_SIZE);
    new_bstr->size = 0;

    int total_bytes = 0;
    int capacity = RECV_CHUNK_SIZE;
    while(1){
        int read_bytes = read(proc.stdout, &new_bstr->str[total_bytes], 1);
        if(read_bytes < 0){
            perror("EOF");
            exit(1);
        }

        total_bytes += read_bytes;
        if(new_bstr->str[total_bytes-1] == '\n'){
            break;
        }
        if(total_bytes > capacity-1){
            new_bstr = bstr_realloc(new_bstr, capacity + RECV_CHUNK_SIZE);
            capacity = capacity + RECV_CHUNK_SIZE;
        }
        
    }
    new_bstr->size = total_bytes;
    return new_bstr;
}

bStr* precvuntil(proc proc, bStr* until){
    // Sliding window
    size_t window_start = 0;
    size_t window_end = until->size;
    bStr* new_bstr = bstr_alloc(window_end);
    
    //Read untill we have atleast the size needed for the sliding window
    int total_bytes = 0;
    int remaining_bytes = window_end;
    while(1){
        int read_bytes = read(proc.stdout, &new_bstr->str[total_bytes], remaining_bytes);
        if(read_bytes < 0){
            perror("read");
            exit(1);
        }
        total_bytes += read_bytes;
        remaining_bytes -= read_bytes;
        if(remaining_bytes == 0){
            break;
        }
    }
    // If we hit it instantly, we good and done
    if(!memcmp(new_bstr->str, until->str, window_end)){
        return new_bstr;
    }

    //Otherwise we need to receive a byte at a time and compare to check if we hit it
    int capacity = RECV_CHUNK_SIZE + window_end;
    new_bstr = bstr_realloc(new_bstr, capacity);
    while(1){
        int read_bytes = read(proc.stdout, &new_bstr->str[window_end], 1);
        if(read_bytes < 0){
            perror("read");
            exit(1);
        }
        window_end += read_bytes;
        window_start = window_end - until->size;
        if(window_end > capacity-1){
            new_bstr = bstr_realloc(new_bstr, capacity + RECV_CHUNK_SIZE);
            capacity += RECV_CHUNK_SIZE;
        }

        if(!memcmp(&new_bstr->str[window_start], until->str, until->size)){
            new_bstr->size = window_end;
            return new_bstr;
        }

    }

}

void psend(proc proc, bStr* str){
    int written_bytes = write(proc.stdin, str->str, str->size);

    if(written_bytes < str->size){
        perror("write");
        exit(1);
    }
    return;
}

void psendline(proc proc, bStr* str){
    bStr* new_bstr = bstr_alloc(str->size+1);

    memcpy(new_bstr->str, str->str, str->size);
    new_bstr->str[str->size] = '\n';

    psend(proc, new_bstr);

    free(new_bstr);

    return;
}






#endif
#endif