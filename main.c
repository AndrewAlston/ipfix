//
// Created by andrew on 3/4/26.
//
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <stdlib.h>
#include "socket.h"

int main() {
    pthread_t sock_thread;
    struct sock_set *s = calloc(1, sizeof(struct sock_set));
    struct sock_set *s6 = calloc(1, sizeof(struct sock_set));
    if (!s) {
        printf("Error allocating for socket set\n");
        return -1;
    }
    s->port = 2055;
    s->buf_size = 9000;
    s->buf_len = 65534;
    pthread_create(&sock_thread, NULL, read_socket_v4, s);
    s6->port = 2054;
    s6->buf_size = 9000;
    s6->buf_len = 65534;
    pthread_create(&sock_thread, NULL, read_socket_v6, s6);
    pthread_join(sock_thread, NULL);
    if (s->error) {
        printf("Error: %s\n", s->errstr);
    }
    free(s);
    return 0;
}

