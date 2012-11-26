/******************************************************************************
 * heaptropy.c 
 *
 * Heaptopy: Heap Scanning Library
 * Because disorder is how the universe works...
 *
 * Heaptropy is a shared library that catches and logs all calls to malloc()
 * and free().  This is to be used with LD_PRELOAD.  Upon program termination
 * the process' heap segment of memory is scanned.  Starting from the beginning
 * of the heap and working towards the end, the value of each address is looked
 * at.  The value is treated as an address and if it resides within the memory
 * of the heap then heaptropy says that the address points to the value.
 * 
 * Copyright (C) 2012 Matt Davis (enferex)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/gpl-2.0.html>
 *****************************************************************************/


/* Special thanks to Google and stackoverflow.com where I learned about wrapping
 * routines in the GNU/Linux system.  Much of the wrapping code here was
 * paraphrased from Checker's post over at stackoverflow.com
 *
 * Thanks Checkers!
 * <http://stackoverflow.com/questions/262439/create-a-wrapper-function-for-malloc-and-free-in-c>
 */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>


#define SEC_TO_NSEC(_sec) ((_sec) * 1000000000)


enum rec_type
{
    REC_ALLOC,
    REC_FREE
};


/* All malloc and free calls detected are stored as a record */
typedef struct 
{
    enum rec_type type;
    const void *addr;
    struct timespec time;
    size_t size;
} record_t;


/* Globals */
static record_t all_records[4096];
static int next_idx;
static int disable_wrap;


static void get_heap_bounds(uintptr_t *st, uintptr_t *en)
{
    FILE *map;
    char buf[256];

    if (!(map = fopen("/proc/self/maps", "r")))
      return;

    while (fgets(buf, sizeof(buf), map))
      if (strstr(buf, "[heap]"))
      {
          *st = strtoll(strtok(buf, "-"), NULL, 16);
          *en = strtoll(strtok(NULL, " "), NULL, 16);
          break;
      }

    fclose(map);
}


/* Output the heap start and end address */
static void emit_heap_bounds(FILE *fp)
{
    uintptr_t st, en;
    get_heap_bounds(&st, &en);
    fprintf(fp, "# Heap Bounds [%p-%p] (%llu %llu)\n",
            (void *)st, (void *)en, 
            (unsigned long long)st, (unsigned long long)en);
}


/* Scan the process' heap */
static void scan(void)
{
    FILE *fp;
    char fname[32]; 
    static int scan_no;
    uintptr_t st, en, d, data;
   
    disable_wrap = 1;
    snprintf(fname, sizeof(fname), "sniff_scan%d.log", ++scan_no);
    if (!(fp = fopen(fname, "w")))
    {
        disable_wrap = 0;
        return;
    }

    get_heap_bounds(&st, &en);
    d = st;
    fprintf(fp, "# Scanning heap range: %p to %p\n", (void *)st, (void *)en);

    while (d < en)
    {
        data = (uintptr_t)*(void **)d;
        if (data >= st && data <= en)
          fprintf(fp, "%p -> %p\n", (void *)d, (void *)data);
        d += sizeof(void *);
    }
    
    fclose(fp); 
    disable_wrap = 0;
}


/* Output records to sniff.log */
static void flush_records(void)
{
    int i;
    const record_t *rec;
    static FILE *fp;

    /* Disable any allocation from glibc while we dump this to disk */
    disable_wrap = 1;

    if (!fp)
      if (!(fp = fopen("sniff.log", "w")))
      {
          fprintf(stderr, "Could not open log");
          return;
      }
    
    /* Safety */
    if (next_idx < 0)
      next_idx = 0;

    /* Emit the heap boundary */
    emit_heap_bounds(fp);
    fprintf(fp, "# CSV Format: Malloc/Free (as 0 or 1), "
                "Nanoseconds, Base Address, Bytes Requested\n");
            
    if (next_idx > sizeof(all_records)/sizeof(all_records[0]))
      next_idx = sizeof(all_records) / sizeof(all_records[0]) - 1;

    for (i=0; i<next_idx; ++i)
    {
        rec = &all_records[i];
        fprintf(fp, "[%d] %lu %s(%p) %lu: %d, %lu, %lu, %lu\n",
                i,
                SEC_TO_NSEC(rec->time.tv_sec) + rec->time.tv_nsec,
                (rec->type == REC_ALLOC) ? "malloc" : "free",
                rec->addr,
                rec->size,
                rec->type, /* As CSV... */
                SEC_TO_NSEC(rec->time.tv_sec) + rec->time.tv_nsec,
                (uintptr_t)rec->addr,
                rec->size);
    }

    disable_wrap = 0;
}


/* Create (and add) a new record */
static record_t *new_record(enum rec_type type, const void *addr, size_t size)
{
    struct timespec ts;
    if (next_idx >= (sizeof(all_records) / sizeof(all_records[0])))
    {
        flush_records();
        next_idx = 0;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    all_records[next_idx].type = type;
    all_records[next_idx].addr = addr;
    all_records[next_idx].size = size;
    all_records[next_idx].time = ts;

    return &all_records[next_idx++];
}


/* nop (new_record()) adds a record */
static inline void add_record(const record_t *rec)
{
    return;
}


/* atexit() hook */
static void buhbuy(void)
{
    scan();
    flush_records();
}


/* malloc() hook */
void *malloc(size_t size)
{
    void *addr;
    record_t *rec;
    void *(*real_malloc)(size_t);
    static int has_initted;

    if (!has_initted)
    {
        atexit(buhbuy);
        has_initted = 1;
    }
   
    *(void **)&real_malloc = dlsym(RTLD_NEXT, "malloc");
    addr = real_malloc(size);

    /* Normal functionality */
    if (!disable_wrap) 
    {
        rec = new_record(REC_ALLOC, addr, size);
        add_record(rec);
    }

    return addr;
}


/* free() hook */
void free(void *addr)
{
    record_t *rec;
    void (*real_free)(void *);

    *(void **)&real_free = dlsym(RTLD_NEXT, "free");

    /* Normal functionality */
    if (!disable_wrap) 
    {
        rec = new_record(REC_FREE, addr, 0);
        add_record(rec);
    }
}
