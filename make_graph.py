#!/usr/bin/env python

 #############################################################################
 # make_graph.py
 #
 # This file is part of the Heaptropy library.  See the README for more
 # information.
 #
 # Heaptropy is a shared library that catches and logs all calls to malloc()
 # and free().  This is to be used with LD_PRELOAD.  Upon program termination
 # the process' heap segment of memory is scanned.  Starting from the beginning
 # of the heap and working towards the end, the value of each address is looked
 # at.  The value is treated as an address and if it resides within the memory
 # of the heap then heaptropy says that the address points to the value.
 # 
 # Copyright (C) 2012 Matt Davis (enferex)
 #
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation; either version 2
 # of the License, or (at your option) any later version.
 #
 # This program is distributed in the hope that it will be useful, but WITHOUT
 # ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 # FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 # more details.
 #
 # You should have received a copy of the GNU General Public License along with
 # this program; if not, see <http://www.gnu.org/licenses/gpl-2.0.html>
 #############################################################################

import sys

def usage():
    print("Usage: " + sys.argv[0] + " sniff.log sniff_scan1.log")
    sys.exit(0)

# Look through the allocation list to see which alloction has this value
def find_alloc(address, allocations):
    for alloc in allocations:
        base = int(alloc.split(',')[2])
        alloc_size = int(alloc.split(',')[3])
        if ((address >= base) and (address <= (base + alloc_size))):
            return base

if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()

    # Load in the CSV values from each line in the alloc file
    allocs = [line.split(':')[1].strip() for line in open(sys.argv[1])
              if line[0] != '#' and line.find("malloc") > 0]

    # Load in each line in the scan: ptr -> data
    scans = [line.strip() for line in open(sys.argv[2])]

    # For address in the heap scan look for its allocation
    print("digraph {")
    for scan in scans:
        if scan[0] == '#':
            continue
        addr = int(scan.split("->")[0].strip(), 16)
        data = int(scan.split("->")[1].strip(), 16)
        alloc = find_alloc(addr, allocs)
        if alloc is None:
            alloc = addr
        alloc = str(hex(alloc))
        data = str(hex(data))
        print('"' + alloc + '" -> "' + data + '"')
    print("}")
