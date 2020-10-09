#!/usr/bin/env python

import argparse
import os
import re
import subprocess
import warnings
from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
# Main function
def oneiter(program,crashdir):
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--program', type=str,
                        required=True, help="The program")
    parser.add_argument('-q', '--crash_dir', type=str,
                        required=True, help="The crash dir")
    args = parser.parse_args()
    """
    #print ("\nPROGRAM: %s" % args.program)
    #print ("\nOUT_DIR: %s" % args.crash_dir)

    path = crashdir
    trigger = 0
    not_trigger = 0
    min_d = 2 << 31
    li = []
    for fname in os.listdir(path):
        if fname == ".state" or "orig:" in fname:
            continue
        if 'README.txt' == fname:
            continue
        array = fname.split(",")
        t = int(array[1])
        d = array[2]
        li.append((t, d))
    li.sort()
    for t, d in li:
        dis = float(d)
        if min_d > dis and dis > 0:
            min_d = dis
        #print (str(t)+"\t"+d+"\t"+str(min_d))
        #cmd=args.program + " " +args.queue_dir+ "/" + fname
        #p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        #out, err = p.communicate()
        #code = p.returncode
        # if code==0:
        #    not_trigger+=1
        # else:
        #    trigger+=1
    # start run
    # find error
    max_val = 2 << 31
    # integer overflow , invalid write, heap buffer overflow,use-after-free
    mintime = [max_val,max_val,max_val,max_val]
    crashtime = [0,0,0,0]
    finalfname = ['','','','']
    for fname in os.listdir(path):
        if fname == ".state" or "orig:" in fname:
            continue
        if 'README.txt' == fname:
            continue
        cmd=program + " " + path + "/" + fname
        timespan = int(fname.split(",")[1])
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr = subprocess.STDOUT)
        out1 = ''
        while p.poll() is None:
            line = p.stdout.readline()
            out1 += str(line)
        out, err = p.communicate()
        out1 += str(out)
        if(out1.find("negative-size-param") != -1):
            # maybe integer overflow
            if(timespan<mintime[0]):
                mintime[0] = timespan
                finalfname[0] = path + "/" + fname
                crashtime[0] += 1
        elif(out1.find("SEGV on unknown address")!=-1):
            # maybe invalid write
            if(timespan<mintime[1]):
                mintime[1] = timespan
                finalfname[1] = path + "/" + fname
                crashtime[1] += 1
        elif(out1.find("heap-buffer-overflow")!=-1):
            # maybe heap-buffer-overflow 
            if(timespan<mintime[2]):
                mintime[2] = timespan
                finalfname[2] = path + "/" + fname
                crashtime[2] += 1
        elif(out1.find("heap-use-after-free")!=-1):
            # maybe heap-buffer-overflow 
            if(timespan<mintime[3]):
                mintime[3] = timespan
                finalfname[3] = path + "/" + fname
                crashtime[3] += 1
        else:
            #gdb start
            """
            gdbmi = GdbController()
            response = gdbmi.write('-file-exec-file '+args.program)
            response = gdbmi.write('run '+path+'/'+fname)
            response = gdbmi.send_signal_to_gdb('SIGKILL')
            response = gdbmi.exit()
            """
        code = p.returncode
    #print ("hello world")
    print(mintime)
    print(crashtime)
    # print "Trigger %d" % trigger
    # print "Not trigger %d" % not_trigger
def main():
    p = "/home/yangke/Desktop/jiaoben/mjs/mjs-int-ofl"
    for i in range(1,9):
        print("iter:"+str(i))
        q = "/home/yangke/Desktop/jiaoben/out-compare/out-4h-origin/mjs-int-ofl_"+str(i)+"_result/crashes"
        oneiter(p,q)
main()
