#!/usr/bin/env python

import argparse
import os
import re
import subprocess
import warnings
from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
# Main function
CVEOBJ = '2016-4488'
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
    cnt = 0
    for fname in os.listdir(path):
        if fname == ".state" or "orig:" in fname:
            continue
        if 'README.txt' == fname:
            continue
        
        #cnt+=1
        #continue

        cmd='valgrind '+program + " < " + path + "/" + fname
        timespan = int(fname.split(",")[1])
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr = subprocess.STDOUT)
        out1 = ''
        while p.poll() is None:
            line = p.stdout.readline()
            out1 += str(line)+'\n'
        out, err = p.communicate()
        out1 += str(out)
        if(CVEOBJ == '2016-4492'):
            if(out1.find("cplus-dem.c")!=-1):
                cnt+=1     
        elif(CVEOBJ == '2016-4488'):
            if(out1.find("register_Btype")!=-1 and out1.find("demangle_fund_type")!=-1):
                cnt+=1
        elif(CVEOBJ == '2016-4489'):
            if(out1.find("string_appendn")!= -1 and out1.find("gnu_special")!= -1 and out1.find("cplus_demangle")!= -1 and out1.find("demangle_it")!= -1):
                cnt+=1   
        elif(CVEOBJ == '2016-4491'):
            if(out1.find("d_print_comp_inner")!=-1):
                cnt+=1
        code = p.returncode

            #gdb start
        '''
        gdbmi = GdbController()
        response = gdbmi.write('-file-exec-file '+program)
        response = gdbmi.write('run '+path+'/'+fname)
        #response = gdbmi.send_signal_to_gdb('SIGKILL')
        response = gdbmi.exit()
        code = p.returncode
        '''
    #print ("hello world")
    #print(mintime)
    #print(crashtime)
    print(cnt)
    # print "Trigger %d" % trigger
    # print "Not trigger %d" % not_trigger
def main():
    p = "/home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/samples/test-aflgo/tests/binutils/obj-2/"+CVEOBJ+"/binutils/cxxfilt"
    print("start")
    for i in range(1,9):
        #print("iter:"+str(i))
        #q = "/home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/samples/test-aflgo/tests/binutils/out/"+CVEOBJ+"-origin/target_"+str(i)+"_result/crashes"
        q = "/home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/samples/test-aflgo/tests/binutils/out/"+CVEOBJ+"/target_"+str(i)+"_result/crashes"
        oneiter(p,q)
main()