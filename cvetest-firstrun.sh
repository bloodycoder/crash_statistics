#!/bin/bash
pushd `pwd`
WORK=`pwd`  # aflgo/tests
NAME=binutils
CVE=$1		# first argv, e.g. 2016-4487
TEST_SUITE_DIR=$WORK/fuzzer-test-suite
DOWNLOAD_DIR=$WORK/$NAME 
cd $DOWNLOAD_DIR
SUBJECT=$DOWNLOAD_DIR

BUILD="BUILD-$1"
TMP_DIR=$SUBJECT/temp/${CVE}
CVE_TARGET=$WORK/CVE-target-line/${CVE}.txt
CVE_PATCH=$WORK/CVE-patch/${CVE}.patch
OBJ_FIXED=$DOWNLOAD_DIR/obj-fixed/${CVE}
OBJ_1=$DOWNLOAD_DIR/obj-1/${CVE}
OBJ_2=$DOWNLOAD_DIR/obj-2/${CVE}
DIR_OUT=$DOWNLOAD_DIR/out/${CVE}
[ ! -d $DOWNLOAD_DIR/out ] && mkdir $DOWNLOAD_DIR/out
[ ! -d $DOWNLOAD_DIR/obj-1 ] && mkdir $DOWNLOAD_DIR/obj-1
[ ! -d $DOWNLOAD_DIR/obj-2 ] && mkdir $DOWNLOAD_DIR/obj-2
[ ! -d $DOWNLOAD_DIR/obj-fixed ] && mkdir $DOWNLOAD_DIR/obj-fixed

if [ -d $TMP_DIR ]; then
	rm  -rf $TMP_DIR
fi	
if [ ! -d $TMP_DIR ]; then
	mkdir $TMP_DIR
fi
if [ -e $TMP_DIR/state ]; then
  echo "1" >$TMP_DIR/state
fi

#### valgrind binutils/cxxfilt _Q10-__9cafebabe.
cd $WORK
#./CVE-analyze-target.sh $CVE
cp $CVE_TARGET $TMP_DIR/BBtargets.txt 
## echo core | sudo tee /proc/sys/kernel/core_pattern
## wget http://ftp.gnu.org/gnu/binutils/binutils-2.26.tar.gz

AFLGO=~/Program/AFL/aflgo/bak/aflgo-good
#AFLGO=~/Program/AFL/aflgo/bak/aflgo-origin

cd $DOWNLOAD_DIR
ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++
export CFLAGS="-g3 $ADDITIONAL"
export CXXFLAGS="-g3  $ADDITIONAL"
export LDFLAGS="-ldl -lutil" 
export AR=llvm-ar
export RANLIB=llvm-ranlib

cd $DOWNLOAD_DIR/obj-1/
rm -rf $OBJ_1
mkdir $OBJ_1; cd $OBJ_1;
$DOWNLOAD_DIR/${BUILD}/configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld AR=llvm-ar RANLIB=llvm-ranlib
rm -rf $TMP_DIR && mkdir $TMP_DIR
cp $CVE_TARGET $TMP_DIR/BBtargets.txt
make -j6
echo "First Compile done."

PROGRAM_NAME=cxxfilt
PROGRAM_DIR=$OBJ_1/binutils/analysis_dir_${PROGRAM_NAME}

if [ -d $PROGRAM_DIR ]; then
	rm -rf $PROGRAM_DIR
fi
mkdir  $PROGRAM_DIR
cp $OBJ_1/binutils/cxxfilt* $PROGRAM_DIR/


#### Clean up
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

#### Generate distance

$AFLGO/scripts/genDistance.sh $PROGRAM_DIR $TMP_DIR $PROGRAM_NAME

cat $TMP_DIR/distance.callgraph.txt | sort | uniq > $TMP_DIR/distance.callgraph2.txt && mv $TMP_DIR/distance.callgraph2.txt $TMP_DIR/distance.callgraph.txt
cat $TMP_DIR/Fnames.txt | sort | uniq > $TMP_DIR/Fnames2.txt && mv $TMP_DIR/Fnames2.txt $TMP_DIR/Fnames.txt

echo "Distance values:"
head -n5 $TMP_DIR/distance.cfg.txt
echo "..."
tail -n5 $TMP_DIR/distance.cfg.txt

CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error -distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
cd $DOWNLOAD_DIR/${BUILD}/


echo "Second compile."
rm -rf $OBJ_2
mkdir $OBJ_2; cd $OBJ_2;
$DOWNLOAD_DIR/${BUILD}/configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld AR=llvm-ar RANLIB=llvm-ranlib
if [[ $AFLGO == *good ]];then
        if [ -d $TMP_DIR/rid_bbname_pairs ];then
		rm -rf $TMP_DIR/rid_bbname_pairs $TMP_DIR/index $TMP_DIR/bb_branch_info
	fi
fi
make
echo "Second compile done."


if [[ $AFLGO == *good ]];then
	$AFLGO/scripts/index_all_cfg_edges.py -t $TMP_DIR
	#$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files
fi

:<<!
if [ ! -e $OBJ_FIXED ]; then 
	echo "Compile patched version."
	cd $DOWNLOAD_DIR/${BUILD}
	patch -p0 < $CVE_PATCH
	mkdir $OBJ_FIXED; cd $OBJ_FIXED
	export CC=clang
	export CXX=clang++
	export CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error"
	export CXXFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error"
	$DOWNLOAD_DIR/${BUILD}/configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld
	make
	cd $DOWNLOAD_DIR/${BUILD}
	patch -Rp0 < $CVE_PATCH
	echo "Compile patched version done."
fi
!

cd $SUBJECT 
TARGET=$OBJ_2/binutils/cxxfilt
TIME=1m

DIR_IN=$SUBJECT/in
if [ ! -d $DIR_IN ];then
	mkdir $DIR_IN
fi
echo "" > $DIR_IN/seeds
ITER=20
for((i=1;i<=$((ITER));i++));
do
	if [ -d $DIR_OUT ]; then
		rm -rf $DIR_OUT
	fi

	#$AFLGO/afl-fuzz -S target_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $TARGET -s arm
	#$AFLGO/afl-fuzz -S target_result -z exp -c $TIME -E $TMP_DIR -i $DIR_IN -o $DIR_OUT $TARGET -s arm
        #$AFLGO/afl-fuzz -S target_result -z exp -c $TIME -x ${AFLGO}/dictionaries/cxx.dict -E $TMP_DIR -i $DIR_IN -o $DIR_OUT $TARGET
        $AFLGO/afl-fuzz -S target_$((i))_result -z exp -c $TIME -E $TMP_DIR -i $DIR_IN -o $DIR_OUT $TARGET
        #$AFLGO/afl-fuzz -S target_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $TARGET
	#gdb --args $AFLGO/afl-fuzz -S target_result -z exp -c $TIME -E $TMP_DIR -i $DIR_IN -o $DIR_OUT $TARGET
        #gdb --args $AFLGO/afl-fuzz -S target_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $TARGET

	#### valgrind ./${BUILD}/obj-${CVE}-2/binutils/cxxfilt < ./crashfile
        mv $DIR_OUT/target_$((i))_result  $DIR_OUT/../../tmp-out/$1/
done
mv $DIR_OUT/../../tmp-out/$1/target_*_result  $DIR_OUT/

popd
