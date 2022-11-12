
set -x
set -e

if ! command -v clang-12 &> /dev/null
then
    echo "clang-12 could not be found"
    exit -1
fi

pushd ./linux-syscall/test/ebpf

make -j 

popd
