# Qemu4_Tainting

This is a taint analysis tool on top of Qemu version 4. The tool is a Qemu plugin, and currently supports linux 64 bits user programs. The tainting has bit level granularity, and the rules are inspired by Valgrind memcheck and DECAF. The optimization proposed by DECAF++ is also implemented.

# Compilation
    ./configure --target-list=x86_64-linux-user --enable-plugins --enable-debug --enable-kvm
    make
    cd ./tests/plugin
    make
    
# Execution
     x86_64-linux-user/qemu-x86_64 -d plugin -D [/PATH/TO/shadow.log] -plugin tests/plugin/libtaint.so,arg=hint [PATH/TO/BINARY]
     
Currently, only the input from the keyboard is considered as a taint source. To change the code, see the file in tests/plugin/taint.c