make
ulimit -c unlimited
./a.out

../pycdb.py -s ./a.out -c ./core backtrace
../pycdb.py -s ./a.out -c ./core list
../pycdb.py -s ./a.out -c ./core info threads
../pycdb.py -s ./a.out -c ./core disassemble
