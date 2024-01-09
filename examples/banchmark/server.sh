rm -rf *.log
cd server
./server -name server1 -ver 1.0 -p :8001 1>output1.txt 2>&1 &
./server -name server2 -ver 1.0 -p :8002 1>output2.txt 2>&1 &
./server -name server3 -ver 2.0 -p :8003 1>output3.txt 2>&1 &
./server -name server4 -ver 2.0 -p :8004 1>output4.txt 2>&1 &
cd ..
sleep 3