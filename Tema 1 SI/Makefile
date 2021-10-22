all:
	g++ code/NodA.cpp -o exec/NodA -lpthread -lpthread -L/usr/lib -lssl -lcrypto
	g++ code/NodB.cpp -o exec/NodB -lpthread -lpthread -L/usr/lib -lssl -lcrypto
	g++ code/KeyManager.cpp -o exec/KeyManager -lpthread -lpthread -L/usr/lib -lssl -lcrypto
clean:
	rm -f *~exec/NodA exec/NodB exec/KeyManager