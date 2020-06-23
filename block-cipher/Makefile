CXX := clang++
CXXFLAGS := -m32

.PHONY: tester
tester:
	$(CXX) $(CXXFLAGS) ./tester.cc ./Decryptor.lib -o tester.exe

mine_bytes:
	$(CXX) $(CXXFLAGS) ./mine_bytes.cc ./Decryptor.lib -o mine_bytes.exe

collisions:
	$(CXX) $(CXXFLAGS) ./collisions.cc ./mininglib.cc ./Decryptor.lib -o collisions.exe

clean:
	rm *.exe
