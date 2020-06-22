CXX := clang++
CXXFLAGS := -m32

.PHONY: tester
tester:
	$(CXX) $(CXXFLAGS) ./tester.cc ./Decryptor.lib -o tester.exe

mine_bytes:
	$(CXX) $(CXXFLAGS) ./mine_bytes.cc ./Decryptor.lib -o mine_bytes.exe

clean:
	rm *.exe
