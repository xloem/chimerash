CXXFLAGS=-fPIC -std=c++20 -ggdb -O0 -Wall -Werror -pedantic -D_GLIBCXX_DEBUG# -fsanitize=address
CPPFLAGS+=$(CXXFLAGS)
LIBS=-lutil -ldl -pthread -lsyscall_intercept# -lasan

test.so: wrappers.o wrappers_syscall_intercept.o fs.o fs_sshfs.o process.o
	$(LINK.cpp) $(LIBS) -shared $^ -o $@

test: wrappers.o test.o fs.o fs_sshfs.o process.o
	$(LINK.cpp) $(LIBS) $^ -o $@

clean:
	-rm *.o *.ii test test.so

%.ii.o: %.ii
	$(COMPILE.cpp) $< -o $@
%.ii: %.cpp
	$(CXX) $(CPPFLAGS) -E $< -o $@
