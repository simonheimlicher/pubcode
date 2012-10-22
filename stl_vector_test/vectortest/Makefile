CLANGFLAGS = -fmessage-length=0 -fpascal-strings -fasm-blocks -fvisibility=hidden -fvisibility-inlines-hidden
GCCFLAGS = -fmessage-length=0 -pipe -fpascal-strings -fasm-blocks -fvisibility=hidden -fvisibility-inlines-hidden
BOOST = -I/Library/Homebrew/include
clang:
	clang++ -O3 -stdlib=libc++ $(CLANGFLAGS) $(BOOST) \
		-o vectortest_clang vectortest.cpp

gcc:
	g++ -O3 $(GCCFLAGS) $(BOOST) \
		-o vectortest_gcc vectortest.cpp
