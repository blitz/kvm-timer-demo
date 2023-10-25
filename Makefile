%.bin: %.asm
	nasm -f bin -o $@ $<

%.inc: %.bin
	xxd -i < $< > $@

SRCS=timer.cpp
DEP=$(patsubst %.cpp,%.d,$(SRCS))

GEN_HDRS=guest.inc

timer: $(SRCS) $(GEN_HDRS)
	g++ -MMD -MP -std=c++11 -O2 -g -pthread -o $@ $(SRCS)

.PHONY: clean
clean:
	rm -f timer $(GEN_HDRS) $(DEP)

-include $(DEP)

