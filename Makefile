%.bin: %.asm
	nasm -f bin -o $@ $<

%.inc: %.bin
	xxd -i < $< > $@

SRCS=l1tf.cpp
DEP=$(patsubst %.cpp,%.d,$(SRCS))

GEN_HDRS=guest.inc

l1tf: $(SRCS) $(GEN_HDRS)
	g++ -MMD -MP -std=c++11 -O2 -g -pthread -o $@ $(SRCS)

.PHONY: clean
clean:
	rm -f l1tf $(GEN_HDRS) $(DEP)

-include $(DEP)

