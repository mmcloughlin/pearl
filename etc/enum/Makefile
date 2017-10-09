types=$(basename $(wildcard *.yaml))

all: $(foreach t,$(types),gen-$(t).go)

gen-%.go: makeenum.py %.yaml
	python $^ >$@
	goimports -w $@
	cite process $@
	golint $@

install: all
	cp --verbose *.go ../..

clean:
	$(RM) *.go
