types=$(basename $(wildcard *.yaml))

all: $(foreach t,$(types),gen-$(t).go)

gen-%.go: makeenum.py %.yaml
	python $^ >$@
	cite process $@
	goimports -w $@
	golint $@

install: all
	cp --verbose *.go ../..

clean:
	$(RM) *.go
