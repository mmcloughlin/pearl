all: gen-command.go

gen-%.go: makeenum.py %.yaml
	python $^ >$@
	goimports -w $@
	cite process $@

install: all
	cp --verbose *.go ../..
