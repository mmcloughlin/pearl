all: gen-command.go gen-relay-command.go gen-circuit-error-code.go gen-cert-type.go

gen-%.go: makeenum.py %.yaml
	python $^ >$@
	goimports -w $@
	cite process $@

install: all
	cp --verbose *.go ../..
