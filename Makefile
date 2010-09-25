all:
	cd lib/ && make
	cd applications/ && make
clean:
	cd lib/ && make clean
	cd applications && make clean
