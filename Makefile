sample-sqlite:
	go run samples/sqlite.go

sample-pg:
	go run samples/pg.go

test:
	go test -v ./...

prepare:
	go mod tidy
	go test -v ./...

commit-tagged: prepare
	echo "Enter commit message: "; \
	read MESSAGE; \
	echo "Enter tag: "; \
	read TAG; \
	git commit -S -m "$$MESSAGE"; \
	git tag -s $$TAG
