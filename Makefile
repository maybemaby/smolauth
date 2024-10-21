test-pg-up:
	docker run --name smolauthtest -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -e POSTGRES_DB=smolauth -p 5432:5432 -d postgres

sample-sqlite:
	dotenvx run -- go run samples/main.go sqlite

sample-pg: test-pg-up
	dotenvx run -- go run samples/main.go pg; docker container stop smolauthtest && docker container rm smolauthtest

test: test-pg-up
	go test -v ./...; docker container stop smolauthtest && docker container rm smolauthtest

test-sqlite:
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

