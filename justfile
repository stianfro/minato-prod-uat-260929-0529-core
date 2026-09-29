set shell := ["sh", "-eu", "-c"]

check: lint test

lint:
    node --check server.mjs
    node --check test/server.test.mjs

test:
    node --test test/*.test.mjs

run:
    node server.mjs
