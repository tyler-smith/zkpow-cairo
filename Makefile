.DEFAULT_GOAL := circuit

CAIRO_CMD_COMPILE ?= $(shell pwd)/venv/bin/cairo-compile
CAIRO_CMD_RUN ?= $(shell pwd)/venv/bin/cairo-run

CIRCUIT_DIR ?= $(shell pwd)/circuit
CIRCUIT_OUT_DIR = $(shell pwd)/circuit/out

.PHONY: circuit
circuit: clean circuit/out/main.json
	${CAIRO_CMD_RUN} \
  		--program=circuit/out/main.json \
		--program_input=test_inputs/batch_from_genesis.json \
		--layout all \
		--print_info \
		--print_output \
		--relocate_prints

.PHONY: circuit_debug
circuit_debug: clean circuit/out/main.json
	${CAIRO_CMD_RUN} \
  		--program=circut/out/main.json \
		--program_input=test-input.json \
		--layout all \
  		--print_info \
  		--print_memory \
		--print_output \
		--relocate_prints

.PHONY: circuit_test
circuit_test: clean circuit/out/difficulty_test.json circuit/out/endian_test.json
	@echo "Running tests..."
	@${CAIRO_CMD_RUN} --program=circuit/out/test/difficulty_test.json --layout all
	@echo "Running tests..."
	@${CAIRO_CMD_RUN} --program=circuit/out/test/endian_test.json --layout all
	@echo "Pass."

.PHONY: clean
clean:
	@rm -rf $(CIRCUIT_OUT_DIR)

## 
## Build files
##

circuit/out:
	@mkdir -p $(CIRCUIT_OUT_DIR)

circuit/out/test: circuit/out
	@mkdir -p $(CIRCUIT_OUT_DIR)/test

circuit/out/main.json: circuit/out
	(cd ${CIRCUIT_DIR} && ${CAIRO_CMD_COMPILE} src/main.cairo > $(CIRCUIT_OUT_DIR)/main.json)

circuit/out/difficulty_test.json: circuit/out/test
	(cd ${CIRCUIT_DIR} && ${CAIRO_CMD_COMPILE} test/difficulty_test.cairo > $(CIRCUIT_OUT_DIR)/test/difficulty_test.json)

circuit/out/endian_test.json: circuit/out/test
	(cd ${CIRCUIT_DIR} && ${CAIRO_CMD_COMPILE} test/endian_test.cairo > $(CIRCUIT_OUT_DIR)/test/endian_test.json)

