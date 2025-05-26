# Test & debug

## Runner

You can find the docker command to start the runner into the script `sts_tests/runner.sh`.

### Relevant Env vars

- `$SOURCEDIR` is the path inside the container which contains a read-only copy of the source code. we will copy the content of this directory inside `$WORKDIR` with `rsync`
- `$WORKDIR` is the path inside the container which contains a writable copy of the source code.
- `$OUTPUTDIR` is the path inside the container which will contain output files. It is mounted as a volume to the host machine under `/tmp`

### Initial configuration

```bash
cd sts_tests
./runner.sh
# Inside the container
$SOURCEDIR/sts_tests/setup_runner.sh
```

## Tests

Once the initial configuration of the runner is done, you can run the tests inside the runner.

```bash
# To run the minimal suite of tests (recommended)
$SOURCEDIR/sts_tests/sts_run_tests.sh
# With 'full-suite' argument we execute all tests, but it could be slow (6/7 min)
$SOURCEDIR/sts_tests/sts_run_tests.sh full-suite
```

### Run specific tests without the script

Sometimes you want to run a specific test without running the whole suite.

```bash
# Inside the container
export SKIP_STS_MARKED_TESTS=true
export SKIP_NOT_EBPF_PREBUILT_TESTS=true
export SKIP_IPTABLE_TESTS=true
rsync -au "$SOURCEDIR"/. $WORKDIR && chown -R root:root $WORKDIR && cd $WORKDIR
# If you changed the ebpf part you need to rebuilt the system-probe before running the tests
invoke system-probe.build
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/usm/. --test-run-name="^TestUSMSuite/prebuilt/.*Mongo.*"
```

## Nettop binary

The nettop binary is a tool that can be used to test the eBPF programs loaded by the system-probe.
It can be used to check if the eBPF programs are working as expected and to debug verifier issues in a fast way.

Once the initial configuration of the runner is done you can build the nettop binary inside the runner.

```bash
$SOURCEDIR/sts_tests/build_nettop.sh
```

Run it inside the runner:

```bash
cd $WORKDIR
# to change verbosity of the verifier
./nettop --ebpf-verbose 1 
# to run for 30min
./nettop --long-run
# See the `nettop` help for more options:
./nettop --help
```

The `build_nettop` script will copy the binary to the output directory, so you can run it outside the container too. You should find the binary under `/tmp/nettop` on the host machine.
