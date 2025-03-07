# Run tests inside docker

## Relevant Env vars

- `$SOURCEDIR` is the path inside the container which contains a read-only copy of the source code. we will copy the content of this directory inside `$WORKDIR` with `rsync`
- `$WORKDIR` is the path inside the container which contains a writable copy of the source code.

## First configuration

```bash
cd sts_tests
./runner.sh
# Inside the container
$SOURCEDIR/sts_tests/sts_run_tests.sh
```

## Fresh Re-run (suggested if you change ebpf code)

```bash
# Inside the container
$SOURCEDIR/sts_tests/sts_run_tests.sh
```

## Run specific tests

```bash
# Inside the container
cd $WORKDIR
export STS_TEST_RUN=true
export PREBUILT_TEST_RUN=true
rsync -au "$SOURCEDIR"/. $WORKDIR && chown -R root:root $WORKDIR
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/usm/. --test-run-name="^TestUSMSuite/prebuilt/.*Mongo.*"
# If you need to rebuilt the system-probe
invoke system-probe.build
```
