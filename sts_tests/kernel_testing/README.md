# Kernel testing

For kernel testing, we will use the `nettop` tool described [here](../README.md#nettop-binary) and the [`bpfvalidator`](https://github.com/Andreagit97/bpfvalidator) tool.

## Clone bpfvalidator

You can follow the instructions in the `bpfvalidator` repository to build and try the tool. <https://github.com/Andreagit97/bpfvalidator>

## Use nettop with bpfvalidator

Usually we are working inside our runner container, and we want to test our ebpf instrumentation.
The script `build_nettop.sh` will build the `nettop` binary and copy it under `/tmp/nettop` on the host machine.
So it's enough to change the bpfvalidator config to find the nettop binary in the right place.
Example of the config file:

```yaml
# Path to the virtme-ng binary
vng_path: "vng"
# Command/script to run inside the VM (path + arguments)
cmd: "iptables -t raw -A PREROUTING -j CT && /tmp/nettop"
# Number of parallel VMs to run
parallel: 2
# Path to the output file for the report (if empty uses stdout)
out_path: ""
# show only the final report and not the individual VM outputs
report_only: false
# kernel versions to test
kernel_versions:
    - v5.4.293
    - v5.10.248
    - v5.15.197
    - v6.1.160
    - v6.6.121
    - v6.12.67
    - v6.18.7
```

> __NOTE:__ We need `iptables -t raw -A PREROUTING -j CT` to load the `conntrack` handlers into the netfiler framework. Loading the `conntrack` kernel module is not enough. We need the `conntrack` handlers to be loaded because we hook them in our ebpf instrumentation. kernel `v5.4.293` refuse to attach kprobes to the conntrack method `__nf_conntrack_hash_insert` returning error `-99 (Cannot assign requested address)`, at the moment we accept this since we usually don't modify the 2 ebpf programs related to `conntrack`.

You can now run the `bpfvalidator` tool on your host against the `nettop` binary.

```bash
./bpfvalidator
```

If you modify the ebpf code inside the runner it would be enough to rebuild `nettop` (`build_nettop.sh`) and run the `bpfvalidator` tool again without touching anything else.

## Using dockerfile

If you want to quickly test if our ebpf instrumentation is working on a specific kernel and you are not in the development phase the best thing to do is to use the Dockerfile in this folder to build the `nettop` binary.

```bash
DOCKER_BUILDKIT=1 docker build  -f Dockerfile --target export-stage --output type=local,dest=./out ./../..
```

The above command will build the `nettop` binary into to the `out` folder.
You can now modiy the `bpfvalidator` config to point to the `nettop` binary and run the tool like in the previous section.

## Generate a docker image with the nettop binary

If you want to generate a docker image with the `nettop` binary to test it for example on a k8s node you can use the `Dockerfile` in this folder.

```bash
docker build -f Dockerfile --tag ebpf_debug:latest ./../..
```

Run it:

```bash
docker run --rm -i -t --privileged ebpf_debug:latest
```
