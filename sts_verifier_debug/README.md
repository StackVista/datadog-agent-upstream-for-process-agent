# Debug verifier errors

Right now we generate a docker image with a simple go binary and the ebpf artifacts inside. This is used just to quickly test on a machine if there are verifier errors. The output should be something like that.

```text
Mounting debugfs for our ebpf progs...
Injecting our ebpf instrumentation...
No verifier errors :)
```

## Build the docker image

Inside this folder:

```bash
docker build -f Dockerfile --tag ebpf_debug:latest ./..
```

## Run it

```bash
docker run --rm -i -t --privileged ebpf_debug:latest
```

## Future improvements

- Create a docker image with also the toolchain to rebuild the binary and the ebpf artifacts directly inside the container. Today we can do that keeping the builder image but the final image is ~ 9 GB.
- Create a tar.gz with the binary and artifacts to support environments where we cannot use docker.
