This is a stackstate fork of github.com/DataDog/datadog-agent. This fork is meant as a dependency in github.com/StackVista/stackstate-process-agent.

## Branching Strategy/Upstream update strategy

Given that DataDog uses trunk-based development (new code goes into the main branch, with release being evolved on separate branches/tags)
we cannot use merging to stay up to date. The strategy we want to apply is:

- Base ourselves on stable tags (like 7.49.1 which is the current branch)
- Make a branch in this repo called stackstate-7.49.1 and push the corresponding (selected) datadog dependency there
- Squash the commits on the latest 'main' branch (say, 7.43.1) to get all StackState changes so far into a single commit (called stackstate-7.43.1-squashed)
- Make sure all 'local' tests run from the process-agent before rebasing.
- Cherry-pick the squashed changes we did on top of the previous branch onto the new branch (first onto a separate branch, stackstate-7.49.1-rebased) and make an MR against stackstate-7.49.1
- Rerun the 'local' tests from stackstate-process-agent to verify correctness.
- Review and merge the rebased commit, be sure to test it with the process agent
- Change the gitlab and github 'default' branch to latest upstreamed version branch (stackstate-7.49.1 in this example).

## Testing

We do not do testing directly on the repo. Our changes here are tested through the stackstate-process-agent CI aswell as
the testing script under `/prebuild-datadog-agent-scripts/rune-datadog-agent-test.sh rerun` for local testing (see Readme.md in process-agent).
