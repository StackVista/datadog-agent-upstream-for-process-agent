This is a stackstate fork of github.com/DataDog/datadog-agent. This fork is meant as a dependency in github.com/StackVista/stackstate-process-agent.

## Branching Strategy/Upstream update strategy

Given that DataDog uses trunk-based development (new code goes into the main branch, with release being evolved on separate branches/tags)
we cannot use merging to stay up to date. The strategy we want to apply is:

- Base ourselves on stable tags (like 7.43.1 which is the current branch)
- Make a branch in this repo called stackstate-7.43.1
- Cherry-pick all changes we did on top of the previous branch onto the new branch

