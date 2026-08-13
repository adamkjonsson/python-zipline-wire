# Reference

This section is the complete technical reference for zpfwire.  It covers how
each of the tool's objects maps onto a specification construct, the full
public API, and the limits worth knowing before you rely on the output.

| Section | What you will find |
|---------|--------------------|
| {doc}`Specification mapping <zpf-mapping>` | Which `.zpf` block each of zpfwire's objects becomes, and every field it sets — including the fields it deliberately leaves out, with the rule that forbids them. |
| {doc}`API Reference <../api/index>` | Full Python API: conversion entry points, the capture reader, reassembly options, statistics, and the flow layer. |
| {doc}`Limits <limits>` | What the output does not carry, what is not yet implemented, and which of those are permanent. |

If you are writing code against zpfwire, start with the API Reference.  If you
are reading a `.zpf` that zpfwire produced and want to know why a field is set
the way it is — or is absent — start with the specification mapping.

```{toctree}
:maxdepth: 1

zpf-mapping
../api/index
limits
```
