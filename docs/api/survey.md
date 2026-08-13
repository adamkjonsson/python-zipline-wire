# Surveying and filtering

Looking at a capture without writing anything, and choosing which packets a
conversion sees.

---

## Survey

```{eval-rst}
.. autofunction:: zpfwire.survey.survey
```

```{eval-rst}
.. autoclass:: zpfwire.survey.FlowSummary
   :members:
```

---

## Filtering

zpfwire does not implement a second dialect of address and port matching;
these adapt packeteer's `PacketFilter`, which already does CIDR ranges, IPv6,
and `!` negation with validated semantics.  See {doc}`../guide/filtering`.

```{eval-rst}
.. autofunction:: zpfwire.filter.matcher
```

```{eval-rst}
.. autofunction:: zpfwire.filter.spec_of
```
