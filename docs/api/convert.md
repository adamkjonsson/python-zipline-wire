# Conversion

The entry points that turn a capture into a `.zpf` file.

---

## One-call conversion

```{eval-rst}
.. autofunction:: zpfwire.convert.capture_to_zpf
```

---

## Driving it yourself

`convert` is the lower half, for a caller who has already built a
{class}`~zpfwire.capture.CaptureReader` — to survey it first, or to override
how it was opened.  It writes the `digest` and `uri` it is given rather than
computing them, so pass both if the output should be checkable against its
input later.

```{eval-rst}
.. autofunction:: zpfwire.convert.convert
```

```{eval-rst}
.. autofunction:: zpfwire.convert.describe_source
```
