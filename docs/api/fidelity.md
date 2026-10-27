# Fidelity

How well a conversion represents the traffic that was actually sent.  packeteer
generates a TCP conversation under impairments of your choosing, and knows
exactly what each application sent and what happened to every packet; zpfwire
converts the impaired capture, and `zpfwire.fidelity` scores the `.zpf`
against what was sent.  See {doc}`../guide/choosing-a-policy` for what to do
with it, and {doc}`../cli/fidelity` for the command line.

This is the one public module **not** importable from the top-level `zpfwire`
package: it loads packeteer's generators, which a conversion never needs, so
`import zpfwire` leaves it alone.  Import it by name:

```python
from zpfwire.fidelity import Impairments, Scenario, evaluate
```

**Public since `0.8.0`, and TCP only.**  The promise covers the scenario, the
truth and ledger, the byte score and the accounting.  The order and timing of
messages, and UDP, are measured by this project's own tool,
`tools/fidelity.py`, without one: their definitions are still settling.

---

## Evaluating a policy

```{eval-rst}
.. autofunction:: zpfwire.fidelity.evaluate
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Evaluation
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Outcome
   :members:
```

```{eval-rst}
.. autofunction:: zpfwire.fidelity.parse_shape
```

---

## The scenario

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Scenario
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Impairments
```

```{eval-rst}
.. autodata:: zpfwire.fidelity.PROTOTYPE
```

---

## The truth and the ledger

```{eval-rst}
.. autofunction:: zpfwire.fidelity.run
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Run
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Truth
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Message
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Ledger
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Entry
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Segment
   :members:
```

```{eval-rst}
.. autofunction:: zpfwire.fidelity.self_check
```

---

## Scoring a conversion

```{eval-rst}
.. autofunction:: zpfwire.fidelity.measure
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Measurement
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.ByteScore
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Accounting
   :members:
```

```{eval-rst}
.. autofunction:: zpfwire.fidelity.score_bytes
```

```{eval-rst}
.. autofunction:: zpfwire.fidelity.account
```

```{eval-rst}
.. autofunction:: zpfwire.fidelity.convert
```

```{eval-rst}
.. autofunction:: zpfwire.fidelity.read
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Conversion
```

```{eval-rst}
.. autoclass:: zpfwire.fidelity.Output
   :members:
```

```{eval-rst}
.. autoexception:: zpfwire.fidelity.Unclean
```

---

## Payloads and constants

```{eval-rst}
.. autofunction:: zpfwire.fidelity.payload
```

```{eval-rst}
.. autodata:: zpfwire.fidelity.BASE_TIME
```

```{eval-rst}
.. autodata:: zpfwire.fidelity.BLOCK
```

```{eval-rst}
.. autodata:: zpfwire.fidelity.CLIENT
```

```{eval-rst}
.. autodata:: zpfwire.fidelity.DIRECTIONS
```
