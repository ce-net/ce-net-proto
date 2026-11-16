# CES-0: the ce-net standards process (v0.1)

1. **Number.** A standard is `CES-<n>`, `n` assigned in order. A number is never reused.
2. **Versions.** `v0.x` is a draft and may change. `v1` is frozen: after it, only clarifications that change no
   verdict. A change that would make a conforming implementation fail takes a new number, or `v2` with its own
   vectors kept beside `v1`'s.
3. **Words.** MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in RFC 2119. A MUST broken is a conformance
   failure; a SHOULD broken is a warning.
4. **Checks.** Every testable rule has a check id `C<n>.<k>` (CES-8 uses rule ids `B<k>`). Checkers report the
   id, the file and line (for static checks) or the measured value (for dynamic ones).
5. **Vectors.** Every standard with checks ships vectors in `tests/ces<n>/`: inputs and the verdict each must
   get. A checker conforms when it reproduces every verdict. Generated vectors state how to regenerate them,
   and the generator fails if the code disagrees with the stated outcome.
6. **Two implementations.** A standard leaves draft only when two independent checkers (one not written from
   the other's code) agree on every vector.
7. **Rollout.** A new MUST is first reported as a warning with a stated date; after that date it fails. The date
   is in the checker's output, so nobody is surprised.
8. **License.** Standards texts, vectors and reference checkers are Apache-2.0, so anyone may implement them.
