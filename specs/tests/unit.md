# Unit Tests

Pure logic, no Windows calls and no sandbox. These are the cases the
system and integration plans cannot pin down, because the behaviour is a
function of its input rather than something observable from a shell.

Naming is specified as tables rather than prose. It is all edge cases, and
a wrong answer is silently wrong — a name that differs from intent still
produces a working sandbox, just not the one the user asked for.

## Sandbox name derivation

`sandbox_name(project_path)` — no `--name` given. Verifies: Sandbox name.

| project directory | expected name | why |
| --- | --- | --- |
| `sandbox` | `sandbox` | fits, unchanged |
| `my-app` | `my-app` | hyphens are legal |
| `MyProject` | `myproject` | lowercased |
| `windows-agent-sandbox` | `windows-agen` | plain truncation at 12 |
| `reallylongsinglewordname` | `reallylongsi` | truncation with no separator |
| `exactly12chr` | `exactly12chr` | 12 is allowed, not 11 |
| `thirteenchars` | `thirteenchar` | 13 truncates to 12 |
| `my project` | `my-project` | space is not worth the trouble |
| `my＊project` | `my-project` | forbidden character replaced |
| `my///project` | `my-project` | runs collapse to one `-` |
| `-leading-dash` | `leading-dash` | leading separator stripped |
| `trailing.` | `trailing` | a name may not end in a period |
| `café` | `caf-` → `caf` | non-ASCII replaced, then trailing `-` stripped |

Refuse, with a message telling the user to pass `--name`:

| project directory | why |
| --- | --- |
| `---` | nothing survives sanitising |
| `...` | nothing survives sanitising |
| `` (drive root, no directory name) | nothing to derive from |

## Explicit names

`sandbox_name(project_path, requested=...)`. A name the user typed is
**validated, not rewritten** — silently changing it would be worse than
refusing, because the name becomes an account they will see in `net user`.

| requested | outcome |
| --- | --- |
| `alpha` | accepted |
| `Alpha` | accepted as `alpha`; lowercasing is not a change of identity |
| `sbx-foo` | accepted as given, yielding the account `sbx-sbx-foo` |
| `thirteenchars` | refused — too long, say the limit |
| `my/name` | refused — say which character |
| `` (empty) | refused |

## Collision suffixes

`suffixed_name(base, n)` — the base shortens so the result stays within 12.

| base | n | expected |
| --- | --- | --- |
| `alpha` | 2 | `alpha2` |
| `windows-agen` | 2 | `windows-age2` |
| `windows-agen` | 10 | `windows-ag10` |
| `reallylongsi` | 2 | `reallylongs2` |
| `a` | 2 | `a2` |

Also: the engine picks the first `n` not already taken, comparing names
case-insensitively, and a suffixed name is validated like any other before
being offered.

## Console input prefill

`encode_console_prefill(text)` — the key events written into the console
input buffer so a suggestion appears typed at the cursor.

- One key-down record per character, in order, each carrying the character
  in `UnicodeChar`.
- Record count equals the length of the text.
- No Enter is appended: the user presses it, and accepting is exactly that
  keypress.
- Empty text yields no records, rather than a single empty one.

## Regressions worth holding

Behaviour fixed earlier that this iteration touches the same code as. These
already have tests; they should still pass unchanged.

- `split_resize_requests` never holds a fragment indefinitely, and forwards
  a lone trailing ESC rather than stalling Esc in interactive programs.
- `read_file` returns bytes above 0x7f intact.
- The store reports a damaged registry rather than reading as empty.
- `StartHandle.close()` is safe to call twice.
- Network policy deregisters under the key it registered with.
