# Binjago 🥷

Set of tools aiding in analysis of stripped Golang binaries with Binary Ninja.

**Current status**: Work in Progress ⚠️

## Features

* Function renamer based on `.gopclntab` section
  * Brute searching section by its magic header(s) if not present in sections.

## Tests

Binjago was tested on the following samples.

|                               Sample<br>`SHA256`                                | Function <br>renamer |
|:-------------------------------------------------------------------------------:|:--------------------:|
|   EKANS<br>`dc403cfef757e9bcb3eaa3cc89f8174fc8de5eef64a0e0ee5e5698991f0437f9`   |          ✅           |
|   DECAF<br>`5da2a2ebe9959e6ac21683a8950055309eb34544962c02ed564e0deaf83c9477`   |          ✅           |
| Deadbolt<br>`444e537f86cbeeea5a4fcf94c485cc9d286de0ccd91718362cecf415bf362bcf`  |          ✅           |
|   Hive<br>`90bf2554202af77fef1c4dd6fbeec01373ffb3076b74ab2db29a149feaf63fd2`    |          ✅           |

## References

Awesome prior work on reverse engineering Go binaries.

* https://github.com/sibears/IDAGolangHelper
* https://github.com/d-we/binja-golang-symbol-restore
* https://github.com/f0rki/bn-goloader
* https://github.com/goretk/pygore
* https://www.sentinelone.com/labs/alphagolang-a-step-by-step-go-malware-reversing-methodology-for-ida-pro/
* https://www.pnfsoftware.com/blog/analyzing-golang-executables/