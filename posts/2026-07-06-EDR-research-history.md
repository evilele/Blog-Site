# History of (anti) MDE analysis

## Primer
Nowadays MDE (MsMpEng and co.) is understood to have 3 different analysis stages, see below. The understanding of MDE (and the stages) evolved and changed slightly over time, at least what was publicly and widely known (i.e. by me).

| attack stage | analysis techniques | data/format of known bad   | supporting tools                           |
|--------------|---------------------|----------------------------|--------------------------------------------|
| store time   | static + emulation  | yara rules and lua scripts | defender2yara, defender_overview, etc.     |
| startup time | + loaded images     | *to be found*              | Defrev, EDR-Introspection, Detonator, etc. |
| runtime      | + memory scans      | *to be found*              | Defrev, EDR-Introspection, Detonator, etc. |

As displayed, the store time analysis techniques are well known, together with the data and format of "known bad" (i.e. yara rules), thus bypassing the store time can be trivial. The startup time and runtime checks of MDE can be observed by some tools, however the data plus format of "known bad" is somewhat unknown.

## Analysis History

For a better summary and nicer text see [Dobin's post](https://blog.deeb.ch/defender-reversing-history). This is a short overview of (in my opinion) relevant MDE analysis tools. Developing your own malware loader and not documenting new findings with regards to EDR internals does not count.

| #  | year | testing type                       | targeted EDR mechanism             | tool name                                                                                        | author            |
|----|------|------------------------------------|------------------------------------|--------------------------------------------------------------------------------------------------|-------------------|
| 1  | 2017 | internal analysis + fuzzing        | mpengine.dll, static analysis      | [loadlibrary](https://github.com/taviso/loadlibrary)                                             | Tavis Ormandi     |
| 2  | 2018 | internal analysis + fuzzing        | mpclient.dll, emulation engine     | [windowsdefendertools](https://github.com/0xalexei/windowsdefendertools)                         | Alexei Bulazel    |
| 3  | 2021 | internal analysis                  | (yara) signatures, static analysis | [experiments](https://github.com/commial/experiments/blob/master/windows-defender/VDM/README.md) | Camille Mougey    |
| 4  | 2022 | fuzzing + observation              | fuzzing MDE (but not anti-EDR)     | [CVE-2022–24548](https://medium.com/s2wblog/fuzzing-the-shield-cve-2022-24548-96f568980c0)       | Daejin Lee et al. |
| 5  | 2023 | observation                        | amsi scanning, static analysis     | [avred](https://github.com/dobin/avred)                                                          | Dobin Rutishauser |
| 6  | 2024 | observation                        | all*                               | [supermega](https://github.com/dobin/avred)                                                      | Dobin Rutishauser |
| 7  | 2025 | observation                        | ETW runtime tracking               | [BamboozlEDR](https://github.com/olafhartong/BamboozlEDR)                                        | Olaf Hartong      |
| 8  | 2025 | internal analysis + observation    | all*                               | [RedEdr](https://github.com/dobin/RedEdr) & [Detonator](https://github.com/dobin/Detonator)      | Dobin Rutishauser |
| 9  | 2025 | observation                        | runtime tracking                   | [Decondition-Enumerator](https://github.com/evilele/Decondition-Enumerator)                      | Levi Cailleret    |
| 10 | 2026 | internal analysis                  | store time, static + emulation     | [defender_overview](https://github.com/HackingLZ/defender_overview)                              | Justin Elze       |
| 11 | 2026 | internal analysis + observation    | all*                               | [EDR-Introspection](https://github.com/evilele/EDR-Introspection)                                | Levi Cailleret    |
| 12 | 2026 | observation                        | all*                               | [iEDR](https://github.com/evilele/iEDR)                                                          | Levi Cailleret    |
| 13 | 2026 | internal analysis -> reversing     | all*                               | [heavener](https://github.com/otterpwn/heavener)                                                 | otterpwn          |
| 14 | 2026 | internal analysis -> LLM reversing | all*                               | [LLM powered EDR analysis](https://specterops.io/blog/2026/06/29/llm-powered-edr-analysis/)      | Adam Chester      |
| 15 | 2026 | observation -> reversing           | all*                               | [DefRev](https://github.com/dobin/DefRev)                                                        | Dobin Rutishauser |

## Interpretation

The tools can be split into 3 "phases", each of which describe the (publicly) available anti-EDR knowledge at that point in time.

### Internal static Analysis

First are "internal" analysis tools, rows 1-3, extracting some part of Defender and attacking and understanding it in isolation. Understanding these parts helped us understand how the store time analysis (static and emulation). Row 4 is special in the regard that it "just" fuzzes MDE to find vulns, with the only part of "anti-EDR" research being to better understand MsMpEng.exe and mpengine.dll.

### Observation of running MDE

From 2021 up until 2025, rows 5-8, a new paradigm of analysis was developed, as in "Observing how the actual MDE behaves in light of malware".[Detonator](https://github.com/dobin/Detonator) leverages insights from [RedEdr](https://github.com/dobin/RedEdr) to further enhance visibility and thus insights into analysis logic of MDE.

### LLM driven internal static Analysis

In 2026 some attempts are made to understand MDE's logic by reversing MsMpEng's code, as in otterpwn's [heavener](https://github.com/otterpwn/heavener), SpectreOps' [LLM powered EDR analysis](https://specterops.io/blog/2026/06/29/llm-powered-edr-analysis/) and Justin's [defender_overview](https://github.com/HackingLZ/defender_overview). While these techniques further the understanding of the store time stage, not too much insights are given into the startup and tracking stage.

### (LLM driven) internal dynamic Analysis

2026 also marks a new era, combining internal analysis and observations for a first time. My [EDR-Introspection](https://github.com/evilele/EDR-Introspection) for example enumerated the protections of EDR, to ultimately hook all MsMpEng syscalls and gain full* insights into its actions at any time, i.e. enumerate scan triggers. Dobin's new [DefRev](https://github.com/dobin/DefRev) project aims to find the logic behind these scan triggers (why is a scan getting triggered) and the known bad (when will the scan return a malware-classification, for example suspicious, syscall history or handles).

## Conclusion

While the scan triggers might be hard-**code**d (do a scan of loaded images at startup, do a memscan after CreateRemoteThread, see [Reversing Defender](https://blog.deeb.ch/posts/reversing-defender-opus/)), the "known bad" might be stored as **data**. Similar to defender2yara, these dynamic, runtime "known bad" IOCs could be extracted and bypassing dynamic (runtime) scans could be as easy as bypassing yara scans.
