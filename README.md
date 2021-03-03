# Note

The sole purpose of this repository is to help me organize recent academic papers related to *fuzzing*, *binary analysis*, *IoT security*, and *general exploitation*. This is a non-exhausting list, even though I'll try to keep it updated...
Feel free to suggest decent papers via a PR.

## Read & Tagged

* [2020 - Corpus Distillation for Effective Fuzzing](https://arxiv.org/pdf/1905.13055.pdf)
    * **Tags:** corpus minimization, afl-cmin, google fuzzer test suite, FTS, minset, AFL
* [2020 - Symbolic execution with SymCC: Don't interpret, compile!](https://www.usenix.org/system/files/sec20-poeplau.pdf)
    * **Tags:** KLEE, QSYM, LLVM, C, C++, compiler, symbolic execution, concolic execution, source code level, IR, angr, Z3, DARPA corpus, AFL
* [2020 - WEIZZ: Automatic Grey-Box Fuzzing for Structured Binary Formats](https://andreafioraldi.github.io/assets/weizz-issta2020.pdf)
    * **Tags:** REDQUEEN, chunk-based formats, AFLSmart, I2S, checksums, magix bytes, QEMU, Eclipser, short fuzzing runs, 
* [2020 - Efficient Binary-Level Coverage Analysis](https://ui.adsabs.harvard.edu/abs/2020arXiv200414191A/abstract)
    * **Tags:** bcov, detour + trampoline, basic block coverage, sliced microexecution, superblocks, strongly connected components, dominator graph, BAP, angr, IDA, DynamoRIO, Intel PI, BAP, angr, IDA, DynamoRIO, Intel PIN
* [2020 - Test-Case Reduction via Test-Case Generation: Insights From the Hypothesis Reducer](https://drmaciver.github.io/papers/reduction-via-generation-preview.pdf)
    * **Tags:** Test case reducer, property based testing, CSmith, test case generation, hierachical delta debugging
* [2020 - AFL++: Combining Incremental Steps of Fuzzing Research](https://aflplus.plus//papers/aflpp-woot2020.pdf)
    * **Tags:** AFL++, AFL, MOpt, LAF-Intel, Fuzzbench, Ngram, RedQueen, Unicorn, QBDI, CmpLog, AFLFast
* [2020 - FirmXRay: Detecting Bluetooth Link Layer Vulnerabilities From Bare-Metal Firmware](http://web.cse.ohio-state.edu/~lin.3021/file/CCS20.pdf)
    * **Tags:** Ghdira, static analysis, sound disassembly, base address finder, BLE, vulnerability discovery
* [2020 - P2IM: Scalable and Hardware-independent Firmware Testing via Automatic Peripheral Interface Modeling](https://www.usenix.org/system/files/sec20spring_feng_prepub_0.pdf)
    * **Tags:** HALucinator, emulation, firmware, QEMU, AFL, requires source, MCU, peripheral abstraction
* [2020 - What Exactly Determines the Type? Inferring Types with Context](https://sci-hub.tw/https://ieeexplore.ieee.org/document/9159142)
    * **Tags:** context assisted type inference, stripped binaries, variable and type reconstruction, IDA Pro, Word2Vec, CNN,
* [2020 - Causal Testing: Understanding Defects’ Root Causes](https://arxiv.org/pdf/1809.06991.pdf)
    * **Tags:** Defects4J, causal relationships, Eclipse plugin, unit test mutation, program trace diffing, static value diffing, user study
* [2020 - AURORA: Statistical Crash Analysis for Automated Root Cause Explanation](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/04/01/aurora.pdf)
  * **Tags:** RCA, program traces, input diversification, Intel PIN, Rust, CFG, 
* [2020 - ParmeSan: Sanitizer-guided Greybox Fuzzing](https://download.vusec.net/papers/parmesan_sec20.pdf)
  * Tags: interprocedural CFG, data flow analysis, directed fuzzing (DGF), disregarding 'hot paths', LAVA-M based primitives, LLVM, Angora, AFLGo, ASAP, santizer dependent
* [2020 - Magma: A Ground-Truth Fuzzing Benchmark](https://hexhive.epfl.ch/magma/docs/preprint.pdf)
  * **Tags:** best practices, fuzzer benchmarking, ground truth, Lava-M 
* [2020 - Fitness Guided Vulnerability Detection with Greybox Fuzzing](https://www.csa.iisc.ac.in/~raghavan/ReadingMaterial/sbst20.pdf)
  * **Tags:** AFL, vuln specific fitness metric (headroom), buffer/integer overflow detection, AFLGo, pointer analysis, CIL, bad benchmarking
* [2020 - GREYONE: Data Flow Sensitive Fuzzing](https://www.usenix.org/system/files/sec20spring_gan_prepub.pdf)
  * **Tags:** data-flow fuzzing, taint-guided mutation, input prioritization, *constraint conformance*, REDQUEEN, good evaluation, VUzzer
* [2020 - FairFuzz-TC: a fuzzer targeting rare branches](https://sci-hub.tw/https://link.springer.com/article/10.1007/s10009-020-00569-w)
  * **Tags:** AFL, required seeding, *branch mask*
* [2020 - Fitness Guided Vulnerability Detection with Greybox Fuzzing](https://www.csa.iisc.ac.in/~raghavan/ReadingMaterial/sbst20.pdf)
  * **Tags:** AFL, vuln specific fitness metric (headroom), buffer/integer overflow detection, AFLGo, pointer analysis, CIL, bad evaluation
* [2020 - TOFU: Target-Oriented FUzzer](https://arxiv.org/pdf/2004.14375.pdf)
  * **Tags:** DGF, structured mutations, staged fuzzing/learning of cli args, target fitness, structure aware, Dijkstra for priority, AFLGo, Superion
* [2020 - FuZZan: Efficient Sanitizer Metadata Design for Fuzzing](https://nebelwelt.net/files/20ATC.pdf)
  * **Tags:**: sanitizer metadata, optimization, ASAN, MSan, AFL
* [2020 - Boosting Fuzzer Efficiency: An Information Theoretic Perspective](https://mboehme.github.io/paper/FSE20.Entropy.pdf)
  * **Tags:**: Shannon entropy, seed power schedule, libfuzzer, active SLAM, DGF, fuzzer efficiency
* [2020 - Learning Input Tokens for Effective Fuzzing](https://publications.cispa.saarland/3098/1/lFuzzer-preprint.pdf)
  * **Tags:** dynamic taint tracking, parser checks, magic bytes, creation of dict inputs for fuzzers
* [2020 - A Review of Memory Errors Exploitation in x86-64](https://www.mdpi.com/2073-431X/9/2/48/htm)
  * **Tags:** NX, canaries, ASLR, new mitigations, mitigation evaluation, recap on memory issues
* [2020 - SoK: The Progress, Challenges, and Perspectives of Directed Greybox Fuzzing](https://arxiv.org/pdf/2005.11907.pdf)
  * **Tags:** SoK, directed grey box fuzzing, AFL, AFL mutation operators, DGF vs CGF 
* [2020 - MemLock: Memory Usage Guided Fuzzing](https://wcventure.github.io/pdf/ICSE2020_MemLock.pdf)
  * **Tags:** memory consumption, AFL, memory leak, uncontrolled-recursion, uncontrolled-memory-allocation, static analysis
* [2019 - Matryoshka: Fuzzing Deeply Nested Branches](https://arxiv.org/pdf/1905.12228.pdf)
    **Tage:** AFL, QSYM, Angora, path constraints, nested conditionals, (post) dominator trees, gradient descent, REDQUEEN, LAVA-M
* [2019 - Building Fast Fuzzers](https://arxiv.org/pdf/1911.07707.pdf)
  * **Tags:** grammar based fuzzing, optimization, bold claims, comparison to badly/non-optimized fuzzers, python, lots of micro-optimizations, nice protocolling of failures, bad ASM optimization
* [2019 - Not All Bugs Are the Same: Understanding, Characterizing, and Classifying the Root Cause of Bugs](https://arxiv.org/pdf/1907.11031.pdf)
    * **Tags:** RCA via bug reports, classification model, F score,
* [2019 - AntiFuzz: Impeding Fuzzing Audits of Binary Executables](https://www.usenix.org/system/files/sec19-guler.pdf)
  * **Tags:** anti fuzzing, prevent crashes, delay executions, obscure coverage information, overload symbolic execution
* [2019 - MOpt: Optimized Mutation Scheduling for Fuzzers](https://www.usenix.org/system/files/sec19-lyu.pdf)
  * **Tags:** mutation scheduling, particle swarm optimization (PSO), AFL, AFL mutation operators, VUzzer, 
* [2019 - FuzzFactory: Domain-Specific Fuzzing with Waypoints](https://dl.acm.org/doi/pdf/10.1145/3360600?download=true)
  * **Tags:** domain-specific fuzzing, AFL, LLVM, solve hard constraints like cmp, find dynamic memory allocations, binary-based
* [2019 - Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://taesoo.kim/pubs/2019/xu:janus.pdf)
  * **Tags:** Ubuntu, file systems, library OS, ext4, brtfs, meta block mutations, edge cases
* [2019 - REDQUEEN: Fuzzing with Input-to-State Correspondence](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2018/12/17/NDSS19-Redqueen.pdf)
  * **Tags:** feedback-driven, AFL, magic-bytes, nested contraints, input-to-state correspondence, I2S
* [2019 - PeriScope: An Effective Probing and Fuzzing Framework for the Hardware-OS Boundary](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-1_Song_paper.pdf)
   * **Tags:** kernel, android, userland, embedded, hardware, Linux, device driver, WiFi
* [2019 - FirmFuzz: Automated IoT Firmware Introspection and Analysis](https://nebelwelt.net/publications/files/19IOTSP.pdf)
  * **Tags:** emulation, firmadyne, BOF, XSS, CI, NPD, semi-automatic
* [2019 - Firm-AFL: High-Throughput Greybox Fuzzing of IoT Firmware via Augmented Process Emulation](https://www.usenix.org/system/files/sec19-zheng_0.pdf)
  * **Tags:** emulation, qemu, afl, full vs user mode, syscall redirect, "augmented process emulation", firmadyne
* [2018 - A Survey of Automated Root Cause Analysisof Software Vulnerability](https://sci-hub.tw/10.1007/978-3-319-93554-6_74)
    * **Tags:** Exploit mitigations, fuzzing basics, symbolic execution basics, fault localization, high level
* [2018 - PhASAR: An Inter-procedural Static Analysis Framework for C/C++](https://link.springer.com/content/pdf/10.1007%2F978-3-030-17465-1_22.pdf)
  * **Tags:** LLVM, (inter-procedural) data-flow analysis, call-graph, points-to, class hierachy, CFG, IR
* [2018 - INSTRIM: Lightweight Instrumentation for Coverage-guided Fuzzing](https://www.csie.ntu.edu.tw/~hchsiao/pub/2018_BAR.pdf)
  * **Tags:** LLVM, instrumentation optimization, graph algorithms, selective instrumentation, coverage calculation
* [2018 - What You Corrupt Is Not What You Crash: Challenges in Fuzzing Embedded Devices](http://s3.eurecom.fr/docs/ndss18_muench.pdf)
  * **Tags:** embedded, challenges, heuristics, emulation, crash classification, fault detection
* [2018 - Evaluating Fuzz Testing](https://www.cs.umd.edu/~mwh/papers/fuzzeval.pdf)
  * **Tags:** fuzzing evaluation, good practices, bad practices
* [2017 - Root Cause Analysis of Software Bugs using Machine Learning Techniques](https://sci-hub.tw/10.1109/CONFLUENCE.2017.7943132)
    * **Tags:** ML, RC prediction for filed bug reports, unsupervised + supervised combination, RC categorisation, F score 
* [2017 - kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf)
  * **Tags:** intel PT, kernel, AFL, file systems, Windows, NTFS, Linux, ext, macOS, APFS, driver, feedback-driven
* [2016 - Driller: Argumenting Fuzzing Through Selective Symbolic Execution](https://sites.cs.ucsb.edu/~vigna/publications/2016_NDSS_Driller.pdf)
  * **Tags:** DARPA, CGC, concolic execution, hybrid fuzzer, binary based
* [2015 - Challenges with Applying Vulnerability Prediction Models](https://www.microsoft.com/en-us/research/wp-content/uploads/2015/04/ChallengesVulnerabilityModelsMicrosoft_HotSOS.pdf)
    * **Tags:** VPM vs DPM, prediction models on large scale systems, files with frequent changes leave more vulns, older code exhibits more vulns
* [2014 - Optimizing Seed Selection for Fuzzing](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-rebert.pdf)
    * **Tags:** BFF, (weighted) minset, peach, cover set problem, seed transferabilty, time minset, size minset, round robin 
* [2013 - Automatic Recovery of Root Causes from Bug-Fixing Changes](https://soarsmu.github.io/papers/wcre13-rootcause.pdfhttps://soarsmu.github.io/papers/wcre13-rootcause.pdf)
    * **Tags:** ML + SCA, F score, AST, PPA, source tree analysis


## Unread

Unread papers categorized by a common main theme.

### General fuzzing implementations

* [2021 - icLibFuzzer: Isolated-context libFuzzer for Improving Fuzzer Comparability](https://bar2021.moyix.net/bar2021-preprint13.pdf)
* [2021 - SN4KE: Practical Mutation Testing at Binary Level](https://bar2021.moyix.net/bar2021-preprint17.pdf)
* [2021 - One Engine to Fuzz ’em All: Generic Language Processor Testing with Semantic Validation](https://faculty.ist.psu.edu/wu/papers/polyglot.pdf)
* [2021 - Growing A Test Corpus with Bonsai Fuzzing](https://rohan.padhye.org/files/bonsai-icse21.pdf)
* [2021 - Fuzzing Symbolic Expressions](https://arxiv.org/pdf/2102.06580.pdf)
* [2021 - JMPscare: Introspection for Binary-Only Fuzzing](https://bar2021.moyix.net/bar2021-preprint3.pdf) 
* [2021 - An Improved Directed Grey-box Fuzzer](https://ieeexplore.ieee.org/abstract/document/9338761)
* [2021 - A Binary Protocol Fuzzing Method Based on SeqGAN](https://ieeexplore.ieee.org/abstract/document/9339152)
* [2021 - Refined Grey-Box Fuzzing with Sivo](https://arxiv.org/pdf/2102.02394.pdf)
* [2021 - PSOFuzzer: A Target-Oriented Software Vulnerability Detection Technology Based on Particle Swarm Optimization](https://www.mdpi.com/2076-3417/11/3/1095/htm)
* [2021 - MooFuzz: Many-Objective Optimization Seed Schedule for Fuzzer](https://www.mdpi.com/2227-7390/9/3/205/htm)
* [2021 - CMFuzz: context-aware adaptive mutation for fuzzers](https://link.springer.com/article/10.1007/s10664-020-09927-3)
* [2021 - GTFuzz: Guard Token Directed Grey-Box Fuzzing](https://ieeexplore.ieee.org/abstract/document/9320425)
* [2021 - ProFuzzBench: A Benchmark for Stateful Protocol Fuzzing](https://arxiv.org/pdf/2101.05102.pdf)
* [2021 - SymQEMU:Compilation-based symbolic execution for binaries](http://www.s3.eurecom.fr/docs/ndss21_symqemu.pdf)
* [2021 - CONCOLIC EXECUTION TAILORED FOR HYBRID FUZZING THESIS](https://smartech.gatech.edu/bitstream/handle/1853/64153/YUN-DISSERTATION-2020.pdf)
* [2021 - Breaking Through Binaries: Compiler-quality Instrumentationfor Better Binary-only Fuzzing](http://static1.1.sqspcdn.com/static/f/543048/28391424/1610229123433/FIBRE_USENIX_21.pdf?token=XvHn0I3h9MvSnRBV%2Fo4dQ675sEA%3D)
* [2021 - AlphaFuzz: Evolutionary Mutation-based Fuzzing as Monte Carlo Tree Search](https://arxiv.org/pdf/2101.00612.pdf)
* [2020 - Fuzzing with Fast Failure Feedback](https://arxiv.org/pdf/2012.13516.pdf)
* [2020 - LAFuzz: Neural Network for Efficient Fuzzing](https://ieeexplore.ieee.org/abstract/document/9288180)
* [2020 - MaxAFL: Maximizing Code Coverage with a Gradient-Based Optimization Technique](https://www.mdpi.com/2079-9292/10/1/11)
* [2020 - Program State Abstraction for Feedback-Driven Fuzz Testing using Likely Invariants](https://arxiv.org/pdf/2012.11182.pdf)
* [2020 - PMFuzz: Test Case Generation for Persistent Memory Programs](https://asplos-conference.org/abstracts/asplos21-paper8-extended_abstract.pdf) 
* [2020 - FuSeBMC: A White-Box Fuzzer for Finding Security Vulnerabilities in C Programs](https://arxiv.org/pdf/2012.11223.pdf)
* [2020 - Integrity: Finding Integer Errors by Targeted Fuzzing](https://link.springer.com/chapter/10.1007/978-3-030-63086-7_20)
* [2020 - ConFuzz: Coverage-guided Property Fuzzing for Event-driven Programs](https://kcsrk.info/papers/confuzz_padl21.pdf)
* [2020 - AFLTurbo: Speed up Path Discovery for Greybox Fuzzing](https://ieeexplore.ieee.org/abstract/document/9251057)
* [2020 - Fuzzing Channel-Based Concurrency Runtimes using Types and Effects](http://soft.vub.ac.be/Publications/2020/vub-tr-soft-20-14.pdf) 
* [2020 - DeFuzz: Deep Learning Guided Directed Fuzzing](https://arxiv.org/pdf/2010.12149.pdf)
* [2020 - CrFuzz: Fuzzing Multi-purpose Programs through InputValidation](https://www.cs.ucr.edu/~csong/fse20-crfuzz.pdf)
* [2020 - EPfuzzer: Improving Hybrid Fuzzing with Hardest-to-reach Branch Prioritization](http://itiis.org/digital-library/23867)
* [2020 - Fuzzing Based on Function Importance by Attributed Call Graph](https://arxiv.org/pdf/2010.03482.pdf)
* [2020 - UNIFUZZ: A Holistic and Pragmatic Metrics-Driven Platform for Evaluating Fuzzers](https://arxiv.org/pdf/2010.01785.pdf)
* [2020 - PathAFL: Path-Coverage Assisted Fuzzing](https://dl.acm.org/doi/abs/10.1145/3320269.3384736)
* [2020 -  Path Sensitive Fuzzing for Native Applications](https://ieeexplore.ieee.org/abstract/document/9208709)
* [2020 - UniFuzz: Optimizing Distributed Fuzzing via Dynamic Centralized Task Scheduling](https://arxiv.org/pdf/2009.06124.pdf)
* [2020 - Fuzzing Error Handling Code using Context-Sensitive Software Fault Injection](https://www.usenix.org/system/files/sec20-jiang.pdf)
* [2020 - SpecFuzz: Bringing Spectre-type vulnerabilities to the surface](https://www.usenix.org/system/files/sec20-oleksenko.pdf)
* [2020 - Zeror: Speed Up Fuzzing with Coverage-sensitive Tracing and Scheduling](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/ase20.pdf)
* [2020 - MUZZ: Thread-aware Grey-box Fuzzing for Effective Bug Hunting in Multithreaded Programs](https://arxiv.org/pdf/2007.15943.pdf)
* [2020 - Evolutionary Grammar-Based Fuzzing](https://arxiv.org/pdf/2008.01150.pdf)
* [2020 - AFLpro: Direction sensitive fuzzing](https://sci-hub.tw/http://www.sciencedirect.com/science/article/pii/S2214212619305733)
* [2020 - CSI-Fuzz: Full-speed Edge Tracing Using Coverage Sensitive Instrumentation](https://sci-hub.tw/10.1109/TDSC.2020.3008826)
* [2020 - Scalable Greybox Fuzzing for Effective Vulnerability Management DISS](https://mediatum.ub.tum.de/doc/1509837/file.pdf)
* [2020 - HotFuzz Discovering Algorithmic Denial-of-Service Vulnerabilities through Guided Micro-Fuzzing](https://pdfs.semanticscholar.org/6515/a12fc8615a401e3c7a80d5ada59e5d057971.pdf)
* [2020 - Fuzzing Binaries for Memory Safety Errors with QASan](https://www.researchgate.net/publication/342493914_Fuzzing_Binaries_for_Memory_Safety_Errors_with_QASan)
* [2020 - Suzzer: A Vulnerability-Guided Fuzzer Based on Deep Learning](https://link.springer.com/chapter/10.1007%2F978-3-030-42921-8_8)
* [2020 - IJON: Exploring Deep State Spaces via Fuzzing](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/02/27/IJON-Oakland20.pdf)
* [2020 - Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities](https://arxiv.org/pdf/2002.10751.pdf)
* [2020 - AFLNET: A Greybox Fuzzer for Network Protocols](https://www.comp.nus.edu.sg/~abhik/pdf/AFLNet-ICST20.pdf)
* [2020 - PANGOLIN: Incremental Hybrid Fuzzing with Polyhedral Path Abstraction](https://qingkaishi.github.io/public_pdfs/SP2020.pdf)
* [2020 - UEFI Firmware Fuzzing with Simics Virtual Platform](http://web.cecs.pdx.edu/~zhenkun/pub/uefi-fuzzing-dac20.pdf)
* [2020 - Finding Security Vulnerabilities in Network Protocol Implementations](https://arxiv.org/pdf/2001.09592.pdf)
* [2020 - Typestate-Guided Fuzzer for Discovering Use-after-Free Vulnerabilities](https://yuleisui.github.io/publications/icse20.pdf)
* [2020 - FuzzGuard: Filtering out Unreachable Inputs in Directed Grey-box Fuzzing through Deep Learning](https://www.usenix.org/system/files/sec20summer_zong_prepub.pdf)
* [2020 - HyDiff: Hybrid Differential Software Analysis](https://yannicnoller.github.io/publications/icse2020_noller_hydiff.pdf)
* [2019 - Engineering a Better Fuzzer with SynergicallyIntegrated Optimizations](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/issre19_betterfuzzer.pdf)
* [2019 - Superion: Grammar-Aware Greybox Fuzzing](https://arxiv.org/pdf/1812.01197.pdf)
* [2019 - ProFuzzer: On-the-fly Input Type Probing for Better Zero-day Vulnerability Discovery](https://www.cs.purdue.edu/homes/ma229/papers/SP19.pdf)
* [2019 - Grimoire: Synthesizing Structure while Fuzzing](https://www.usenix.org/system/files/sec19-blazytko.pdf)
* [2019 - Ptrix: Efficient Hardware-Assisted Fuzzing for COTS Binary](https://arxiv.org/pdf/1905.10499.pdf)
* [2019 - SAVIOR: Towards Bug-Driven Hybrid Testing](https://arxiv.org/pdf/1906.07327.pdf)
* [2019 - FUDGE: Fuzz Driver Generation at Scale](https://www.domagoj-babic.com/uploads/Pubs/Fudge/esecfse19fudge.pdf)
* [2019 - NAUTILUS: Fishing for Deep Bugs with Grammars](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2018/12/17/NDSS19-Nautilus.pdf)
* [2019 - Send Hardest Problems My Way: Probabilistic Path Prioritization for Hybrid Fuzzing](https://www.cs.ucr.edu/~heng/pubs/digfuzz_ndss19.pdf)
* [2019 - EnFuzz: Ensemble Fuzzing with Seed Synchronization among Diverse Fuzzers](https://www.usenix.org/system/files/sec19-chen-yuanliang.pdf)
* [2018 - Fuzz Testing in Practice: Obstacles and Solutions](https://sci-hub.se/10.1109/SANER.2018.8330260)
* [2018 - PAFL: Extend Fuzzing Optimizations of Single Mode to Industrial Parallel Mode](https://sci-hub.se/https://doi.org/10.1145/3236024.3275525)
* [2018 - PTfuzz: Guided Fuzzing with Processor Trace Feedback](https://sci-hub.se/10.1109/ACCESS.2018.2851237)
* [2018 - Angora: Efficient Fuzzing by Principled Search](https://web.cs.ucdavis.edu/~hchen/paper/chen2018angora.pdf)
* [2018 - FairFuzz: A Targeted Mutation Strategy for Increasing Greybox Fuzz Testing Coverage](https://www.carolemieux.com/fairfuzz-ase18.pdf)
* [2018 - NEUZZ: Efficient Fuzzing with Neural Program Smoothing](https://arxiv.org/pdf/1807.05620.pdf)
* [2018 - CollAFL: path Sensitive Fuzzing](http://chao.100871.net/papers/oakland18.pdf)
* [2018 - Full-speed Fuzzing: Reducing Fuzzing Overhead through Coverage-guided Tracing](https://arxiv.org/pdf/1812.11875.pdf)
* [2018 - QSYM: A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-yun.pdf)
* [2018 - Coverage-based Greybox Fuzzing as Markov Chain](https://mboehme.github.io/paper/TSE18.pdf)
* [2018 - MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf)
* [2018 - Singularity: Pattern Fuzzing for Worst Case Complexity](https://fredfeng.github.io/papers/fse18.pdf)
* [2018 - Smart Greybox Fuzzing](https://arxiv.org/pdf/1811.09447.pdf)
* [2018 - Hawkeye: Towards a Desired Directed Grey-box Fuzzer](https://chenbihuan.github.io/paper/ccs18-chen-hawkeye.pdf)
* [2018 - PerfFuzz: Automatically Generating Pathological Inputs](https://www.carolemieux.com/perffuzz-issta2018.pdf)
* [2018 - FairFuzz: A Targeted Mutation Strategy for Increasing Greybox Fuzz Testing Coverage](https://www.carolemieux.com/fairfuzz-ase18.pdf)
* [2018 - Enhancing Memory Error Detection forLarge-Scale Applications and Fuzz Testing](https://lifeasageek.github.io/papers/han:meds.pdf)
* [2018 - T-Fuzz: fuzzing by program transformation](https://nebelwelt.net/publications/files/18Oakland.pdf)
* [2017 - Evaluating and improving fault localization](https://www.sci-hub.ren/10.1109/ICSE.2017.62) 
* [2017 - IMF: Inferred Model-based Fuzzer](https://acmccs.github.io/papers/p2345-hanA.pdf)
* [2017 - Synthesizing Program Input Grammars](https://obastani.github.io/docs/pldi17.pdf)
* [2017 - Stateful Fuzzing of Wireless Device Drivers in an Emulated Environment](https://pdfs.semanticscholar.org/26b9/97d7a83ce950db6d311ee65c268e756e0794.pdf)
* [2017 - Steelix: Program-State Based Binary Fuzzing](https://dl.acm.org/doi/pdf/10.1145/3106237.3106295?download=true)
* [2017 - Designing New Operating Primitives to ImproveFuzzing Performance](https://acmccs.github.io/papers/p2313-xuA.pdf)
* [2017 - VUzzer: Application-aware Evolutionary Fuzzing](https://www.cs.vu.nl/~giuffrida/papers/vuzzer-ndss-2017.pdf)
* [2017 - DIFUZE: Interface Aware Fuzzing for Kernel Drivers](https://acmccs.github.io/papers/p2123-corinaA.pdf)
* [2017 - Instruction Punning: Lightweight Instrumentation for x86-64](https://dl.acm.org/doi/pdf/10.1145/3062341.3062344?download=true)
* [2017 - Designing New Operating Primitives to Improve Fuzzing Performance](http://iisp.gatech.edu/sites/default/files/images/designing_new_operating_primitives_to_improve_fuzzing_performance_vt.pdf)
* [2014 - A Large-Scale Analysis of the Security  of Embedded Firmwares](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-costin.pdf)
* [2013 - Scheduling Black-box Mutational Fuzzing](https://dl.acm.org/doi/pdf/10.1145/2508859.2516736?download=true)
* [2013 - Dowsing for Overflows: A Guided Fuzzer to Find Buffer Boundary Violations](https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_haller.pdf)
* [2013 - RPFuzzer: A Framework for Discovering Router Protocols Vulnerabilities Based on Fuzzing](http://www.itiis.org/journals/tiis/digital-library/manuscript/file/20353/14.TIIS-RP-2012-Dec-0966.R1.pdf)
* [2011 - Offset-Aware Mutation based Fuzzing for Buffer Overflow Vulnerabilities: Few Preliminary Results](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=5954459)
* [2010 - TaintScope: A Checksum-Aware Directed Fuzzing Tool for Automatic Software Vulnerability Detection](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=5504701)
* [2009 - Taint-based Directed Whitebox Fuzzing](https://ece.uwaterloo.ca/~vganesh/Publications_files/vg-ICSE2009-BuzzFuzz.pdf)
* [2009 - Dynamic Test Generation To Find Integer Bugs in x86 Binary Linux Programs](https://argp.github.io/public/50a11f65857c12c76995f843dbfe6dda.pdf)
* [2008 - Grammar-based Whitebox Fuzzing](https://people.csail.mit.edu/akiezun/pldi-kiezun.pdf)
* [2008 - Vulnerability Analysis for X86 Executables Using Genetic Algorithm and Fuzzing](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=4682289)
* [2008 - Fuzzing Wi-Fi Drivers to Locate Security Vulnerabilities](https://www.di.fc.ul.pt/~nuno/PAPERS/EDCC08.pdf)
* [2008 - KLEE: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs](https://hci.stanford.edu/cstr/reports/2008-03.pdf)
* [2008 - Automated Whitebox Fuzz Testing](https://patricegodefroid.github.io/public_psfiles/ndss2008.pdf)
* [2005 - DART: Directed Automated Random Testing](https://web.eecs.umich.edu/~weimerw/2014-6610/reading/p213-godefroid.pdf)
* [1994 - Dominators, Super Blocks, and Program Coverage](https://www.sci-hub.ren/10.1145/174675.175935)

### IoT fuzzing

* [2020 - Device-agnostic Firmware Execution is Possible: A Concolic Execution Approach for Peripheral Emulation](https://dl.acm.org/doi/abs/10.1145/3427228.3427280)
* [2020 - Vulnerability Detection in SIoT Applications: A Fuzzing Method on their Binaries](https://ieeexplore.ieee.org/abstract/document/9259242)
* [2020 - FirmAE: Towards Large-Scale Emulation of IoT Firmware forDynamic Analysis](https://syssec.kaist.ac.kr/pub/2020/kim_acsac2020.pdf)
* [2020 - FIRMNANO: Toward IoT Firmware Fuzzing Through Augmented Virtual Execution](https://ieeexplore.ieee.org/abstract/document/9237719)
* [2020 - ARM-AFL: Coverage-Guided Fuzzing Framework for ARM-Based IoT Devices](https://link.springer.com/chapter/10.1007/978-3-030-61638-0_14)
* [2020 - Bug detection in embedded environments by fuzzing and symbolic execution](http://docs.mipro-proceedings.com/iss/04_ISS_5762.pdf)
* [2020 - FirmXRay: Detecting Bluetooth Link Layer Vulnerabilities From Bare-Metal Firmware](http://web.cse.ohio-state.edu/~lin.3021/file/CCS20.pdf)
* [2020 - EM-Fuzz: Augmented Firmware Fuzzing via Memory Checking](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/EMSOFT20.pdf)
* [2020 - Verification of Embedded Binaries using Coverage-guided Fuzzing with System C-based Virtual Prototypes](http://www.informatik.uni-bremen.de/agra/doc/konf/2020GLSVLSI_Verification-of-Embedded-Binaries-using-Coverage-guided-Fuzzing-with-SystemC-Virtual-Prototypes.pdf)
* [2020 - DICE: Automatic Emulation of DMA Input Channels for Dynamic Firmware Analysis](https://arxiv.org/pdf/2007.01502.pdf)
* [2020 - Fw‐fuzz: A code coverage‐guided fuzzing framework for network protocols on firmware](https://onlinelibrary.wiley.com/doi/full/10.1002/cpe.5756)
* [2020 - TAINT-DRIVEN FIRMWARE FUZZING OF EMBEDDED SYSTEMS THESIS](https://melisasavich.io/papers/thesis.pdf)
* [2020 - A Dynamic Instrumentation Technology for IoT Devices](https://link.springer.com/chapter/10.1007/978-3-030-50399-4_29)
* [2020 - Vulcan: a state-aware fuzzing tool for wear OS ecosystem](https://dl.acm.org/doi/abs/10.1145/3386901.3397492)
* [2020 - A Novel Concolic Execution Approach on Embedded Device](https://dl.acm.org/doi/abs/10.1145/3377644.3377654)
* [2020 - HFuzz: Towards automatic fuzzing testing of NB-IoT core network protocols implementations](https://www.sciencedirect.com/science/article/pii/S0167739X19324409)
* [2020 - FIRMCORN: Vulnerability-Oriented Fuzzing of IoT Firmware via Optimized Virtual Execution](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8990098)
* [2018 - IoTFuzzer: Discovering Memory Corruptions in IoT Through App-based Fuzzing](https://web.cse.ohio-state.edu/~lin.3021/file/NDSS18b.pdf)
* [2017 - Towards Automated Dynamic Analysis for Linux-based Embedded Firmware](https://www.ndss-symposium.org/wp-content/uploads/2017/09/towards-automated-dynamic-analysis-linux-based-embedded-firmware.pdf)
* [2016 - Scalable Graph-based Bug Search for Firmware Images](https://www.cs.ucr.edu/~heng/pubs/genius-ccs16.pdf)
* [2015 - SURROGATES: Enabling Near-Real-Time Dynamic Analyses of Embedded Systems](https://www.usenix.org/system/files/conference/woot15/woot15-paper-koscher.pdf)
* [2015 - Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware](https://pdfs.semanticscholar.org/b006/72fc5ff99434bf5347418a2d2762a3bb2639.pdf)
* [2014 - A Large-Scale Analysis of the Security  of Embedded Firmwares](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-costin.pdf)
* [2013 - RPFuzzer: A Framework for Discovering Router Protocols Vulnerabilities Based on Fuzzing](http://www.itiis.org/journals/tiis/digital-library/manuscript/file/20353/14.TIIS-RP-2012-Dec-0966.R1.pdf)


### Kernel fuzzing

* [2020 - FINDING RACE CONDITIONS IN KERNELS:FROM FUZZING TO SYMBOLIC EXECUTION - THESIS](https://gts3.org/assets/papers/2020/xu:thesis.pdf)
* [2020 - Agamotto: Accelerating Kernel Driver Fuzzing with Lightweight Virtual Machine Checkpoints](https://www.usenix.org/conference/usenixsecurity20/presentation/song) 
* [2020 - X-AFL: a kernel fuzzer combining passive and active fuzzing](https://dl.acm.org/doi/abs/10.1145/3380786.3391400)
* [2020 - Identification of Kernel Memory Corruption Using Kernel Memory Secret Observation Mechanism](https://search.ieice.org/bin/summary.php?id=e103-d_7_1462)
* [2020 - HFL: Hybrid Fuzzing on the Linux Kernel](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24018.pdf)
* [2020 - Realistic Error Injection for System Calls](https://arxiv.org/pdf/2006.04444.pdf)
* [2020 - KRACE: Data Race Fuzzing for Kernel File Systems](https://www.cc.gatech.edu/~mxu80/pubs/xu:krace.pdf)
* [2020 - USBFuzz: A Framework for Fuzzing USB Drivers by Device Emulation](https://hexhive.epfl.ch/publications/files/20SEC3.pdf)
* [2019 - Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8835267)
* [2019 - Razzer: Finding Kernel Race Bugs through Fuzzing](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8835326)
* [2019 - Unicorefuzz: On the Viability of Emulation for Kernel space Fuzzing](https://www.usenix.org/system/files/woot19-paper_maier.pdf)
* [2017 - Stateful Fuzzing of Wireless Device Drivers in an Emulated Environment](https://pdfs.semanticscholar.org/26b9/97d7a83ce950db6d311ee65c268e756e0794.pdf)
* [2017 - DIFUZE: Interface Aware Fuzzing for Kernel Drivers](https://acmccs.github.io/papers/p2123-corinaA.pdf)
* [2008 - Fuzzing Wi-Fi Drivers to Locate Security Vulnerabilities](https://www.di.fc.ul.pt/~nuno/PAPERS/EDCC08.pdf)


### Format specific fuzzing

* [2020 - NYX: Greybox Hypervisor Fuzzing using Fast Snapshots and Affine Types](https://www.usenix.org/system/files/sec21summer_schumilo.pdf)
* [2020 - Tree2tree Structural Language Modeling for Compiler Fuzzing](https://link.springer.com/chapter/10.1007/978-3-030-60245-1_38)
* [2020 - Detecting Critical Bugs in SMT Solvers Using Blackbox Mutational Fuzzing](https://arxiv.org/pdf/2004.05934.pdf)
* [2020 - JS Engine - Montage: A Neural Network Language Model-Guided JavaScript Engine Fuzzer](https://arxiv.org/abs/2001.04107.pdf)
* [2020 - JS Engine - Fuzzing JavaScript Engines with Aspect-preserving Mutation](https://jakkdu.github.io/pubs/2020/park:die.pdf)
* [2020 - CUDA Compiler - CUDAsmith: A Fuzzer for CUDA Compilers](http://jiangbo.buaa.edu.cn/compsac20-CUDAsmith.pdf)
* [2020 - Smart Contracts - sFuzz: An Efficient Adaptive Fuzzer for Solidity Smart Contracts](https://arxiv.org/abs/2004.08563)
* [2019 - Compiler Fuzzing: How Much Does It Matter?](https://srg.doc.ic.ac.uk/files/papers/compilerbugs-oopsla-19.pdf)
* [2019 - Smart Contracts - Harvey: A Greybox Fuzzer for Smart Contracts](https://arxiv.org/abs/1905.06944.pdf)
* [2017 - XML - Skyfire: Data-Driven Seed Generation for Fuzzing](https://www.ieee-security.org/TC/SP2017/papers/42.pdf)


### Exploitation

* [2020 - Shadow-Heap: Preventing Heap-based Memory Corruptions by Metadata Validation](https://lukasatkinson.de/research/Bouche2020ShadowHeapValidation.pdf)
* [2020 - Practical Fine-Grained Binary Code Randomization](https://dl.acm.org/doi/abs/10.1145/3427228.3427292)
* [2020 - Tiny-CFA: Minimalistic Control-Flow Attestation UsingVerified Proofs of Execution](http://sprout.ics.uci.edu/pubs/tiny-cfa.pdf)
* [2020 - Greybox Automatic Exploit Generation for Heap Overflows in Language Interpreters - PHD THESIS](https://seanhn.files.wordpress.com/2020/11/heelan_phd_thesis.pdf)
* [2020 - ABCFI: Fast and Lightweight Fine-Grained Hardware-Assisted Control-Flow Integrity](https://www.sci-hub.ren/10.1109/TCAD.2020.3012640)
* [2020 - HeapExpo: Pinpointing Promoted Pointers to Prevent Use-After-Free Vulnerabilities](http://moyix.net/~moyix/papers/heapexpo.pdf)
* [2020 - Localizing Patch Points From One Exploit](https://arxiv.org/pdf/2008.04516.pdf)
* [2020 - Speculative Dereferencing of Registers: Reviving Foreshadow](https://arxiv.org/pdf/2008.02307.pdf)
* [2020 - HAEPG: An Automatic Multi-hop Exploitation Generation Framework](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7338205/)
* [2020 - Exploiting More Binaries by Using Planning to Assemble ROP Exploiting More Binaries by Using Planning to Assemble ROP Attacks Attacks](https://scholars.unh.edu/cgi/viewcontent.cgi?article=2376&context=thesis)
* [2020 - ROPminer: Learning-Based Static Detection of ROP Chain Considering Linkability of ROP Gadgets](https://search.ieice.org/bin/summary.php?id=e103-d_7_1476)
* [2020 - KOOBE: Towards Facilitating Exploit Generation of Kernel Out-Of-Bounds Write Vulnerabilities](http://www.cs.ucr.edu/~zhiyunq/pub/sec20_koobe.pdf)
* [2020 - Preventing Return Oriented Programming Attacks By Preventing Return Instruction Pointer Overwrites](https://www.csee.umbc.edu/~allgood1/papers/611-rop.pdf)
* [2020 - KASLR: Break It, Fix It, Repeat](http://cc0x1f.net/publications/kaslr.pdf)
* [2020 - ShadowGuard : Optimizing the Policy and Mechanism of Shadow Stack Instrumentation using Binary Static Analysis](https://arxiv.org/pdf/2002.07748.pdf)
* [2020 - VulHunter: An Automated Vulnerability Detection System Based on Deep Learning and Bytecode](https://link.springer.com/chapter/10.1007/978-3-030-41579-2_12)
* [2020 - Analysis and Evaluation of ROPInjector](http://dione.lib.unipi.gr/xmlui/bitstream/handle/unipi/12622/Tsioutsias_1633.pdf?sequence=1)
* [2020 - API Misuse Detection in C Programs: Practice on SSL APIs](https://www.worldscientific.com/doi/abs/10.1142/S0218194019400205)
* [2020 - KOOBE: Towards Facilitating Exploit Generation of Kernel Out-Of-Bounds Write Vulnerabilities](http://www.cs.ucr.edu/~zhiyunq/pub/sec20_koobe.pdf)
* [2020 - Egalito: Layout-Agnostic Binary Recompilation](http://www.cs.columbia.edu/~junfeng/papers/egalito-asplos20.pdf)
* [2020 - Verifying Software Vulnerabilities in IoT Cryptographic Protocols](https://arxiv.org/pdf/2001.09837.pdf)
* [2020 - μRAI: Securing Embedded Systems with Return Address Integrity](https://nebelwelt.net/files/20NDSS.pdf)
* [2020 - Preventing Return Oriented Programming Attacks By Preventing Return Instruction Pointer Overwrites](https://www.csee.umbc.edu/~allgood1/papers/611-rop.pdf)
* [2019 - Kernel Protection Against Just-In-Time Code Reuse](https://dl.acm.org/doi/abs/10.1145/3277592)
* [2019 - Kernel Exploitation Via Uninitialized Stack](https://infocon.org/cons/DEF%20CON/DEF%20CON%2019/DEF%20CON%2019%20presentations/DEF%20CON%2019%20-%20Cook-Kernel-Exploitation.pdf)
* [2019 - KEPLER: Facilitating Control-flow Hijacking Primitive Evaluation for Linux Kernel Vulnerabilities](https://www.usenix.org/system/files/sec19-wu-wei.pdf)
* [2019 - SLAKE: Facilitating Slab Manipulation for Exploiting Vulnerabilities in the Linux Kernel](https://dl.acm.org/doi/abs/10.1145/3319535.3363212)
* [2018 - K-Miner: Uncovering Memory Corruption in Linux](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_05A-1_Gens_paper.pdf)
* [2017 - DROP THE ROP: Fine-grained Control-flow Integrity for the Linux Kernel](https://pdfs.semanticscholar.org/c143/95767b618a014472a0b835464aeb4aaf7734.pdf)
* [2017 - kR^X: Comprehensive Kernel Protection against Just-In-Time Code Reuse](https://dl.acm.org/doi/abs/10.1145/3064176.3064216)
* [2017 - Unleashing Use-Before-Initialization Vulnerabilities in the Linux Kernel Using Targeted Stack Spraying](https://www.ndss-symposium.org/wp-content/uploads/2017/09/ndss2017_09-2_Lu_paper.pdf)
* [2017 - Towards Automated Dynamic Analysis for Linux-based Embedded Firmware](https://www.ndss-symposium.org/wp-content/uploads/2017/09/towards-automated-dynamic-analysis-linux-based-embedded-firmware.pdf)
* [2016 - Scalable Graph-based Bug Search for Firmware Images](https://www.cs.ucr.edu/~heng/pubs/genius-ccs16.pdf)
* [2015 - Cross-Architecture Bug Search in Binary Executables](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7163056)
* [2015 - SURROGATES: Enabling Near-Real-Time Dynamic Analyses of Embedded Systems](https://www.usenix.org/system/files/conference/woot15/woot15-paper-koscher.pdf)
* [2015 - From Collision To Exploitation: Unleashing Use-After-Free Vulnerabilities in Linux Kernel](http://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20From%20collision%20to%20exploitation%3A%20Unleashing%20Use-After-Free%20vulnerabilities%20in%20Linux%20Kernel.pdf)
* [2015 - PIE: Parser Identification in Embedded Systems](http://www.s3.eurecom.fr/docs/acsac15_cojocar.pdf)
* [2014 - ret2dir: Rethinking Kernel Isolation](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-kemerlis.pdf)
* [2014 - Make It Work, Make It Right, Make It Fast: Building a Platform-Neutral Whole-System Dynamic Binary Analysis Platform](https://dl.acm.org/doi/pdf/10.1145/2610384.2610407?download=true)
* [2012 - Anatomy of a Remote Kernel Exploit](https://www.cs.dartmouth.edu/~sergey/cs108/2012/Dan-Rosenberg-lecture.pdf)
* [2012 - A Heap of Trouble:  Breaking the LinuxKernel SLOB Allocator](https://vsecurity.com//download/publications/slob-exploitation.pdf)
* [2011 - Linux kernel vulnerabilities: state-of-the-art defenses and open problems](https://dl.acm.org/doi/abs/10.1145/2103799.2103805)
* [2011 - Protecting the Core: Kernel Exploitation Mitigations](http://census.gr/media/bheu-2011-wp.pdf)
* [2015 - From Collision To Exploitation: Unleashing Use-After-Free Vulnerabilities in Linux Kernel](http://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20From%20collision%20to%20exploitation%3A%20Unleashing%20Use-After-Free%20vulnerabilities%20in%20Linux%20Kernel.pdf)
* [2014 - ret2dir: Rethinking Kernel Isolation](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-kemerlis.pdf)
* [2012 - Anatomy of a Remote Kernel Exploit](https://www.cs.dartmouth.edu/~sergey/cs108/2012/Dan-Rosenberg-lecture.pdf)
* [2012 - A Heap of Trouble:  Breaking the Linux Kernel SLOB Allocator](https://vsecurity.com//download/publications/slob-exploitation.pdf)
* [2011 - Linux kernel vulnerabilities: state-of-the-art defenses and open problems](https://dl.acm.org/doi/abs/10.1145/2103799.2103805)
* [2011 - Protecting the Core: Kernel Exploitation Mitigations](http://census.gr/media/bheu-2011-wp.pdf)


### Static Binary Analysis

* [2020 - VulDetector: Detecting Vulnerabilities using Weighted Feature Graph Comparison](https://ieeexplore.ieee.org/abstract/document/9309254) 
* [2020 - DEEPBINDIFF: Learning Program-Wide Code Representations for Binary Diffing](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24311-paper.pdf)
* [2020 - BinDeep:  A Deep Learning Approach to Binary Code Similarity Detection](https://www.sci-hub.ren/10.1016/j.eswa.2020.114348)
* [2020 - Revisiting Binary Code Similarity Analysis using Interpretable Feature Engineering and Lessons Learned](https://0xdkay.me/pub/2020/kim-arxiv2020.pdf)
* [2020 - iDEA: Static Analysis on the Security of Apple Kernel Drivers](http://homes.sice.indiana.edu/luyixing/bib/CCS20-iDEA.pdf)
* [2020 - HART: Hardware-Assisted Kernel Module Tracing on Arm](https://sci-hub.tw/10.1007/978-3-030-58951-6)
* [2020 - AN APPROACH TO COMPARING CONTROL FLOW GRAPHS BASED ON BASIC BLOCK MATCHING](http://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
* [2020 - How Far We Have Come: Testing Decompilation Correctness of C Decompilers](https://dl.acm.org/doi/pdf/10.1145/3395363.3397370)
* [2020 - Dynamic Binary Lifting and Recompilation DISS](https://escholarship.org/content/qt8pz574mn/qt8pz574mn_noSplash_b11493cfba04b6b9c737eb3e42038820.pdf)
* [2020 - Similarity Based Binary Backdoor Detection via Attributed Control Flow Graph](https://ieeexplore.ieee.org/abstract/document/9085069)
* [2020 - IoTSIT: A Static Instrumentation Tool for IoT Devices](https://ieeexplore.ieee.org/document/9084145)
* [2019 - Code Similarity Detection using AST and Textual Information](http://www.ijpe-online.com/EN/10.23940/ijpe.19.10.p14.26832691)
* [2018 - CodEX: Source Code Plagiarism DetectionBased on Abstract Syntax Trees](https://pdfs.semanticscholar.org/d5bd/a9161deac69e4fed8da63971f773c60f3caf.pdf)
* [2017 - rev.ng: a unified binary analysis framework to recover CFGs and function boundaries](https://dl.acm.org/doi/abs/10.1145/3033019.3033028)
* [2017 - Angr: The Next Generation of Binary Analysis](https://ieeexplore.ieee.org/abstract/document/8077799)
* [2016 - Binary code is not easy](https://dl.acm.org/doi/abs/10.1145/2931037.2931047)
* [2015 - Cross-Architecture Bug Search in Binary Executables](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7163056)
* [2014 - A platform for secure static binary instrumentation](https://dl.acm.org/doi/abs/10.1145/2576195.2576208)
* [2013 - MIL: A language to build program analysis tools through static binary instrumentation](https://ieeexplore.ieee.org/abstract/document/6799106)
* [2013 - Binary Code Analysis](https://ieeexplore.ieee.org/abstract/document/6583187)
* [2013 - A compiler-level intermediate representation based binary analysis and rewriting system](https://dl.acm.org/doi/abs/10.1145/2465351.2465380)
* [2013 - Protocol reverse engineering through dynamic and static binary analysis](https://www.sciencedirect.com/science/article/abs/pii/S1005888513602174)
* [2013 - BinaryPig: Scalable Static Binary Analysis Over Hadoop](https://media.blackhat.com/us-13/US-13-Hanif-Binarypig-Scalable-Malware-Analytics-in-Hadoop-WP.pdf)
* [2011 - BAP: A Binary Analysis Platform](https://link.springer.com/chapter/10.1007/978-3-642-22110-1_37)
* [2009 - Syntax tree fingerprinting for source code similarity detection](https://www.researchgate.net/publication/221219530_Syntax_tree_fingerprinting_for_source_code_similarity_detection)
* [2008 - BitBlaze: A New Approach to Computer Security via Binary Analysis](https://link.springer.com/chapter/10.1007/978-3-540-89862-7_1)
* [2005 - Practical analysis of stripped binary code](https://dl.acm.org/doi/abs/10.1145/1127577.1127590)
* [2004 - Detecting kernel-level rootkits through binary analysis](https://ieeexplore.ieee.org/abstract/document/1377219)


### Misc

* [2021 - FuzzSplore: Visualizing Feedback-Driven Fuzzing Techniques](https://arxiv.org/pdf/2102.02527.pdf)
* [2020 - Memory Error Detection Based on Dynamic Binary Translation](https://ieeexplore.ieee.org/abstract/document/9295756/keywords#keywords)
* [2020 - Sydr: Cutting Edge Dynamic Symbolic Execution](https://arxiv.org/pdf/2011.09269.pdf)
* [2020 - DrPin: A dynamic binary instumentator for multiple processor architectures](http://wscad.sbc.org.br/2020/artigos/trilha-principal/s05p02-209710-1.pdf)
* [2020 - MVP: Detecting Vulnerabilities using Patch-Enhanced Vulnerability Signatures](https://www.usenix.org/system/files/sec20-xiao.pdf)
* [2020 - Collecting Vulnerable Source Code from Open-Source Repositories for Dataset Generation](https://www.mdpi.com/2076-3417/10/4/1270/htm)
* [2020 - LEOPARD: Identifying Vulnerable Code for Vulnerability Assessment through Program Metrics](https://arxiv.org/pdf/1901.11479.pdf)
* [2020 - Dynamic Program Analysis Tools in GCC and CLANG Compilers](https://sci-hub.tw/https://doi.org/10.1134/S0361768820010089)
* [2020 - On Using k-means Clustering for Test Suite Reduction](https://sci-hub.tw/https://ieeexplore.ieee.org/document/9155590)
* [2020 - Optimizing the Parameters of an Evolutionary Algorithm for Fuzzing and Test Data Generation](https://sci-hub.tw/10.1109/ICSTW50294.2020.00061)
* [2020 - Inputs from Hell: Learning Input Distributions for Grammar-Based Test Generation](https://publications.cispa.saarland/3167/7/inputs-from-hell.pdf)
* [2020 - IdSan: An identity-based memory sanitizer for fuzzing binaries](https://arxiv.org/pdf/2007.13113.pdf)
* [2020 - An experimental study oncombining automated andstochastic test data generation - MASTER THESIS](https://gupea.ub.gu.se/bitstream/2077/65502/1/gupea_2077_65502_1.pdf)
* [2020 - FuzzGen: Automatic Fuzzer Generation](https://www.usenix.org/system/files/sec20fall_ispoglou_prepub.pdf)
* [2020 - Fuzzing: On the Exponential Cost of Vulnerability Discovery](https://mboehme.github.io/paper/FSE20.EmpiricalLaw.pdf)
* [2020 - Poster: Debugging Inputs](https://publications.cispa.saarland/3062/1/icse2020-poster-paper42-camera-ready.pdf)
* [2020 - API Misuse Detection in C Programs: Practice on SSL APIs](https://www.worldscientific.com/doi/abs/10.1142/S0218194019400205)
* [2020 - Egalito: Layout-Agnostic Binary Recompilation](http://www.cs.columbia.edu/~junfeng/papers/egalito-asplos20.pdf)
* [2020 - Verifying Software Vulnerabilities in IoT Cryptographic Protocols](https://arxiv.org/pdf/2001.09837.pdf)
* [2020 - μRAI: Securing Embedded Systems with Return Address Integrity](https://nebelwelt.net/files/20NDSS.pdf)
* [2020 - Fast Bit-Vector Satisfiability](https://qingkaishi.github.io/public_pdfs/ISSTA20-Trident.pdf)
* [2020 - MARDU: Efficient and Scalable Code Re-randomization](https://dl.acm.org/doi/pdf/10.1145/3383669.3398280)
* [2020 - Towards formal verification of IoT protocols: A Review](https://www.sciencedirect.com/science/article/abs/pii/S1389128619317116)
* [2020 - Automating the fuzzing triage process](https://dr.ntu.edu.sg/handle/10356/140674)
* [2020 - COMPARING AFL SCALABILITY IN VIRTUAL-AND NATIVE ENVIRONMENT](https://jyx.jyu.fi/bitstream/handle/123456789/69772/URN%3ANBN%3Afi%3Ajyu-202006084029.pdf?sequence=1)
* [2020 - SYMBION: Interleaving Symbolic with Concrete Execution](https://conand.me/publications/gritti-symbion-2020.pdf)
* [2020 - Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization](https://ajax4sec.github.io/papers/ndss20-fall-paper422.pdf)
* [2019 - Toward the Analysis of Embedded Firmware through Automated Re-hosting](http://subwire.net/papers/pretender-final.pdf)
* [2019 - FUZZIFICATION: Anti-Fuzzing Techniques](https://www.usenix.org/system/files/sec19fall_jung_prepub.pdf)
* [2018 - VulinOSS: A Dataset of Security Vulnerabilities in Open-source Systems](https://antonisgkortzis.github.io/files/GMS_MSR_18.pdf)
* [2018 - HDDr: A Recursive Variantof the Hierarchical Delta Debugging Algorithm](https://sci-hub.se/https://doi.org/10.1145/3278186.3278189)
* [2017 - Coarse Hierarchical Delta Debugging](https://sci-hub.se/10.1109/ICSME.2017.26)
* [2017 - VUDDY: A Scalable Approach for Vulnerable CodeClone Discovery](https://squizz617.github.io/pubs/vuddy-sp17.pdf)
* [2017 - Postmortem Program Analysis with Hardware-Enhanced Post-Crash Artifacts](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-xu.pdf)
* [2017 - Synthesizing Program Input Grammars](https://obastani.github.io/docs/pldi17.pdf)
* [2017 - Designing New Operating Primitives to Improve Fuzzing Performance](https://acmccs.github.io/papers/p2313-xuA.pdf)
* [2017 - Instruction Punning: Lightweight Instrumentation for x86-64](https://dl.acm.org/doi/pdf/10.1145/3062341.3062344?download=true)
* [2016 - Modernizing Hierarchical Delta Debugging](https://sci-hub.se/https://doi.org/10.1145/2994291.2994296)
* [2016 - VulPecker: An Automated Vulnerability Detection SystemBased on Code Similarity Analysis](http://www.cs.utsa.edu/~shxu/socs/VulPecker.pdf)
* [2016 - CREDAL: Towards Locating a Memory Corruption Vulnerability with Your Core Dump](https://mudongliang.github.io/files/papers/p529-xu.pdf)
* [2016 - RETracer: Triaging Crashes by Reverse Execution fromPartial Memory Dumps](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/06/retracer-2.pdf)
* [2015 - PIE: Parser Identification in Embedded Systems](http://www.s3.eurecom.fr/docs/acsac15_cojocar.pdf)
* [2010 - Iterative Delta Debugging](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.296.5948&rep=rep1&type=pdf)
* [2009 - Dynamic Test Generation To Find Integer Bugs in x86 Binary Linux Programs](https://argp.github.io/public/50a11f65857c12c76995f843dbfe6dda.pdf)
* [2006 - HDD: Hierarchical Delta Debugging](https://sci-hub.se/https://doi.org/10.1145/1134285.1134307)

### Surveys, SoKs, and Studies

* [2020 - A Systemic Review of Kernel Fuzzing](https://dl.acm.org/doi/abs/10.1145/3444370.3444586)
* [2020 - A Survey of Hybrid Fuzzing based on Symbolic Execution](https://dl.acm.org/doi/abs/10.1145/3444370.3444570)
* [2020 - A Study on Using Code Coverage Information Extracted from Binary to Guide Fuzzing](https://www.cscjournals.org/manuscript/Journals/IJCSS/Volume14/Issue5/IJCSS-1589.pdf)
* [2020 - Study of Security Flaws in the Linux Kernel by Fuzzing](https://ieeexplore.ieee.org/abstract/document/9271516)
* [2020 - Dynamic vulnerability detection approaches and tools: State of the Art](https://ieeexplore.ieee.org/abstract/document/9268686)
* [2020 - Fuzzing: Challenges and Reflections](https://www.comp.nus.edu.sg/~abhik/pdf/IEEE-SW-Fuzzing.pdf)
* [2020 - The Relevance of Classic Fuzz Testing: Have We Solved This One?](https://arxiv.org/pdf/2008.06537.pdf)
* [2020 - A Practical, Principled Measure of Fuzzer Appeal:A Preliminary Study](https://agroce.github.io/qrs20-1.pdf)
* [2020 - SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly But Were Afraid to Ask](https://arxiv.org/ftp/arxiv/papers/2007/2007.14266.pdf)
* [2020 - A Quantitative Comparison of Coverage-Based Greybox Fuzzers](https://sites.google.com/site/yoshidaatnu/TsuzukiAST2020.pdf)
* [2020 - A Survey of Security Vulnerability Analysis, Discovery, Detection, and Mitigation on IoT Devices](https://www.mdpi.com/1999-5903/12/2/27)
* [2020 - A systematic review of fuzzing based on machine learning techniques](https://arxiv.org/pdf/1908.01262.pdf)
* [2019 - A Survey of Binary Code Similarity](https://arxiv.org/pdf/1909.11424.pdf)
* [2019 - The Art, Science, and Engineering of Fuzzing: A Survey](https://arxiv.org/pdf/1812.00140.pdf)
* [2012 - Regression testingminimization, selection and prioritization: a survey](https://www.sci-hub.ren/10.1002/stvr.430)
