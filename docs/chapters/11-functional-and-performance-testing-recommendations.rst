================================================
Functional & Performance Testing Recommendations
================================================

Any new feature must also contain a test tool/PoC that demonstrates
protection capabilities.

We cannot impose particular performance tests, or specific metrics
regarding the performance of HVI. This has to be done on a case-by-case
basis, with several factors in consideration:

- What will be protected? Endpoints, servers, VDIs?
- How many VMs/hosts will be protected?
- What is the regular workload/purpose of the protected VMs?
- What level of protection will be enabled for HVI? Will there be custom protection features?

Once these - at a minimum - questions are answered, performance can be
assessed individually for each case. Generally, we recommend some tests
to get a general picture about the impact of the Introspection module:

- Application startup time - measure how long it takes an application to start, with and without HVI;
- Browser performance - done in at least two ways:

  - measure the time taken to open URLs, to navigate through pages, etc.;
  - run a browser benchmark to assess the in-browser performance;

- Micro-benchmarks - performed for each intercepted code flow:

- process creation/termination;
- changing memory permissions;
- executing code from a data page;
- loading/unloading modules;

- Host performance - assess the overall host behavior when HVI is used
  (for example, the number of VMs that can be realistically used with
  vs. without HVI); in this regard, we recommend LoginVSI;
- Specific benchmarks to assess various other aspects of the in-VM performance, such as:

  - unixbench;
  - phoronix;

- General benchmarks which measure the hardware performance will
  usually yield an insignificant performance impact (for example, FPU
  performance, memory performance, etc.);

Any new feature will be subject to performance measurements before being
accepted into introcore.
