# Third-party / upstream source notice

The standalone app keeps the ChromaPlex compiler/runtime code separate from the
GUI and AI integration.

Authoritative upstream projects supplied for this integration:

1. `https://github.com/Janus5G/chromaplex-os`
   - Current ChromaPlex/CPL compiler, CPA assembler and CrystalSimulator path.
2. `https://github.com/Janus5G/Cplex`
   - Compiler bridge architecture and dialect routing reference.
3. `https://github.com/Janus5G/chromaplex-os-compiler`
   - Original/legacy `chromaplex_os` compiler, assembler, VM and storage path.

The vendored `chromaplex` and `chromaplex_os` packages were taken from the
supplied Refract Studio package, where they were already kept separate with the
upstream MIT license files and verification material. They are not modified by
the application UI. Compatibility changes are implemented in
`chromaplex_agent/runtimes/chromaplex.py`.
