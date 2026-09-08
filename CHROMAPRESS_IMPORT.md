# Import Chromaplex Coding Agent into ChromaPress

Chromaplex Coding Agent is designed to remain an external application. ChromaPress should treat it as a normal local Linux package rather than embedding its source into the builder.

## Intended flow

1. Build or download `chromaplex-coding-agent_0.3.0_all.deb`.
2. In ChromaPress open **Applications**.
3. Choose **Add local Linux package/file**.
4. Select the `.deb` package.
5. Let ChromaPress inspect package metadata and dependencies.
6. Stage the package in **Changes**.
7. Test the staged change when that feature is available.
8. Apply it and continue to **Build & Verify**.

The package installs a normal desktop entry and `/usr/bin/chromaplex-coding-agent`.

This import path is a design target until ChromaPress' local-package Applications engine has been verified end-to-end on the user's machine.
