/**
 * Mermaid initialization for Material for MkDocs (instant navigation).
 *
 * Material for MkDocs replaces page content on navigation without
 * reloading scripts. We subscribe to the document$ observable so
 * mermaid is re-initialised after every page transition.
 */
document$.subscribe(function () {
    mermaid.initialize({
        startOnLoad: false,
        theme: "dark",
        securityLevel: "loose",
    });
    mermaid.run({ querySelector: ".mermaid" });
});
