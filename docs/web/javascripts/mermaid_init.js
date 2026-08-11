/**
 * Mermaid initialization for Material for MkDocs (instant navigation).
 *
 * Material for MkDocs replaces page content on navigation without
 * reloading scripts. We subscribe to the document$ observable so
 * mermaid is re-initialised after every page transition.
 */
document$.subscribe(function () {
    var palette = __md_get("__palette");
    var isDark = palette && palette.color && palette.color.scheme === "slate";

    mermaid.initialize({
        startOnLoad: false,
        theme: isDark ? "dark" : "default",
        themeVariables: {
            fontFamily: "Inter, sans-serif",
            fontSize: "15px",
            primaryColor: isDark ? "#161b22" : "#ffffff",
            primaryTextColor: isDark ? "#f0f6fc" : "#1f2328",
            primaryBorderColor: isDark ? "#22d3ee" : "#0ea5e9",
            lineColor: isDark ? "#8b949e" : "#656d76",
            secondaryColor: isDark ? "#0d1117" : "#f6f8fa",
            tertiaryColor: isDark ? "#161b22" : "#ffffff",
            nodeBorder: isDark ? "#22d3ee" : "#0ea5e9",
            clusterBdrColor: isDark ? "#30363d" : "#d0d7de",
            clusterBgColor: isDark ? "#0d1117" : "#f6f8fa",
            titleColor: isDark ? "#f0f6fc" : "#1f2328"
        },
        securityLevel: "loose",
    });
    mermaid.run({ querySelector: ".mermaid" });
});
