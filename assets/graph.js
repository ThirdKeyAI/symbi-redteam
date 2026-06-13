/* symbi-redteam engagement graph view.
 *
 * Loaded only on /graph (after cytoscape.min.js + fcose-bundle.js). CSP is
 * script-src 'self': no inline script, no eval. Data comes from /api/graph
 * (same-origin fetch).
 *
 * Nodes: findings (kind="finding") and knowledge concepts (kind="concept").
 * Edges: reflector knowledge relations (subject->object) plus finding->subject
 * "derived" links. Findings cluster (compound parent) by host / severity /
 * phase; the user recolors client-side without refetch. Concept nodes are
 * grouped under a single "knowledge" cluster.
 */
(function () {
  "use strict";

  var CY = null;
  var RAW = { nodes: [], edges: [] };

  // Color palettes per "color by" dimension. "" = the absent/none value.
  var PALETTE = {
    severity: { critical: "#ff5d5d", high: "#ff9152", medium: "#e3c14f", low: "#6fa8dc", info: "#9aa0a6", "": "#565b63" },
    status:   { verified: "#4ec08d", false_positive: "#8a8f98", pending: "#d9a13b", "": "#565b63" },
    phase:    { recon: "#6fa8dc", enum: "#1098ad", vuln: "#e3c14f", exploit: "#ff9152", post_exploit: "#ff5d5d", "": "#565b63" }
  };
  var TOOL_PALETTE = ["#7048e8", "#1098ad", "#0ca678", "#e8590c", "#d6336c", "#5c940d", "#1864ab", "#9c36b5", "#495057"];
  var toolColorMap = {};
  var CONCEPT_COLOR = "#8aa0c7";

  function toolColor(tool) {
    if (!tool) return "#ced4da";
    if (!(tool in toolColorMap)) {
      toolColorMap[tool] = TOOL_PALETTE[Object.keys(toolColorMap).length % TOOL_PALETTE.length];
    }
    return toolColorMap[tool];
  }

  function colorFor(n, dim) {
    if (n.kind === "concept") return CONCEPT_COLOR;
    if (dim === "tool") return toolColor(n.tool || "");
    var p = PALETTE[dim] || {};
    return p[n[dim] || ""] || "#ced4da";
  }

  function clusterKey(n, dim) {
    if (n.kind === "concept") return "knowledge";
    if (dim === "none") return null;
    if (dim === "host") return n.host || "(no host)";
    if (dim === "severity") return n.severity || "(none)";
    if (dim === "phase") return n.phase || "(none)";
    return null;
  }

  function buildElements(clusterBy, colorBy) {
    var els = [];
    var parents = {};
    RAW.nodes.forEach(function (n) {
      var parentKey = clusterKey(n, clusterBy);
      var parentId = null;
      if (parentKey !== null) {
        parentId = "cluster:" + parentKey;
        if (!parents[parentId]) {
          parents[parentId] = true;
          els.push({ data: { id: parentId, label: parentKey, isParent: true } });
        }
      }
      var label = n.kind === "concept" ? (n.label || n.id) : n.id;
      els.push({
        data: {
          id: n.id,
          parent: parentId,
          label: label,
          kind: n.kind,
          color: colorFor(n, colorBy),
          shape: n.kind === "concept" ? "diamond" : "ellipse",
          title: n.title || "",
          severity: n.severity, status: n.status, phase: n.phase, tool: n.tool, host: n.host
        }
      });
    });
    RAW.edges.forEach(function (e) {
      els.push({
        data: {
          id: "e:" + e.source + ">" + e.target,
          source: e.source, target: e.target,
          label: e.label || "",
          derived: e.kind === "derived"
        }
      });
    });
    return els;
  }

  var STYLE = [
    { selector: "node", style: {
      "background-color": "data(color)", "label": "data(label)", "shape": "data(shape)",
      "font-size": 6, "color": "#8b93a7", "text-valign": "bottom", "text-halign": "center",
      "text-margin-y": 2, "width": 16, "height": 16, "border-width": 1, "border-color": "#fff"
    }},
    { selector: 'node[kind = "concept"]', style: { "width": 11, "height": 11, "font-size": 5.5, "color": "#7a89a8" } },
    { selector: ":parent", style: {
      "background-color": "#808890", "background-opacity": 0.07,
      "border-width": 1, "border-color": "#b0b6bd", "border-opacity": 0.6,
      "label": "data(label)", "font-size": 10, "font-weight": "bold",
      "text-valign": "top", "text-halign": "center", "color": "#7a828a",
      "shape": "round-rectangle", "padding": "14px"
    }},
    { selector: "edge", style: {
      "width": 1.1, "line-color": "#9aa0a6", "target-arrow-color": "#9aa0a6",
      "target-arrow-shape": "triangle", "curve-style": "bezier", "opacity": 0.45, "arrow-scale": 0.7,
      "label": "data(label)", "font-size": 5, "color": "#9aa0a6", "text-rotation": "autorotate"
    }},
    { selector: 'edge[?derived]', style: { "line-style": "dashed", "line-color": "#c7ccd1", "target-arrow-color": "#c7ccd1" } },
    { selector: "node:selected", style: { "border-width": 3, "border-color": "#1971c2" } },
    { selector: ".faded", style: { "opacity": 0.12 } }
  ];

  var FCOSE_OK = false;
  function registerFcose() {
    if (FCOSE_OK) return;
    try {
      if (window.cytoscape && window.cytoscapeFcose) {
        window.cytoscape.use(window.cytoscapeFcose);
        FCOSE_OK = true;
      }
    } catch (e) { FCOSE_OK = !!window.cytoscapeFcose; }
  }

  function layoutOpts() {
    if (FCOSE_OK) {
      return {
        name: "fcose", quality: "default", animate: false, randomize: true,
        padding: 28, nodeSeparation: 80, idealEdgeLength: 80, nodeRepulsion: 6500,
        packComponents: true, nodeDimensionsIncludeLabels: true
      };
    }
    return {
      name: "cose", animate: false, padding: 24, nodeDimensionsIncludeLabels: true,
      idealEdgeLength: 70, nodeRepulsion: 7000, nestingFactor: 0.9, gravity: 0.4,
      componentSpacing: 60, randomize: true
    };
  }

  function statusText() {
    var findings = RAW.nodes.filter(function (n) { return n.kind === "finding"; }).length;
    var concepts = RAW.nodes.length - findings;
    var clusters = CY ? CY.nodes(":parent").length : 0;
    return findings + " findings · " + concepts + " concepts · " + RAW.edges.length + " links" +
      (clusters ? " · " + clusters + " clusters" : "");
  }

  function renderLegend(colorBy) {
    var box = document.getElementById("cy-legend");
    if (!box) return;
    box.textContent = "";
    var title = document.createElement("div");
    title.className = "legend-title";
    title.textContent = "color: " + colorBy;
    box.appendChild(title);

    var entries;
    if (colorBy === "tool") {
      entries = Object.keys(toolColorMap).map(function (k) { return [k || "(none)", toolColorMap[k]]; });
    } else {
      var p = PALETTE[colorBy] || {};
      entries = Object.keys(p).map(function (k) { return [k || "(none)", p[k]]; });
    }
    entries.push(["knowledge concept", CONCEPT_COLOR]);
    entries.forEach(function (pair) {
      var row = document.createElement("div");
      row.className = "legend-row";
      var sw = document.createElement("span");
      sw.className = "legend-swatch";
      sw.style.backgroundColor = pair[1];
      var lab = document.createElement("span");
      lab.textContent = pair[0];
      row.appendChild(sw);
      row.appendChild(lab);
      box.appendChild(row);
    });
  }

  function render() {
    var clusterBy = document.getElementById("cluster-by").value;
    var colorBy = document.getElementById("color-by").value;
    var els = buildElements(clusterBy, colorBy);

    if (CY) { CY.destroy(); CY = null; }
    CY = cytoscape({
      container: document.getElementById("cy"),
      elements: els,
      style: STYLE,
      layout: layoutOpts(),
      wheelSensitivity: 0.2
    });

    CY.on("tap", "node", function (evt) {
      var n = evt.target;
      if (n.data("isParent") || n.data("kind") === "concept") return;
      // Open the finding in a new tab so the graph view stays put.
      window.open("/findings/" + encodeURIComponent(n.id()), "_blank", "noopener");
    });
    CY.on("mouseover", "node", function (evt) {
      var n = evt.target;
      if (n.data("isParent")) return;
      var hood = n.closedNeighborhood();
      CY.elements().not(hood).addClass("faded");
    });
    CY.on("mouseout", "node", function () { CY.elements().removeClass("faded"); });

    renderLegend(colorBy);
    var st = document.getElementById("graph-status");
    if (st) st.textContent = statusText();
  }

  function recolorOnly() {
    if (!CY) { render(); return; }
    var colorBy = document.getElementById("color-by").value;
    CY.batch(function () {
      RAW.nodes.forEach(function (n) {
        var el = CY.getElementById(n.id);
        if (el) el.data("color", colorFor(n, colorBy));
      });
    });
    renderLegend(colorBy);
  }

  function init() {
    registerFcose();
    var status = document.getElementById("graph-status");
    fetch("/api/graph", { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        RAW = { nodes: data.nodes || [], edges: data.edges || [] };
        if (!RAW.nodes.length) {
          if (status) status.textContent = "no findings in this engagement";
          return;
        }
        render();
        document.getElementById("cluster-by").addEventListener("change", render);
        document.getElementById("color-by").addEventListener("change", recolorOnly);
        document.getElementById("graph-relayout").addEventListener("click", function () {
          if (CY) CY.layout(layoutOpts()).run();
        });
        document.getElementById("graph-fit").addEventListener("click", function () {
          if (CY) CY.fit(undefined, 30);
        });
      })
      .catch(function (e) {
        if (status) status.textContent = "failed to load graph: " + e.message;
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
