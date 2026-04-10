// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

const graphCytoscapeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmokedMeat - Attack Graph</title>
    <script src="https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js"></script>
    <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
    <script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            background: #1a1a2e;
            color: #eee;
            overflow: hidden;
        }
        #cy { width: 100vw; height: 100vh; }

        #controls {
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(22, 33, 62, 0.95);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 12px;
            font-size: 12px;
            min-width: 180px;
            z-index: 100;
        }
        #controls h3 {
            color: #e94560;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .control-section {
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 1px solid #333;
        }
        .control-section:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
        .control-section h4 {
            color: #888;
            margin-bottom: 6px;
            font-size: 10px;
            text-transform: uppercase;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin: 4px 0;
        }
        .legend-color {
            width: 12px;
            height: 12px;
            margin-right: 8px;
            border-radius: 2px;
        }
        .layout-btn, .mode-btn {
            background: #2a2a4e;
            border: 1px solid #444;
            color: #eee;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            margin: 2px;
            font-size: 11px;
            transition: all 0.2s;
        }
        .layout-btn:hover, .mode-btn:hover { background: #3a3a5e; }
        .layout-btn.active, .mode-btn.active { background: #e94560; border-color: #e94560; }
        .button-row {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }
        .scope-text {
            line-height: 1.4;
        }
        #filter-status {
            color: #fff;
            margin-bottom: 6px;
        }
        #filter-description {
            color: #bbb;
            margin-top: 8px;
        }
        #layout-warning {
            color: #ffd700;
            margin-top: 8px;
        }

        #stats {
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(22, 33, 62, 0.95);
            border: 1px solid #333;
            border-radius: 4px;
            padding: 10px;
            font-size: 11px;
            color: #888;
        }
        #connection-status {
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(22, 33, 62, 0.95);
            border: 1px solid #333;
            border-radius: 4px;
            padding: 8px 12px;
            font-size: 11px;
        }
        #connection-status.connected { color: #50c878; border-color: #50c878; }
        #connection-status.disconnected { color: #e94560; border-color: #e94560; }
        #connection-status.connecting { color: #ffd700; border-color: #ffd700; }

        #tooltip {
            position: absolute;
            background: #16213e;
            border: 1px solid #e94560;
            border-radius: 4px;
            padding: 10px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            max-width: 300px;
            z-index: 1000;
            transition: opacity 0.15s;
        }
        #tooltip .title { color: #e94560; font-weight: bold; margin-bottom: 5px; }
        #tooltip .field { color: #888; }
        #tooltip .value {
            color: #fff;
            white-space: pre-wrap;
            word-break: break-word;
        }

        @keyframes pulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(233, 69, 96, 0.4); }
            50% { box-shadow: 0 0 0 10px rgba(233, 69, 96, 0); }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.8); }
            to { opacity: 1; transform: scale(1); }
        }
    </style>
</head>
<body>
    <div id="cy"></div>
    <div id="tooltip"></div>
    <div id="controls">
        <h3>SmokedMeat</h3>
        <div class="control-section">
            <h4>Layout</h4>
            <button class="layout-btn active" data-layout="dagre">Hierarchical</button>
            <button class="layout-btn" data-layout="concentric">Radial</button>
            <button class="layout-btn" data-layout="cose">Force</button>
        </div>
        <div class="control-section">
            <h4>Scope</h4>
            <div id="filter-status" class="scope-text">Loading graph...</div>
            <div class="button-row">
                <button class="mode-btn" data-mode="filtered">Vuln Paths</button>
                <button class="mode-btn" data-mode="full">Full Graph</button>
            </div>
            <div id="filter-description" class="scope-text"></div>
            <div id="layout-warning" class="scope-text"></div>
        </div>
        <div class="control-section">
            <h4>Types</h4>
            <div class="legend-item" data-type="organization"><div class="legend-color" style="background: #ff7f50;"></div>Organization</div>
            <div class="legend-item" data-type="repository"><div class="legend-color" style="background: #4a9eff;"></div>Repository</div>
            <div class="legend-item" data-type="workflow"><div class="legend-color" style="background: #50c878;"></div>Workflow</div>
            <div class="legend-item" data-type="secret"><div class="legend-color" style="background: #ffd700;"></div>Secret</div>
            <div class="legend-item" data-type="cloud"><div class="legend-color" style="background: #95e1d3;"></div>Cloud</div>
            <div class="legend-item" data-type="loot"><div class="legend-color" style="background: #e94560;"></div>Vulnerability</div>
            <div class="legend-item" data-type="private-repo"><div class="legend-color" style="background: #e94560; border: 2px solid #fff;"></div>Private Repo</div>
            <div class="legend-item" data-type="ssh-read"><div class="legend-color" style="background: #4a9eff; border: 3px solid #50c878;"></div>SSH Read</div>
            <div class="legend-item" data-type="ssh-write"><div class="legend-color" style="background: #4a9eff; border: 3px solid #ffd700;"></div>SSH Write</div>
            <div class="legend-item" data-type="agent"><div class="legend-color" style="background: #aa96da;"></div>Agent</div>
        </div>
    </div>
    <div id="stats">Loading...</div>
    <div id="connection-status" class="connecting">Connecting...</div>

    <script>
        const nodeColors = {
            'organization': '#ff7f50',
            'repository': '#4a9eff',
            'workflow': '#50c878',
            'secret': '#ffd700',
            'cloud': '#95e1d3',
            'loot': '#e94560',
            'agent': '#aa96da'
        };

        const nodeShapes = {
            'organization': 'round-rectangle',
            'repository': 'round-rectangle',
            'workflow': 'diamond',
            'secret': 'star',
            'cloud': 'ellipse',
            'loot': 'hexagon',
            'agent': 'pentagon'
        };

        const layouts = {
            dagre: { name: 'dagre', rankDir: 'TB', nodeSep: 50, rankSep: 80, animate: true, animationDuration: 300 },
            concentric: { name: 'concentric', concentric: n => n.data('type') === 'repository' ? 2 : 1, levelWidth: () => 2, animate: true, animationDuration: 300 },
            cose: { name: 'cose', animate: true, animationDuration: 300, nodeRepulsion: 8000, idealEdgeLength: 80 }
        };

        let cy;
        let ws;
        let graphVersion = 0;
        let reconnectAttempts = 0;
        let requestedGraphMode = readGraphMode();
        let resolvedGraphMode = 'full';
        let graphMeta = { totalNodes: 0, totalEdges: 0, largeGraph: false, filterDescription: '' };
        let filteredRefreshTimer = null;

        function initCytoscape() {
            cy = cytoscape({
                container: document.getElementById('cy'),
                style: [
                    {
                        selector: 'node',
                        style: {
                            'label': 'data(label)',
                            'text-valign': 'bottom',
                            'text-halign': 'center',
                            'text-margin-y': 8,
                            'font-size': '10px',
                            'color': '#fff',
                            'text-outline-color': '#1a1a2e',
                            'text-outline-width': 2,
                            'background-color': ele => {
                                if (ele.data('type') === 'repository' && ele.data('properties') && ele.data('properties').private) return '#e94560';
                                if (ele.data('type') === 'vulnerability' && ele.data('properties') && ele.data('properties').exploit_supported === false) return '#6b7280';
                                return nodeColors[ele.data('type')] || '#666';
                            },
                            'shape': ele => nodeShapes[ele.data('type')] || 'ellipse',
                            'width': ele => ele.data('type') === 'organization' ? 50 : (ele.data('type') === 'repository' ? 40 : 30),
                            'height': ele => ele.data('type') === 'organization' ? 50 : (ele.data('type') === 'repository' ? 40 : 30),
                            'border-width': ele => {
                                if (ele.data('type') === 'repository' && ele.data('properties') && ele.data('properties').ssh_access === 'write') return 5;
                                if (ele.data('type') === 'repository' && ele.data('properties') && ele.data('properties').ssh_access === 'read') return 4;
                                if (ele.data('type') === 'repository' && ele.data('properties') && ele.data('properties').private) return 3;
                                return ele.data('state') === 'high_value' ? 3 : 1;
                            },
                            'border-color': ele => {
                                if (ele.data('type') === 'repository' && ele.data('properties') && ele.data('properties').ssh_access === 'write') return '#ffd700';
                                if (ele.data('type') === 'repository' && ele.data('properties') && ele.data('properties').ssh_access === 'read') return '#50c878';
                                if (ele.data('type') === 'repository' && ele.data('properties') && ele.data('properties').private) return '#fff';
                                return ele.data('state') === 'high_value' ? '#fff' : (nodeColors[ele.data('type')] || '#666');
                            },
                            'border-style': ele => {
                                if (ele.data('type') === 'vulnerability' && ele.data('properties') && ele.data('properties').exploit_supported === false) return 'dashed';
                                return ele.data('state') === 'deadend' ? 'dashed' : 'solid';
                            },
                            'opacity': ele => {
                                if (ele.data('type') === 'vulnerability' && ele.data('properties') && ele.data('properties').exploit_supported === false) return 0.65;
                                return ele.data('state') === 'deadend' ? 0.5 : 1;
                            }
                        }
                    },
                    {
                        selector: 'node.new-node',
                        style: { 'overlay-color': '#50c878', 'overlay-opacity': 0.3, 'overlay-padding': 8 }
                    },
                    {
                        selector: 'node.updated-node',
                        style: { 'overlay-color': '#ffd700', 'overlay-opacity': 0.3, 'overlay-padding': 8 }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'width': 2,
                            'line-color': '#555',
                            'target-arrow-color': '#555',
                            'target-arrow-shape': 'triangle',
                            'curve-style': 'bezier',
                            'arrow-scale': 0.8
                        }
                    },
                    {
                        selector: 'node.highlighted',
                        style: { 'border-width': 4, 'border-color': '#e94560' }
                    },
                    {
                        selector: 'edge.highlighted',
                        style: { 'width': 3, 'line-color': '#e94560', 'target-arrow-color': '#e94560' }
                    },
                    {
                        selector: '.dimmed',
                        style: { 'opacity': 0.15 }
                    }
                ],
                layout: layouts.dagre,
                wheelSensitivity: 0.3
            });

            cy.on('tap', 'node', function(e) {
                const node = e.target;
                highlightConnected(node);
            });

            cy.on('tap', function(e) {
                if (e.target === cy) {
                    clearHighlight();
                }
            });

            cy.on('mouseover', 'node', function(e) {
                showTooltip(e.target, e.renderedPosition);
            });

            cy.on('mouseout', 'node', function() {
                hideTooltip();
            });
        }

        function connectWebSocket() {
            const currentUrl = new URL(window.location.href);
            const token = currentUrl.searchParams.get('token');
            const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            let wsUrl = wsProtocol + '//' + window.location.host + '/graph/ws';
            const wsParams = new URLSearchParams();
            if (token) {
                wsParams.set('token', token);
            }
            wsParams.set('mode', requestedGraphMode);
            wsUrl += '?' + wsParams.toString();

            updateConnectionStatus('connecting');
            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                reconnectAttempts = 0;
                updateConnectionStatus('connected');
            };

            ws.onmessage = function(event) {
                const msg = JSON.parse(event.data);
                handleMessage(msg);
            };

            ws.onclose = function() {
                updateConnectionStatus('disconnected');
                scheduleReconnect();
            };

            ws.onerror = function() {
                updateConnectionStatus('disconnected');
            };
        }

        function scheduleReconnect() {
            reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
            setTimeout(connectWebSocket, delay);
        }

        function handleMessage(msg) {
            switch (msg.type) {
                case 'snapshot':
                    handleSnapshot(msg.data);
                    break;
                case 'delta':
                    handleDelta(msg.data);
                    break;
                case 'pong':
                    break;
            }
        }

        function handleSnapshot(data) {
            graphVersion = data.version;
            resolvedGraphMode = data.mode || 'full';
            graphMeta = {
                totalNodes: data.total_nodes || 0,
                totalEdges: data.total_edges || 0,
                largeGraph: !!data.large_graph,
                filterDescription: data.filter_description || ''
            };
            updateScopeControls();
            cy.elements().remove();

            const elements = [];
            (data.nodes || []).forEach(node => {
                elements.push({
                    group: 'nodes',
                    data: {
                        id: node.id,
                        label: truncateLabel(node.label || node.id, 15),
                        type: node.type,
                        state: node.state,
                        properties: node.properties,
                        tooltipProperties: node.tooltip_properties
                    }
                });
            });

            (data.edges || []).forEach(edge => {
                elements.push({
                    group: 'edges',
                    data: {
                        id: edge.source + '-' + edge.target,
                        source: edge.source,
                        target: edge.target,
                        type: edge.type
                    }
                });
            });

            cy.add(elements);
            runLayout();
            updateStats();
        }

        function handleDelta(data) {
            if (resolvedGraphMode !== 'full' || prefersFilteredSnapshots()) {
                scheduleFilteredRefresh();
                return;
            }

            graphVersion = data.version;

            (data.added_nodes || []).forEach(node => {
                cy.add({
                    group: 'nodes',
                    data: {
                        id: node.id,
                        label: truncateLabel(node.label || node.id, 15),
                        type: node.type,
                        state: node.state,
                        properties: node.properties,
                        tooltipProperties: node.tooltip_properties
                    }
                });
                const addedNode = cy.getElementById(node.id);
                addedNode.addClass('new-node');
                setTimeout(() => addedNode.removeClass('new-node'), 2000);
            });

            (data.updated_nodes || []).forEach(update => {
                const node = cy.getElementById(update.id);
                if (node.length) {
                    node.data('state', update.new_state);
                    if (update.label) node.data('label', truncateLabel(update.label, 15));
                    if (update.properties) node.data('properties', update.properties);
                    if (update.tooltip_properties) node.data('tooltipProperties', update.tooltip_properties);
                    node.addClass('updated-node');
                    setTimeout(() => node.removeClass('updated-node'), 2000);
                }
            });

            (data.removed_nodes || []).forEach(id => {
                cy.getElementById(id).remove();
            });

            (data.added_edges || []).forEach(edge => {
                cy.add({
                    group: 'edges',
                    data: {
                        id: edge.source + '-' + edge.target,
                        source: edge.source,
                        target: edge.target,
                        type: edge.type
                    }
                });
            });

            (data.removed_edges || []).forEach(ref => {
                cy.getElementById(ref.source + '-' + ref.target).remove();
            });

            if (!graphMeta.largeGraph && (data.added_nodes || []).length > 2) {
                runLayout();
            }
            updateStats();
        }

        function runLayout() {
            const activeLayout = document.querySelector('.layout-btn.active').dataset.layout;
            cy.layout(layoutConfig(activeLayout)).run();
        }

        function highlightConnected(node) {
            clearHighlight();
            const neighborhood = node.neighborhood().add(node);
            cy.elements().addClass('dimmed');
            neighborhood.removeClass('dimmed');
            neighborhood.addClass('highlighted');
        }

        function clearHighlight() {
            cy.elements().removeClass('dimmed highlighted');
        }

        function showTooltip(node, pos) {
            const tooltip = document.getElementById('tooltip');
            const data = node.data();
            let html = '<div class="title">' + escapeHtml(data.label || data.id) + '</div>';
            html += '<div><span class="field">Type:</span> <span class="value">' + data.type + '</span></div>';
            html += '<div><span class="field">State:</span> <span class="value">' + data.state + '</span></div>';
            html += '<div><span class="field">ID:</span> <span class="value">' + escapeHtml(data.id) + '</span></div>';
            if (data.tooltipProperties) {
                Object.entries(data.tooltipProperties).forEach(([k, v]) => {
                    html += '<div><span class="field">' + escapeHtml(k) + ':</span> <span class="value">' + escapeHtml(v) + '</span></div>';
                });
            }
            tooltip.innerHTML = html;
            tooltip.style.left = (pos.x + 15) + 'px';
            tooltip.style.top = (pos.y + 15) + 'px';
            tooltip.style.opacity = 1;
        }

        function hideTooltip() {
            document.getElementById('tooltip').style.opacity = 0;
        }

        function updateStats() {
            const nodes = cy.nodes().length;
            const edges = cy.edges().length;
            if (resolvedGraphMode === 'filtered') {
                document.getElementById('stats').textContent =
                    'Filtered: ' + nodes + '/' + graphMeta.totalNodes + ' nodes, ' + edges + '/' + graphMeta.totalEdges + ' edges (v' + graphVersion + ')';
                return;
            }
            document.getElementById('stats').textContent = 'Full: ' + nodes + ' nodes, ' + edges + ' edges (v' + graphVersion + ')';
        }

        function updateConnectionStatus(status) {
            const el = document.getElementById('connection-status');
            el.className = status;
            switch (status) {
                case 'connected': el.textContent = 'Connected'; break;
                case 'disconnected': el.textContent = 'Disconnected'; break;
                case 'connecting': el.textContent = 'Connecting...'; break;
            }
        }

        function truncateLabel(label, maxLen) {
            if (!label) return '';
            if (label.length <= maxLen) return label;
            return label.substring(0, maxLen - 1) + '...';
        }

        function readGraphMode() {
            const currentUrl = new URL(window.location.href);
            const mode = currentUrl.searchParams.get('mode');
            if (mode === 'filtered' || mode === 'full') {
                return mode;
            }
            return 'auto';
        }

        function updateGraphURLMode(mode) {
            const currentUrl = new URL(window.location.href);
            if (mode === 'auto') {
                currentUrl.searchParams.delete('mode');
            } else {
                currentUrl.searchParams.set('mode', mode);
            }
            window.history.replaceState({}, '', currentUrl.toString());
        }

        function requestSnapshot(mode) {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                return;
            }
            ws.send(JSON.stringify({
                type: 'snapshot_request',
                data: { mode: mode }
            }));
        }

        function scheduleFilteredRefresh() {
            if (filteredRefreshTimer) {
                return;
            }
            filteredRefreshTimer = window.setTimeout(function() {
                filteredRefreshTimer = null;
                requestSnapshot(requestedGraphMode);
            }, 250);
        }

        function prefersFilteredSnapshots() {
            return requestedGraphMode === 'filtered' || (requestedGraphMode === 'auto' && graphMeta.largeGraph);
        }

        function setGraphMode(mode) {
            if (mode !== 'filtered' && mode !== 'full') {
                return;
            }
            if (mode === 'full' && graphMeta.largeGraph) {
                const proceed = window.confirm('This graph is large. Full mode may be slow and harder to explore. Continue?');
                if (!proceed) {
                    return;
                }
            }
            requestedGraphMode = mode;
            updateGraphURLMode(mode);
            requestSnapshot(mode);
        }

        function updateScopeControls() {
            const status = document.getElementById('filter-status');
            const description = document.getElementById('filter-description');
            const warning = document.getElementById('layout-warning');

            let statusText = resolvedGraphMode === 'filtered' ? 'Filtered graph' : 'Full graph';
            if (requestedGraphMode === 'auto' && graphMeta.largeGraph) {
                statusText += ' (auto)';
            }
            status.textContent = statusText;
            description.textContent = graphMeta.filterDescription || (resolvedGraphMode === 'filtered' ? 'Showing vuln-bearing paths only.' : 'Showing the full graph.');

            if (graphMeta.largeGraph) {
                if (resolvedGraphMode === 'filtered') {
                    warning.textContent = 'Large graph detected. Filtered mode keeps the first view smaller and safer.';
                } else {
                    warning.textContent = 'Full mode on a large graph may be slow. Force layout is the riskiest option.';
                }
            } else {
                warning.textContent = '';
            }

            document.querySelectorAll('.mode-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.mode === resolvedGraphMode);
            });
        }

        function layoutConfig(name) {
            const config = Object.assign({}, layouts[name]);
            if (!graphMeta.largeGraph) {
                return config;
            }
            config.animate = false;
            if (name === 'dagre') {
                config.nodeSep = 25;
                config.rankSep = 50;
            }
            if (name === 'cose') {
                config.numIter = 250;
                config.nodeRepulsion = 4000;
                config.idealEdgeLength = 70;
            }
            return config;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        document.querySelectorAll('.layout-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                if (graphMeta.largeGraph && this.dataset.layout === 'cose') {
                    const proceed = window.confirm('Force layout can be slow on large graphs. Continue?');
                    if (!proceed) {
                        return;
                    }
                }
                document.querySelectorAll('.layout-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                runLayout();
            });
        });

        document.querySelectorAll('.mode-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                setGraphMode(this.dataset.mode);
            });
        });

        document.addEventListener('keydown', function(e) {
            if (e.key === '1') { document.querySelector('[data-layout="dagre"]').click(); }
            if (e.key === '2') { document.querySelector('[data-layout="concentric"]').click(); }
            if (e.key === '3') { document.querySelector('[data-layout="cose"]').click(); }
            if (e.key === 'f') { cy.fit(cy.elements(':visible'), 50); }
            if (e.key === 'r') { clearHighlight(); }
        });

        initCytoscape();
        connectWebSocket();
    </script>
</body>
</html>`
