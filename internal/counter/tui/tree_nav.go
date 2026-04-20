// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

func (m *Model) TreeCursorUp() {
	if len(m.treeNodes) == 0 {
		return
	}
	m.treeCursor--
	if m.treeCursor < 0 {
		m.treeCursor = len(m.treeNodes) - 1
	}
}

func (m *Model) TreeCursorDown() {
	if len(m.treeNodes) == 0 {
		return
	}
	m.treeCursor++
	if m.treeCursor >= len(m.treeNodes) {
		m.treeCursor = 0
	}
}

func (m *Model) TreeToggleExpand() {
	node := m.SelectedTreeNode()
	if node == nil {
		return
	}

	if node.HasChildren() {
		node.Toggle()
		m.ReflattenTree()
	}
}

func (m *Model) TreeExpand() {
	node := m.SelectedTreeNode()
	if node == nil {
		return
	}

	if node.HasChildren() && !node.Expanded {
		node.Expanded = true
		m.ReflattenTree()
	}
}

func (m *Model) TreeCollapse() {
	node := m.SelectedTreeNode()
	if node == nil {
		return
	}

	if node.HasChildren() && node.Expanded {
		node.Expanded = false
		m.ReflattenTree()
	} else if node.Parent != nil && node.Parent.ID != "root" {
		m.treeGoToParent()
	}
}

func (m *Model) TreeExpandAll() {
	if m.treeRoot == nil {
		return
	}
	expandAllRecursive(m.treeRoot)
	m.ReflattenTree()
}

func expandAllRecursive(node *TreeNode) {
	node.Expanded = true
	for _, child := range node.Children {
		expandAllRecursive(child)
	}
}

func (m *Model) TreeCollapseAll() {
	if m.treeRoot == nil {
		return
	}
	collapseAllRecursive(m.treeRoot)
	m.treeRoot.Expanded = true
	m.ReflattenTree()
}

func collapseAllRecursive(node *TreeNode) {
	node.Expanded = false
	for _, child := range node.Children {
		collapseAllRecursive(child)
	}
}

func (m *Model) treeGoToParent() {
	node := m.SelectedTreeNode()
	if node == nil || node.Parent == nil {
		return
	}

	if node.Parent.ID == "root" {
		return
	}

	for i, n := range m.treeNodes {
		if n == node.Parent {
			m.treeCursor = i
			return
		}
	}
}

func (m *Model) TreeSelectByID(id string) bool {
	node := findNodeByID(m.treeRoot, id)
	if node == nil {
		node = m.findTreeNodeForVulnerabilityID(id)
	}
	if node == nil {
		return false
	}
	expandNodeAncestors(node)
	m.ReflattenTree()
	for i, current := range m.treeNodes {
		if current == node {
			m.treeCursor = i
			return true
		}
	}
	return false
}

func (m *Model) findTreeNodeForVulnerabilityID(id string) *TreeNode {
	if id == "" {
		return nil
	}
	for i := range m.vulnerabilities {
		if m.vulnerabilities[i].ID != id {
			continue
		}
		return m.findTreeNodeForVulnerability(m.treeRoot, m.vulnerabilities[i])
	}
	return nil
}

func (m *Model) findTreeNodeForVulnerability(node *TreeNode, vuln Vulnerability) *TreeNode {
	if node == nil {
		return nil
	}
	if node.Type == TreeNodeVuln && m.nodeMatchesVuln(node, vuln) {
		return node
	}
	for _, child := range node.Children {
		if match := m.findTreeNodeForVulnerability(child, vuln); match != nil {
			return match
		}
	}
	return nil
}

func findNodeByID(root *TreeNode, id string) *TreeNode {
	if root == nil {
		return nil
	}
	if root.ID == id {
		return root
	}
	for _, child := range root.Children {
		if node := findNodeByID(child, id); node != nil {
			return node
		}
	}
	return nil
}

func expandNodeAncestors(node *TreeNode) {
	for current := node; current != nil; current = current.Parent {
		current.Expanded = true
	}
}
