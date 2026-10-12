import type { EvidenceGraph } from '@phishlens/shared';

export interface LaidOutNode {
  id: string;
  x: number;
  y: number;
  depth: number;
}
export interface Layout {
  nodes: Map<string, LaidOutNode>;
  treeEdges: Set<string>;
  width: number;
  height: number;
}

export const NODE_W = 196;
export const NODE_H = 46;
const COL_W = 256;
const ROW_H = 60;

/**
 * Left-to-right tidy tree. A spanning tree is taken by BFS from the root along
 * edge direction (first parent wins); leaves get consecutive rows and parents are
 * centred on their children. Edges outside the spanning tree are still drawn,
 * just not used for placement. Deterministic for a given graph.
 */
export function layoutGraph(g: EvidenceGraph): Layout {
  const out = new Map<string, string[]>();
  for (const n of g.nodes) out.set(n.id, []);
  for (const e of g.edges) out.get(e.from)?.push(e.to);

  const parent = new Map<string, string | null>([[g.rootId, null]]);
  const children = new Map<string, string[]>();
  const depth = new Map<string, number>([[g.rootId, 0]]);
  const treeEdges = new Set<string>();
  const queue = [g.rootId];
  while (queue.length) {
    const id = queue.shift()!;
    children.set(id, []);
    for (const to of out.get(id) ?? []) {
      if (parent.has(to)) continue;
      parent.set(to, id);
      depth.set(to, depth.get(id)! + 1);
      children.get(id)!.push(to);
      treeEdges.add(`${id}->${to}`);
      queue.push(to);
    }
  }
  // Nodes unreachable along edge direction hang off the root.
  for (const n of g.nodes) {
    if (parent.has(n.id)) continue;
    parent.set(n.id, g.rootId);
    depth.set(n.id, 1);
    children.get(g.rootId)!.push(n.id);
    children.set(n.id, []);
  }

  const nodes = new Map<string, LaidOutNode>();
  let leaf = 0;
  const place = (id: string): number => {
    const kids = children.get(id) ?? [];
    let row: number;
    if (kids.length === 0) row = leaf++;
    else {
      const rows = kids.map(place);
      row = (rows[0]! + rows[rows.length - 1]!) / 2;
    }
    nodes.set(id, { id, depth: depth.get(id)!, x: depth.get(id)! * COL_W, y: row * ROW_H });
    return row;
  };
  place(g.rootId);

  const maxDepth = Math.max(0, ...[...nodes.values()].map((n) => n.depth));
  return { nodes, treeEdges, width: maxDepth * COL_W + NODE_W, height: Math.max(1, leaf) * ROW_H };
}
