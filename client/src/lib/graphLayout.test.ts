import { describe, expect, it } from 'vitest';
import type { EvidenceGraph, GraphNode } from '@phishlens/shared';
import { layoutGraph } from './graphLayout';

const n = (id: string): GraphNode => ({ id, type: 'domain', label: id, indicatorIds: [], risk: null, facts: [] });

describe('layoutGraph', () => {
  it('places every node, children to the right of parents, parents centred on children', () => {
    const g: EvidenceGraph = {
      rootId: 'r',
      nodes: ['r', 'a', 'b', 'a1', 'a2', 'orphan'].map(n),
      edges: [
        { id: '1', from: 'r', to: 'a', label: '' },
        { id: '2', from: 'r', to: 'b', label: '' },
        { id: '3', from: 'a', to: 'a1', label: '' },
        { id: '4', from: 'a', to: 'a2', label: '' },
        { id: '5', from: 'b', to: 'a1', label: '' },
      ],
    };
    const l = layoutGraph(g);
    expect(l.nodes.size).toBe(6);
    const p = (id: string) => l.nodes.get(id)!;
    expect(p('a1').x).toBeGreaterThan(p('a').x);
    expect(p('a').y).toBe((p('a1').y + p('a2').y) / 2);
    expect(l.treeEdges.has('b->a1')).toBe(false); // a1 already placed under a
    expect(p('orphan').depth).toBe(1);
    const ys = [...l.nodes.values()].filter((x) => x.depth === 2).map((x) => x.y);
    expect(new Set(ys).size).toBe(ys.length); // no overlaps in a column
  });

  it('handles a lone root', () => {
    expect(layoutGraph({ rootId: 'r', nodes: [n('r')], edges: [] }).nodes.get('r')).toMatchObject({ x: 0, y: 0 });
  });
});
