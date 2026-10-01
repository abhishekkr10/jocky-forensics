import React from 'react';
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { IntegrityChain, RiskGauge, Sparkline, TimeAxis } from './InvestigationVisuals';
import { CoverageIntelligence } from './App';

describe('investigation views', () => {
  it('keeps gaps in historical metrics instead of implying measurements', () => {
    const html = renderToStaticMarkup(<Sparkline values={[1, null, 2]} label="Recorded findings"/>);
    expect(html).toContain('1, unavailable, 2');
    expect(html).toContain('d="M4,19  M116,6"');
    expect(html).toContain('gaps unavailable');
  });
  it('handles empty and malformed timestamps without inventing time', () => {
    expect(renderToStaticMarkup(<TimeAxis timeline={[]} onEvent={() => {}}/>)).toContain('No timestamped observations');
    expect(renderToStaticMarkup(<TimeAxis timeline={[{ event_time: 'invalid' }]} onEvent={() => {}}/>)).not.toContain('NaN');
    const html = renderToStaticMarkup(<TimeAxis timeline={[1, 2].map(i => ({ observed_at: '2026-01-01T00:00:00Z', provenance_kind: 'synthetic', evidence_ids: [String(i)] }))} onEvent={() => {}}/>);
    expect(html).toContain('T+0.0s');
    expect(html).toContain('share one timestamp');
    expect(html).not.toContain('T+3');
  });
  it('uses the collector artifact types for system and startup coverage', () => {
    const html = renderToStaticMarkup(<CoverageIntelligence evidence={[{artifact_type:'system_information'},{artifact_type:'startup_items'}]} coverage={[]} operations={[]}/>);
    expect(html.match(/coverage-dot available/g)).toHaveLength(2);
  });
  it('shows real chain fields and does not certify records in an invalid bundle', () => {
    const html = renderToStaticMarkup(<IntegrityChain evidence={[{ evidence_id:'one', sequence:1, record_digest:'abcdef123456', previous_hash:'9876543210', artifact_type:'files' }]} verification={{integrity:'invalid',error:'Signature mismatch'}} onOpen={() => {}}/>);
    expect(html).toContain('abcdef12'); expect(html).toContain('98765432');
    expect(html).toContain('Unverified record'); expect(html).not.toContain('Verified bundle');
  });
  it('clamps the gauge and links actual contribution evidence', () => {
    const html = renderToStaticMarkup(<RiskGauge risk={{score:150,contributions:[{reason:'Sigma',points:25,detection_id:'d'}]}} detections={[{id:'d',evidence_ids:['record-a']}]} onEvidence={() => {}}/>);
    expect(html).toContain('100 of 100'); expect(html).toContain('record-a');
  });
});
