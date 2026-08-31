import {
  AlertTriangle,
  Play,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';

import { IconButton } from '../../components/IconButton';
import type {
  ProtectionItemResult,
  ProtectionSnapshot,
  ProtectionSuiteResult,
} from './contracts';
import type { SystemProtectionController } from './useSystemProtection';

interface SystemProtectionPanelProps {
  controller: SystemProtectionController;
}

export function SystemProtectionPanel(
  { controller }: SystemProtectionPanelProps,
) {
  const snapshot = controller.snapshot;
  const busy = controller.state === 'loading' || snapshot?.check_running === true;
  const unknownCheckRunning = snapshot?.check_running === true &&
    controller.activeCommand === null;
  const selfTestRunning = snapshot?.check_running === true &&
    (controller.activeCommand === 'self_test' || unknownCheckRunning);
  const integrityRunning = snapshot?.check_running === true &&
    (controller.activeCommand === 'integrity' || unknownCheckRunning);

  const run = (command: () => Promise<void>) => {
    void command().catch(() => undefined);
  };

  return (
    <section className="operational-section protection-section"
      aria-labelledby="system-protection-heading">
      <div className="section-heading protection-heading">
        <div>
          <h2 id="system-protection-heading">
            <ShieldCheck size={18} aria-hidden="true" />
            System protection
          </h2>
          <p>Security self-tests and signed firmware integrity</p>
        </div>
        <IconButton label="Refresh system protection" disabled={busy}
          onClick={() => run(controller.refresh)}>
          <RefreshCw size={17} aria-hidden="true" />
        </IconButton>
      </div>

      {snapshot === null ? (
        <ProtectionUnavailable controller={controller} />
      ) : (
        <>
          <ProtectionSummary snapshot={snapshot} />
          {controller.publicMessage !== null && (
            <p className={controller.state === 'stale'
              ? 'protection-message protection-message-stale'
              : 'protection-message protection-message-error'}
              role={controller.state === 'stale' ? 'status' : 'alert'}>
              {controller.publicMessage}
            </p>
          )}
          <div className="protection-suites">
            <ProtectionSuite label="Security self-test" result={snapshot.self_test} />
            <ProtectionSuite label="Integrity check" result={snapshot.integrity} />
          </div>
          <div className="protection-actions" aria-label="System protection commands">
            <button type="button" className="protection-command-button"
              aria-label={selfTestRunning
                ? unknownCheckRunning
                  ? 'Protection check running; security self-test unavailable'
                  : 'Security self-test running'
                : 'Run security self-test'}
              title={selfTestRunning ? 'Security self-test running' : 'Run security self-test'}
              aria-busy={selfTestRunning || undefined}
              disabled={busy} onClick={() => run(controller.runSelfTest)}>
              {selfTestRunning
                ? <RefreshCw className="protection-progress-icon" size={16}
                    aria-hidden="true" />
                : <Play size={16} aria-hidden="true" />}
              {selfTestRunning
                ? unknownCheckRunning ? 'Check running' : 'Self-test running'
                : 'Run self-test'}
            </button>
            <button type="button" className="protection-command-button"
              aria-label={integrityRunning
                ? unknownCheckRunning
                  ? 'Protection check running; integrity check unavailable'
                  : 'Integrity check running'
                : 'Run integrity check'}
              title={integrityRunning ? 'Integrity check running' : 'Run integrity check'}
              aria-busy={integrityRunning || undefined}
              disabled={busy} onClick={() => run(controller.runIntegrityCheck)}>
              {integrityRunning
                ? <RefreshCw className="protection-progress-icon" size={16}
                    aria-hidden="true" />
                : <Play size={16} aria-hidden="true" />}
              {integrityRunning
                ? unknownCheckRunning ? 'Check running' : 'Integrity check running'
                : 'Run integrity check'}
            </button>
          </div>
        </>
      )}
    </section>
  );
}

function formatUtc(seconds: number): string {
  if (seconds === 0) {
    return 'Not scheduled';
  }
  const date = new Date(seconds * 1_000);
  return Number.isFinite(date.getTime())
    ? date.toISOString().replace(/T(\d{2}:\d{2}:\d{2})\.\d{3}Z$/, ' $1 UTC')
    : 'Unavailable';
}

function stateLabel(state: ProtectionSnapshot['state']): string {
  if (state === 'operational') return 'Operational';
  if (state === 'restricted') return 'Restricted';
  return 'Checking';
}

function ProtectionSummary({ snapshot }: { snapshot: ProtectionSnapshot }) {
  const restricted = snapshot.state === 'restricted';
  return (
    <div className="protection-summary" aria-label="System protection status">
      <div>
        <span>Protection state</span>
        <strong className={`protection-state protection-state-${snapshot.state}`}>
          {restricted && <AlertTriangle size={15} aria-hidden="true" />}
          {stateLabel(snapshot.state)}
        </strong>
      </div>
      <div>
        <span>Next scheduled run</span>
        <strong>{formatUtc(snapshot.next_periodic_at_seconds)}</strong>
      </div>
    </div>
  );
}

function itemCategory(item: ProtectionItemResult): string | null {
  if (item.category === null) return null;
  return item.category.replace(/_/g, ' ');
}

function ProtectionSuite({ label, result }: {
  label: string;
  result: ProtectionSuiteResult | null;
}) {
  return (
    <div className="protection-suite">
      <div className="protection-suite-heading">
        <div>
          <h3>{label}</h3>
          <span>{result === null
            ? 'Not run'
            : `${result.trigger} at ${formatUtc(result.finished_at_seconds)}`}</span>
        </div>
        <strong className={result === null
          ? 'protection-suite-neutral'
          : result.passed ? 'protection-suite-passed' : 'protection-suite-failed'}>
          {result === null ? 'Pending' : result.passed ? 'Passed' : 'Failed'}
        </strong>
      </div>
      {result !== null && result.items.length === 0 && (
        <p className="protection-empty-items">No individual results reported.</p>
      )}
      {result !== null && result.items.length > 0 && (
        <ul className="protection-item-list" aria-label={`${label} results`}>
          {result.items.map((item, index) => (
            <li key={`${item.id}-${index}`} className={item.passed
              ? 'protection-item protection-item-passed'
              : 'protection-item protection-item-failed'}>
              <span className="protection-item-identity">
                <strong>{item.id === '' ? 'Unnamed check' : item.id}</strong>
                {itemCategory(item) !== null && <small>{itemCategory(item)}</small>}
              </span>
              <span>{item.passed ? 'Passed' : 'Failed'}</span>
              <code className="protection-item-code">
                {item.code === '' ? '-' : item.code}
              </code>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ProtectionUnavailable({ controller }: {
  controller: SystemProtectionController;
}) {
  if (controller.state === 'loading') {
    return <p className="protection-resource-state" role="status">
      Loading system protection...
    </p>;
  }
  return (
    <div className="protection-resource-state protection-resource-error" role="alert">
      <span>{controller.publicMessage ??
        'System protection is temporarily unavailable.'}</span>
      <button type="button" className="protection-command-button"
        aria-label="Retry system protection" title="Retry system protection"
        onClick={() => void controller.refresh().catch(() => undefined)}>
        <RefreshCw size={16} aria-hidden="true" />
        Retry
      </button>
    </div>
  );
}
