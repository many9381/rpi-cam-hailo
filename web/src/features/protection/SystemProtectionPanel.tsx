import {
  AlertTriangle,
  Play,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';

import { IconButton } from '../../components/IconButton';
import { useTranslation } from '../../i18n/LanguageContext';
import type {
  IntegrityCategory,
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
  const { t } = useTranslation();
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
            {t('protection.title')}
          </h2>
          <p>{t('protection.subtitle')}</p>
        </div>
        <IconButton label={t('protection.refresh')} disabled={busy}
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
            <ProtectionSuite label={t('protection.selfTestSuite')} result={snapshot.self_test} />
            <ProtectionSuite label={t('protection.integrityCheckSuite')}
              result={snapshot.integrity} />
          </div>
          <div className="protection-actions" aria-label={t('protection.commandsLabel')}>
            <button type="button" className="protection-command-button"
              aria-label={selfTestRunning
                ? unknownCheckRunning
                  ? t('protection.selfTestUnavailableWhileChecking')
                  : t('protection.selfTestRunningAria')
                : t('protection.runSelfTestAria')}
              title={selfTestRunning
                ? t('protection.selfTestRunningAria')
                : t('protection.runSelfTestAria')}
              aria-busy={selfTestRunning || undefined}
              disabled={busy} onClick={() => run(controller.runSelfTest)}>
              {selfTestRunning
                ? <RefreshCw className="protection-progress-icon" size={16}
                    aria-hidden="true" />
                : <Play size={16} aria-hidden="true" />}
              {selfTestRunning
                ? unknownCheckRunning
                  ? t('protection.checkRunning')
                  : t('protection.selfTestRunningShort')
                : t('protection.runSelfTestShort')}
            </button>
            <button type="button" className="protection-command-button"
              aria-label={integrityRunning
                ? unknownCheckRunning
                  ? t('protection.integrityUnavailableWhileChecking')
                  : t('protection.integrityCheckRunning')
                : t('protection.runIntegrityCheck')}
              title={integrityRunning
                ? t('protection.integrityCheckRunning')
                : t('protection.runIntegrityCheck')}
              aria-busy={integrityRunning || undefined}
              disabled={busy} onClick={() => run(controller.runIntegrityCheck)}>
              {integrityRunning
                ? <RefreshCw className="protection-progress-icon" size={16}
                    aria-hidden="true" />
                : <Play size={16} aria-hidden="true" />}
              {integrityRunning
                ? unknownCheckRunning
                  ? t('protection.checkRunning')
                  : t('protection.integrityCheckRunning')
                : t('protection.runIntegrityCheck')}
            </button>
          </div>
        </>
      )}
    </section>
  );
}

// Formatted UTC text is data, not copy, so it is returned directly; the
// 'not scheduled' and 'unavailable' cases return an i18n key instead since
// this module-scope helper has no access to the translator.
type UtcText = { text: string } | { key: string };

function formatUtc(seconds: number): UtcText {
  if (seconds === 0) {
    return { key: 'protection.notScheduled' };
  }
  const date = new Date(seconds * 1_000);
  return Number.isFinite(date.getTime())
    ? { text: date.toISOString().replace(/T(\d{2}:\d{2}:\d{2})\.\d{3}Z$/, ' $1 UTC') }
    : { key: 'stream.unavailable' };
}

function resolveUtcText(result: UtcText, t: (key: string) => string): string {
  return 'text' in result ? result.text : t(result.key);
}

const PROTECTION_STATE_LABEL_KEYS: Record<ProtectionSnapshot['state'], string> = {
  operational: 'status.deviceOperational',
  restricted: 'status.deviceRestricted',
  checking: 'status.deviceChecking',
};

const INTEGRITY_CATEGORY_LABEL_KEYS: Record<IntegrityCategory, string> = {
  firmware: 'protection.categoryFirmware',
  library: 'protection.categoryLibrary',
  configuration: 'protection.categoryConfiguration',
  web_asset: 'protection.categoryWebAsset',
  kernel: 'protection.categoryKernel',
  kernel_module: 'protection.categoryKernelModule',
};

function ProtectionSummary({ snapshot }: { snapshot: ProtectionSnapshot }) {
  const { t } = useTranslation();
  const restricted = snapshot.state === 'restricted';
  return (
    <div className="protection-summary" aria-label={t('protection.statusLabel')}>
      <div>
        <span>{t('protection.protectionState')}</span>
        <strong className={`protection-state protection-state-${snapshot.state}`}>
          {restricted && <AlertTriangle size={15} aria-hidden="true" />}
          {t(PROTECTION_STATE_LABEL_KEYS[snapshot.state])}
        </strong>
      </div>
      <div>
        <span>{t('protection.nextScheduledRun')}</span>
        <strong>{resolveUtcText(formatUtc(snapshot.next_periodic_at_seconds), t)}</strong>
      </div>
    </div>
  );
}

function itemCategoryKey(item: ProtectionItemResult): string | null {
  if (item.category === null) return null;
  return INTEGRITY_CATEGORY_LABEL_KEYS[item.category];
}

function ProtectionSuite({ label, result }: {
  label: string;
  result: ProtectionSuiteResult | null;
}) {
  const { t } = useTranslation();
  return (
    <div className="protection-suite">
      <div className="protection-suite-heading">
        <div>
          <h3>{label}</h3>
          <span>{result === null
            ? t('protection.notRun')
            : t('protection.triggerAt', {
              trigger: result.trigger,
              timestamp: resolveUtcText(formatUtc(result.finished_at_seconds), t),
            })}</span>
        </div>
        <strong className={result === null
          ? 'protection-suite-neutral'
          : result.passed ? 'protection-suite-passed' : 'protection-suite-failed'}>
          {result === null ? t('protection.pending')
            : result.passed ? t('protection.passed') : t('protection.failed')}
        </strong>
      </div>
      {result !== null && result.items.length === 0 && (
        <p className="protection-empty-items">{t('protection.noItemResults')}</p>
      )}
      {result !== null && result.items.length > 0 && (
        <ul className="protection-item-list" aria-label={t('protection.suiteResultsLabel', { label })}>
          {result.items.map((item, index) => {
            const categoryKey = itemCategoryKey(item);
            return (
              <li key={`${item.id}-${index}`} className={item.passed
                ? 'protection-item protection-item-passed'
                : 'protection-item protection-item-failed'}>
                <span className="protection-item-identity">
                  <strong>{item.id === '' ? t('protection.unnamedCheck') : item.id}</strong>
                  {categoryKey !== null && <small>{t(categoryKey)}</small>}
                </span>
                <span>{item.passed ? t('protection.passed') : t('protection.failed')}</span>
                <code className="protection-item-code">
                  {item.code === '' ? '-' : item.code}
                </code>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function ProtectionUnavailable({ controller }: {
  controller: SystemProtectionController;
}) {
  const { t } = useTranslation();
  if (controller.state === 'loading') {
    return <p className="protection-resource-state" role="status">
      {t('protection.loading')}
    </p>;
  }
  return (
    <div className="protection-resource-state protection-resource-error" role="alert">
      <span>{controller.publicMessage ??
        t('protection.unavailableMessage')}</span>
      <button type="button" className="protection-command-button"
        aria-label={t('protection.retry')} title={t('protection.retry')}
        onClick={() => void controller.refresh().catch(() => undefined)}>
        <RefreshCw size={16} aria-hidden="true" />
        {t('common.retry')}
      </button>
    </div>
  );
}
