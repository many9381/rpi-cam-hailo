import type { AuditStatusController } from './useAuditStatus';

interface AuditCapacityNoticeProps {
  controller?: AuditStatusController;
}

export function AuditCapacityNotice({ controller }: AuditCapacityNoticeProps) {
  const status = controller?.data;
  if (status === null || status === undefined || !status.warning) {
    return null;
  }

  return (
    <div className="settings-shell-notice audit-capacity-notice" role="alert">
      <span>
        Audit storage is at {status.usage_percent}%: {status.current_events} of{' '}
        {status.max_events} audit records are retained.
        {controller?.state === 'stale' && ' Capacity status may be out of date.'}
      </span>
      <a href="#/system#audit-records">Review audit records</a>
    </div>
  );
}
