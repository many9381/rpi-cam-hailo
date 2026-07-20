import { AlertTriangle } from 'lucide-react';

import type { SystemProtectionController } from './useSystemProtection';

interface ProtectionNoticeProps {
  controller?: SystemProtectionController;
}

export function ProtectionNotice({ controller }: ProtectionNoticeProps) {
  if (controller?.snapshot?.state !== 'restricted') {
    return null;
  }
  return (
    <div className="settings-shell-notice protection-shell-notice" role="alert">
      <span>
        <AlertTriangle size={17} aria-hidden="true" />
        System protection is restricted. Camera, stream, and AI runtime are stopped.
      </span>
      <a href="#/system">Review system protection</a>
    </div>
  );
}
