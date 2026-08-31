import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { LanguageProvider } from '../i18n';
import { StreamPanel } from './StreamPanel';

afterEach(cleanup);

describe('StreamPanel', () => {
  it('renders RTSP as connection information with secure media diagnostics', () => {
    render(<LanguageProvider><StreamPanel stream={{
      url: 'rtsps://camera.local:8555/imx708/main',
      control_tls: true,
      media_srtp: true,
      secure_media: {
        control_scheme: 'rtsps', media_profile: 'RTP/SAVPF',
        keying: 'SDES-over-RTSPS', requires_tls_control_channel: true,
        per_media_key_zeroize_count: 7,
      },
    }} /></LanguageProvider>);

    expect(screen.getByText('rtsps://camera.local:8555/imx708/main')).toBeVisible();
    expect(screen.getByText('RTP/SAVPF')).toBeVisible();
    expect(screen.getByText('7')).toBeVisible();
    expect(screen.queryByRole('video')).not.toBeInTheDocument();
  });
});
