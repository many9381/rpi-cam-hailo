import type { StreamStatus } from '../api/types';

export function StreamPanel({ stream }: { stream: StreamStatus }) {
  const zeroizeCount = stream.secure_media.per_media_key_zeroize_count;
  return (
    <section className="operational-section" aria-labelledby="stream-heading">
      <div className="section-heading">
        <div>
          <h2 id="stream-heading">Stream connection</h2>
          <p>RTSP client connection details</p>
        </div>
      </div>
      <dl className="detail-grid data-card stream-details">
        <div className="detail-wide"><dt>Address</dt><dd>{stream.url}</dd></div>
        <div><dt>Control</dt><dd>{stream.control_tls ? 'RTSPS / TLS' : 'RTSP'}</dd></div>
        <div><dt>Media</dt><dd>{stream.media_srtp ? 'SRTP' : 'RTP'}</dd></div>
        <div><dt>Profile</dt><dd>{stream.secure_media.media_profile}</dd></div>
        <div><dt>Keying</dt><dd>{stream.secure_media.keying}</dd></div>
        <div><dt>TLS control required</dt><dd>
          {stream.secure_media.requires_tls_control_channel ? 'Yes' : 'No'}
        </dd></div>
        <div><dt>Media keys zeroized</dt><dd>{zeroizeCount ?? 'Unavailable'}</dd></div>
      </dl>
    </section>
  );
}
