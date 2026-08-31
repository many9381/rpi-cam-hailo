import type { StreamStatus } from '../api/types';
import { useTranslation } from '../i18n/LanguageContext';

export function StreamPanel({ stream }: { stream: StreamStatus }) {
  const { t } = useTranslation();
  const zeroizeCount = stream.secure_media.per_media_key_zeroize_count;
  return (
    <section className="operational-section" aria-labelledby="stream-heading">
      <div className="section-heading">
        <div>
          <h2 id="stream-heading">{t('stream.title')}</h2>
          <p>{t('stream.subtitle')}</p>
        </div>
      </div>
      <dl className="detail-grid data-card stream-details">
        <div className="detail-wide"><dt>{t('stream.address')}</dt><dd>{stream.url}</dd></div>
        <div><dt>{t('stream.control')}</dt><dd>{stream.control_tls ? t('stream.rtspsTls') : t('stream.rtsp')}</dd></div>
        <div><dt>{t('stream.media')}</dt><dd>{stream.media_srtp ? t('stream.srtp') : t('stream.rtp')}</dd></div>
        <div><dt>{t('stream.profile')}</dt><dd>{stream.secure_media.media_profile}</dd></div>
        <div><dt>{t('stream.keying')}</dt><dd>{stream.secure_media.keying}</dd></div>
        <div><dt>{t('stream.tlsControlRequired')}</dt><dd>
          {stream.secure_media.requires_tls_control_channel ? t('stream.yes') : t('stream.no')}
        </dd></div>
        <div><dt>{t('stream.mediaKeysZeroized')}</dt><dd>{zeroizeCount ?? t('stream.unavailable')}</dd></div>
      </dl>
    </section>
  );
}
