import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { ApiClient } from './api/client';
import { App } from './App';
import { LanguageProvider } from './i18n';
import './styles.css';

const root = document.getElementById('root');

if (root === null) {
  throw new Error('Application root is missing');
}

createRoot(root).render(
  <StrictMode>
    <LanguageProvider>
      <App client={new ApiClient()} />
    </LanguageProvider>
  </StrictMode>,
);
